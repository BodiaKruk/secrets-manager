"""CachedSecretProvider — in-memory TTL cache with primary/fallback and audit logging.

Architecture:
  - Decorates two SecretProvider instances: primary (always tried first) and
    optional fallback (used when primary raises BackendUnavailableError,
    TimeoutError, or AccessDeniedError).
  - Cache key: (name, version_or_empty_string)
  - Concurrency: threading.RLock (reentrant — safe to call from audit callbacks).
  - Monotonic clock: time.monotonic() for TTL arithmetic (immune to NTP jumps).
  - Dynamic secret TTL: min(configured_ttl, lease_duration * 0.9).
  - Fallback results carry is_fallback=True but are NOT stored in the cache
    (next call still tries primary first).

Prometheus counters (if prometheus_client available):
  secrets_cache_hits_total{backend}
  secrets_cache_misses_total{backend}
  secrets_cache_size{backend}
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any

from secretsmanager.audit import AuditLogger
from secretsmanager.interface import (
    AccessDeniedError,
    BackendUnavailableError,
    RotationPolicy,
    SecretProvider,
    SecretValue,
)

try:
    from prometheus_client import Counter, Gauge  # type: ignore[import-untyped]

    _PROMETHEUS = True
    _CACHE_HITS = Counter(
        "secrets_cache_hits_total",
        "Cache hits",
        ["backend"],
    )
    _CACHE_MISSES = Counter(
        "secrets_cache_misses_total",
        "Cache misses (backend calls)",
        ["backend"],
    )
    _CACHE_SIZE = Gauge(
        "secrets_cache_size",
        "Current number of live cache entries",
        ["backend"],
    )
except ImportError:  # pragma: no cover
    _PROMETHEUS = False


# ---------------------------------------------------------------------------
# Internal entry
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _Entry:
    secret: SecretValue
    cache_expires: float  # time.monotonic() deadline for the cache entry
    hits: int = 0


# ---------------------------------------------------------------------------
# CachedSecretProvider
# ---------------------------------------------------------------------------


class CachedSecretProvider(SecretProvider):
    """TTL cache wrapping a primary provider with an optional fallback.

    Args:
        primary:      The authoritative backend to query on a cache miss.
        fallback:     Optional secondary provider used when *primary* is
                      unavailable.  Fallback responses are NOT cached.
        ttl_seconds:  Default cache TTL in seconds (default 300).
                      For dynamic secrets, effective TTL = min(ttl, lease*0.9).
        max_size:     Max entries before LFU eviction (default 1 024).
        audit_logger: Optional :class:`AuditLogger` — every hit/miss/fallback
                      is recorded when provided.
        client_id:    Identity tag appended to audit records.
    """

    def __init__(
        self,
        primary: SecretProvider,
        fallback: SecretProvider | None = None,
        *,
        ttl_seconds: float = 300.0,
        max_size: int = 1024,
        audit_logger: AuditLogger | None = None,
        client_id: str = "cache",
    ) -> None:
        self._primary = primary
        self._fallback = fallback
        self._ttl = ttl_seconds
        self._max_size = max_size
        self._audit = audit_logger
        self._client_id = client_id
        self._store: dict[tuple[str, str], _Entry] = {}
        self._lock = threading.RLock()

    @property
    def backend_name(self) -> str:
        return self._primary.backend_name

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _key(self, name: str, version: str | None) -> tuple[str, str]:
        return (name, version or "")

    def _effective_ttl(self, secret: SecretValue) -> float:
        """Effective cache TTL for a secret.

        For dynamic secrets (Vault DB leases) the cache must not outlive
        the lease itself.  We cap at 90 % of the remaining lease time so
        there is a safety margin before the credential expires.
        This matches §2.4 and §4.7 of the thesis (90 % rule).
        """
        if secret.is_dynamic and secret.expires_at is not None:
            lease_remaining = secret.expires_at - time.time()
            return min(self._ttl, lease_remaining * 0.9)
        return self._ttl

    def _evict_expired(self) -> None:
        now = time.monotonic()
        dead = [k for k, e in self._store.items() if e.cache_expires <= now]
        for k in dead:
            del self._store[k]

    def _evict_lfu(self) -> None:
        if len(self._store) < self._max_size:
            return
        lfu = min(self._store, key=lambda k: self._store[k].hits)
        del self._store[lfu]

    def _update_gauge(self) -> None:
        if _PROMETHEUS:
            _CACHE_SIZE.labels(backend=self.backend_name).set(len(self._store))

    def _audit_log(
        self,
        *,
        secret_name: str,
        operation: str,
        result: str,
        backend: str,
        duration_ms: float,
        error_message: str = "",
        **extra: Any,
    ) -> None:
        if self._audit is None:
            return
        self._audit.log(
            client_id=self._client_id,
            secret_name=secret_name,
            operation=operation,
            result=result,
            backend=backend,
            duration_ms=duration_ms,
            error_message=error_message,
            **extra,
        )

    # ------------------------------------------------------------------
    # Public cache management
    # ------------------------------------------------------------------

    def invalidate(self, name: str, version: str | None = None) -> None:
        """Remove *name* (optionally *version*) from the cache."""
        with self._lock:
            if version is not None:
                self._store.pop(self._key(name, version), None)
            else:
                for k in [k for k in self._store if k[0] == name]:
                    del self._store[k]
            self._update_gauge()

    def invalidate_all(self) -> None:
        """Flush the entire cache."""
        with self._lock:
            self._store.clear()
            self._update_gauge()

    def cache_stats(self) -> dict[str, Any]:
        """Return a snapshot suitable for health endpoints."""
        with self._lock:
            total = len(self._store)
            now = time.monotonic()
            alive = sum(1 for e in self._store.values() if e.cache_expires > now)
            total_hits = sum(e.hits for e in self._store.values())
        return {
            "total_entries": total,
            "alive_entries": alive,
            "total_hits": total_hits,
            "ttl_seconds": self._ttl,
            "max_size": self._max_size,
            "has_fallback": self._fallback is not None,
        }

    # ------------------------------------------------------------------
    # SecretProvider — required abstracts
    # ------------------------------------------------------------------

    def get_secret(self, name: str, *, version: str | None = None) -> SecretValue:
        key = self._key(name, version)
        t0 = time.perf_counter()
        now_mono = time.monotonic()

        # ----- cache hit -----
        with self._lock:
            entry = self._store.get(key)
            if entry is not None and entry.cache_expires > now_mono:
                entry.hits += 1
                if _PROMETHEUS:
                    _CACHE_HITS.labels(backend=self.backend_name).inc()
                self._audit_log(
                    secret_name=name,
                    operation="get_secret",
                    result=AuditLogger.HIT,
                    backend=self.backend_name,
                    duration_ms=(time.perf_counter() - t0) * 1000,
                )
                return entry.secret

        # ----- cache miss — try primary -----
        if _PROMETHEUS:
            _CACHE_MISSES.labels(backend=self.backend_name).inc()

        try:
            secret = self._primary.get_secret(name, version=version)
            effective_ttl = self._effective_ttl(secret)
            with self._lock:
                self._evict_expired()
                self._evict_lfu()
                self._store[key] = _Entry(
                    secret=secret,
                    cache_expires=time.monotonic() + effective_ttl,
                )
                self._update_gauge()
            self._audit_log(
                secret_name=name,
                operation="get_secret",
                result=AuditLogger.MISS,
                backend=self.backend_name,
                duration_ms=(time.perf_counter() - t0) * 1000,
                version=secret.version,
            )
            return secret

        except (BackendUnavailableError, TimeoutError, AccessDeniedError) as primary_exc:
            # ----- fallback -----
            if self._fallback is not None:
                try:
                    fb_secret = self._fallback.get_secret(name, version=version).as_fallback()
                    # Do NOT cache fallback responses.
                    self._audit_log(
                        secret_name=name,
                        operation="get_secret",
                        result=AuditLogger.FALLBACK,
                        backend=self._fallback.backend_name,
                        duration_ms=(time.perf_counter() - t0) * 1000,
                        primary_error_message=type(primary_exc).__name__,
                    )
                    return fb_secret
                except Exception as fb_exc:
                    self._audit_log(
                        secret_name=name,
                        operation="get_secret",
                        result=AuditLogger.ERROR,
                        backend=self._fallback.backend_name,
                        duration_ms=(time.perf_counter() - t0) * 1000,
                        error_message=f"fallback failed: {fb_exc}",
                    )
            self._audit_log(
                secret_name=name,
                operation="get_secret",
                result=AuditLogger.ERROR,
                backend=self.backend_name,
                duration_ms=(time.perf_counter() - t0) * 1000,
                error_message=str(primary_exc),
            )
            raise

    def get_dynamic_secret(self, role: str, **kwargs: Any) -> SecretValue:
        """Delegate to primary; cache with TTL = min(ttl, lease*0.9)."""
        key = self._key(role, kwargs.get("mount_point"))
        t0 = time.perf_counter()
        now_mono = time.monotonic()

        with self._lock:
            entry = self._store.get(key)
            if entry is not None and entry.cache_expires > now_mono:
                entry.hits += 1
                self._audit_log(
                    secret_name=role,
                    operation="get_dynamic_secret",
                    result=AuditLogger.HIT,
                    backend=self.backend_name,
                    duration_ms=(time.perf_counter() - t0) * 1000,
                )
                return entry.secret

        try:
            secret = self._primary.get_dynamic_secret(role, **kwargs)
            effective_ttl = self._effective_ttl(secret)
            with self._lock:
                self._evict_expired()
                self._evict_lfu()
                self._store[key] = _Entry(
                    secret=secret,
                    cache_expires=time.monotonic() + effective_ttl,
                )
                self._update_gauge()
            self._audit_log(
                secret_name=role,
                operation="get_dynamic_secret",
                result=AuditLogger.MISS,
                backend=self.backend_name,
                duration_ms=(time.perf_counter() - t0) * 1000,
            )
            return secret
        except Exception as exc:
            self._audit_log(
                secret_name=role,
                operation="get_dynamic_secret",
                result=AuditLogger.ERROR,
                backend=self.backend_name,
                duration_ms=(time.perf_counter() - t0) * 1000,
                error_message=str(exc),
            )
            raise

    def list_secrets(self, prefix: str = "") -> list[str]:
        """Listing always delegates to primary (never cached)."""
        return self._primary.list_secrets(prefix)

    def health_check(self) -> bool:
        primary_ok = self._primary.health_check()
        if self._fallback is not None:
            return primary_ok or self._fallback.health_check()
        return primary_ok

    # ------------------------------------------------------------------
    # Optional overrides
    # ------------------------------------------------------------------

    def set_secret(self, name: str, value: str, *, metadata: dict[str, Any] | None = None) -> str:
        version = self._primary.set_secret(name, value, metadata=metadata)
        self.invalidate(name)
        return version

    def delete_secret(self, name: str, *, force: bool = False) -> None:
        self._primary.delete_secret(name, force=force)
        self.invalidate(name)

    def rotate_secret(self, name: str, *, policy: RotationPolicy | None = None) -> str:
        version = self._primary.rotate_secret(name, policy=policy)
        self.invalidate(name)
        return version
