"""Core abstractions: SecretProvider ABC, SecretValue, domain exceptions, RotationPolicy.

Hierarchy:
    SecretProvider (ABC)
        .get_secret(name, version=None) -> SecretValue
        .get_dynamic_secret(role, **kwargs) -> SecretValue
        .list_secrets(prefix="") -> list[str]
        .health_check() -> bool
        # optional overrides
        .set_secret(name, value, metadata=None) -> str
        .delete_secret(name, force=False) -> None
        .rotate_secret(name, policy=None) -> str

    SecretValue (frozen dataclass)
        .value, .version, .backend, .obtained_at, .expires_at
        .path, .metadata, .is_dynamic, .is_fallback
        .is_expired() -> bool
        .ttl_remaining() -> float | None
        .checksum -> str

    Exceptions:
        SecretError
        ├── SecretNotFoundError
        ├── AccessDeniedError      (alias: SecretAccessDeniedError)
        └── BackendUnavailableError (alias: SecretBackendError)
"""

from __future__ import annotations

import hashlib
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# Domain exceptions
# ---------------------------------------------------------------------------


class SecretError(Exception):
    """Base class for all secrets-manager errors."""

    def __init__(self, message: str = "", *, backend: str = "", path: str = "") -> None:
        super().__init__(message)
        self.backend = backend
        self.path = path

    def __str__(self) -> str:
        parts = [super().__str__()]
        if self.backend:
            parts.append(f"backend={self.backend!r}")
        if self.path:
            parts.append(f"path={self.path!r}")
        return " | ".join(parts)


class SecretNotFoundError(SecretError):
    """Secret path does not exist in the backend."""


class AccessDeniedError(SecretError):
    """Caller lacks permission to access the secret."""


class BackendUnavailableError(SecretError):
    """Backend is unreachable, timed-out, or misconfigured."""


# Backward-compatible aliases used in Phase-0 code
SecretAccessDeniedError = AccessDeniedError
SecretBackendError = BackendUnavailableError
SecretRotationError = BackendUnavailableError  # keep old import working


# ---------------------------------------------------------------------------
# Value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SecretValue:
    """Immutable container for a resolved secret.

    Fields with no default must appear before those with defaults
    (Python dataclass ordering rule).

    Args:
        value:       Plaintext secret string (never logged or repr'd).
        version:     Provider-specific version identifier.
        backend:     Short provider name tag, e.g. ``"hashicorp"``.
        obtained_at: Unix timestamp when the value was retrieved.
        expires_at:  Unix timestamp when the value expires (``None`` = eternal).
        path:        Canonical path used to retrieve the secret.
        metadata:    Arbitrary key-value pairs from the provider.
        is_dynamic:  True for ephemeral secrets (Vault DB engine leases, etc.).
        is_fallback: True when the value was served from a fallback provider.
    """

    # --- required (no default) ---
    value: str
    version: str
    backend: str

    # --- optional ---
    obtained_at: float = field(default_factory=time.time)
    expires_at: float | None = None
    path: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    is_dynamic: bool = False
    is_fallback: bool = False

    # ------------------------------------------------------------------
    # Derived properties
    # ------------------------------------------------------------------

    @property
    def checksum(self) -> str:
        """SHA-256 hex digest of the plaintext (for integrity assertions)."""
        return hashlib.sha256(self.value.encode()).hexdigest()

    def is_expired(self) -> bool:
        """Return True if *expires_at* is set and has passed."""
        return self.expires_at is not None and time.time() > self.expires_at

    def ttl_remaining(self) -> float | None:
        """Seconds until expiry, or None if the secret never expires.

        Returns a negative value if already expired.
        """
        if self.expires_at is None:
            return None
        return self.expires_at - time.time()

    def as_fallback(self) -> SecretValue:
        """Return a copy of this value with is_fallback=True."""
        # frozen=True means we must use object.__setattr__ via a new instance.
        return SecretValue(
            value=self.value,
            version=self.version,
            backend=self.backend,
            obtained_at=self.obtained_at,
            expires_at=self.expires_at,
            path=self.path,
            metadata=self.metadata,
            is_dynamic=self.is_dynamic,
            is_fallback=True,
        )

    def __repr__(self) -> str:
        flags = []
        if self.is_dynamic:
            flags.append("dynamic")
        if self.is_fallback:
            flags.append("fallback")
        flag_str = f"[{','.join(flags)}]" if flags else ""
        ttl = self.ttl_remaining()
        ttl_str = f", ttl={ttl:.0f}s" if ttl is not None else ""
        return (
            f"SecretValue({flag_str}path={self.path!r}, version={self.version!r}, "
            f"backend={self.backend!r}{ttl_str})"
        )


# ---------------------------------------------------------------------------
# Rotation policy (unchanged from Phase 0)
# ---------------------------------------------------------------------------


class RotationSchedule(str, Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CUSTOM = "custom"


@dataclass
class RotationPolicy:
    schedule: RotationSchedule = RotationSchedule.MONTHLY
    interval_days: int = 30
    notify_before: int = 7
    auto_rotate: bool = False


# ---------------------------------------------------------------------------
# Provider interface
# ---------------------------------------------------------------------------


class SecretProvider(ABC):
    """Abstract base class for all backend adapters.

    Every adapter MUST implement:
        - backend_name (property)
        - get_secret
        - get_dynamic_secret
        - list_secrets
        - health_check

    Adapters MAY override:
        - set_secret / delete_secret / rotate_secret
    """

    @property
    @abstractmethod
    def backend_name(self) -> str:
        """Short identifier string, e.g. ``"hashicorp"`` or ``"aws"``."""

    # ------------------------------------------------------------------
    # Required abstract methods
    # ------------------------------------------------------------------

    @abstractmethod
    def get_secret(self, name: str, *, version: str | None = None) -> SecretValue:
        """Retrieve a static secret by *name*.

        Args:
            name:    Backend-specific path or key name.
            version: Optional version specifier (provider-dependent syntax).

        Returns:
            Immutable :class:`SecretValue`.

        Raises:
            SecretNotFoundError:      Path does not exist.
            AccessDeniedError:        Insufficient permissions.
            BackendUnavailableError:  Backend unreachable or misconfigured.
        """

    @abstractmethod
    def get_dynamic_secret(self, role: str, **kwargs: Any) -> SecretValue:
        """Generate a short-lived credential via a dynamic secrets engine.

        For HashiCorp Vault this calls the database engine's
        ``generate_credentials``; other providers may raise
        ``NotImplementedError`` if they do not support dynamic secrets.

        Args:
            role:    Provider-specific role / template name.
            **kwargs: Optional mount_point, ttl, etc.

        Returns:
            :class:`SecretValue` with ``is_dynamic=True`` and ``expires_at``
            set from the backend's lease duration.

        Raises:
            SecretNotFoundError:      Role not configured.
            AccessDeniedError:        Insufficient permissions.
            BackendUnavailableError:  Backend unreachable or misconfigured.
        """

    @abstractmethod
    def list_secrets(self, prefix: str = "") -> list[str]:
        """Return a sorted list of secret names under *prefix*.

        Raises:
            AccessDeniedError:       Insufficient permissions.
            BackendUnavailableError: Backend unreachable.
        """

    @abstractmethod
    def health_check(self) -> bool:
        """Return True if the backend is reachable and authenticated."""

    # ------------------------------------------------------------------
    # Optional overrides
    # ------------------------------------------------------------------

    def set_secret(self, name: str, value: str, *, metadata: dict[str, Any] | None = None) -> str:
        """Create or update a secret.  Returns new version identifier."""
        raise NotImplementedError(f"{self.backend_name} does not support set_secret")

    def delete_secret(self, name: str, *, force: bool = False) -> None:
        """Delete a secret (soft-delete by default unless *force* is True)."""
        raise NotImplementedError(f"{self.backend_name} does not support delete_secret")

    def rotate_secret(self, name: str, *, policy: RotationPolicy | None = None) -> str:
        """Trigger rotation for *name*.  Returns new version identifier."""
        raise NotImplementedError(f"{self.backend_name} does not support rotate_secret")
