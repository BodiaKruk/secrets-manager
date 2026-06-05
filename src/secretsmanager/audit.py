"""AuditLogger — structured in-memory audit trail with query, export, and statistics.

Design:
  - All records stored in a bounded collections.deque (default 10 000 entries).
  - Thread-safe via threading.RLock (reentrant — log() can be called from
    within a lock-holding context without deadlock).
  - Every secrets operation (hit / miss / fallback / error) is captured with
    sub-millisecond timestamps via time.perf_counter_ns().
  - JSONL export is compatible with ELK bulk-import and Splunk HEC.
  - Optional Prometheus side-channel via prometheus_client.

Usage::

    logger = AuditLogger(max_buffer_size=10_000, export_path="/var/log/sm/audit.jsonl")
    logger.log(
        client_id="pod/app-7d4f9",
        secret_name="prod/db/password",
        operation="get_secret",
        result="hit",
        backend="hashicorp",
        duration_ms=1.2,
    )
    stats = logger.get_statistics()
    logger.export_to_file()
"""

from __future__ import annotations

import collections
import json
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from prometheus_client import Counter, Histogram  # type: ignore[import-untyped]

    _PROMETHEUS_AVAILABLE = True

    _OP_TOTAL = Counter(
        "secrets_operations_total",
        "Total secrets operations by kind and outcome",
        ["operation", "backend", "result"],
    )
    _OP_LATENCY = Histogram(
        "secrets_operation_duration_seconds",
        "Latency of secrets operations",
        ["operation", "backend"],
        buckets=[0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0],
    )
except ImportError:  # pragma: no cover
    _PROMETHEUS_AVAILABLE = False


# ---------------------------------------------------------------------------
# Record dataclass
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class AuditRecord:
    """Single immutable audit event.

    Attributes:
        event_id:    UUID4 string, unique per record.
        timestamp:   ISO-8601 UTC string, e.g. ``"2026-06-03T12:00:00.123456+00:00"``.
        client_id:   Caller identity: pod name, user email, AppRole role-id, etc.
        secret_name: Logical secret path / name (never the value).
        operation:   ``"get_secret" | "get_dynamic_secret" | "set_secret" |
                       "delete_secret" | "rotate_secret" | "list_secrets"``.
        result:      ``"hit" | "miss" | "fallback" | "success" | "error"``.
        backend:     Provider tag, e.g. ``"hashicorp"``.
        duration_ms: Wall-clock time for the operation in milliseconds.
        error_message: Exception class name + message on ``result="error"``.
        extra:       Freeform dict for version, lease_duration, etc.
    """

    event_id: str
    timestamp: str
    client_id: str
    secret_name: str
    operation: str
    result: str
    backend: str
    duration_ms: float
    error_message: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


# ---------------------------------------------------------------------------
# AuditLogger
# ---------------------------------------------------------------------------


class AuditLogger:
    """Thread-safe in-memory audit log with query, export, and statistics.

    Args:
        max_buffer_size: Maximum number of in-memory records (FIFO eviction).
        export_path:     File path for JSONL export (created on demand).
                         Pass ``None`` to disable file export.
    """

    # Result constants exposed as class attributes for callers.
    HIT = "hit"
    MISS = "miss"
    FALLBACK = "fallback"
    SUCCESS = "success"
    ERROR = "error"

    def __init__(
        self,
        max_buffer_size: int = 10_000,
        export_path: str | Path | None = None,
    ) -> None:
        self._buffer: collections.deque[AuditRecord] = collections.deque(maxlen=max_buffer_size)
        self._lock = threading.RLock()
        self._export_path = Path(export_path) if export_path else None
        if self._export_path:
            self._export_path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def log(
        self,
        *,
        client_id: str = "system",
        secret_name: str,
        operation: str,
        result: str,
        backend: str,
        duration_ms: float,
        error_message: str = "",
        **extra: Any,
    ) -> AuditRecord:
        """Append one audit record.

        Thread-safe. Returns the created :class:`AuditRecord` for inspection.
        """
        record = AuditRecord(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            client_id=client_id,
            secret_name=secret_name,
            operation=operation,
            result=result,
            backend=backend,
            duration_ms=round(duration_ms, 3),
            error_message=error_message,
            extra=dict(extra),
        )
        with self._lock:
            self._buffer.append(record)

        if _PROMETHEUS_AVAILABLE:
            _OP_TOTAL.labels(operation=operation, backend=backend, result=result).inc()
            _OP_LATENCY.labels(operation=operation, backend=backend).observe(duration_ms / 1000.0)

        return record

    # ------------------------------------------------------------------
    # Read / query
    # ------------------------------------------------------------------

    def query(
        self,
        *,
        secret_name: str | None = None,
        operation: str | None = None,
        result: str | None = None,
        backend: str | None = None,
        client_id: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
    ) -> list[AuditRecord]:
        """Filter records and return them sorted by timestamp descending.

        All filter arguments are optional and ANDed together.
        ``start_time`` / ``end_time`` are inclusive timezone-aware datetimes.
        """
        with self._lock:
            records = list(self._buffer)

        def _matches(r: AuditRecord) -> bool:
            if secret_name is not None and r.secret_name != secret_name:
                return False
            if operation is not None and r.operation != operation:
                return False
            if result is not None and r.result != result:
                return False
            if backend is not None and r.backend != backend:
                return False
            if client_id is not None and r.client_id != client_id:
                return False
            if start_time is not None:
                rec_dt = datetime.fromisoformat(r.timestamp)
                if rec_dt < start_time:
                    return False
            if end_time is not None:
                rec_dt = datetime.fromisoformat(r.timestamp)
                if rec_dt > end_time:
                    return False
            return True

        filtered = [r for r in records if _matches(r)]
        # Sort descending (most recent first).
        filtered.sort(key=lambda r: r.timestamp, reverse=True)
        return filtered[:limit]

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_to_file(self, path: str | Path | None = None) -> Path:
        """Write all buffered records as JSONL to *path* (or the configured export_path).

        Compatible with ELK ``/_bulk`` and Splunk HEC formats.

        Returns the path written to.

        Raises:
            ValueError: if no path is configured and none is supplied.
        """
        target = Path(path) if path else self._export_path
        if target is None:
            raise ValueError(
                "No export_path configured — pass a path to export_to_file() "
                "or set export_path in the constructor."
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            records = list(self._buffer)
        with open(target, "w", encoding="utf-8") as fh:
            for rec in records:
                fh.write(rec.to_json() + "\n")
        return target

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_statistics(self) -> dict[str, Any]:
        """Compute aggregate metrics over all buffered records.

        Returns::

            {
                "total_operations": int,
                "cache_hit_ratio":  float,   # hits / total (0.0 if no cache ops)
                "fallback_count":   int,
                "error_count":      int,
                "top_10_secrets":   list[tuple[str, int]],  # (name, count)
                "by_backend":       dict[str, int],
                "by_operation":     dict[str, int],
                "avg_duration_ms":  float,
            }
        """
        with self._lock:
            records = list(self._buffer)

        total = len(records)
        if total == 0:
            return {
                "total_operations": 0,
                "cache_hit_ratio": 0.0,
                "fallback_count": 0,
                "error_count": 0,
                "top_10_secrets": [],
                "by_backend": {},
                "by_operation": {},
                "avg_duration_ms": 0.0,
            }

        hits = sum(1 for r in records if r.result == self.HIT)
        misses = sum(1 for r in records if r.result == self.MISS)
        cache_ops = hits + misses
        fallbacks = sum(1 for r in records if r.result == self.FALLBACK)
        errors = sum(1 for r in records if r.result == self.ERROR)

        # Top-10 secrets by access frequency.
        name_counts: dict[str, int] = {}
        for r in records:
            name_counts[r.secret_name] = name_counts.get(r.secret_name, 0) + 1
        top_10 = sorted(name_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        by_backend: dict[str, int] = {}
        by_op: dict[str, int] = {}
        total_ms = 0.0
        for r in records:
            by_backend[r.backend] = by_backend.get(r.backend, 0) + 1
            by_op[r.operation] = by_op.get(r.operation, 0) + 1
            total_ms += r.duration_ms

        return {
            "total_operations": total,
            "cache_hit_ratio": hits / cache_ops if cache_ops > 0 else 0.0,
            "fallback_count": fallbacks,
            "error_count": errors,
            "top_10_secrets": top_10,
            "by_backend": by_backend,
            "by_operation": by_op,
            "avg_duration_ms": round(total_ms / total, 3),
        }

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        with self._lock:
            return len(self._buffer)

    def clear(self) -> None:
        """Discard all buffered records."""
        with self._lock:
            self._buffer.clear()
