"""Unit tests — Phase 4: AuditLogger (deque-based)."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone

import pytest

from secretsmanager.audit import AuditLogger, AuditRecord


@pytest.fixture()
def logger():
    return AuditLogger(max_buffer_size=100)


@pytest.fixture()
def logger_with_file(tmp_path):
    return AuditLogger(max_buffer_size=100, export_path=tmp_path / "audit.jsonl")


def _log(logger: AuditLogger, **overrides: object) -> AuditRecord:
    defaults = dict(
        secret_name="prod/db",
        operation="get_secret",
        result=AuditLogger.SUCCESS,
        backend="mock",
        duration_ms=5.0,
    )
    defaults.update(overrides)
    return logger.log(**defaults)  # type: ignore[arg-type]


@pytest.mark.unit
class TestAuditLoggerWrite:
    def test_log_returns_record(self, logger):
        rec = _log(logger)
        assert isinstance(rec, AuditRecord)

    def test_record_fields(self, logger):
        rec = _log(logger, secret_name="my/secret", backend="hashicorp", duration_ms=12.5)
        assert rec.secret_name == "my/secret"
        assert rec.backend == "hashicorp"
        assert rec.duration_ms == 12.5

    def test_event_id_is_uuid(self, logger):
        import uuid

        rec = _log(logger)
        uuid.UUID(rec.event_id)  # raises if not valid UUID

    def test_timestamp_is_iso_utc(self, logger):
        rec = _log(logger)
        dt = datetime.fromisoformat(rec.timestamp)
        assert dt.tzinfo is not None

    def test_len_increases(self, logger):
        assert len(logger) == 0
        _log(logger)
        assert len(logger) == 1
        _log(logger)
        assert len(logger) == 2

    def test_maxlen_eviction(self):
        logger = AuditLogger(max_buffer_size=3)
        for i in range(5):
            _log(logger, secret_name=f"s{i}")
        assert len(logger) == 3

    def test_clear(self, logger):
        _log(logger)
        logger.clear()
        assert len(logger) == 0

    def test_extra_kwargs_stored(self, logger):
        rec = _log(logger, version="v-abc", lease_duration=3600)
        assert rec.extra["version"] == "v-abc"
        assert rec.extra["lease_duration"] == 3600

    def test_default_client_id(self, logger):
        rec = _log(logger)
        assert rec.client_id == "system"

    def test_custom_client_id(self, logger):
        rec = _log(logger, client_id="pod/app")
        assert rec.client_id == "pod/app"

    def test_duration_rounded(self, logger):
        rec = _log(logger, duration_ms=1.23456789)
        assert rec.duration_ms == 1.235

    def test_result_constants(self):
        assert AuditLogger.HIT == "hit"
        assert AuditLogger.MISS == "miss"
        assert AuditLogger.FALLBACK == "fallback"
        assert AuditLogger.SUCCESS == "success"
        assert AuditLogger.ERROR == "error"


@pytest.mark.unit
class TestAuditLoggerQuery:
    def _seed(self, logger: AuditLogger) -> None:
        _log(
            logger,
            secret_name="prod/db",
            operation="get_secret",
            result="hit",
            backend="hashicorp",
            duration_ms=1.0,
        )
        _log(
            logger,
            secret_name="prod/db",
            operation="get_secret",
            result="miss",
            backend="hashicorp",
            duration_ms=10.0,
        )
        _log(
            logger,
            secret_name="dev/api",
            operation="set_secret",
            result="success",
            backend="aws",
            duration_ms=30.0,
        )
        _log(
            logger,
            secret_name="dev/api",
            operation="get_secret",
            result="error",
            backend="aws",
            duration_ms=5.0,
        )

    def test_query_all(self, logger):
        self._seed(logger)
        results = logger.query(limit=100)
        assert len(results) == 4

    def test_query_by_secret_name(self, logger):
        self._seed(logger)
        results = logger.query(secret_name="prod/db")
        assert all(r.secret_name == "prod/db" for r in results)
        assert len(results) == 2

    def test_query_by_result(self, logger):
        self._seed(logger)
        results = logger.query(result="error")
        assert len(results) == 1
        assert results[0].backend == "aws"

    def test_query_by_operation(self, logger):
        self._seed(logger)
        results = logger.query(operation="set_secret")
        assert len(results) == 1

    def test_query_by_backend(self, logger):
        self._seed(logger)
        results = logger.query(backend="aws")
        assert len(results) == 2

    def test_query_sorted_descending(self, logger):
        self._seed(logger)
        results = logger.query(limit=100)
        timestamps = [r.timestamp for r in results]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_query_limit(self, logger):
        for _ in range(10):
            _log(logger)
        assert len(logger.query(limit=3)) == 3

    def test_query_start_time(self, logger):
        _log(logger, secret_name="old")
        time.sleep(0.01)
        boundary = datetime.now(tz=timezone.utc)
        time.sleep(0.01)
        _log(logger, secret_name="new")
        results = logger.query(start_time=boundary)
        assert len(results) == 1
        assert results[0].secret_name == "new"


@pytest.mark.unit
class TestAuditLoggerExport:
    def test_export_creates_file(self, logger_with_file, tmp_path):
        _log(logger_with_file)
        path = logger_with_file.export_to_file()
        assert path.exists()

    def test_export_jsonl_format(self, logger_with_file, tmp_path):
        _log(logger_with_file, secret_name="x/y")
        path = logger_with_file.export_to_file()
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 1
        obj = json.loads(lines[0])
        assert obj["secret_name"] == "x/y"

    def test_export_multiple_records(self, logger_with_file, tmp_path):
        for _ in range(5):
            _log(logger_with_file)
        path = logger_with_file.export_to_file()
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 5

    def test_export_no_path_raises(self, logger):
        with pytest.raises(ValueError, match="No export_path"):
            logger.export_to_file()

    def test_export_to_custom_path(self, logger, tmp_path):
        _log(logger)
        target = tmp_path / "custom.jsonl"
        logger.export_to_file(target)
        assert target.exists()


@pytest.mark.unit
class TestAuditLoggerStatistics:
    def test_empty_stats(self, logger):
        stats = logger.get_statistics()
        assert stats["total_operations"] == 0
        assert stats["cache_hit_ratio"] == 0.0
        assert stats["fallback_count"] == 0

    def test_hit_ratio(self, logger):
        _log(logger, result="hit")
        _log(logger, result="hit")
        _log(logger, result="miss")
        stats = logger.get_statistics()
        # 2 hits out of 3 cache-ops
        assert abs(stats["cache_hit_ratio"] - 2 / 3) < 0.001

    def test_fallback_count(self, logger):
        _log(logger, result="fallback")
        _log(logger, result="fallback")
        assert logger.get_statistics()["fallback_count"] == 2

    def test_error_count(self, logger):
        _log(logger, result="error")
        assert logger.get_statistics()["error_count"] == 1

    def test_top_10_secrets(self, logger):
        for _ in range(5):
            _log(logger, secret_name="prod/db")
        for _ in range(2):
            _log(logger, secret_name="dev/key")
        stats = logger.get_statistics()
        top = dict(stats["top_10_secrets"])
        assert top["prod/db"] == 5
        assert top["dev/key"] == 2

    def test_by_backend(self, logger):
        _log(logger, backend="hashicorp")
        _log(logger, backend="aws")
        _log(logger, backend="hashicorp")
        stats = logger.get_statistics()
        assert stats["by_backend"]["hashicorp"] == 2
        assert stats["by_backend"]["aws"] == 1

    def test_avg_duration(self, logger):
        _log(logger, duration_ms=10.0)
        _log(logger, duration_ms=20.0)
        stats = logger.get_statistics()
        assert stats["avg_duration_ms"] == 15.0
