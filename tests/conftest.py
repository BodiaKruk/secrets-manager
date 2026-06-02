"""Shared pytest fixtures for all test levels."""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from secretsmanager.audit import AuditLogger
from secretsmanager.interface import (
    AccessDeniedError,
    BackendUnavailableError,
    SecretNotFoundError,
    SecretProvider,
    SecretValue,
)


# ---------------------------------------------------------------------------
# SecretValue factory helpers
# ---------------------------------------------------------------------------


def make_secret(
    value: str = "s3cr3t",
    version: str = "1",
    backend: str = "mock",
    path: str = "test/key",
    is_dynamic: bool = False,
    lease_seconds: float | None = None,
) -> SecretValue:
    expires_at = time.time() + lease_seconds if lease_seconds is not None else None
    return SecretValue(
        value=value,
        version=version,
        backend=backend,
        path=path,
        expires_at=expires_at,
        is_dynamic=is_dynamic,
    )


# ---------------------------------------------------------------------------
# Mock providers
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_provider() -> MagicMock:
    p = MagicMock(spec=SecretProvider)
    p.backend_name = "mock"
    p.get_secret.return_value = make_secret()
    p.get_dynamic_secret.return_value = make_secret(
        value='{"username":"user","password":"pass"}',
        is_dynamic=True,
        lease_seconds=3600,
    )
    p.set_secret.return_value = "2"
    p.list_secrets.return_value = ["test/key"]
    p.health_check.return_value = True
    return p


@pytest.fixture()
def mock_fallback() -> MagicMock:
    p = MagicMock(spec=SecretProvider)
    p.backend_name = "fallback"
    p.get_secret.return_value = make_secret(value="fallback-value", backend="fallback")
    p.health_check.return_value = True
    return p


@pytest.fixture()
def audit_logger(tmp_path) -> AuditLogger:
    return AuditLogger(
        max_buffer_size=1000,
        export_path=tmp_path / "audit.jsonl",
    )
