"""Integration tests for HashiCorp Vault adapter.

Requires a running Vault dev server:
  docker run --rm -p 8200:8200 -e 'VAULT_DEV_ROOT_TOKEN_ID=root' vault:1.15

Run with:  pytest -m integration tests/integration/test_vault_integration.py
"""

from __future__ import annotations

import os

import pytest

VAULT_URL = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN", "root")


@pytest.fixture(scope="module")
def vault():
    pytest.importorskip("hvac")
    from secretsmanager.adapters.hashicorp import HashiCorpVaultAdapter

    adapter = HashiCorpVaultAdapter(vault_url=VAULT_URL, vault_token=VAULT_TOKEN, verify_ssl=False)
    if not adapter.health_check():
        pytest.skip("Vault dev server not reachable")
    return adapter


@pytest.mark.integration
def test_vault_set_and_get(vault):
    vault.set_secret("integration/test-key", "hello-vault")
    sv = vault.get_secret("integration/test-key")
    assert sv.value == "hello-vault"
    assert sv.backend == "hashicorp"


@pytest.mark.integration
def test_vault_version_increments(vault):
    vault.set_secret("integration/versioned", "v1")
    vault.set_secret("integration/versioned", "v2")
    sv = vault.get_secret("integration/versioned")
    assert int(sv.version) >= 2


@pytest.mark.integration
def test_vault_list_includes_written_key(vault):
    vault.set_secret("integration/listed-key", "val")
    keys = vault.list_secrets("integration")
    assert any("listed-key" in k for k in keys)


@pytest.mark.integration
def test_vault_delete(vault):
    from secretsmanager.interface import SecretNotFoundError

    vault.set_secret("integration/to-delete", "bye")
    vault.delete_secret("integration/to-delete")
    with pytest.raises((SecretNotFoundError, Exception)):
        vault.get_secret("integration/to-delete")


@pytest.mark.integration
def test_vault_not_found_raises(vault):
    from secretsmanager.interface import SecretNotFoundError

    with pytest.raises(SecretNotFoundError):
        vault.get_secret("integration/definitely-does-not-exist-xyz-123")


@pytest.mark.integration
def test_vault_cache_integration(vault):
    """Smoke test: cached adapter returns same value as direct adapter."""
    from secretsmanager.cache import CachedSecretProvider

    cached = CachedSecretProvider(vault, ttl_seconds=30)
    vault.set_secret("integration/cached-key", "cached-value")
    sv1 = cached.get_secret("integration/cached-key")
    sv2 = cached.get_secret("integration/cached-key")
    assert sv1.value == sv2.value == "cached-value"
    stats = cached.cache_stats()
    assert stats["alive_entries"] >= 1


@pytest.mark.integration
def test_vault_audit_records_event(vault, tmp_path):
    import json
    import time
    from secretsmanager.audit import AuditLogger

    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(max_buffer_size=100, export_path=log)

    t0 = time.perf_counter()
    sv = vault.get_secret("integration/test-key")
    duration_ms = (time.perf_counter() - t0) * 1000

    logger.log(
        client_id="integration-test",
        secret_name="integration/test-key",
        operation="get_secret",
        result=AuditLogger.SUCCESS,
        backend="hashicorp",
        duration_ms=duration_ms,
        version=sv.version,
    )

    logger.export_to_file()
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert records[0]["result"] == "success"
    assert records[0]["operation"] == "get_secret"
    assert records[0]["backend"] == "hashicorp"
