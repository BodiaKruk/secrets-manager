"""Unit tests — Phase 2: CachedSecretProvider (primary+fallback+audit)."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, call

import pytest

from secretsmanager.audit import AuditLogger
from secretsmanager.cache import CachedSecretProvider
from secretsmanager.interface import (
    AccessDeniedError,
    BackendUnavailableError,
    SecretNotFoundError,
    SecretValue,
)
from tests.conftest import make_secret


@pytest.fixture()
def primary():
    p = MagicMock()
    p.backend_name = "primary"
    p.get_secret.return_value = make_secret(value="primary-value")
    p.get_dynamic_secret.return_value = make_secret(
        value='{"username":"u","password":"p"}',
        is_dynamic=True,
        lease_seconds=3600,
    )
    p.set_secret.return_value = "v2"
    p.list_secrets.return_value = ["test/key"]
    p.health_check.return_value = True
    return p


@pytest.fixture()
def fallback():
    p = MagicMock()
    p.backend_name = "fallback"
    p.get_secret.return_value = make_secret(value="fallback-value", backend="fallback")
    p.health_check.return_value = True
    return p


@pytest.fixture()
def audit():
    return AuditLogger(max_buffer_size=500)


@pytest.fixture()
def cached(primary):
    return CachedSecretProvider(primary, ttl_seconds=60)


@pytest.fixture()
def cached_with_fallback(primary, fallback, audit):
    return CachedSecretProvider(
        primary, fallback, ttl_seconds=60, audit_logger=audit, client_id="test"
    )


@pytest.mark.unit
class TestCacheHitMiss:
    def test_first_call_hits_backend(self, cached, primary):
        cached.get_secret("test/key")
        primary.get_secret.assert_called_once_with("test/key", version=None)

    def test_second_call_from_cache(self, cached, primary):
        cached.get_secret("test/key")
        cached.get_secret("test/key")
        assert primary.get_secret.call_count == 1

    def test_returns_same_value_from_cache(self, cached, primary):
        sv1 = cached.get_secret("test/key")
        sv2 = cached.get_secret("test/key")
        assert sv1 is sv2

    def test_ttl_expiry_triggers_backend(self, primary):
        c = CachedSecretProvider(primary, ttl_seconds=0.05)
        c.get_secret("test/key")
        time.sleep(0.1)
        c.get_secret("test/key")
        assert primary.get_secret.call_count == 2

    def test_different_versions_cached_separately(self, cached, primary):
        primary.get_secret.side_effect = lambda name, **kw: make_secret(
            version=kw.get("version") or "latest"
        )
        cached.get_secret("test/key", version="1")
        cached.get_secret("test/key", version="2")
        assert primary.get_secret.call_count == 2

    def test_backend_name_delegates_to_primary(self, cached, primary):
        assert cached.backend_name == "primary"


@pytest.mark.unit
class TestCacheInvalidation:
    def test_invalidate_single(self, cached, primary):
        cached.get_secret("test/key")
        cached.invalidate("test/key")
        cached.get_secret("test/key")
        assert primary.get_secret.call_count == 2

    def test_invalidate_all(self, cached, primary):
        primary.get_secret.side_effect = [
            make_secret(path="a"), make_secret(path="b"),
            make_secret(path="a"), make_secret(path="b"),
        ]
        cached.get_secret("a")
        cached.get_secret("b")
        cached.invalidate_all()
        cached.get_secret("a")
        cached.get_secret("b")
        assert primary.get_secret.call_count == 4

    def test_set_secret_invalidates(self, cached, primary):
        cached.get_secret("test/key")
        cached.set_secret("test/key", "new-value")
        cached.get_secret("test/key")
        assert primary.get_secret.call_count == 2

    def test_delete_secret_invalidates(self, cached, primary):
        cached.get_secret("test/key")
        cached.delete_secret("test/key")
        cached.get_secret("test/key")
        assert primary.get_secret.call_count == 2


@pytest.mark.unit
class TestFallback:
    def test_fallback_called_on_backend_unavailable(self, cached_with_fallback, primary, fallback):
        primary.get_secret.side_effect = BackendUnavailableError("down", backend="primary")
        sv = cached_with_fallback.get_secret("test/key")
        assert sv.value == "fallback-value"
        fallback.get_secret.assert_called_once()

    def test_fallback_result_has_is_fallback_true(self, cached_with_fallback, primary, fallback):
        primary.get_secret.side_effect = BackendUnavailableError("down", backend="primary")
        sv = cached_with_fallback.get_secret("test/key")
        assert sv.is_fallback is True

    def test_fallback_not_cached(self, cached_with_fallback, primary, fallback):
        primary.get_secret.side_effect = BackendUnavailableError("down", backend="primary")
        cached_with_fallback.get_secret("test/key")
        cached_with_fallback.get_secret("test/key")
        assert fallback.get_secret.call_count == 2

    def test_fallback_called_on_access_denied(self, cached_with_fallback, primary, fallback):
        primary.get_secret.side_effect = AccessDeniedError("forbidden", backend="primary")
        cached_with_fallback.get_secret("test/key")
        fallback.get_secret.assert_called_once()

    def test_fallback_called_on_timeout(self, cached_with_fallback, primary, fallback):
        primary.get_secret.side_effect = TimeoutError("timed out")
        cached_with_fallback.get_secret("test/key")
        fallback.get_secret.assert_called_once()

    def test_no_fallback_reraises(self, primary):
        c = CachedSecretProvider(primary)
        primary.get_secret.side_effect = BackendUnavailableError("down", backend="primary")
        with pytest.raises(BackendUnavailableError):
            c.get_secret("test/key")

    def test_not_found_not_redirected_to_fallback(self, cached_with_fallback, primary, fallback):
        primary.get_secret.side_effect = SecretNotFoundError("nf", backend="primary")
        with pytest.raises(SecretNotFoundError):
            cached_with_fallback.get_secret("test/key")
        fallback.get_secret.assert_not_called()


@pytest.mark.unit
class TestAuditIntegration:
    def test_hit_logged(self, cached_with_fallback, primary, audit):
        cached_with_fallback.get_secret("test/key")
        cached_with_fallback.get_secret("test/key")  # hit
        hits = audit.query(result=AuditLogger.HIT)
        assert len(hits) == 1

    def test_miss_logged(self, cached_with_fallback, primary, audit):
        cached_with_fallback.get_secret("test/key")
        misses = audit.query(result=AuditLogger.MISS)
        assert len(misses) == 1

    def test_fallback_logged(self, cached_with_fallback, primary, audit, fallback):
        primary.get_secret.side_effect = BackendUnavailableError("down", backend="primary")
        cached_with_fallback.get_secret("test/key")
        fallbacks = audit.query(result=AuditLogger.FALLBACK)
        assert len(fallbacks) == 1

    def test_error_logged_when_both_fail(self, cached_with_fallback, primary, audit, fallback):
        primary.get_secret.side_effect = BackendUnavailableError("down", backend="primary")
        fallback.get_secret.side_effect = BackendUnavailableError("also down", backend="fallback")
        with pytest.raises(BackendUnavailableError):
            cached_with_fallback.get_secret("test/key")
        errors = audit.query(result=AuditLogger.ERROR)
        assert len(errors) >= 1


@pytest.mark.unit
class TestDynamicSecretTTL:
    def test_dynamic_secret_cached_with_lease_ttl(self, primary):
        """Effective TTL should be min(ttl_seconds, lease*0.9)."""
        # lease=100s, ttl=300s → effective = 100*0.9 = 90s
        primary.get_dynamic_secret.return_value = make_secret(
            is_dynamic=True, lease_seconds=100
        )
        c = CachedSecretProvider(primary, ttl_seconds=300)
        c.get_dynamic_secret("db-role")
        c.get_dynamic_secret("db-role")
        assert primary.get_dynamic_secret.call_count == 1  # served from cache

    def test_dynamic_secret_ttl_capped_by_config(self, primary):
        """When ttl_seconds < lease*0.9, use ttl_seconds."""
        primary.get_dynamic_secret.return_value = make_secret(
            is_dynamic=True, lease_seconds=7200  # 7200*0.9=6480 > 300
        )
        c = CachedSecretProvider(primary, ttl_seconds=300)
        c.get_dynamic_secret("db-role")
        c.get_dynamic_secret("db-role")
        assert primary.get_dynamic_secret.call_count == 1


@pytest.mark.unit
class TestCacheStats:
    def test_stats_shape(self, cached, primary):
        cached.get_secret("test/key")
        stats = cached.cache_stats()
        assert "alive_entries" in stats
        assert "total_entries" in stats
        assert "ttl_seconds" in stats
        assert "has_fallback" in stats

    def test_stats_alive_count(self, cached, primary):
        cached.get_secret("test/key")
        assert cached.cache_stats()["alive_entries"] == 1

    def test_stats_has_fallback_false(self, cached):
        assert cached.cache_stats()["has_fallback"] is False

    def test_max_size_eviction(self, primary):
        c = CachedSecretProvider(primary, ttl_seconds=60, max_size=3)
        for i in range(5):
            primary.get_secret.return_value = make_secret(path=f"p/{i}")
            c.get_secret(f"p/{i}")
        assert c.cache_stats()["total_entries"] <= 3

    def test_list_not_cached(self, cached, primary):
        cached.list_secrets()
        cached.list_secrets()
        assert primary.list_secrets.call_count == 2

    def test_health_check_primary_ok(self, cached, primary):
        primary.health_check.return_value = True
        assert cached.health_check() is True

    def test_health_check_fallback_ok_when_primary_fails(self, primary, fallback):
        primary.health_check.return_value = False
        fallback.health_check.return_value = True
        c = CachedSecretProvider(primary, fallback)
        assert c.health_check() is True
