"""Unit tests — Phase 1: SecretValue, exceptions, RotationPolicy, SecretProvider ABC."""

from __future__ import annotations

import time

import pytest

from secretsmanager.interface import (
    AccessDeniedError,
    BackendUnavailableError,
    RotationPolicy,
    RotationSchedule,
    SecretAccessDeniedError,
    SecretBackendError,
    SecretError,
    SecretNotFoundError,
    SecretProvider,
    SecretValue,
)


# ===========================================================================
# SecretValue
# ===========================================================================


@pytest.mark.unit
class TestSecretValue:
    def test_required_fields(self):
        sv = SecretValue(value="x", version="1", backend="mock")
        assert sv.value == "x"
        assert sv.version == "1"
        assert sv.backend == "mock"

    def test_immutable(self):
        sv = SecretValue(value="x", version="1", backend="b")
        with pytest.raises(AttributeError):
            sv.value = "y"  # type: ignore[misc]

    def test_obtained_at_auto(self):
        before = time.time()
        sv = SecretValue(value="x", version="1", backend="b")
        after = time.time()
        assert before <= sv.obtained_at <= after

    def test_expires_at_default_none(self):
        sv = SecretValue(value="x", version="1", backend="b")
        assert sv.expires_at is None
        assert sv.is_expired() is False
        assert sv.ttl_remaining() is None

    def test_expires_at_future(self):
        sv = SecretValue(value="x", version="1", backend="b", expires_at=time.time() + 3600)
        assert sv.is_expired() is False
        ttl = sv.ttl_remaining()
        assert ttl is not None and ttl > 3500

    def test_expires_at_past(self):
        sv = SecretValue(value="x", version="1", backend="b", expires_at=time.time() - 1)
        assert sv.is_expired() is True
        ttl = sv.ttl_remaining()
        assert ttl is not None and ttl < 0

    def test_is_dynamic_default_false(self):
        sv = SecretValue(value="x", version="1", backend="b")
        assert sv.is_dynamic is False

    def test_is_fallback_default_false(self):
        sv = SecretValue(value="x", version="1", backend="b")
        assert sv.is_fallback is False

    def test_as_fallback_copy(self):
        sv = SecretValue(value="x", version="1", backend="b")
        fb = sv.as_fallback()
        assert fb.is_fallback is True
        assert fb.value == sv.value
        assert fb.version == sv.version
        assert fb is not sv

    def test_checksum_deterministic(self):
        sv = SecretValue(value="hello", version="1", backend="b")
        assert sv.checksum == sv.checksum

    def test_checksum_changes_with_value(self):
        a = SecretValue(value="aaa", version="1", backend="b")
        b = SecretValue(value="bbb", version="1", backend="b")
        assert a.checksum != b.checksum

    def test_repr_does_not_leak_value(self):
        sv = SecretValue(value="topsecret!", version="2", path="x/y", backend="aws")
        r = repr(sv)
        assert "topsecret!" not in r
        assert "x/y" in r

    def test_path_default_empty_string(self):
        sv = SecretValue(value="x", version="1", backend="b")
        assert sv.path == ""

    def test_metadata_default_empty(self):
        sv = SecretValue(value="x", version="1", backend="b")
        assert sv.metadata == {}

    def test_dynamic_repr_shows_ttl(self):
        sv = SecretValue(
            value="x", version="1", backend="b",
            expires_at=time.time() + 3600, is_dynamic=True,
        )
        r = repr(sv)
        assert "dynamic" in r
        assert "ttl=" in r


# ===========================================================================
# Exceptions
# ===========================================================================


@pytest.mark.unit
class TestExceptions:
    def test_hierarchy(self):
        assert issubclass(SecretNotFoundError, SecretError)
        assert issubclass(AccessDeniedError, SecretError)
        assert issubclass(BackendUnavailableError, SecretError)

    def test_aliases(self):
        assert SecretAccessDeniedError is AccessDeniedError
        assert SecretBackendError is BackendUnavailableError

    def test_fields(self):
        exc = SecretNotFoundError("msg", backend="hashicorp", path="a/b")
        assert exc.backend == "hashicorp"
        assert exc.path == "a/b"

    def test_str_includes_backend(self):
        exc = BackendUnavailableError("timeout", backend="aws", path="x")
        s = str(exc)
        assert "timeout" in s
        assert "aws" in s

    def test_exception_is_catchable_as_base(self):
        with pytest.raises(SecretError):
            raise SecretNotFoundError("not found")


# ===========================================================================
# RotationPolicy
# ===========================================================================


@pytest.mark.unit
class TestRotationPolicy:
    def test_defaults(self):
        rp = RotationPolicy()
        assert rp.schedule == RotationSchedule.MONTHLY
        assert rp.interval_days == 30
        assert rp.notify_before == 7
        assert rp.auto_rotate is False

    def test_custom(self):
        rp = RotationPolicy(schedule=RotationSchedule.CUSTOM, interval_days=14, auto_rotate=True)
        assert rp.interval_days == 14
        assert rp.auto_rotate is True


# ===========================================================================
# SecretProvider ABC
# ===========================================================================


@pytest.mark.unit
class TestSecretProviderABC:
    def test_cannot_instantiate_directly(self):
        with pytest.raises(TypeError):
            SecretProvider()  # type: ignore[abstract]

    def test_concrete_must_implement_all_abstract(self):
        class Incomplete(SecretProvider):
            @property
            def backend_name(self) -> str:
                return "test"
            def get_secret(self, name, *, version=None):  # type: ignore[override]
                return SecretValue(value="v", version="1", backend="test")
            # Missing get_dynamic_secret, list_secrets, health_check

        with pytest.raises(TypeError):
            Incomplete()  # type: ignore[abstract]

    def test_minimal_concrete_works(self):
        class Minimal(SecretProvider):
            @property
            def backend_name(self) -> str:
                return "test"
            def get_secret(self, name, *, version=None):  # type: ignore[override]
                return SecretValue(value="v", version="1", backend="test")
            def get_dynamic_secret(self, role, **kwargs):  # type: ignore[override]
                raise NotImplementedError
            def list_secrets(self, prefix=""):  # type: ignore[override]
                return []
            def health_check(self) -> bool:  # type: ignore[override]
                return True

        p = Minimal()
        assert p.backend_name == "test"
        assert p.health_check() is True
