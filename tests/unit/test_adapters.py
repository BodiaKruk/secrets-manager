"""Unit tests — all four adapters with mocks.

Canonical class names (matching thesis §3.2):
  HashiCorpVaultAdapter, AwsSecretsManagerAdapter,
  GoogleSecretManagerAdapter, AzureKeyVaultAdapter

backend_name values:
  "hashicorp", "aws_secrets_manager", "google_secret_manager", "azure_key_vault"
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from secretsmanager.interface import (
    AccessDeniedError,
    BackendUnavailableError,
    SecretNotFoundError,
)

# ==========================================================================
# HashiCorp Vault — static + dynamic
# ==========================================================================


@pytest.fixture()
def vault_adapter():
    import hvac
    import hvac.exceptions  # use real exception classes so except clauses match

    with patch("secretsmanager.adapters.hashicorp.hvac") as mock_hvac:
        client = MagicMock()
        mock_hvac.Client.return_value = client
        mock_hvac.exceptions = hvac.exceptions
        from secretsmanager.adapters.hashicorp import HashiCorpVaultAdapter

        adapter = HashiCorpVaultAdapter(vault_url="http://vault:8200", vault_token="root")
        adapter._client = client
        yield adapter, client


@pytest.mark.unit
class TestHashiCorpVaultAdapter:
    def test_backend_name(self, vault_adapter):
        adapter, _ = vault_adapter
        assert adapter.backend_name == "hashicorp"

    def test_constructor_uses_vault_url_and_token(self):
        """Verify constructor signature matches thesis §3.2.2."""

        with patch("secretsmanager.adapters.hashicorp.hvac") as mock_hvac:
            mock_hvac.Client.return_value = MagicMock()
            from secretsmanager.adapters.hashicorp import HashiCorpVaultAdapter

            HashiCorpVaultAdapter(vault_url="http://v:8200", vault_token="root-token")
            mock_hvac.Client.assert_called_once()
            call_kwargs = mock_hvac.Client.call_args
            assert call_kwargs.kwargs["url"] == "http://v:8200"
            assert call_kwargs.kwargs["token"] == "root-token"

    def test_get_secret_success_single_key(self, vault_adapter):
        adapter, client = vault_adapter
        client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"value": "supersecret"}, "metadata": {"version": 3}}
        }
        sv = adapter.get_secret("prod/db")
        assert sv.value == "supersecret"
        assert sv.version == "3"
        assert sv.backend == "hashicorp"
        assert sv.is_dynamic is False

    def test_get_secret_multi_key_serialised_as_json(self, vault_adapter):
        adapter, client = vault_adapter
        client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"user": "admin", "pass": "s3cr3t"}, "metadata": {"version": 1}}
        }
        sv = adapter.get_secret("prod/db")
        parsed = json.loads(sv.value)
        assert parsed["user"] == "admin"

    def test_get_secret_not_found(self, vault_adapter):
        import hvac.exceptions

        adapter, client = vault_adapter
        client.secrets.kv.v2.read_secret_version.side_effect = hvac.exceptions.InvalidPath()
        with pytest.raises(SecretNotFoundError) as exc_info:
            adapter.get_secret("missing/path")
        assert exc_info.value.backend == "hashicorp"

    def test_get_secret_forbidden(self, vault_adapter):
        import hvac.exceptions

        adapter, client = vault_adapter
        client.secrets.kv.v2.read_secret_version.side_effect = hvac.exceptions.Forbidden()
        with pytest.raises(AccessDeniedError):
            adapter.get_secret("forbidden/path")

    def test_get_secret_generic_error_raises_backend_unavailable(self, vault_adapter):
        adapter, client = vault_adapter
        client.secrets.kv.v2.read_secret_version.side_effect = ConnectionError("refused")
        with pytest.raises(BackendUnavailableError):
            adapter.get_secret("prod/key")

    # ------ dynamic secrets ------

    def test_get_dynamic_secret_success(self, vault_adapter):
        adapter, client = vault_adapter
        client.secrets.database.generate_credentials.return_value = {
            "data": {"username": "v-user-abc", "password": "X!p@ssw0rd"},
            "lease_id": "database/creds/readonly/abc123",
            "lease_duration": 3600,
            "renewable": True,
        }
        sv = adapter.get_dynamic_secret("readonly-role")
        assert sv.is_dynamic is True
        assert sv.expires_at is not None
        data = json.loads(sv.value)
        assert data["username"] == "v-user-abc"
        assert sv.metadata["lease_duration"] == 3600
        assert sv.metadata["renewable"] is True

    def test_get_dynamic_secret_role_not_found(self, vault_adapter):
        import hvac.exceptions

        adapter, client = vault_adapter
        client.secrets.database.generate_credentials.side_effect = hvac.exceptions.InvalidPath()
        with pytest.raises(SecretNotFoundError):
            adapter.get_dynamic_secret("nonexistent-role")

    def test_get_dynamic_secret_forbidden(self, vault_adapter):
        import hvac.exceptions

        adapter, client = vault_adapter
        client.secrets.database.generate_credentials.side_effect = hvac.exceptions.Forbidden()
        with pytest.raises(AccessDeniedError):
            adapter.get_dynamic_secret("locked-role")

    def test_set_secret_returns_version(self, vault_adapter):
        adapter, client = vault_adapter
        client.secrets.kv.v2.create_or_update_secret.return_value = {"data": {"version": 5}}
        assert adapter.set_secret("prod/key", "value") == "5"

    def test_list_secrets_sorted(self, vault_adapter):
        adapter, client = vault_adapter
        client.secrets.kv.v2.list_secrets.return_value = {"data": {"keys": ["c", "a", "b"]}}
        keys = adapter.list_secrets()
        assert keys == sorted(keys)

    def test_health_check_authenticated(self, vault_adapter):
        adapter, client = vault_adapter
        client.is_authenticated.return_value = True
        assert adapter.health_check() is True

    def test_health_check_exception_returns_false(self, vault_adapter):
        adapter, client = vault_adapter
        client.is_authenticated.side_effect = Exception("unreachable")
        assert adapter.health_check() is False

    def test_get_secret_with_version(self, vault_adapter):
        adapter, client = vault_adapter
        client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"value": "v2val"}, "metadata": {"version": 2}}
        }
        sv = adapter.get_secret("prod/db", version="2")
        call_kw = client.secrets.kv.v2.read_secret_version.call_args.kwargs
        assert call_kw["version"] == 2
        assert sv.value == "v2val"

    def test_get_dynamic_secret_generic_error(self, vault_adapter):
        adapter, client = vault_adapter
        client.secrets.database.generate_credentials.side_effect = ConnectionError("down")
        with pytest.raises(BackendUnavailableError):
            adapter.get_dynamic_secret("any-role")

    def test_set_secret_forbidden(self, vault_adapter):
        import hvac.exceptions

        adapter, client = vault_adapter
        client.secrets.kv.v2.create_or_update_secret.side_effect = hvac.exceptions.Forbidden()
        with pytest.raises(AccessDeniedError):
            adapter.set_secret("prod/key", "val")

    def test_set_secret_generic_error(self, vault_adapter):
        adapter, client = vault_adapter
        client.secrets.kv.v2.create_or_update_secret.side_effect = ConnectionError("down")
        with pytest.raises(BackendUnavailableError):
            adapter.set_secret("prod/key", "val")

    def test_delete_secret_soft(self, vault_adapter):
        adapter, client = vault_adapter
        adapter.delete_secret("prod/key")
        client.secrets.kv.v2.delete_latest_version_of_secret.assert_called_once()

    def test_delete_secret_force(self, vault_adapter):
        adapter, client = vault_adapter
        adapter.delete_secret("prod/key", force=True)
        client.secrets.kv.v2.delete_metadata_and_all_versions.assert_called_once()

    def test_delete_secret_not_found(self, vault_adapter):
        import hvac.exceptions

        adapter, client = vault_adapter
        client.secrets.kv.v2.delete_latest_version_of_secret.side_effect = (
            hvac.exceptions.InvalidPath()
        )
        with pytest.raises(SecretNotFoundError):
            adapter.delete_secret("missing/key")

    def test_delete_secret_forbidden(self, vault_adapter):
        import hvac.exceptions

        adapter, client = vault_adapter
        client.secrets.kv.v2.delete_latest_version_of_secret.side_effect = (
            hvac.exceptions.Forbidden()
        )
        with pytest.raises(AccessDeniedError):
            adapter.delete_secret("prod/key")

    def test_delete_secret_generic_error(self, vault_adapter):
        adapter, client = vault_adapter
        client.secrets.kv.v2.delete_latest_version_of_secret.side_effect = ConnectionError("down")
        with pytest.raises(BackendUnavailableError):
            adapter.delete_secret("prod/key")

    def test_list_secrets_forbidden(self, vault_adapter):
        import hvac.exceptions

        adapter, client = vault_adapter
        client.secrets.kv.v2.list_secrets.side_effect = hvac.exceptions.Forbidden()
        with pytest.raises(AccessDeniedError):
            adapter.list_secrets("prod/")

    def test_list_secrets_generic_error(self, vault_adapter):
        adapter, client = vault_adapter
        client.secrets.kv.v2.list_secrets.side_effect = ConnectionError("down")
        with pytest.raises(BackendUnavailableError):
            adapter.list_secrets()

    def test_list_secrets_empty_on_invalid_path(self, vault_adapter):
        import hvac.exceptions

        adapter, client = vault_adapter
        client.secrets.kv.v2.list_secrets.side_effect = hvac.exceptions.InvalidPath()
        assert adapter.list_secrets("empty/") == []

    def test_rotate_secret_increments_version(self, vault_adapter):
        adapter, client = vault_adapter
        client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"value": "current"}, "metadata": {"version": 1}}
        }
        client.secrets.kv.v2.create_or_update_secret.return_value = {"data": {"version": 2}}
        version = adapter.rotate_secret("prod/key")
        assert version == "2"


# ==========================================================================
# AWS Secrets Manager — AwsSecretsManagerAdapter
# ==========================================================================


@pytest.fixture()
def aws_adapter():
    with patch("secretsmanager.adapters.aws.boto3") as mock_boto3:
        session = MagicMock()
        client = MagicMock()
        mock_boto3.session.Session.return_value = session
        session.client.return_value = client
        from secretsmanager.adapters.aws import AwsSecretsManagerAdapter

        adapter = AwsSecretsManagerAdapter(region_name="us-east-1")
        adapter._client = client
        yield adapter, client


@pytest.mark.unit
class TestAwsSecretsManagerAdapter:
    def test_backend_name(self, aws_adapter):
        adapter, _ = aws_adapter
        assert adapter.backend_name == "aws_secrets_manager"

    def test_get_secret_string(self, aws_adapter):
        adapter, client = aws_adapter
        client.get_secret_value.return_value = {
            "SecretString": "mypassword",
            "VersionId": "v-abc",
            "ARN": "arn:aws:...",
            "Name": "prod/db",
        }
        sv = adapter.get_secret("prod/db")
        assert sv.value == "mypassword"
        assert sv.version == "v-abc"
        assert sv.backend == "aws_secrets_manager"

    def test_get_secret_binary_base64_encoded(self, aws_adapter):
        """SecretBinary must be returned as a base64-encoded string (thesis §3.2.3)."""
        import base64

        adapter, client = aws_adapter
        raw_bytes = b"\x00\x01\x02\x03binary_data"
        client.get_secret_value.return_value = {
            "SecretBinary": raw_bytes,
            "VersionId": "v-bin",
            "ARN": "arn:aws:...",
            "Name": "prod/cert",
        }
        sv = adapter.get_secret("prod/cert")
        assert sv.value == base64.b64encode(raw_bytes).decode("utf-8")

    def test_get_secret_not_found(self, aws_adapter):
        from botocore.exceptions import ClientError

        adapter, client = aws_adapter
        client.get_secret_value.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "nf"}}, "op"
        )
        with pytest.raises(SecretNotFoundError):
            adapter.get_secret("missing")

    def test_get_secret_access_denied(self, aws_adapter):
        from botocore.exceptions import ClientError

        adapter, client = aws_adapter
        client.get_secret_value.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "op"
        )
        with pytest.raises(AccessDeniedError):
            adapter.get_secret("denied/path")

    def test_get_dynamic_secret_raises_not_implemented(self, aws_adapter):
        adapter, _ = aws_adapter
        with pytest.raises(NotImplementedError):
            adapter.get_dynamic_secret("any-role")

    def test_alias_still_works(self):
        """AWSSecretsManagerAdapter is an alias for backward compatibility."""
        from secretsmanager.adapters.aws import AWSSecretsManagerAdapter, AwsSecretsManagerAdapter

        assert AWSSecretsManagerAdapter is AwsSecretsManagerAdapter

    def test_health_check_ok(self, aws_adapter):
        adapter, client = aws_adapter
        client.list_secrets.return_value = {"SecretList": []}
        assert adapter.health_check() is True

    def test_health_check_fail(self, aws_adapter):
        adapter, client = aws_adapter
        client.list_secrets.side_effect = Exception("network error")
        assert adapter.health_check() is False

    def test_get_secret_with_version(self, aws_adapter):
        adapter, client = aws_adapter
        client.get_secret_value.return_value = {
            "SecretString": "versioned",
            "VersionId": "v2",
            "ARN": "",
            "Name": "k",
        }
        sv = adapter.get_secret("k", version="v2")
        call_kw = client.get_secret_value.call_args.kwargs
        assert call_kw.get("VersionId") == "v2"
        assert sv.value == "versioned"

    def test_get_secret_generic_error(self, aws_adapter):
        adapter, client = aws_adapter
        client.get_secret_value.side_effect = RuntimeError("timeout")
        with pytest.raises(BackendUnavailableError):
            adapter.get_secret("k")

    def test_raise_unknown_code_raises_backend_unavailable(self, aws_adapter):
        from botocore.exceptions import ClientError

        adapter, client = aws_adapter
        client.get_secret_value.side_effect = ClientError(
            {"Error": {"Code": "InternalServiceError", "Message": "oops"}}, "op"
        )
        with pytest.raises(BackendUnavailableError):
            adapter.get_secret("k")

    def test_set_secret_update_existing(self, aws_adapter):
        adapter, client = aws_adapter
        client.put_secret_value.return_value = {"VersionId": "v5"}
        ver = adapter.set_secret("existing", "newval")
        assert ver == "v5"
        client.put_secret_value.assert_called_once()
        client.create_secret.assert_not_called()

    def test_set_secret_creates_when_not_found(self, aws_adapter):
        from botocore.exceptions import ClientError

        adapter, client = aws_adapter
        client.put_secret_value.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "nf"}}, "op"
        )
        client.create_secret.return_value = {"VersionId": "v1"}
        ver = adapter.set_secret("new-key", "val")
        assert ver == "v1"
        client.create_secret.assert_called_once()

    def test_set_secret_with_tags(self, aws_adapter):
        adapter, client = aws_adapter
        client.put_secret_value.side_effect = __import__("botocore").exceptions.ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "nf"}}, "op"
        )
        client.create_secret.return_value = {"VersionId": "v1"}
        adapter.set_secret("k", "v", metadata={"env": "prod"})
        call_kw = client.create_secret.call_args.kwargs
        assert call_kw["Tags"] == [{"Key": "env", "Value": "prod"}]

    def test_set_secret_generic_error(self, aws_adapter):
        adapter, client = aws_adapter
        client.put_secret_value.side_effect = RuntimeError("boom")
        with pytest.raises(BackendUnavailableError):
            adapter.set_secret("k", "v")

    def test_delete_secret_soft(self, aws_adapter):
        adapter, client = aws_adapter
        adapter.delete_secret("k")
        call_kw = client.delete_secret.call_args.kwargs
        assert "RecoveryWindowInDays" in call_kw

    def test_delete_secret_force(self, aws_adapter):
        adapter, client = aws_adapter
        adapter.delete_secret("k", force=True)
        call_kw = client.delete_secret.call_args.kwargs
        assert "ForceDeleteWithoutRecovery" in call_kw

    def test_delete_secret_not_found(self, aws_adapter):
        from botocore.exceptions import ClientError

        adapter, client = aws_adapter
        client.delete_secret.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "nf"}}, "op"
        )
        with pytest.raises(SecretNotFoundError):
            adapter.delete_secret("missing")

    def test_delete_secret_generic_error(self, aws_adapter):
        adapter, client = aws_adapter
        client.delete_secret.side_effect = RuntimeError("boom")
        with pytest.raises(BackendUnavailableError):
            adapter.delete_secret("k")

    def test_list_secrets_no_prefix(self, aws_adapter):
        adapter, client = aws_adapter
        page = {"SecretList": [{"Name": "b"}, {"Name": "a"}]}
        client.get_paginator.return_value.paginate.return_value = [page]
        result = adapter.list_secrets()
        assert result == ["a", "b"]

    def test_list_secrets_with_prefix(self, aws_adapter):
        adapter, client = aws_adapter
        page = {"SecretList": [{"Name": "prod/db"}]}
        client.get_paginator.return_value.paginate.return_value = [page]
        result = adapter.list_secrets("prod/")
        call_kw = client.get_paginator.return_value.paginate.call_args.kwargs
        assert call_kw["Filters"] == [{"Key": "name", "Values": ["prod/"]}]
        assert "prod/db" in result

    def test_list_secrets_generic_error(self, aws_adapter):
        adapter, client = aws_adapter
        client.get_paginator.return_value.paginate.side_effect = RuntimeError("down")
        with pytest.raises(BackendUnavailableError):
            adapter.list_secrets()

    def test_rotate_secret_calls_aws(self, aws_adapter):
        adapter, client = aws_adapter
        client.rotate_secret.return_value = {"VersionId": "rotated-v"}
        ver = adapter.rotate_secret("k")
        assert ver == "rotated-v"

    def test_rotate_secret_generic_error(self, aws_adapter):
        adapter, client = aws_adapter
        client.rotate_secret.side_effect = RuntimeError("boom")
        with pytest.raises(BackendUnavailableError):
            adapter.rotate_secret("k")


# ==========================================================================
# Google Secret Manager — GoogleSecretManagerAdapter
# ==========================================================================


@pytest.fixture()
def gcp_adapter():
    with patch("secretsmanager.adapters.google.secretmanager") as mock_sm:
        client = MagicMock()
        mock_sm.SecretManagerServiceClient.return_value = client
        from secretsmanager.adapters.google import GoogleSecretManagerAdapter

        adapter = GoogleSecretManagerAdapter(project_id="my-project")
        adapter._client = client
        yield adapter, client


@pytest.mark.unit
class TestGoogleSecretManagerAdapter:
    def test_backend_name(self, gcp_adapter):
        adapter, _ = gcp_adapter
        assert adapter.backend_name == "google_secret_manager"

    def test_class_name(self):
        from secretsmanager.adapters.google import GoogleSecretManagerAdapter

        assert GoogleSecretManagerAdapter.__name__ == "GoogleSecretManagerAdapter"

    def test_gcp_alias_still_works(self):
        from secretsmanager.adapters.google import (
            GCPSecretManagerAdapter,
            GoogleSecretManagerAdapter,
        )

        assert GCPSecretManagerAdapter is GoogleSecretManagerAdapter

    def test_get_secret_success(self, gcp_adapter):
        adapter, client = gcp_adapter
        resp = MagicMock()
        resp.payload.data = b"gcp-secret"
        resp.name = "projects/p/secrets/prod-db/versions/5"
        client.access_secret_version.return_value = resp
        sv = adapter.get_secret("prod-db")
        assert sv.value == "gcp-secret"
        assert sv.version == "5"
        assert sv.backend == "google_secret_manager"

    def test_get_secret_not_found(self, gcp_adapter):
        from google.api_core.exceptions import NotFound

        adapter, client = gcp_adapter
        client.access_secret_version.side_effect = NotFound("nf")
        with pytest.raises(SecretNotFoundError):
            adapter.get_secret("missing")

    def test_get_secret_permission_denied(self, gcp_adapter):
        from google.api_core.exceptions import PermissionDenied

        adapter, client = gcp_adapter
        client.access_secret_version.side_effect = PermissionDenied("denied")
        with pytest.raises(AccessDeniedError):
            adapter.get_secret("forbidden")

    def test_get_dynamic_secret_raises_not_implemented(self, gcp_adapter):
        adapter, _ = gcp_adapter
        with pytest.raises(NotImplementedError):
            adapter.get_dynamic_secret("any-role")

    def test_get_secret_with_explicit_version(self, gcp_adapter):
        adapter, client = gcp_adapter
        resp = MagicMock()
        resp.payload.data = b"val"
        resp.name = "projects/p/secrets/s/versions/3"
        client.access_secret_version.return_value = resp
        sv = adapter.get_secret("s", version="3")
        req = client.access_secret_version.call_args.kwargs["request"]
        assert req["name"].endswith("/versions/3")
        assert sv.version == "3"

    def test_get_secret_google_api_error(self, gcp_adapter):
        from google.api_core.exceptions import GoogleAPICallError

        adapter, client = gcp_adapter
        client.access_secret_version.side_effect = GoogleAPICallError("api error")
        with pytest.raises(BackendUnavailableError):
            adapter.get_secret("s")

    def test_set_secret_existing(self, gcp_adapter):
        adapter, client = gcp_adapter
        resp = MagicMock()
        resp.name = "projects/p/secrets/s/versions/2"
        client.add_secret_version.return_value = resp
        ver = adapter.set_secret("s", "val")
        assert ver == "2"
        client.create_secret.assert_not_called()

    def test_set_secret_creates_new(self, gcp_adapter):
        from google.api_core.exceptions import NotFound

        adapter, client = gcp_adapter
        client.get_secret.side_effect = NotFound("nf")
        resp = MagicMock()
        resp.name = "projects/p/secrets/s/versions/1"
        client.add_secret_version.return_value = resp
        ver = adapter.set_secret("s", "val")
        assert ver == "1"
        client.create_secret.assert_called_once()

    def test_set_secret_permission_denied(self, gcp_adapter):
        from google.api_core.exceptions import PermissionDenied

        adapter, client = gcp_adapter
        client.get_secret.side_effect = PermissionDenied("denied")
        with pytest.raises(AccessDeniedError):
            adapter.set_secret("s", "val")

    def test_set_secret_google_api_error(self, gcp_adapter):
        from google.api_core.exceptions import GoogleAPICallError

        adapter, client = gcp_adapter
        client.get_secret.side_effect = GoogleAPICallError("api error")
        with pytest.raises(BackendUnavailableError):
            adapter.set_secret("s", "val")

    def test_delete_secret_success(self, gcp_adapter):
        adapter, client = gcp_adapter
        adapter.delete_secret("s")
        client.delete_secret.assert_called_once()

    def test_delete_secret_not_found(self, gcp_adapter):
        from google.api_core.exceptions import NotFound

        adapter, client = gcp_adapter
        client.delete_secret.side_effect = NotFound("nf")
        with pytest.raises(SecretNotFoundError):
            adapter.delete_secret("missing")

    def test_delete_secret_permission_denied(self, gcp_adapter):
        from google.api_core.exceptions import PermissionDenied

        adapter, client = gcp_adapter
        client.delete_secret.side_effect = PermissionDenied("denied")
        with pytest.raises(AccessDeniedError):
            adapter.delete_secret("s")

    def test_delete_secret_google_api_error(self, gcp_adapter):
        from google.api_core.exceptions import GoogleAPICallError

        adapter, client = gcp_adapter
        client.delete_secret.side_effect = GoogleAPICallError("api error")
        with pytest.raises(BackendUnavailableError):
            adapter.delete_secret("s")

    def test_list_secrets_no_prefix(self, gcp_adapter):
        adapter, client = gcp_adapter
        s1, s2 = MagicMock(), MagicMock()
        s1.name = "projects/p/secrets/beta"
        s2.name = "projects/p/secrets/alpha"
        client.list_secrets.return_value = [s1, s2]
        result = adapter.list_secrets()
        assert result == ["alpha", "beta"]

    def test_list_secrets_with_prefix(self, gcp_adapter):
        adapter, client = gcp_adapter
        s1, s2 = MagicMock(), MagicMock()
        s1.name = "projects/p/secrets/prod-db"
        s2.name = "projects/p/secrets/dev-db"
        client.list_secrets.return_value = [s1, s2]
        result = adapter.list_secrets("prod")
        assert result == ["prod-db"]

    def test_list_secrets_permission_denied(self, gcp_adapter):
        from google.api_core.exceptions import PermissionDenied

        adapter, client = gcp_adapter
        client.list_secrets.side_effect = PermissionDenied("denied")
        with pytest.raises(AccessDeniedError):
            adapter.list_secrets()

    def test_list_secrets_google_api_error(self, gcp_adapter):
        from google.api_core.exceptions import GoogleAPICallError

        adapter, client = gcp_adapter
        client.list_secrets.side_effect = GoogleAPICallError("api error")
        with pytest.raises(BackendUnavailableError):
            adapter.list_secrets()

    def test_rotate_secret(self, gcp_adapter):
        adapter, client = gcp_adapter
        get_resp = MagicMock()
        get_resp.payload.data = b"current-val"
        get_resp.name = "projects/p/secrets/s/versions/1"
        client.access_secret_version.return_value = get_resp
        set_resp = MagicMock()
        set_resp.name = "projects/p/secrets/s/versions/2"
        client.add_secret_version.return_value = set_resp
        ver = adapter.rotate_secret("s")
        assert ver == "2"

    def test_health_check_ok(self, gcp_adapter):
        adapter, client = gcp_adapter
        client.list_secrets.return_value = []
        assert adapter.health_check() is True

    def test_health_check_fail(self, gcp_adapter):
        from google.api_core.exceptions import GoogleAPICallError

        adapter, client = gcp_adapter
        client.list_secrets.side_effect = GoogleAPICallError("down")
        assert adapter.health_check() is False


# ==========================================================================
# Azure Key Vault — AzureKeyVaultAdapter
# ==========================================================================


@pytest.fixture()
def azure_adapter():
    with (
        patch("secretsmanager.adapters.azure.SecretClient") as mock_sc,
        patch("secretsmanager.adapters.azure.DefaultAzureCredential"),
    ):
        client = MagicMock()
        mock_sc.return_value = client
        from secretsmanager.adapters.azure import AzureKeyVaultAdapter

        adapter = AzureKeyVaultAdapter(vault_url="https://myvault.vault.azure.net")
        adapter._client = client
        yield adapter, client


@pytest.mark.unit
class TestAzureKeyVaultAdapter:
    def test_backend_name(self, azure_adapter):
        adapter, _ = azure_adapter
        assert adapter.backend_name == "azure_key_vault"

    def test_auth_mode_default_uses_default_credential(self):
        """auth_mode='default' should call DefaultAzureCredential (thesis §3.2.3)."""
        with (
            patch("secretsmanager.adapters.azure.SecretClient"),
            patch("secretsmanager.adapters.azure.DefaultAzureCredential") as mock_dac,
            patch("secretsmanager.adapters.azure.ClientSecretCredential"),
        ):
            from secretsmanager.adapters.azure import AzureKeyVaultAdapter

            AzureKeyVaultAdapter("https://v.vault.azure.net", auth_mode="default")
            mock_dac.assert_called_once()

    def test_auth_mode_service_principal_uses_client_secret_credential(self):
        """auth_mode='service_principal' must use ClientSecretCredential (thesis §3.2.3)."""
        with (
            patch("secretsmanager.adapters.azure.SecretClient"),
            patch("secretsmanager.adapters.azure.DefaultAzureCredential"),
            patch("secretsmanager.adapters.azure.ClientSecretCredential") as mock_csc,
        ):
            from secretsmanager.adapters.azure import AzureKeyVaultAdapter

            AzureKeyVaultAdapter(
                "https://v.vault.azure.net",
                auth_mode="service_principal",
                tenant_id="t1",
                client_id="c1",
                client_secret="s1",
            )
            mock_csc.assert_called_once_with(tenant_id="t1", client_id="c1", client_secret="s1")

    def test_service_principal_reads_env_vars(self, monkeypatch):
        """If params not supplied, AZURE_* env vars must be used (thesis §3.2.3)."""
        monkeypatch.setenv("AZURE_TENANT_ID", "env-tenant")
        monkeypatch.setenv("AZURE_CLIENT_ID", "env-client")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "env-secret")
        with (
            patch("secretsmanager.adapters.azure.SecretClient"),
            patch("secretsmanager.adapters.azure.DefaultAzureCredential"),
            patch("secretsmanager.adapters.azure.ClientSecretCredential") as mock_csc,
        ):
            from secretsmanager.adapters.azure import AzureKeyVaultAdapter

            AzureKeyVaultAdapter("https://v.vault.azure.net", auth_mode="service_principal")
            mock_csc.assert_called_once_with(
                tenant_id="env-tenant", client_id="env-client", client_secret="env-secret"
            )

    def test_get_secret_success(self, azure_adapter):
        adapter, client = azure_adapter
        resp = MagicMock()
        resp.value = "azure-secret"
        resp.properties.version = "ver1"
        resp.properties.tags = {"env": "prod"}
        client.get_secret.return_value = resp
        sv = adapter.get_secret("prod-db")
        assert sv.value == "azure-secret"
        assert sv.version == "ver1"
        assert sv.backend == "azure_key_vault"
        assert sv.metadata["env"] == "prod"

    def test_get_secret_not_found(self, azure_adapter):
        from azure.core.exceptions import ResourceNotFoundError

        adapter, client = azure_adapter
        client.get_secret.side_effect = ResourceNotFoundError("nf")
        with pytest.raises(SecretNotFoundError):
            adapter.get_secret("missing")

    def test_get_secret_auth_error(self, azure_adapter):
        from azure.core.exceptions import ClientAuthenticationError

        adapter, client = azure_adapter
        client.get_secret.side_effect = ClientAuthenticationError("bad token")
        with pytest.raises(AccessDeniedError):
            adapter.get_secret("any")

    def test_get_dynamic_secret_raises_not_implemented(self, azure_adapter):
        adapter, _ = azure_adapter
        with pytest.raises(NotImplementedError):
            adapter.get_dynamic_secret("any-role")

    def test_health_check_ok(self, azure_adapter):
        adapter, client = azure_adapter
        client.list_properties_of_secrets.return_value = iter([])
        assert adapter.health_check() is True

    def test_health_check_fail(self, azure_adapter):
        adapter, client = azure_adapter
        client.list_properties_of_secrets.side_effect = Exception("network error")
        assert adapter.health_check() is False

    def test_custom_credential_bypasses_auth_mode(self):
        custom_cred = MagicMock()
        with (
            patch("secretsmanager.adapters.azure.SecretClient") as mock_sc,
            patch("secretsmanager.adapters.azure.DefaultAzureCredential") as mock_dac,
            patch("secretsmanager.adapters.azure.ClientSecretCredential") as mock_csc,
        ):
            from secretsmanager.adapters.azure import AzureKeyVaultAdapter

            AzureKeyVaultAdapter("https://v.vault.azure.net", credential=custom_cred)
            mock_dac.assert_not_called()
            mock_csc.assert_not_called()
            mock_sc.assert_called_once_with(
                vault_url="https://v.vault.azure.net", credential=custom_cred
            )

    def test_get_secret_http_response_error_403(self, azure_adapter):
        from azure.core.exceptions import HttpResponseError

        adapter, client = azure_adapter
        exc = HttpResponseError()
        exc.status_code = 403
        client.get_secret.side_effect = exc
        with pytest.raises(AccessDeniedError):
            adapter.get_secret("k")

    def test_get_secret_http_response_error_non_403(self, azure_adapter):
        from azure.core.exceptions import HttpResponseError

        adapter, client = azure_adapter
        exc = HttpResponseError()
        exc.status_code = 500
        client.get_secret.side_effect = exc
        with pytest.raises(BackendUnavailableError):
            adapter.get_secret("k")

    def test_set_secret_success(self, azure_adapter):
        adapter, client = azure_adapter
        resp = MagicMock()
        resp.properties.version = "ver2"
        client.set_secret.return_value = resp
        ver = adapter.set_secret("k", "val")
        assert ver == "ver2"

    def test_set_secret_with_metadata(self, azure_adapter):
        adapter, client = azure_adapter
        resp = MagicMock()
        resp.properties.version = "v1"
        client.set_secret.return_value = resp
        adapter.set_secret("k", "val", metadata={"env": "prod"})
        call_kw = client.set_secret.call_args.kwargs
        assert call_kw["tags"] == {"env": "prod"}

    def test_set_secret_auth_error(self, azure_adapter):
        from azure.core.exceptions import ClientAuthenticationError

        adapter, client = azure_adapter
        client.set_secret.side_effect = ClientAuthenticationError("bad token")
        with pytest.raises(AccessDeniedError):
            adapter.set_secret("k", "val")

    def test_set_secret_http_error(self, azure_adapter):
        from azure.core.exceptions import HttpResponseError

        adapter, client = azure_adapter
        exc = HttpResponseError()
        exc.status_code = 500
        client.set_secret.side_effect = exc
        with pytest.raises(BackendUnavailableError):
            adapter.set_secret("k", "val")

    def test_delete_secret_success(self, azure_adapter):
        adapter, client = azure_adapter
        poller = MagicMock()
        client.begin_delete_secret.return_value = poller
        adapter.delete_secret("k")
        poller.wait.assert_called_once()
        client.purge_deleted_secret.assert_not_called()

    def test_delete_secret_force(self, azure_adapter):
        adapter, client = azure_adapter
        poller = MagicMock()
        client.begin_delete_secret.return_value = poller
        adapter.delete_secret("k", force=True)
        client.purge_deleted_secret.assert_called_once_with("k")

    def test_delete_secret_not_found(self, azure_adapter):
        from azure.core.exceptions import ResourceNotFoundError

        adapter, client = azure_adapter
        client.begin_delete_secret.side_effect = ResourceNotFoundError("nf")
        with pytest.raises(SecretNotFoundError):
            adapter.delete_secret("missing")

    def test_delete_secret_auth_error(self, azure_adapter):
        from azure.core.exceptions import ClientAuthenticationError

        adapter, client = azure_adapter
        client.begin_delete_secret.side_effect = ClientAuthenticationError("bad token")
        with pytest.raises(AccessDeniedError):
            adapter.delete_secret("k")

    def test_delete_secret_http_error(self, azure_adapter):
        from azure.core.exceptions import HttpResponseError

        adapter, client = azure_adapter
        exc = HttpResponseError()
        exc.status_code = 500
        client.begin_delete_secret.side_effect = exc
        with pytest.raises(BackendUnavailableError):
            adapter.delete_secret("k")

    def test_list_secrets_no_prefix(self, azure_adapter):
        adapter, client = azure_adapter
        p1, p2 = MagicMock(), MagicMock()
        p1.name = "beta"
        p2.name = "alpha"
        client.list_properties_of_secrets.return_value = [p1, p2]
        result = adapter.list_secrets()
        assert result == ["alpha", "beta"]

    def test_list_secrets_with_prefix(self, azure_adapter):
        adapter, client = azure_adapter
        p1, p2 = MagicMock(), MagicMock()
        p1.name = "prod-db"
        p2.name = "dev-db"
        client.list_properties_of_secrets.return_value = [p1, p2]
        result = adapter.list_secrets("prod")
        assert result == ["prod-db"]

    def test_list_secrets_auth_error(self, azure_adapter):
        from azure.core.exceptions import ClientAuthenticationError

        adapter, client = azure_adapter
        client.list_properties_of_secrets.side_effect = ClientAuthenticationError("bad")
        with pytest.raises(AccessDeniedError):
            adapter.list_secrets()

    def test_list_secrets_http_error(self, azure_adapter):
        from azure.core.exceptions import HttpResponseError

        adapter, client = azure_adapter
        exc = HttpResponseError()
        exc.status_code = 500
        client.list_properties_of_secrets.side_effect = exc
        with pytest.raises(BackendUnavailableError):
            adapter.list_secrets()

    def test_rotate_secret(self, azure_adapter):
        adapter, client = azure_adapter
        get_resp = MagicMock()
        get_resp.value = "current"
        get_resp.properties.version = "v1"
        get_resp.properties.tags = {}
        client.get_secret.return_value = get_resp
        set_resp = MagicMock()
        set_resp.properties.version = "v2"
        client.set_secret.return_value = set_resp
        ver = adapter.rotate_secret("k")
        assert ver == "v2"
