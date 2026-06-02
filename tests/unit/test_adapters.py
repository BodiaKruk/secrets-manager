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
        adapter = HashiCorpVaultAdapter(
            vault_url="http://vault:8200", vault_token="root"
        )
        adapter._client = client
        yield adapter, client


@pytest.mark.unit
class TestHashiCorpVaultAdapter:
    def test_backend_name(self, vault_adapter):
        adapter, _ = vault_adapter
        assert adapter.backend_name == "hashicorp"

    def test_constructor_uses_vault_url_and_token(self):
        """Verify constructor signature matches thesis §3.2.2."""
        import hvac
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
        client.secrets.database.generate_credentials.side_effect = (
            hvac.exceptions.InvalidPath()
        )
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
        from secretsmanager.adapters.google import GCPSecretManagerAdapter, GoogleSecretManagerAdapter
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


# ==========================================================================
# Azure Key Vault — AzureKeyVaultAdapter
# ==========================================================================


@pytest.fixture()
def azure_adapter():
    with patch("secretsmanager.adapters.azure.SecretClient") as mock_sc, \
         patch("secretsmanager.adapters.azure.DefaultAzureCredential"):
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
        with patch("secretsmanager.adapters.azure.SecretClient"), \
             patch("secretsmanager.adapters.azure.DefaultAzureCredential") as mock_dac, \
             patch("secretsmanager.adapters.azure.ClientSecretCredential"):
            from secretsmanager.adapters.azure import AzureKeyVaultAdapter
            AzureKeyVaultAdapter("https://v.vault.azure.net", auth_mode="default")
            mock_dac.assert_called_once()

    def test_auth_mode_service_principal_uses_client_secret_credential(self):
        """auth_mode='service_principal' must use ClientSecretCredential (thesis §3.2.3)."""
        with patch("secretsmanager.adapters.azure.SecretClient"), \
             patch("secretsmanager.adapters.azure.DefaultAzureCredential"), \
             patch("secretsmanager.adapters.azure.ClientSecretCredential") as mock_csc:
            from secretsmanager.adapters.azure import AzureKeyVaultAdapter
            AzureKeyVaultAdapter(
                "https://v.vault.azure.net",
                auth_mode="service_principal",
                tenant_id="t1",
                client_id="c1",
                client_secret="s1",
            )
            mock_csc.assert_called_once_with(
                tenant_id="t1", client_id="c1", client_secret="s1"
            )

    def test_service_principal_reads_env_vars(self, monkeypatch):
        """If params not supplied, AZURE_* env vars must be used (thesis §3.2.3)."""
        monkeypatch.setenv("AZURE_TENANT_ID", "env-tenant")
        monkeypatch.setenv("AZURE_CLIENT_ID", "env-client")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "env-secret")
        with patch("secretsmanager.adapters.azure.SecretClient"), \
             patch("secretsmanager.adapters.azure.DefaultAzureCredential"), \
             patch("secretsmanager.adapters.azure.ClientSecretCredential") as mock_csc:
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
