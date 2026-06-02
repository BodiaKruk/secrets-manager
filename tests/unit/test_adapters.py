"""Unit tests — Phases 1.2/1.3: all four adapters with mocks.

Covers:
  - get_secret (success + error mapping)
  - get_dynamic_secret (HashiCorp Vault DB engine; NotImplementedError for others)
  - health_check
  - exception hierarchy mapping
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
        mock_hvac.exceptions = hvac.exceptions  # keep real exception hierarchy
        from secretsmanager.adapters.hashicorp import HashiCorpVaultAdapter
        adapter = HashiCorpVaultAdapter(url="http://vault:8200", token="root")
        adapter._client = client
        yield adapter, client


@pytest.mark.unit
class TestHashiCorpVaultAdapter:
    def test_backend_name(self, vault_adapter):
        adapter, _ = vault_adapter
        assert adapter.backend_name == "hashicorp"

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
        assert sv.is_fallback is False

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


# ==========================================================================
# AWS Secrets Manager
# ==========================================================================


@pytest.fixture()
def aws_adapter():
    with patch("secretsmanager.adapters.aws.boto3") as mock_boto3:
        session = MagicMock()
        client = MagicMock()
        mock_boto3.session.Session.return_value = session
        session.client.return_value = client
        from secretsmanager.adapters.aws import AWSSecretsManagerAdapter
        adapter = AWSSecretsManagerAdapter(region_name="us-east-1")
        adapter._client = client
        yield adapter, client


@pytest.mark.unit
class TestAWSSecretsManagerAdapter:
    def test_backend_name(self, aws_adapter):
        adapter, _ = aws_adapter
        assert adapter.backend_name == "aws"

    def test_get_secret_success(self, aws_adapter):
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
        assert sv.is_dynamic is False

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

    def test_health_check_ok(self, aws_adapter):
        adapter, client = aws_adapter
        client.list_secrets.return_value = {"SecretList": []}
        assert adapter.health_check() is True

    def test_health_check_fail(self, aws_adapter):
        adapter, client = aws_adapter
        client.list_secrets.side_effect = Exception("network error")
        assert adapter.health_check() is False


# ==========================================================================
# GCP Secret Manager
# ==========================================================================


@pytest.fixture()
def gcp_adapter():
    with patch("secretsmanager.adapters.google.secretmanager") as mock_sm:
        client = MagicMock()
        mock_sm.SecretManagerServiceClient.return_value = client
        from secretsmanager.adapters.google import GCPSecretManagerAdapter
        adapter = GCPSecretManagerAdapter(project_id="my-project")
        adapter._client = client
        yield adapter, client


@pytest.mark.unit
class TestGCPSecretManagerAdapter:
    def test_backend_name(self, gcp_adapter):
        adapter, _ = gcp_adapter
        assert adapter.backend_name == "google"

    def test_get_secret_success(self, gcp_adapter):
        adapter, client = gcp_adapter
        resp = MagicMock()
        resp.payload.data = b"gcp-secret"
        resp.name = "projects/p/secrets/prod-db/versions/5"
        client.access_secret_version.return_value = resp
        sv = adapter.get_secret("prod-db")
        assert sv.value == "gcp-secret"
        assert sv.version == "5"

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
# Azure Key Vault
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
        assert adapter.backend_name == "azure"

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
