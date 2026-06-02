"""Azure Key Vault (Secrets plane) adapter via azure-keyvault-secrets + azure-identity.

Supports two authentication modes:
  - ``'default'``            → :class:`~azure.identity.DefaultAzureCredential`
                               (env vars, managed identity, CLI, VS Code…)
  - ``'service_principal'``  → :class:`~azure.identity.ClientSecretCredential`
                               reads AZURE_TENANT_ID / AZURE_CLIENT_ID /
                               AZURE_CLIENT_SECRET from env if not passed explicitly.
"""

from __future__ import annotations

import os
import time
from typing import Any

from azure.core.exceptions import (  # type: ignore[import-untyped]
    ClientAuthenticationError,
    HttpResponseError,
    ResourceNotFoundError,
)
from azure.identity import (  # type: ignore[import-untyped]
    ClientSecretCredential,
    DefaultAzureCredential,
)
from azure.keyvault.secrets import SecretClient  # type: ignore[import-untyped]

from secretsmanager.interface import (
    AccessDeniedError,
    BackendUnavailableError,
    SecretNotFoundError,
    SecretProvider,
    SecretValue,
    RotationPolicy,
)


class AzureKeyVaultAdapter(SecretProvider):
    """Adapter for Azure Key Vault (Secrets plane).

    Args:
        vault_url:     Key Vault URL, e.g. ``"https://myvault.vault.azure.net"``.
        auth_mode:     ``'default'`` (DefaultAzureCredential) or
                       ``'service_principal'`` (ClientSecretCredential).
        tenant_id:     Azure AD tenant ID (service_principal mode).
                       Falls back to the ``AZURE_TENANT_ID`` environment variable.
        client_id:     Application (client) ID (service_principal mode).
                       Falls back to ``AZURE_CLIENT_ID``.
        client_secret: Client secret value (service_principal mode).
                       Falls back to ``AZURE_CLIENT_SECRET``.
        credential:    Pass a custom credential object to bypass auth_mode logic.
    """

    def __init__(
        self,
        vault_url: str,
        auth_mode: str = "default",
        *,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        credential: Any = None,
    ) -> None:
        if credential is not None:
            cred = credential
        elif auth_mode == "service_principal":
            cred = ClientSecretCredential(
                tenant_id=tenant_id or os.environ.get("AZURE_TENANT_ID", ""),
                client_id=client_id or os.environ.get("AZURE_CLIENT_ID", ""),
                client_secret=client_secret or os.environ.get("AZURE_CLIENT_SECRET", ""),
            )
        else:
            cred = DefaultAzureCredential()

        self._client = SecretClient(vault_url=vault_url, credential=cred)
        self._vault_url = vault_url
        self._auth_mode = auth_mode

    @property
    def backend_name(self) -> str:
        return "azure_key_vault"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _wrap(self, exc: Exception, path: str) -> BackendUnavailableError:
        return BackendUnavailableError(str(exc), backend=self.backend_name, path=path)

    def _check_http(self, exc: HttpResponseError, path: str) -> None:
        if exc.status_code == 403:
            raise AccessDeniedError(str(exc), backend=self.backend_name, path=path) from exc
        raise self._wrap(exc, path) from exc

    # ------------------------------------------------------------------
    # Static secrets
    # ------------------------------------------------------------------

    def get_secret(self, name: str, *, version: str | None = None) -> SecretValue:
        try:
            resp = self._client.get_secret(name, version=version)
        except ResourceNotFoundError:
            raise SecretNotFoundError(
                f"Secret not found: {name}", backend=self.backend_name, path=name
            )
        except ClientAuthenticationError as exc:
            raise AccessDeniedError(str(exc), backend=self.backend_name, path=name) from exc
        except HttpResponseError as exc:
            self._check_http(exc, name)

        ver = resp.properties.version or ""
        tags: dict[str, Any] = dict(resp.properties.tags or {})
        return SecretValue(
            value=resp.value or "",
            version=ver,
            backend=self.backend_name,
            path=name,
            metadata={"vault_url": self._vault_url, **tags},
        )

    def get_dynamic_secret(self, role: str, **kwargs: Any) -> SecretValue:
        """Azure Key Vault does not support dynamic secrets — raises NotImplementedError."""
        raise NotImplementedError(
            "Azure Key Vault does not support dynamic secrets. "
            "Use Azure Managed Identity or service principal credentials instead."
        )

    def set_secret(
        self, name: str, value: str, *, metadata: dict[str, Any] | None = None
    ) -> str:
        tags = {str(k): str(v) for k, v in (metadata or {}).items()}
        try:
            resp = self._client.set_secret(name, value, tags=tags or None)
            return resp.properties.version or ""
        except ClientAuthenticationError as exc:
            raise AccessDeniedError(str(exc), backend=self.backend_name, path=name) from exc
        except HttpResponseError as exc:
            self._check_http(exc, name)
        return ""

    def delete_secret(self, name: str, *, force: bool = False) -> None:
        try:
            poller = self._client.begin_delete_secret(name)
            poller.wait()
            if force:
                self._client.purge_deleted_secret(name)
        except ResourceNotFoundError:
            raise SecretNotFoundError(
                f"Secret not found: {name}", backend=self.backend_name, path=name
            )
        except ClientAuthenticationError as exc:
            raise AccessDeniedError(str(exc), backend=self.backend_name, path=name) from exc
        except HttpResponseError as exc:
            self._check_http(exc, name)

    def list_secrets(self, prefix: str = "") -> list[str]:
        try:
            return sorted(
                p.name
                for p in self._client.list_properties_of_secrets()
                if p.name and (not prefix or p.name.startswith(prefix))
            )
        except ClientAuthenticationError as exc:
            raise AccessDeniedError(str(exc), backend=self.backend_name, path=prefix) from exc
        except HttpResponseError as exc:
            self._check_http(exc, prefix)
        return []

    def rotate_secret(self, name: str, *, policy: RotationPolicy | None = None) -> str:
        current = self.get_secret(name)
        return self.set_secret(name, current.value)

    def health_check(self) -> bool:
        try:
            next(iter(self._client.list_properties_of_secrets()), None)
            return True
        except Exception:
            return False
