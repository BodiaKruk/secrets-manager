"""Google Cloud Secret Manager adapter."""

from __future__ import annotations

from typing import Any

from google.api_core.exceptions import (  # type: ignore[import-untyped]
    GoogleAPICallError,
    NotFound,
    PermissionDenied,
)
from google.cloud import secretmanager  # type: ignore[import-untyped]

from secretsmanager.interface import (
    AccessDeniedError,
    BackendUnavailableError,
    RotationPolicy,
    SecretNotFoundError,
    SecretProvider,
    SecretValue,
)


class GoogleSecretManagerAdapter(SecretProvider):
    """Adapter for Google Cloud Secret Manager.

    Args:
        project_id:  GCP project ID.
        credentials: Optional Credentials object (falls back to ADC / Workload Identity).
    """

    def __init__(self, project_id: str, *, credentials: Any = None) -> None:
        self._project = project_id
        self._client = secretmanager.SecretManagerServiceClient(credentials=credentials)

    @property
    def backend_name(self) -> str:
        return "google_secret_manager"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _secret_fqn(self, name: str) -> str:
        return f"projects/{self._project}/secrets/{name}"

    def _version_fqn(self, name: str, version: str | None) -> str:
        return f"{self._secret_fqn(name)}/versions/{version or 'latest'}"

    def _wrap(self, exc: Exception, path: str) -> BackendUnavailableError:
        return BackendUnavailableError(str(exc), backend=self.backend_name, path=path)

    # ------------------------------------------------------------------
    # Static secrets
    # ------------------------------------------------------------------

    def get_secret(self, name: str, *, version: str | None = None) -> SecretValue:
        fqn = self._version_fqn(name, version)
        try:
            resp = self._client.access_secret_version(request={"name": fqn})
        except NotFound as exc:
            raise SecretNotFoundError(
                f"Secret not found: {name}", backend=self.backend_name, path=name
            ) from exc
        except PermissionDenied as exc:
            raise AccessDeniedError(
                f"Access denied: {name}", backend=self.backend_name, path=name
            ) from exc
        except GoogleAPICallError as exc:
            raise self._wrap(exc, name) from exc

        payload = resp.payload.data.decode("utf-8")
        version_str = resp.name.split("/")[-1]
        return SecretValue(
            value=payload,
            version=version_str,
            backend=self.backend_name,
            path=name,
            metadata={"resource_name": resp.name},
        )

    def get_dynamic_secret(self, role: str, **kwargs: Any) -> SecretValue:
        """GCP Secret Manager does not support dynamic secrets — raises NotImplementedError."""
        raise NotImplementedError(
            "GCP Secret Manager does not support dynamic secrets. "
            "Use Workload Identity + service account impersonation instead."
        )

    def set_secret(self, name: str, value: str, *, metadata: dict[str, Any] | None = None) -> str:
        parent = f"projects/{self._project}"
        fqn = self._secret_fqn(name)
        try:
            try:
                self._client.get_secret(request={"name": fqn})
            except NotFound:
                labels = {k: str(v) for k, v in (metadata or {}).items()}
                self._client.create_secret(
                    request={
                        "parent": parent,
                        "secret_id": name,
                        "secret": {"replication": {"automatic": {}}, "labels": labels},
                    }
                )
            resp = self._client.add_secret_version(
                request={"parent": fqn, "payload": {"data": value.encode()}}
            )
            return resp.name.split("/")[-1]
        except (AccessDeniedError, BackendUnavailableError):
            raise
        except PermissionDenied as exc:
            raise AccessDeniedError(str(exc), backend=self.backend_name, path=name) from exc
        except GoogleAPICallError as exc:
            raise self._wrap(exc, name) from exc

    def delete_secret(self, name: str, *, force: bool = False) -> None:
        try:
            self._client.delete_secret(request={"name": self._secret_fqn(name)})
        except NotFound as exc:
            raise SecretNotFoundError(
                f"Secret not found: {name}", backend=self.backend_name, path=name
            ) from exc
        except PermissionDenied as exc:
            raise AccessDeniedError(str(exc), backend=self.backend_name, path=name) from exc
        except GoogleAPICallError as exc:
            raise self._wrap(exc, name) from exc

    def list_secrets(self, prefix: str = "") -> list[str]:
        try:
            pager = self._client.list_secrets(request={"parent": f"projects/{self._project}"})
            return sorted(
                s.name.split("/secrets/")[-1]
                for s in pager
                if not prefix or s.name.split("/secrets/")[-1].startswith(prefix)
            )
        except PermissionDenied as exc:
            raise AccessDeniedError(str(exc), backend=self.backend_name, path=prefix) from exc
        except GoogleAPICallError as exc:
            raise self._wrap(exc, prefix) from exc

    def rotate_secret(self, name: str, *, policy: RotationPolicy | None = None) -> str:
        current = self.get_secret(name)
        return self.set_secret(name, current.value)

    def health_check(self) -> bool:
        try:
            self.list_secrets(prefix="__health__")
            return True
        except (AccessDeniedError, BackendUnavailableError):
            return False


# Backward-compatible alias (pre-rename)
GCPSecretManagerAdapter = GoogleSecretManagerAdapter
