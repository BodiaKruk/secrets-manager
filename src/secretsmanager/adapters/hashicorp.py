"""HashiCorp Vault adapter — KV v2 (static secrets) + Database engine (dynamic secrets).

Static secrets:   KV v2 via hvac.secrets.kv.v2.read_secret_version()
Dynamic secrets:  Database engine via hvac.secrets.database.generate_credentials()
                  Returns SecretValue with is_dynamic=True and expires_at from lease.
"""

from __future__ import annotations

import json
import time
from typing import Any

import hvac  # type: ignore[import-untyped]
import hvac.exceptions  # type: ignore[import-untyped]

from secretsmanager.interface import (
    AccessDeniedError,
    BackendUnavailableError,
    SecretNotFoundError,
    SecretProvider,
    SecretValue,
    RotationPolicy,
)


class HashiCorpVaultAdapter(SecretProvider):
    """Adapter for HashiCorp Vault.

    KV v2 mount is used for static secrets; the Database secrets engine is used
    for ``get_dynamic_secret`` (generates short-lived DB credentials).

    Args:
        url:          Vault server address, e.g. ``"http://127.0.0.1:8200"``.
        token:        Vault token.
        mount_point:  KV v2 mount path (default ``"secret"``).
        db_mount:     Database engine mount path (default ``"database"``).
        namespace:    Vault Enterprise namespace (optional).
        verify_ssl:   Whether to verify the TLS certificate (default True).
    """

    def __init__(
        self,
        url: str,
        token: str,
        *,
        mount_point: str = "secret",
        db_mount: str = "database",
        namespace: str | None = None,
        verify_ssl: bool = True,
    ) -> None:
        self._mount = mount_point
        self._db_mount = db_mount
        self._client = hvac.Client(
            url=url,
            token=token,
            namespace=namespace,
            verify=verify_ssl,
        )

    @property
    def backend_name(self) -> str:
        return "hashicorp"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _backend_err(self, exc: Exception, path: str) -> BackendUnavailableError:
        return BackendUnavailableError(str(exc), backend=self.backend_name, path=path)

    # ------------------------------------------------------------------
    # Static secrets — KV v2
    # ------------------------------------------------------------------

    def get_secret(self, name: str, *, version: str | None = None) -> SecretValue:
        """Retrieve a KV v2 secret.

        Multi-key secrets (more than one key inside the KV entry) are returned
        as JSON.  Single-key secrets stored under the ``"value"`` key are
        returned as a plain string.
        """
        kw: dict[str, Any] = {"path": name, "mount_point": self._mount}
        if version is not None:
            kw["version"] = int(version)
        try:
            resp = self._client.secrets.kv.v2.read_secret_version(**kw)
        except hvac.exceptions.InvalidPath:
            raise SecretNotFoundError(
                f"Secret not found: {name}", backend=self.backend_name, path=name
            )
        except hvac.exceptions.Forbidden:
            raise AccessDeniedError(
                f"Access denied: {name}", backend=self.backend_name, path=name
            )
        except Exception as exc:
            raise self._backend_err(exc, name) from exc

        data: dict[str, Any] = resp["data"]["data"]
        meta: dict[str, Any] = resp["data"]["metadata"]
        raw_version = str(meta.get("version", "0"))

        secret_str = data.get("value") or json.dumps(data)

        return SecretValue(
            value=secret_str,
            version=raw_version,
            backend=self.backend_name,
            path=name,
            metadata={k: v for k, v in meta.items() if k not in ("custom_metadata",)},
        )

    # ------------------------------------------------------------------
    # Dynamic secrets — Database engine
    # ------------------------------------------------------------------

    def get_dynamic_secret(self, role: str, **kwargs: Any) -> SecretValue:
        """Generate ephemeral database credentials via the Vault Database engine.

        Args:
            role:        Database role name configured in Vault
                         (e.g. ``"readonly-role"``).
            mount_point: Override the database engine mount (default from ctor).

        Returns:
            :class:`SecretValue` with:
              - ``value`` = JSON ``{"username": "...", "password": "..."}``
              - ``is_dynamic = True``
              - ``expires_at`` = ``time.time() + lease_duration``
              - ``metadata`` includes ``lease_id``, ``lease_duration``, ``renewable``
        """
        mount = kwargs.get("mount_point", self._db_mount)
        try:
            resp = self._client.secrets.database.generate_credentials(
                name=role, mount_point=mount
            )
        except hvac.exceptions.InvalidPath:
            raise SecretNotFoundError(
                f"Database role not found: {role}", backend=self.backend_name, path=role
            )
        except hvac.exceptions.Forbidden:
            raise AccessDeniedError(
                f"Access denied for DB role: {role}", backend=self.backend_name, path=role
            )
        except Exception as exc:
            raise self._backend_err(exc, role) from exc

        creds: dict[str, str] = resp["data"]
        lease_duration: int = resp.get("lease_duration", 3600)
        lease_id: str = resp.get("lease_id", "")
        renewable: bool = resp.get("renewable", False)

        return SecretValue(
            value=json.dumps(creds),
            version=lease_id or "dynamic",
            backend=self.backend_name,
            path=role,
            obtained_at=time.time(),
            expires_at=time.time() + lease_duration,
            is_dynamic=True,
            metadata={
                "lease_id": lease_id,
                "lease_duration": lease_duration,
                "renewable": renewable,
                "role": role,
            },
        )

    # ------------------------------------------------------------------
    # Write / delete
    # ------------------------------------------------------------------

    def set_secret(
        self, name: str, value: str, *, metadata: dict[str, Any] | None = None
    ) -> str:
        try:
            resp = self._client.secrets.kv.v2.create_or_update_secret(
                path=name,
                secret={"value": value},
                mount_point=self._mount,
            )
        except hvac.exceptions.Forbidden:
            raise AccessDeniedError(
                f"Access denied: {name}", backend=self.backend_name, path=name
            )
        except Exception as exc:
            raise self._backend_err(exc, name) from exc
        return str(resp["data"]["version"])

    def delete_secret(self, name: str, *, force: bool = False) -> None:
        try:
            if force:
                self._client.secrets.kv.v2.delete_metadata_and_all_versions(
                    path=name, mount_point=self._mount
                )
            else:
                self._client.secrets.kv.v2.delete_latest_version_of_secret(
                    path=name, mount_point=self._mount
                )
        except hvac.exceptions.InvalidPath:
            raise SecretNotFoundError(
                f"Secret not found: {name}", backend=self.backend_name, path=name
            )
        except hvac.exceptions.Forbidden:
            raise AccessDeniedError(
                f"Access denied: {name}", backend=self.backend_name, path=name
            )
        except Exception as exc:
            raise self._backend_err(exc, name) from exc

    # ------------------------------------------------------------------
    # Listing
    # ------------------------------------------------------------------

    def list_secrets(self, prefix: str = "") -> list[str]:
        try:
            resp = self._client.secrets.kv.v2.list_secrets(
                path=prefix, mount_point=self._mount
            )
        except hvac.exceptions.InvalidPath:
            return []
        except hvac.exceptions.Forbidden:
            raise AccessDeniedError(
                f"Access denied listing: {prefix}", backend=self.backend_name, path=prefix
            )
        except Exception as exc:
            raise self._backend_err(exc, prefix) from exc

        keys: list[str] = resp.get("data", {}).get("keys", [])
        pfx = f"{prefix}/" if prefix and not prefix.endswith("/") else prefix
        return sorted(f"{pfx}{k}" for k in keys)

    # ------------------------------------------------------------------
    # Rotation
    # ------------------------------------------------------------------

    def rotate_secret(self, name: str, *, policy: RotationPolicy | None = None) -> str:
        current = self.get_secret(name)
        return self.set_secret(name, current.value)

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health_check(self) -> bool:
        try:
            return bool(self._client.is_authenticated())
        except Exception:
            return False
