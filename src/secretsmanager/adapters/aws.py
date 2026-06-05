"""AWS Secrets Manager adapter via boto3.

Handles both SecretString (UTF-8 text) and SecretBinary (base64-encoded binary).
"""

from __future__ import annotations

import base64
from typing import Any

import boto3  # type: ignore[import-untyped]
from botocore.exceptions import ClientError, EndpointResolutionError  # type: ignore[import-untyped]

from secretsmanager.interface import (
    AccessDeniedError,
    BackendUnavailableError,
    RotationPolicy,
    SecretNotFoundError,
    SecretProvider,
    SecretValue,
)

_ACCESS_DENIED_CODES = frozenset({"AccessDeniedException", "UnauthorizedOperation"})
_NOT_FOUND_CODES = frozenset({"ResourceNotFoundException", "SecretNotFound"})


class AwsSecretsManagerAdapter(SecretProvider):
    """Adapter for AWS Secrets Manager.

    Args:
        region_name:           AWS region, e.g. ``"us-east-1"``.
        aws_access_key_id:     Explicit credentials (optional; env / IAM role fallback).
        aws_secret_access_key: Explicit credentials (optional).
        endpoint_url:          Override for LocalStack / moto testing.
    """

    def __init__(
        self,
        region_name: str = "us-east-1",
        *,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        endpoint_url: str | None = None,
    ) -> None:
        session = boto3.session.Session()
        self._client = session.client(
            service_name="secretsmanager",
            region_name=region_name,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            endpoint_url=endpoint_url,
        )

    @property
    def backend_name(self) -> str:
        return "aws_secrets_manager"

    # ------------------------------------------------------------------
    # Error mapping
    # ------------------------------------------------------------------

    def _raise(self, exc: ClientError, path: str) -> None:
        code = exc.response["Error"]["Code"]
        if code in _NOT_FOUND_CODES:
            raise SecretNotFoundError(str(exc), backend=self.backend_name, path=path) from exc
        if code in _ACCESS_DENIED_CODES:
            raise AccessDeniedError(str(exc), backend=self.backend_name, path=path) from exc
        raise BackendUnavailableError(str(exc), backend=self.backend_name, path=path) from exc

    # ------------------------------------------------------------------
    # Static secrets
    # ------------------------------------------------------------------

    def get_secret(self, name: str, *, version: str | None = None) -> SecretValue:
        """Retrieve a secret value.

        Supports both ``SecretString`` (text) and ``SecretBinary`` (binary data
        returned as a base64-encoded string for uniform handling downstream).
        """
        kw: dict[str, Any] = {"SecretId": name}
        if version is not None:
            kw["VersionId"] = version
        try:
            resp = self._client.get_secret_value(**kw)
        except ClientError as exc:
            self._raise(exc, name)
        except (EndpointResolutionError, Exception) as exc:
            raise BackendUnavailableError(str(exc), backend=self.backend_name, path=name) from exc

        # SecretString takes priority; SecretBinary is returned as base64.
        raw: str = resp.get("SecretString") or ""
        if not raw:
            binary_data: bytes = resp.get("SecretBinary") or b""
            raw = base64.b64encode(binary_data).decode("utf-8")

        return SecretValue(
            value=raw,
            version=resp.get("VersionId", ""),
            backend=self.backend_name,
            path=name,
            metadata={"arn": resp.get("ARN", ""), "name": resp.get("Name", "")},
        )

    def get_dynamic_secret(self, role: str, **kwargs: Any) -> SecretValue:
        """AWS does not have a generic dynamic secret engine — raises NotImplementedError."""
        raise NotImplementedError(
            "AWS Secrets Manager does not support dynamic secrets via this adapter. "
            "Use IAM temporary credentials (STS) directly."
        )

    def set_secret(self, name: str, value: str, *, metadata: dict[str, Any] | None = None) -> str:
        tags = [{"Key": k, "Value": str(v)} for k, v in (metadata or {}).items()]
        try:
            try:
                resp = self._client.put_secret_value(SecretId=name, SecretString=value)
                return resp["VersionId"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in _NOT_FOUND_CODES:
                    self._raise(exc, name)
            kw: dict[str, Any] = {"Name": name, "SecretString": value}
            if tags:
                kw["Tags"] = tags
            create_resp = self._client.create_secret(**kw)
            return create_resp["VersionId"]
        except (AccessDeniedError, BackendUnavailableError, SecretNotFoundError):
            raise
        except Exception as exc:
            raise BackendUnavailableError(str(exc), backend=self.backend_name, path=name) from exc

    def delete_secret(self, name: str, *, force: bool = False) -> None:
        kw: dict[str, Any] = {"SecretId": name}
        kw["ForceDeleteWithoutRecovery" if force else "RecoveryWindowInDays"] = True if force else 7
        try:
            self._client.delete_secret(**kw)
        except ClientError as exc:
            self._raise(exc, name)
        except Exception as exc:
            raise BackendUnavailableError(str(exc), backend=self.backend_name, path=name) from exc

    def list_secrets(self, prefix: str = "") -> list[str]:
        paginator = self._client.get_paginator("list_secrets")
        filters = [{"Key": "name", "Values": [prefix]}] if prefix else []
        try:
            names = [
                s["Name"]
                for page in paginator.paginate(Filters=filters)  # type: ignore[arg-type]
                for s in page.get("SecretList", [])
            ]
            return sorted(names)
        except ClientError as exc:
            self._raise(exc, prefix)
        except Exception as exc:
            raise BackendUnavailableError(str(exc), backend=self.backend_name, path=prefix) from exc
        return []

    def rotate_secret(self, name: str, *, policy: RotationPolicy | None = None) -> str:
        try:
            return self._client.rotate_secret(SecretId=name).get("VersionId", "")
        except ClientError as exc:
            self._raise(exc, name)
        except Exception as exc:
            raise BackendUnavailableError(str(exc), backend=self.backend_name, path=name) from exc
        return ""

    def health_check(self) -> bool:
        try:
            self._client.list_secrets(MaxResults=1)
            return True
        except Exception:
            return False


# Backward-compatible alias (pre-rename)
AWSSecretsManagerAdapter = AwsSecretsManagerAdapter
