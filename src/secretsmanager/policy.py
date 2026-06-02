"""PolicyTranslator — pure-function static class for multi-cloud IAM policy generation.

Input format (YAML / dict):

    version: "1.0"
    rules:
      - path: "prod/db/*"
        capabilities:
          - read
          - list
        principals:
          - type: vault_policy
            id: app-read-role
          - type: aws_iam_role
            id: arn:aws:iam::123456789012:role/app
          - type: gcp_service_account
            id: app@project.iam.gserviceaccount.com
          - type: azure_sp
            id: "<client-object-id>"

Output:
  - toHCL()         → Vault HCL policy string
  - toIAMJson()     → AWS resource-based policy dict
  - toGcpIamCond()  → list of GCP IAM bindings (with optional CEL conditions)
  - toAzureRbac()   → list of Azure role-assignment dicts

Usage::

    doc = PolicyTranslator.load_yaml(open("policy.yaml").read())
    PolicyTranslator.validate_yaml(doc)   # raises ValueError on bad input
    hcl = PolicyTranslator.toHCL(doc)
    aws = PolicyTranslator.toIAMJson(doc, account_id="123", region="us-east-1")
"""

from __future__ import annotations

import json
import re
from typing import Any

import yaml


# ---------------------------------------------------------------------------
# Supported values
# ---------------------------------------------------------------------------

_VALID_CAPS = frozenset({"read", "write", "delete", "list", "rotate", "create", "update"})

_VAULT_CAPS_MAP: dict[str, list[str]] = {
    "read":   ["read"],
    "write":  ["create", "update"],
    "delete": ["delete"],
    "list":   ["list"],
    "rotate": ["create", "update"],
    "create": ["create"],
    "update": ["update"],
}

_AWS_ACTIONS_MAP: dict[str, list[str]] = {
    "read":   ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
    "write":  ["secretsmanager:PutSecretValue", "secretsmanager:CreateSecret",
               "secretsmanager:UpdateSecret"],
    "delete": ["secretsmanager:DeleteSecret"],
    "list":   ["secretsmanager:ListSecrets", "secretsmanager:ListSecretVersionIds"],
    "rotate": ["secretsmanager:RotateSecret"],
    "create": ["secretsmanager:CreateSecret"],
    "update": ["secretsmanager:PutSecretValue", "secretsmanager:UpdateSecret"],
}

_GCP_ROLE_MAP: dict[str, str] = {
    "read":   "roles/secretmanager.secretAccessor",
    "list":   "roles/secretmanager.viewer",
    "write":  "roles/secretmanager.secretVersionAdder",
    "create": "roles/secretmanager.secretVersionAdder",
    "update": "roles/secretmanager.secretVersionAdder",
    "delete": "roles/secretmanager.admin",
    "rotate": "roles/secretmanager.secretVersionAdder",
}

_AZURE_ROLE_MAP: dict[str, str] = {
    "read":   "Key Vault Secrets User",
    "list":   "Key Vault Secrets User",
    "write":  "Key Vault Secrets Officer",
    "create": "Key Vault Secrets Officer",
    "update": "Key Vault Secrets Officer",
    "delete": "Key Vault Secrets Officer",
    "rotate": "Key Vault Secrets Officer",
}

_PRINCIPAL_TYPES = frozenset(
    {"vault_policy", "aws_iam_role", "aws_iam_user", "gcp_service_account",
     "gcp_user", "gcp_group", "azure_sp", "azure_group"}
)


# ---------------------------------------------------------------------------
# PolicyTranslator
# ---------------------------------------------------------------------------


class PolicyTranslator:
    """Static class of pure translation functions.  Do not instantiate."""

    def __new__(cls, *args: Any, **kwargs: Any) -> "PolicyTranslator":  # type: ignore[misc]
        raise TypeError(
            "PolicyTranslator cannot be instantiated — all methods are @staticmethod."
        )

    def __init_subclass__(cls, **kwargs: Any) -> None:  # pragma: no cover
        raise TypeError("PolicyTranslator is not meant to be subclassed.")

    # ------------------------------------------------------------------
    # Load & validate
    # ------------------------------------------------------------------

    @staticmethod
    def load_yaml(text: str) -> dict[str, Any]:
        """Parse YAML text and return the raw dict."""
        doc = yaml.safe_load(text)
        if not isinstance(doc, dict):
            raise ValueError("Policy document must be a YAML mapping at the top level.")
        return doc

    @staticmethod
    def validate_yaml(doc: dict[str, Any]) -> None:
        """Validate a policy document dict.

        Raises:
            ValueError: with a human-readable description of the problem.
        """
        if "rules" not in doc:
            raise ValueError("Policy document must have a top-level 'rules' key.")
        if not isinstance(doc["rules"], list) or len(doc["rules"]) == 0:
            raise ValueError("'rules' must be a non-empty list.")

        for i, rule in enumerate(doc["rules"]):
            prefix = f"rules[{i}]"
            if not isinstance(rule, dict):
                raise ValueError(f"{prefix} must be a mapping.")
            if "path" not in rule or not isinstance(rule["path"], str):
                raise ValueError(f"{prefix}.path must be a non-empty string.")
            caps = rule.get("capabilities")
            if not caps or not isinstance(caps, list):
                raise ValueError(f"{prefix}.capabilities must be a non-empty list.")
            unknown = set(caps) - _VALID_CAPS
            if unknown:
                raise ValueError(
                    f"{prefix}.capabilities contains unknown values: {unknown}. "
                    f"Valid: {sorted(_VALID_CAPS)}"
                )
            principals = rule.get("principals", [])
            if not isinstance(principals, list):
                raise ValueError(f"{prefix}.principals must be a list.")
            for j, p in enumerate(principals):
                if not isinstance(p, dict) or "type" not in p or "id" not in p:
                    raise ValueError(f"{prefix}.principals[{j}] must have 'type' and 'id'.")
                if p["type"] not in _PRINCIPAL_TYPES:
                    raise ValueError(
                        f"{prefix}.principals[{j}].type={p['type']!r} is unknown. "
                        f"Valid: {sorted(_PRINCIPAL_TYPES)}"
                    )

    # ------------------------------------------------------------------
    # Phase 3 — HashiCorp Vault HCL
    # ------------------------------------------------------------------

    @staticmethod
    def toHCL(doc: dict[str, Any]) -> str:
        """Emit a Vault HCL policy string from *doc*.

        Wildcards ``*`` in paths are converted to ``+`` (single-segment glob)
        for the KV v2 ``secret/data/`` prefix.  A trailing ``/*`` also
        generates a ``secret/metadata/`` list block automatically.

        Returns a string ready to be passed to ``vault policy write``.
        """
        version = doc.get("version", "1.0")
        lines: list[str] = [
            f"# Generated by PolicyTranslator v{version}",
            "# Do not edit manually — regenerate from policy.yaml",
            "",
        ]

        for rule in doc.get("rules", []):
            raw_path: str = rule["path"]
            caps: list[str] = rule.get("capabilities", [])
            description: str = rule.get("description", "")

            # Collect unique Vault capabilities.
            vault_caps: set[str] = set()
            for cap in caps:
                vault_caps.update(_VAULT_CAPS_MAP.get(cap, [cap]))

            # Convert glob: path/to/* → path/to/+
            vault_path = raw_path.replace("*", "+")
            caps_str = ", ".join(f'"{c}"' for c in sorted(vault_caps))

            if description:
                lines.append(f"# {description}")

            # Data path (read/write operations).
            lines.append(f'path "secret/data/{vault_path}" {{')
            lines.append(f"  capabilities = [{caps_str}]")
            lines.append("}")
            lines.append("")

            # Metadata path (needed for list).
            if "list" in caps:
                lines.append(f'path "secret/metadata/{vault_path}" {{')
                lines.append('  capabilities = ["list"]')
                lines.append("}")
                lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Phase 3 — AWS resource-based policy
    # ------------------------------------------------------------------

    @staticmethod
    def toIAMJson(
        doc: dict[str, Any],
        *,
        account_id: str = "*",
        region: str = "*",
    ) -> dict[str, Any]:
        """Return an AWS resource-based policy dict (JSON-serialisable).

        Capability mapping:
          read  → secretsmanager:GetSecretValue + DescribeSecret
          list  → secretsmanager:ListSecrets + ListSecretVersionIds
          write → PutSecretValue + CreateSecret + UpdateSecret
          …etc.

        ARN format: ``arn:aws:secretsmanager:{region}:{account_id}:secret:{path}``
        """
        statements: list[dict[str, Any]] = []

        for rule in doc.get("rules", []):
            raw_path: str = rule["path"]
            caps: list[str] = rule.get("capabilities", [])
            principals_cfg: list[dict[str, str]] = rule.get("principals", [])

            # Build action set.
            actions: set[str] = set()
            for cap in caps:
                actions.update(_AWS_ACTIONS_MAP.get(cap, []))

            # Build principal list (only AWS IAM types).
            aws_principals: list[str] = []
            for p in principals_cfg:
                ptype = p["type"]
                pid = p["id"]
                if ptype == "aws_iam_role":
                    aws_principals.append(pid if pid.startswith("arn:") else
                                          f"arn:aws:iam::{account_id}:role/{pid}")
                elif ptype == "aws_iam_user":
                    aws_principals.append(pid if pid.startswith("arn:") else
                                          f"arn:aws:iam::{account_id}:user/{pid}")

            if not aws_principals:
                continue

            # Path → ARN resource.
            arn_path = raw_path.rstrip("/")
            resource = f"arn:aws:secretsmanager:{region}:{account_id}:secret:{arn_path}"

            sid = re.sub(r"[^A-Za-z0-9]", "", raw_path.replace("/", "Slash"))[:64]

            stmt: dict[str, Any] = {
                "Sid": sid or "Rule",
                "Effect": "Allow",
                "Principal": {"AWS": aws_principals},
                "Action": sorted(actions),
                "Resource": [resource],
            }
            statements.append(stmt)

        return {"Version": "2012-10-17", "Statement": statements}

    # ------------------------------------------------------------------
    # Phase 3 — GCP IAM bindings with CEL conditions
    # ------------------------------------------------------------------

    @staticmethod
    def toGcpIamCond(
        doc: dict[str, Any],
        *,
        gcp_project: str = "PROJECT_ID",
    ) -> list[dict[str, Any]]:
        """Return GCP IAM binding dicts with optional CEL resource conditions.

        Each binding has the shape::

            {
                "role": "roles/secretmanager.secretAccessor",
                "members": ["serviceAccount:x@p.iam.gserviceaccount.com"],
                "condition": {           # present when path has a wildcard
                    "title": "<slug>",
                    "expression": "<CEL>",
                },
            }

        Suitable for Terraform ``google_project_iam_binding`` resources or the
        GCP IAM REST API (``projects.setIamPolicy``).
        """
        # role → {members: set, paths: list}
        binding_map: dict[str, dict[str, Any]] = {}

        for rule in doc.get("rules", []):
            raw_path: str = rule["path"]
            caps: list[str] = rule.get("capabilities", [])
            principals_cfg: list[dict[str, str]] = rule.get("principals", [])

            for cap in caps:
                role = _GCP_ROLE_MAP.get(cap, "roles/secretmanager.viewer")
                entry = binding_map.setdefault(
                    f"{role}::{raw_path}", {"role": role, "members": set(), "path": raw_path}
                )
                for p in principals_cfg:
                    ptype = p["type"]
                    pid = p["id"]
                    if ptype == "gcp_service_account":
                        entry["members"].add(f"serviceAccount:{pid}")
                    elif ptype == "gcp_user":
                        entry["members"].add(f"user:{pid}")
                    elif ptype == "gcp_group":
                        entry["members"].add(f"group:{pid}")

        result: list[dict[str, Any]] = []
        for entry in binding_map.values():
            if not entry["members"]:
                continue
            binding: dict[str, Any] = {
                "role": entry["role"],
                "members": sorted(entry["members"]),
            }
            # Add CEL condition when path contains a wildcard.
            raw_path = entry["path"]
            if "*" in raw_path or "+" in raw_path:
                prefix = raw_path.rstrip("/*+").rstrip("/")
                cel = (
                    f'resource.name.startsWith("projects/{gcp_project}'
                    f'/secrets/{prefix}/")'
                )
                slug = re.sub(r"[^a-z0-9_]", "_", prefix.lower())[:64]
                binding["condition"] = {
                    "title": f"restrict_{slug}",
                    "expression": cel,
                }
            result.append(binding)

        return sorted(result, key=lambda b: (b["role"], b["members"][0]))

    # ------------------------------------------------------------------
    # Phase 3 — Azure RBAC assignments
    # ------------------------------------------------------------------

    @staticmethod
    def toAzureRbac(
        doc: dict[str, Any],
        *,
        subscription_id: str = "SUBSCRIPTION_ID",
        resource_group: str = "RESOURCE_GROUP",
        vault_name: str = "VAULT_NAME",
    ) -> list[dict[str, Any]]:
        """Return Azure role-assignment dicts for Key Vault.

        Each entry has the shape::

            {
                "role":           "Key Vault Secrets User",
                "principal_id":   "<object-id or client-id>",
                "principal_type": "ServicePrincipal",
                "scope":          "/subscriptions/.../vaults/VAULT_NAME",
            }

        Suitable for Terraform ``azurerm_role_assignment`` resources.
        """
        scope = (
            f"/subscriptions/{subscription_id}"
            f"/resourceGroups/{resource_group}"
            f"/providers/Microsoft.KeyVault/vaults/{vault_name}"
        )

        assignments: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()

        for rule in doc.get("rules", []):
            caps: list[str] = rule.get("capabilities", [])
            principals_cfg: list[dict[str, str]] = rule.get("principals", [])

            # Pick the highest role implied by all capabilities.
            officer_caps = {"write", "create", "update", "delete", "rotate"}
            role = (
                "Key Vault Secrets Officer"
                if set(caps) & officer_caps
                else "Key Vault Secrets User"
            )

            for p in principals_cfg:
                ptype = p["type"]
                if ptype not in ("azure_sp", "azure_group"):
                    continue
                pid = p["id"]
                principal_type = "Group" if ptype == "azure_group" else "ServicePrincipal"
                key = (role, pid)
                if key in seen:
                    continue
                seen.add(key)
                assignments.append({
                    "role": role,
                    "principal_id": pid,
                    "principal_type": principal_type,
                    "scope": scope,
                })

        return assignments

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    @staticmethod
    def summary(doc: dict[str, Any]) -> dict[str, Any]:
        """Return a human-readable summary of a policy document."""
        rules = doc.get("rules", [])
        all_caps: set[str] = set()
        all_paths: set[str] = set()
        all_principals: set[str] = set()
        for rule in rules:
            all_caps.update(rule.get("capabilities", []))
            all_paths.add(rule["path"])
            for p in rule.get("principals", []):
                all_principals.add(p["id"])
        return {
            "version": doc.get("version", "1.0"),
            "rule_count": len(rules),
            "capabilities": sorted(all_caps),
            "paths": sorted(all_paths),
            "principal_count": len(all_principals),
        }
