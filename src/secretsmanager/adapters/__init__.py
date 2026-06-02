"""Backend adapters: HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault."""

from secretsmanager.adapters.hashicorp import HashiCorpVaultAdapter
from secretsmanager.adapters.aws import AwsSecretsManagerAdapter, AWSSecretsManagerAdapter
from secretsmanager.adapters.google import GoogleSecretManagerAdapter, GCPSecretManagerAdapter
from secretsmanager.adapters.azure import AzureKeyVaultAdapter

__all__ = [
    "HashiCorpVaultAdapter",
    # Canonical names (matching thesis text)
    "AwsSecretsManagerAdapter",
    "GoogleSecretManagerAdapter",
    "AzureKeyVaultAdapter",
    # Backward-compatible aliases
    "AWSSecretsManagerAdapter",
    "GCPSecretManagerAdapter",
]
