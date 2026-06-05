"""Backend adapters: HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault."""

from secretsmanager.adapters.aws import AWSSecretsManagerAdapter, AwsSecretsManagerAdapter
from secretsmanager.adapters.azure import AzureKeyVaultAdapter
from secretsmanager.adapters.google import GCPSecretManagerAdapter, GoogleSecretManagerAdapter
from secretsmanager.adapters.hashicorp import HashiCorpVaultAdapter

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
