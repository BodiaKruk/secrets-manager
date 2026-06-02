"""Backend adapters: HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault."""

from secretsmanager.adapters.hashicorp import HashiCorpVaultAdapter
from secretsmanager.adapters.aws import AWSSecretsManagerAdapter
from secretsmanager.adapters.google import GCPSecretManagerAdapter
from secretsmanager.adapters.azure import AzureKeyVaultAdapter

__all__ = [
    "HashiCorpVaultAdapter",
    "AWSSecretsManagerAdapter",
    "GCPSecretManagerAdapter",
    "AzureKeyVaultAdapter",
]
