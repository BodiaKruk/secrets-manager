import os

from secretsmanager.adapters.aws import AwsSecretsManagerAdapter
from secretsmanager.adapters.azure import AzureKeyVaultAdapter
from secretsmanager.adapters.google import GoogleSecretManagerAdapter
from secretsmanager.adapters.hashicorp import HashiCorpVaultAdapter

hc = HashiCorpVaultAdapter(
    vault_url=os.environ["VAULT_ADDR"], vault_token=os.environ["VAULT_TOKEN"], verify_ssl=False
)
print("HC :", hc.get_secret("myapp/db-password").value)

print(
    "GSM:",
    GoogleSecretManagerAdapter(project_id="diploma-498423").get_secret("test-db-password").value,
)

print(
    "AWS:", AwsSecretsManagerAdapter(region_name="us-east-1").get_secret("test-db-password").value
)

print(
    "AZ :",
    AzureKeyVaultAdapter(
        vault_url="https://vault-practica-bk.vault.azure.net", auth_mode="service_principal"
    )
    .get_secret("test-db-password")
    .value,
)
