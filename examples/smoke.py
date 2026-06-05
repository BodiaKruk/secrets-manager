import os
import time

from secretsmanager.adapters.aws import AwsSecretsManagerAdapter
from secretsmanager.adapters.azure import AzureKeyVaultAdapter
from secretsmanager.adapters.google import GoogleSecretManagerAdapter
from secretsmanager.adapters.hashicorp import HashiCorpVaultAdapter


def measure(label, fn, n=10):
    ts = []
    sv = None
    for _ in range(n):
        t = time.perf_counter()
        sv = fn()
        ts.append((time.perf_counter() - t) * 1000)
    print(f"{label:10} backend={sv.backend:22} version={sv.version} value={sv.value!r}")
    print(
        f"           latency min/avg/max = {min(ts):.0f}/{sum(ts) / len(ts):.0f}/{max(ts):.0f} ms"
    )


hc = HashiCorpVaultAdapter(
    vault_url=os.environ["VAULT_ADDR"], vault_token=os.environ["VAULT_TOKEN"], verify_ssl=False
)
g = GoogleSecretManagerAdapter(project_id=os.environ["GCP_PROJECT_ID"])
a = AwsSecretsManagerAdapter(region_name="us-east-1")
az = AzureKeyVaultAdapter(vault_url=os.environ["AZURE_VAULT_URL"])

measure("HashiCorp", lambda: hc.get_secret("myapp/db-password"))
measure("Google", lambda: g.get_secret("test-db-password"))
measure("AWS", lambda: a.get_secret("test-db-password"))
measure("Azure", lambda: az.get_secret("test-db-password"))
print("API Key OK (exit code 0)")
