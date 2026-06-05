import os

from secretsmanager.adapters.google import GoogleSecretManagerAdapter
from secretsmanager.adapters.hashicorp import HashiCorpVaultAdapter
from secretsmanager.audit import AuditLogger
from secretsmanager.cache import CachedSecretProvider

logger = AuditLogger(max_buffer_size=1000, export_path="results/audit.jsonl")
dead = HashiCorpVaultAdapter(
    vault_url="http://127.0.0.1:9", vault_token="x", verify_ssl=False
)  # недоступний
gsm = GoogleSecretManagerAdapter(project_id=os.environ["GCP_PROJECT_ID"])
c = CachedSecretProvider(dead, fallback=gsm, ttl_seconds=10, audit_logger=logger)
sv = c.get_secret("test-db-password")
print(f"value={sv.value!r} backend={sv.backend} is_fallback={sv.is_fallback}")
logger.export_to_file()
print("stats:", logger.get_statistics())
