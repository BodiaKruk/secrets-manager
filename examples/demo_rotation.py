import os

from secretsmanager.adapters.google import GoogleSecretManagerAdapter
from secretsmanager.cache import CachedSecretProvider

g = GoogleSecretManagerAdapter(project_id=os.environ["GCP_PROJECT_ID"])
c = CachedSecretProvider(g, ttl_seconds=300)
print(
    "before:", c.get_secret("test-db-password").value, "v", c.get_secret("test-db-password").version
)
input("Додайте нову версію в GSM в іншому терміналі, потім Enter...")
c.invalidate("test-db-password")
sv = c.get_secret("test-db-password")
print("after :", sv.value, "v", sv.version)
