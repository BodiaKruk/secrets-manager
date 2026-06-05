import os
import time

from secretsmanager.adapters.google import GoogleSecretManagerAdapter
from secretsmanager.cache import CachedSecretProvider

g = GoogleSecretManagerAdapter(project_id=os.environ["GCP_PROJECT_ID"])
c = CachedSecretProvider(g, ttl_seconds=10)
for i in range(1, 10):
    t = time.perf_counter()
    sv = c.get_secret("test-db-password")
    dt = (time.perf_counter() - t) * 1000
    print(f"call {i}: {dt:8.1f} ms   fallback={sv.is_fallback}")
    time.sleep(0.5)
print("cache_stats:", c.cache_stats())
