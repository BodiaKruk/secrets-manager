"""Скрін 16-17: демонстрація відмови доступу + аудит-лог.

Обмежений токен ($TOK) має лише demo-policy (read на prod/db-password).
Спроба отримати prod/other-secret → PermissionDeniedError → result=error.
"""

import json
import os
import sys
from collections import Counter
from pathlib import Path

from secretsmanager.adapters.hashicorp import HashiCorpVaultAdapter
from secretsmanager.audit import AuditLogger
from secretsmanager.cache import CachedSecretProvider
from secretsmanager.interface import AccessDeniedError

vault_url = os.environ.get("VAULT_ADDR", "http://35.194.60.80:8200")
vault_token = os.environ.get("VAULT_TOKEN")  # обмежений токен

if not vault_token:
    print("Встановіть VAULT_TOKEN=<обмежений токен>")
    sys.exit(1)

logger = AuditLogger(max_buffer_size=1000, export_path="results/audit.jsonl")

adapter = HashiCorpVaultAdapter(
    vault_url=vault_url,
    vault_token=vault_token,
    verify_ssl=False,
)
provider = CachedSecretProvider(adapter, ttl_seconds=60, audit_logger=logger)

# --- Дозволена операція ---
print("=== Дозволений доступ ===")
try:
    sv = provider.get_secret("prod/db-password")
    print(f"  prod/db-password = {sv.value!r}  (result=miss → в лозі)")
except Exception as e:
    print(f"  ПОМИЛКА: {e}")

# --- Заборонена операція ---
print("\n=== Заборонений доступ (очікується PermissionDeniedError) ===")
try:
    sv = provider.get_secret("prod/other-secret")
    print(f"  НЕСПОДІВАНО ОТРИМАНО: {sv.value!r}")
except AccessDeniedError as e:
    print(f"  PermissionDeniedError: {e}")
    print("  → result=error записано в аудит-лог")
except Exception as e:
    print(f"  Інша помилка: {e}")

logger.export_to_file()

print("\n=== Статистика аудит-логу ===")
stats = logger.get_statistics()
for k, v in stats.items():
    print(f"  {k}: {v}")

print("\n=== Розподіл результатів (results/audit.jsonl) ===")
records = [
    json.loads(line) for line in Path("results/audit.jsonl").read_text().splitlines() if line
]
dist = Counter(r["result"] for r in records)
for result, count in sorted(dist.items()):
    print(f"  {result}: {count}")

print("\n=== Перевірка відсутності плейнтексту ===")
raw = Path("results/audit.jsonl").read_text()
secret_val = "MyS3cr3tP@ssw0rd"
if secret_val in raw:
    print("  УВАГА: плейнтекст знайдено!")
else:
    print(f"  OK: плейнтексту '{secret_val}' в логах немає")
