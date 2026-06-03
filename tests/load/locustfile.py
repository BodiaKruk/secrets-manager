"""Locust load test for the secrets manager — direct adapter vs in-memory cache.

This file models the read-path latency under concurrent load to produce
the p50/p95/p99 figures used in section 4.4 of the thesis.

Run (matches §4.4 parameters — 500 users, ramp 50/s, 60 s):
  locust -f tests/load/locustfile.py --host=http://127.0.0.1:8200 \
         --users=500 --spawn-rate=50 --run-time=60s --headless \
         --csv=results/load

Environment variables:
  VAULT_ADDR     — Vault URL (default http://127.0.0.1:8200)
  VAULT_TOKEN    — Vault root token (default root)
  SM_SECRET_PATH — path to benchmark secret (default load/benchmark-key)
"""

from __future__ import annotations

import os
import time

from locust import User, between, events, task  # type: ignore[import-untyped]

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN", "root")
SECRET_PATH = os.getenv("SM_SECRET_PATH", "load/benchmark-key")


# ---------------------------------------------------------------------------
# Setup: ensure the benchmark secret exists before any test starts.
# ---------------------------------------------------------------------------

@events.test_start.add_listener
def seed_secret(environment, **kwargs):  # type: ignore[misc]
    try:
        from secretsmanager.adapters.hashicorp import HashiCorpVaultAdapter

        adapter = HashiCorpVaultAdapter(vault_url=VAULT_ADDR, vault_token=VAULT_TOKEN, verify_ssl=False)
        adapter.set_secret(SECRET_PATH, "benchmark-value-xyz")
        print(f"[locust] Seeded secret at {SECRET_PATH}")
    except Exception as exc:
        print(f"[locust] WARNING: could not seed secret: {exc}")


# ---------------------------------------------------------------------------
# User behaviour
# ---------------------------------------------------------------------------


class VaultDirectUser(User):
    """Simulates a pod reading a secret directly via the HashiCorp adapter.

    No cache — measures raw backend latency.
    """

    wait_time = between(0.1, 0.5)

    def on_start(self) -> None:
        from secretsmanager.adapters.hashicorp import HashiCorpVaultAdapter

        self._adapter = HashiCorpVaultAdapter(
            vault_url=VAULT_ADDR, vault_token=VAULT_TOKEN, verify_ssl=False
        )

    @task(3)
    def read_secret(self) -> None:
        start = time.perf_counter()
        exc: Exception | None = None
        try:
            self._adapter.get_secret(SECRET_PATH)
        except Exception as e:
            exc = e
        elapsed_ms = (time.perf_counter() - start) * 1000
        self.environment.events.request.fire(
            request_type="VaultKV",
            name="get_secret",
            response_time=elapsed_ms,
            response_length=0,
            exception=exc,
            context={},
        )

    @task(1)
    def list_secrets(self) -> None:
        start = time.perf_counter()
        exc: Exception | None = None
        try:
            self._adapter.list_secrets("load")
        except Exception as e:
            exc = e
        elapsed_ms = (time.perf_counter() - start) * 1000
        self.environment.events.request.fire(
            request_type="VaultKV",
            name="list_secrets",
            response_time=elapsed_ms,
            response_length=0,
            exception=exc,
            context={},
        )


class CachedVaultUser(User):
    """Simulates a pod reading secrets via the in-memory cache (TTL=300s, §4.1 table).

    Models steady-state production traffic where cache hit rate is high.
    """

    wait_time = between(0.05, 0.2)

    def on_start(self) -> None:
        from secretsmanager.adapters.hashicorp import HashiCorpVaultAdapter
        from secretsmanager.cache import CachedSecretProvider

        raw = HashiCorpVaultAdapter(vault_url=VAULT_ADDR, vault_token=VAULT_TOKEN, verify_ssl=False)
        self._adapter = CachedSecretProvider(raw, ttl_seconds=300)

    @task
    def read_cached_secret(self) -> None:
        start = time.perf_counter()
        exc: Exception | None = None
        try:
            self._adapter.get_secret(SECRET_PATH)
        except Exception as e:
            exc = e
        elapsed_ms = (time.perf_counter() - start) * 1000
        self.environment.events.request.fire(
            request_type="CachedVaultKV",
            name="get_secret_cached",
            response_time=elapsed_ms,
            response_length=0,
            exception=exc,
            context={},
        )
