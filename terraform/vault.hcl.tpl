#!/usr/bin/env bash
# Vault startup script — rendered by Terraform templatefile().
set -euo pipefail

VAULT_VERSION="${vault_version}"
VAULT_ZIP="vault_$${VAULT_VERSION}_linux_amd64.zip"
VAULT_URL="https://releases.hashicorp.com/vault/$${VAULT_VERSION}/$${VAULT_ZIP}"

apt-get update -qq && apt-get install -y -qq unzip curl jq

curl -fsSL "$${VAULT_URL}" -o /tmp/$${VAULT_ZIP}
unzip -o /tmp/$${VAULT_ZIP} -d /usr/local/bin/
chmod +x /usr/local/bin/vault

# Create dedicated user
useradd --system --home /etc/vault.d --shell /bin/false vault || true
mkdir -p /etc/vault.d /var/log/vault /opt/vault/data
chown -R vault:vault /etc/vault.d /var/log/vault /opt/vault

# Resolve IPs before writing config (heredoc must NOT be single-quoted)
INTERNAL_IP=$(hostname -I | awk '{print $1}')
EXTERNAL_IP=$(curl -s http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip -H 'Metadata-Flavor: Google')

# Write Vault configuration
cat > /etc/vault.d/vault.hcl <<CONFIG
ui            = true
disable_mlock = true

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

storage "raft" {
  path    = "/opt/vault/data"
  node_id = "vault-node-1"
}

api_addr     = "http://$${EXTERNAL_IP}:8200"
cluster_addr = "http://$${INTERNAL_IP}:8201"

telemetry {
  prometheus_retention_time = "30s"
  disable_hostname          = true
}
CONFIG

chown vault:vault /etc/vault.d/vault.hcl

# Systemd unit
cat > /etc/systemd/system/vault.service <<'UNIT'
[Unit]
Description=HashiCorp Vault
Documentation=https://www.vaultproject.io/docs/
Requires=network-online.target
After=network-online.target

[Service]
User=vault
Group=vault
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
ExecStart=/usr/local/bin/vault server -config=/etc/vault.d/vault.hcl
ExecReload=/bin/kill --signal HUP $MAINPID
KillMode=process
KillSignal=SIGINT
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable vault
systemctl start vault

echo "Vault $${VAULT_VERSION} installed and started."
