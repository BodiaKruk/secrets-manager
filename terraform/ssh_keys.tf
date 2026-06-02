# Generate an ephemeral SSH key pair for bootstrap access.
# In production, replace with your organisation's key management.

resource "tls_private_key" "vault_ssh" {
  algorithm = "ED25519"
}

resource "local_sensitive_file" "vault_ssh_private_key" {
  content         = tls_private_key.vault_ssh.private_key_openssh
  filename        = "${path.module}/.ssh/vault_id_ed25519"
  file_permission = "0600"
}

output "vault_ssh_public_key" {
  value       = tls_private_key.vault_ssh.public_key_openssh
  description = "Public key for SSH access to the Vault VM."
  sensitive   = false
}
