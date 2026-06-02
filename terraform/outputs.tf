output "vault_public_ip" {
  value       = google_compute_instance.vault.network_interface[0].access_config[0].nat_ip
  description = "Public IP of the Vault server (for API access and SSH)."
}

output "vault_api_address" {
  value       = "http://${google_compute_instance.vault.network_interface[0].access_config[0].nat_ip}:8200"
  description = "Vault API URL."
}

output "vault_service_account_email" {
  value       = google_service_account.vault_sa.email
  description = "GCP service account used by the Vault VM."
}

output "vault_storage_bucket_name" {
  value       = google_storage_bucket.vault_snapshots.name
  description = "GCS bucket for Vault snapshots."
}

output "approle_role_id" {
  value       = vault_approle_auth_backend_role.app.role_id
  description = "AppRole role_id for secrets-manager-app."
  sensitive   = false
}
