resource "google_storage_bucket" "vault_snapshots" {
  name          = var.vault_storage_bucket
  location      = var.gcp_region
  force_destroy = var.environment != "production"

  versioning {
    enabled = true
  }

  lifecycle_rule {
    action { type = "Delete" }
    condition { age = 90 }
  }

  uniform_bucket_level_access = true

  labels = {
    environment = var.environment
    managed_by  = "terraform"
  }
}

resource "google_storage_bucket_iam_member" "vault_sa_storage_rw" {
  bucket = google_storage_bucket.vault_snapshots.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.vault_sa.email}"
}
