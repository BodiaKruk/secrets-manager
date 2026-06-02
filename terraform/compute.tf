data "google_compute_image" "ubuntu" {
  family  = "ubuntu-2204-lts"
  project = "ubuntu-os-cloud"
}

resource "google_service_account" "vault_sa" {
  account_id   = "vault-server-${var.environment}"
  display_name = "Vault Server Service Account (${var.environment})"
}

resource "google_project_iam_member" "vault_sa_storage" {
  project = var.gcp_project_id
  role    = "roles/storage.objectAdmin"
  member  = "serviceAccount:${google_service_account.vault_sa.email}"
}

resource "google_project_iam_member" "vault_sa_secret_viewer" {
  project = var.gcp_project_id
  role    = "roles/secretmanager.viewer"
  member  = "serviceAccount:${google_service_account.vault_sa.email}"
}

resource "google_compute_instance" "vault" {
  name         = "vault-server-${var.environment}"
  machine_type = var.machine_type
  zone         = var.gcp_zone
  tags         = ["vault-server"]

  boot_disk {
    initialize_params {
      image = data.google_compute_image.ubuntu.self_link
      size  = 20
      type  = "pd-ssd"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.vault_subnet.id
    access_config {}
  }

  service_account {
    email  = google_service_account.vault_sa.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    ssh-keys = "ubuntu:${tls_private_key.vault_ssh.public_key_openssh}"
  }

  metadata_startup_script = templatefile(
    "${path.module}/vault.hcl.tpl",
    {
      vault_version        = var.vault_version
      storage_bucket       = var.vault_storage_bucket
      gcp_project_id       = var.gcp_project_id
    }
  )

  labels = {
    environment = var.environment
    managed_by  = "terraform"
  }

  lifecycle {
    ignore_changes = [metadata_startup_script]
  }
}
