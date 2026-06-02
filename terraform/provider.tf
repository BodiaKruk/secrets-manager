terraform {
  required_version = ">= 1.7.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.25"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.2"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # Remote state — uncomment when GCS bucket is created.
  # backend "gcs" {
  #   bucket = "tf-state-secrets-manager"
  #   prefix = "terraform/state"
  # }
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

provider "vault" {
  address = "http://${google_compute_instance.vault.network_interface[0].access_config[0].nat_ip}:8200"
  token   = var.vault_root_token

  # Wait until the instance is fully initialised before using Vault provider.
  skip_tls_verify = true
}
