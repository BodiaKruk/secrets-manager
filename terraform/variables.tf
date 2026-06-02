variable "gcp_project_id" {
  type        = string
  description = "GCP project ID for all resources."
}

variable "gcp_region" {
  type        = string
  default     = "us-central1"
  description = "GCP region."
}

variable "gcp_zone" {
  type        = string
  default     = "us-central1-a"
  description = "GCP zone for compute instances."
}

variable "vault_root_token" {
  type        = string
  sensitive   = true
  description = "Vault root / init token (used during bootstrap only)."
}

variable "vault_version" {
  type    = string
  default = "1.15.6"
}

variable "machine_type" {
  type    = string
  default = "e2-medium"
}

variable "allowed_ssh_cidr" {
  type    = string
  default = "0.0.0.0/0"
  description = "CIDR block allowed to SSH into the Vault instance."
}

variable "vault_storage_bucket" {
  type        = string
  description = "GCS bucket name for Vault integrated storage snapshots."
}

variable "environment" {
  type    = string
  default = "dev"
  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "environment must be dev, staging, or production."
  }
}
