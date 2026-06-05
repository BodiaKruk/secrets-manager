resource "google_compute_network" "vault_vpc" {
  name                    = "vault-vpc-${var.environment}"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "vault_subnet" {
  name          = "vault-subnet-${var.environment}"
  ip_cidr_range = "10.10.0.0/24"
  region        = var.gcp_region
  network       = google_compute_network.vault_vpc.id

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# Firewall — allow SSH from operator CIDR
resource "google_compute_firewall" "allow_ssh" {
  name    = "vault-allow-ssh-${var.environment}"
  network = google_compute_network.vault_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = [var.allowed_ssh_cidr]
  target_tags   = ["vault-server"]
}

# Firewall — allow Vault API from VPC and operator CIDR (Terraform runner)
resource "google_compute_firewall" "allow_vault_api" {
  name    = "vault-allow-api-${var.environment}"
  network = google_compute_network.vault_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["8200", "8201"]
  }
  source_ranges = ["10.10.0.0/24", var.allowed_ssh_cidr]
  target_tags   = ["vault-server"]
}

# NAT gateway — lets the Vault VM reach the internet without a public IP
resource "google_compute_router" "router" {
  name    = "vault-router-${var.environment}"
  region  = var.gcp_region
  network = google_compute_network.vault_vpc.id
}

resource "google_compute_router_nat" "nat" {
  name                               = "vault-nat-${var.environment}"
  router                             = google_compute_router.router.name
  region                             = var.gcp_region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}
