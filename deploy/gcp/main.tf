# ============================================================================
# KISS Mail - Google Cloud Platform Terraform Configuration
# ============================================================================
# Deploy: terraform init && terraform apply
# ============================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.5"
    }
  }
}

# ----------------------------------------------------------------------------
# Variables
# ----------------------------------------------------------------------------
variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone"
  type        = string
  default     = "us-central1-a"
}

variable "machine_type" {
  description = "Compute Engine machine type"
  type        = string
  default     = "e2-micro" # Free tier eligible
}

variable "domain" {
  description = "Mail domain"
  type        = string
  default     = "mail.example.com"

  validation {
    condition     = can(regex("^[A-Za-z0-9.-]+$", var.domain))
    error_message = "The domain may only contain letters, digits, '.' and '-'."
  }
}

variable "disk_size" {
  description = "Boot disk size in GB"
  type        = number
  default     = 20
}

# ----------------------------------------------------------------------------
# Provider
# ----------------------------------------------------------------------------
provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

# ----------------------------------------------------------------------------
# Network
# ----------------------------------------------------------------------------
resource "google_compute_network" "kiss_mail" {
  name                    = "kiss-mail-network"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "kiss_mail" {
  name          = "kiss-mail-subnet"
  ip_cidr_range = "10.0.1.0/24"
  region        = var.region
  network       = google_compute_network.kiss_mail.id
}

# ----------------------------------------------------------------------------
# Firewall
# ----------------------------------------------------------------------------
resource "google_compute_firewall" "kiss_mail" {
  name    = "kiss-mail-firewall"
  network = google_compute_network.kiss_mail.name

  allow {
    protocol = "tcp"
    ports    = ["22", "25", "80", "110", "143", "443", "587"]
  }

  allow {
    protocol = "icmp"
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["kiss-mail"]
}

# ----------------------------------------------------------------------------
# Static IP
# ----------------------------------------------------------------------------
resource "google_compute_address" "kiss_mail" {
  name   = "kiss-mail-ip"
  region = var.region
}

# ----------------------------------------------------------------------------
# Service account (no IAM roles: the VM needs no Google Cloud API access)
# ----------------------------------------------------------------------------
resource "google_service_account" "kiss_mail" {
  account_id   = "kiss-mail-vm"
  display_name = "KISS Mail VM (no roles)"
}

# ----------------------------------------------------------------------------
# Compute Instance
# ----------------------------------------------------------------------------
resource "google_compute_instance" "kiss_mail" {
  name         = "kiss-mail"
  machine_type = var.machine_type
  zone         = var.zone
  tags         = ["kiss-mail"]

  boot_disk {
    initialize_params {
      # Ubuntu + Docker (installed by the startup script). The container
      # publishes 25/587/143/110 -> 2525/1143/1100 and Nginx proxies the web
      # admin/API on port 80, matching the firewall rule above.
      image = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
      size  = var.disk_size
      type  = "pd-standard"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.kiss_mail.id
    access_config {
      nat_ip = google_compute_address.kiss_mail.address
    }
  }

  # Runs on every boot; the script provisions only once (data lives in
  # /opt/kiss-mail/data on the boot disk).
  # The admin password is generated on the VM and kept only in the root-only
  # /opt/kiss-mail/credentials.txt.
  metadata_startup_script = templatefile("${path.module}/../common/bootstrap.sh.tftpl", {
    provider_name = "gcp"
    domain        = var.domain
    public_ip_cmd = "curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip"
  })

  # Dedicated service account without roles, and only the logging scope
  # (not the default compute account with cloud-platform).
  service_account {
    email  = google_service_account.kiss_mail.email
    scopes = ["https://www.googleapis.com/auth/logging.write"]
  }

  labels = {
    app     = "kiss-mail"
    env     = "production"
    managed = "terraform"
  }

  lifecycle {
    ignore_changes = [metadata_startup_script]
  }
}

# ----------------------------------------------------------------------------
# Outputs
# ----------------------------------------------------------------------------
output "public_ip" {
  description = "Public IP address"
  value       = google_compute_address.kiss_mail.address
}

output "web_admin_url" {
  description = "Web admin URL"
  value       = "http://${google_compute_address.kiss_mail.address}/admin"
}

output "smtp_server" {
  description = "SMTP server address"
  value       = "${google_compute_address.kiss_mail.address}:25"
}

output "imap_server" {
  description = "IMAP server address"
  value       = "${google_compute_address.kiss_mail.address}:143"
}

output "pop3_server" {
  description = "POP3 server address"
  value       = "${google_compute_address.kiss_mail.address}:110"
}

output "credentials_command" {
  description = "Show the generated credentials (admin password, API key)"
  value       = "gcloud compute ssh kiss-mail --zone ${var.zone} --command 'sudo cat /opt/kiss-mail/credentials.txt'"
}

output "ssh_command" {
  description = "SSH command"
  value       = "gcloud compute ssh kiss-mail --zone ${var.zone}"
}

output "dns_records" {
  description = "DNS records to configure"
  value       = <<-EOT
    
    Configure these DNS records for ${var.domain}:
    
    A     ${var.domain}              ${google_compute_address.kiss_mail.address}
    MX    ${var.domain}    10        ${var.domain}
    TXT   ${var.domain}              "v=spf1 ip4:${google_compute_address.kiss_mail.address} -all"
    
  EOT
}
