# ============================================================================
# KISS Mail - Hetzner Cloud Terraform Configuration
# ============================================================================

terraform {
  required_version = ">= 1.3" # lifecycle precondition + startswith()
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.69" # primary IP "location" argument
    }
  }
}

# ----------------------------------------------------------------------------
# Variables
# ----------------------------------------------------------------------------
variable "hcloud_token" {
  description = "Hetzner Cloud API token"
  type        = string
  sensitive   = true
}

variable "location" {
  description = "Hetzner location (nbg1, fsn1, hel1, ash, hil, sin)"
  type        = string
  default     = "nbg1" # Nuremberg
}

# NOTE: the cx* (shared Intel) types are only offered in the EU locations
# (nbg1, fsn1, hel1). In ash, hil (US) and sin (Singapore) use an AMD type
# such as cpx11 or cpx21.
variable "server_type" {
  description = "Server type (cx* only in nbg1/fsn1/hel1; use cpx11/cpx21 in ash, hil and sin)"
  type        = string
  default     = "cx22" # 2 vCPU, 4GB RAM (cx11 has been discontinued)
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

variable "ssh_keys" {
  description = "SSH key names"
  type        = list(string)
  default     = []
}

# ----------------------------------------------------------------------------
# Provider
# ----------------------------------------------------------------------------
provider "hcloud" {
  token = var.hcloud_token
}

# ----------------------------------------------------------------------------
# SSH Key (optional)
# ----------------------------------------------------------------------------
# resource "hcloud_ssh_key" "default" {
#   name       = "kiss-mail"
#   public_key = file("~/.ssh/id_rsa.pub")
# }

# ----------------------------------------------------------------------------
# Firewall
# ----------------------------------------------------------------------------
resource "hcloud_firewall" "kiss_mail" {
  name = "kiss-mail-firewall"

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "25"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "587"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "143"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "110"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "465"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "993"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "995"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "80"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "443"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "icmp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
}

# ----------------------------------------------------------------------------
# Primary IP (Static) - created first and attached to the server at creation
# ----------------------------------------------------------------------------
resource "hcloud_primary_ip" "kiss_mail" {
  name        = "kiss-mail-ip"
  location    = var.location
  type        = "ipv4"
  auto_delete = false

  labels = {
    app     = "kiss-mail"
    managed = "terraform"
  }
}

# ----------------------------------------------------------------------------
# Server
# ----------------------------------------------------------------------------
resource "hcloud_server" "kiss_mail" {
  name        = "kiss-mail"
  image       = "ubuntu-24.04" # Docker is installed by the bootstrap script
  server_type = var.server_type
  location    = var.location
  ssh_keys    = var.ssh_keys

  firewall_ids = [hcloud_firewall.kiss_mail.id]

  public_net {
    ipv4_enabled = true
    ipv4         = hcloud_primary_ip.kiss_mail.id
    ipv6_enabled = true
  }

  # Shared bootstrap script. The admin password is generated on the server
  # and kept only in the root-only /opt/kiss-mail/credentials.txt.
  user_data = templatefile("${path.module}/../common/bootstrap.sh.tftpl", {
    provider_name = "hetzner"
    domain        = var.domain
    public_ip_cmd = "curl -s http://169.254.169.254/hetzner/v1/metadata/public-ipv4"
  })

  labels = {
    app     = "kiss-mail"
    managed = "terraform"
  }

  lifecycle {
    ignore_changes = [user_data]

    precondition {
      condition     = !(startswith(var.server_type, "cx") && contains(["ash", "hil", "sin"], var.location))
      error_message = "cx* server types are only available in nbg1, fsn1 and hel1; use cpx11 or cpx21 in ash, hil and sin."
    }
  }
}

# ----------------------------------------------------------------------------
# Outputs
# ----------------------------------------------------------------------------
output "public_ip" {
  value = hcloud_primary_ip.kiss_mail.ip_address
}

output "web_admin_url" {
  value = "http://${hcloud_primary_ip.kiss_mail.ip_address}/admin"
}

output "ssh_command" {
  value = "ssh root@${hcloud_primary_ip.kiss_mail.ip_address}"
}

output "credentials_command" {
  value = "ssh root@${hcloud_primary_ip.kiss_mail.ip_address} cat /opt/kiss-mail/credentials.txt"
}
