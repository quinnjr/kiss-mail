# ============================================================================
# KISS Mail - Linode (Akamai) Terraform Configuration
# ============================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    linode = {
      source  = "linode/linode"
      version = "~> 2.0"
    }
  }
}

# ----------------------------------------------------------------------------
# Variables
# ----------------------------------------------------------------------------
variable "linode_token" {
  description = "Linode API token"
  type        = string
  sensitive   = true
}

variable "region" {
  description = "Linode region"
  type        = string
  default     = "us-east"
}

variable "type" {
  description = "Linode instance type"
  type        = string
  default     = "g6-nanode-1" # $5/month
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

variable "root_password" {
  description = "Root password for Linode"
  type        = string
  sensitive   = true
}

variable "ssh_keys" {
  description = "SSH public keys"
  type        = list(string)
  default     = []
}

# ----------------------------------------------------------------------------
# Provider
# ----------------------------------------------------------------------------
provider "linode" {
  token = var.linode_token
}

# ----------------------------------------------------------------------------
# Firewall
# ----------------------------------------------------------------------------
resource "linode_firewall" "kiss_mail" {
  label = "kiss-mail-firewall"

  inbound {
    label    = "allow-ssh"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "22"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  inbound {
    label    = "allow-smtp"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "25"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  inbound {
    label    = "allow-submission"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "587"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  inbound {
    label    = "allow-imap"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "143"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  inbound {
    label    = "allow-pop3"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "110"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  inbound {
    label    = "allow-http"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "80"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  inbound {
    label    = "allow-https"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "443"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  inbound_policy  = "DROP"
  outbound_policy = "ACCEPT"

  linodes = [linode_instance.kiss_mail.id]
}

# ----------------------------------------------------------------------------
# Linode Instance
# ----------------------------------------------------------------------------
resource "linode_instance" "kiss_mail" {
  label           = "kiss-mail"
  image           = "linode/ubuntu24.04"
  region          = var.region
  type            = var.type
  root_pass       = var.root_password
  authorized_keys = var.ssh_keys

  # The StackScript installs Docker, Nginx and KISS Mail. The admin password
  # is generated on the Linode and kept only in the root-only
  # /opt/kiss-mail/credentials.txt.
  stackscript_id = linode_stackscript.kiss_mail.id

  tags = ["kiss-mail", "mail-server"]
}

# ----------------------------------------------------------------------------
# StackScript (cloud-init equivalent)
# ----------------------------------------------------------------------------
resource "linode_stackscript" "kiss_mail" {
  label       = "kiss-mail-setup"
  description = "KISS Mail Server Setup"
  # The shared bootstrap script, rendered with the domain (no UDF fields).
  script = templatefile("${path.module}/../common/bootstrap.sh.tftpl", {
    provider_name = "linode"
    domain        = var.domain
    public_ip_cmd = "curl -s --max-time 10 ifconfig.me || curl -s --max-time 10 icanhazip.com"
  })
  images   = ["linode/ubuntu24.04"]
  rev_note = "Install Docker, Nginx and KISS Mail"
}

# ----------------------------------------------------------------------------
# Outputs
# ----------------------------------------------------------------------------
locals {
  # ip_address is deprecated; the first public IPv4 address replaces it.
  public_ip = tolist(linode_instance.kiss_mail.ipv4)[0]
}

output "public_ip" {
  value = local.public_ip
}

output "web_admin_url" {
  value = "http://${local.public_ip}/admin"
}

output "ssh_command" {
  value = "ssh root@${local.public_ip}"
}

output "credentials_command" {
  value = "ssh root@${local.public_ip} cat /opt/kiss-mail/credentials.txt"
}
