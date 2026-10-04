# ============================================================================
# KISS Mail - Digital Ocean Terraform Configuration
# ============================================================================
# Deploy KISS Mail on Digital Ocean with a single command:
#   terraform init && terraform apply
# ============================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

# ----------------------------------------------------------------------------
# Variables
# ----------------------------------------------------------------------------
variable "do_token" {
  description = "Digital Ocean API token"
  type        = string
  sensitive   = true
}

variable "region" {
  description = "Digital Ocean region"
  type        = string
  default     = "nyc1"
}

variable "droplet_size" {
  description = "Droplet size"
  type        = string
  default     = "s-1vcpu-1gb" # $6/month
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
  description = "List of SSH key IDs or fingerprints"
  type        = list(string)
  default     = []
}

variable "project_name" {
  description = "Project name for organization"
  type        = string
  default     = "kiss-mail"
}

variable "enable_backups" {
  description = "Enable automated backups"
  type        = bool
  default     = false
}

variable "enable_monitoring" {
  description = "Enable monitoring"
  type        = bool
  default     = true
}

# ----------------------------------------------------------------------------
# Provider
# ----------------------------------------------------------------------------
provider "digitalocean" {
  token = var.do_token
}

# ----------------------------------------------------------------------------
# SSH Key (optional - create from file)
# ----------------------------------------------------------------------------
# Uncomment if you want to create a key from a local file
# resource "digitalocean_ssh_key" "default" {
#   name       = "kiss-mail-key"
#   public_key = file("~/.ssh/id_rsa.pub")
# }

# ----------------------------------------------------------------------------
# Firewall
# ----------------------------------------------------------------------------
resource "digitalocean_firewall" "kiss_mail" {
  name = "kiss-mail-fw"

  droplet_ids = [digitalocean_droplet.kiss_mail.id]

  # SSH
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # HTTP
  inbound_rule {
    protocol         = "tcp"
    port_range       = "80"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # HTTPS
  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # SMTP
  inbound_rule {
    protocol         = "tcp"
    port_range       = "25"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # SMTP Submission
  inbound_rule {
    protocol         = "tcp"
    port_range       = "587"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # IMAP
  inbound_rule {
    protocol         = "tcp"
    port_range       = "143"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # POP3
  inbound_rule {
    protocol         = "tcp"
    port_range       = "110"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # SMTPS (submission, implicit TLS)
  inbound_rule {
    protocol         = "tcp"
    port_range       = "465"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # IMAPS (IMAP over TLS)
  inbound_rule {
    protocol         = "tcp"
    port_range       = "993"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # POP3S (POP3 over TLS)
  inbound_rule {
    protocol         = "tcp"
    port_range       = "995"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # All outbound
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

# ----------------------------------------------------------------------------
# Droplet
# ----------------------------------------------------------------------------
resource "digitalocean_droplet" "kiss_mail" {
  name       = "kiss-mail"
  region     = var.region
  size       = var.droplet_size
  image      = "ubuntu-24-04-x64" # Docker is installed by the bootstrap script
  backups    = var.enable_backups
  monitoring = var.enable_monitoring
  ssh_keys   = var.ssh_keys
  tags       = ["kiss-mail", "mail-server"]

  # Shared bootstrap script. The admin password is generated on the droplet
  # and kept only in the root-only /opt/kiss-mail/credentials.txt.
  user_data = templatefile("${path.module}/../common/bootstrap.sh.tftpl", {
    provider_name = "digitalocean"
    domain        = var.domain
    public_ip_cmd = "curl -s http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address"
  })

  lifecycle {
    ignore_changes = [user_data]
  }
}

# ----------------------------------------------------------------------------
# Reserved IP (Static)
# ----------------------------------------------------------------------------
resource "digitalocean_reserved_ip" "kiss_mail" {
  region = var.region
}

resource "digitalocean_reserved_ip_assignment" "kiss_mail" {
  ip_address = digitalocean_reserved_ip.kiss_mail.ip_address
  droplet_id = digitalocean_droplet.kiss_mail.id
}

# ----------------------------------------------------------------------------
# Project (Organization)
# ----------------------------------------------------------------------------
resource "digitalocean_project" "kiss_mail" {
  name        = var.project_name
  description = "KISS Mail Server"
  purpose     = "Service or API"
  environment = "Production"

  resources = [
    digitalocean_droplet.kiss_mail.urn,
    digitalocean_reserved_ip.kiss_mail.urn,
  ]
}

# ----------------------------------------------------------------------------
# Volume (Optional - for extra storage)
# ----------------------------------------------------------------------------
# resource "digitalocean_volume" "kiss_mail_data" {
#   region      = var.region
#   name        = "kiss-mail-data"
#   size        = 50  # GB
#   description = "KISS Mail data volume"
# }
#
# resource "digitalocean_volume_attachment" "kiss_mail_data" {
#   droplet_id = digitalocean_droplet.kiss_mail.id
#   volume_id  = digitalocean_volume.kiss_mail_data.id
# }

# ----------------------------------------------------------------------------
# Outputs
# ----------------------------------------------------------------------------
output "droplet_ip" {
  description = "Droplet IP address"
  value       = digitalocean_droplet.kiss_mail.ipv4_address
}

output "reserved_ip" {
  description = "Reserved (static) IP address"
  value       = digitalocean_reserved_ip.kiss_mail.ip_address
}

output "web_admin_url" {
  description = "Web admin URL"
  value       = "http://${digitalocean_reserved_ip.kiss_mail.ip_address}/admin"
}

output "smtp_server" {
  description = "SMTP server address"
  value       = "${digitalocean_reserved_ip.kiss_mail.ip_address}:25"
}

output "imap_server" {
  description = "IMAP server address"
  value       = "${digitalocean_reserved_ip.kiss_mail.ip_address}:143"
}

output "pop3_server" {
  description = "POP3 server address"
  value       = "${digitalocean_reserved_ip.kiss_mail.ip_address}:110"
}

output "ssh_command" {
  description = "SSH command"
  value       = "ssh root@${digitalocean_reserved_ip.kiss_mail.ip_address}"
}

output "credentials_command" {
  description = "Show the generated credentials (admin password, API key)"
  value       = "ssh root@${digitalocean_reserved_ip.kiss_mail.ip_address} cat /opt/kiss-mail/credentials.txt"
}

output "dns_records" {
  description = "DNS records to configure"
  value       = <<-EOT
    
    Configure these DNS records for ${var.domain}:
    
    A     ${var.domain}              ${digitalocean_reserved_ip.kiss_mail.ip_address}
    MX    ${var.domain}    10        ${var.domain}
    TXT   ${var.domain}              "v=spf1 ip4:${digitalocean_reserved_ip.kiss_mail.ip_address} -all"
    
  EOT
}
