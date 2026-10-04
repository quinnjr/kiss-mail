# ============================================================================
# KISS Mail - Vultr Terraform Configuration
# ============================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    vultr = {
      source  = "vultr/vultr"
      version = "~> 2.0"
    }
  }
}

# ----------------------------------------------------------------------------
# Variables
# ----------------------------------------------------------------------------
variable "vultr_api_key" {
  description = "Vultr API key"
  type        = string
  sensitive   = true
}

variable "region" {
  description = "Vultr region"
  type        = string
  default     = "ewr" # New Jersey
}

variable "plan" {
  description = "Vultr plan"
  type        = string
  default     = "vc2-1c-1gb" # $5/month
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
  description = "SSH key IDs"
  type        = list(string)
  default     = []
}

# ----------------------------------------------------------------------------
# Provider
# ----------------------------------------------------------------------------
provider "vultr" {
  api_key = var.vultr_api_key
}

# ----------------------------------------------------------------------------
# Startup Script
# ----------------------------------------------------------------------------
resource "vultr_startup_script" "kiss_mail" {
  name = "kiss-mail-setup"
  # "boot" scripts run on every boot; the script provisions only once.
  type = "boot"
  # Shared bootstrap script. The admin password is generated on the server
  # and kept only in the root-only /opt/kiss-mail/credentials.txt.
  script = base64encode(templatefile("${path.module}/../common/bootstrap.sh.tftpl", {
    provider_name = "vultr"
    domain        = var.domain
    public_ip_cmd = "curl -s http://169.254.169.254/latest/meta-data/public-ipv4"
  }))
}

# ----------------------------------------------------------------------------
# Image: Ubuntu 24.04 LTS (looked up by name rather than a hard-coded os_id)
# ----------------------------------------------------------------------------
data "vultr_os" "ubuntu" {
  filter {
    name   = "name"
    values = ["Ubuntu 24.04 LTS x64"]
  }
}

# ----------------------------------------------------------------------------
# Firewall
# ----------------------------------------------------------------------------
resource "vultr_firewall_group" "kiss_mail" {
  description = "KISS Mail Firewall"
}

resource "vultr_firewall_rule" "ssh" {
  firewall_group_id = vultr_firewall_group.kiss_mail.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "22"
}

resource "vultr_firewall_rule" "smtp" {
  firewall_group_id = vultr_firewall_group.kiss_mail.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "25"
}

resource "vultr_firewall_rule" "submission" {
  firewall_group_id = vultr_firewall_group.kiss_mail.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "587"
}

resource "vultr_firewall_rule" "imap" {
  firewall_group_id = vultr_firewall_group.kiss_mail.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "143"
}

resource "vultr_firewall_rule" "pop3" {
  firewall_group_id = vultr_firewall_group.kiss_mail.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "110"
}

resource "vultr_firewall_rule" "smtps" {
  firewall_group_id = vultr_firewall_group.kiss_mail.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "465"
}

resource "vultr_firewall_rule" "imaps" {
  firewall_group_id = vultr_firewall_group.kiss_mail.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "993"
}

resource "vultr_firewall_rule" "pop3s" {
  firewall_group_id = vultr_firewall_group.kiss_mail.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "995"
}

resource "vultr_firewall_rule" "http" {
  firewall_group_id = vultr_firewall_group.kiss_mail.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "80"
}

resource "vultr_firewall_rule" "https" {
  firewall_group_id = vultr_firewall_group.kiss_mail.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "443"
}

# ----------------------------------------------------------------------------
# Reserved IP (created first, attached to the instance at creation)
# ----------------------------------------------------------------------------
resource "vultr_reserved_ip" "kiss_mail" {
  region  = var.region
  ip_type = "v4"
  label   = "kiss-mail-ip"
}

# ----------------------------------------------------------------------------
# Instance
# ----------------------------------------------------------------------------
resource "vultr_instance" "kiss_mail" {
  label             = "kiss-mail"
  region            = var.region
  plan              = var.plan
  os_id             = data.vultr_os.ubuntu.id # Ubuntu 24.04 LTS x64 (id 2284)
  script_id         = vultr_startup_script.kiss_mail.id
  firewall_group_id = vultr_firewall_group.kiss_mail.id
  ssh_key_ids       = var.ssh_keys
  enable_ipv6       = true
  reserved_ip_id    = vultr_reserved_ip.kiss_mail.id

  tags = ["kiss-mail"]
}

# ----------------------------------------------------------------------------
# Outputs
# ----------------------------------------------------------------------------
output "public_ip" {
  value = vultr_reserved_ip.kiss_mail.subnet
}

output "web_admin_url" {
  value = "http://${vultr_reserved_ip.kiss_mail.subnet}/admin"
}

output "ssh_command" {
  value = "ssh root@${vultr_reserved_ip.kiss_mail.subnet}"
}

output "credentials_command" {
  value = "ssh root@${vultr_reserved_ip.kiss_mail.subnet} cat /opt/kiss-mail/credentials.txt"
}
