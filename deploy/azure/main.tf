# ============================================================================
# KISS Mail - Microsoft Azure Terraform Configuration
# ============================================================================
# Deploy: terraform init && terraform apply
# ============================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.7"
    }
  }
}

# ----------------------------------------------------------------------------
# Variables
# ----------------------------------------------------------------------------
variable "subscription_id" {
  description = "Azure subscription ID (or leave null and export ARM_SUBSCRIPTION_ID)"
  type        = string
  default     = null
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "eastus"
}

variable "vm_size" {
  description = "Virtual machine size"
  type        = string
  default     = "Standard_B1s" # Cheapest option
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

variable "admin_username" {
  description = "VM admin username"
  type        = string
  default     = "azureuser"
}

variable "ssh_public_key" {
  description = "SSH public key for VM access"
  type        = string
  default     = ""
}

variable "disk_size" {
  description = "OS disk size in GB"
  type        = number
  default     = 30
}

# ----------------------------------------------------------------------------
# Provider
# ----------------------------------------------------------------------------
# azurerm 4.x no longer falls back to the Azure CLI's default subscription:
# set subscription_id here or export ARM_SUBSCRIPTION_ID.
provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

# ----------------------------------------------------------------------------
# Resource Group
# ----------------------------------------------------------------------------
resource "azurerm_resource_group" "kiss_mail" {
  name     = "kiss-mail-rg"
  location = var.location

  tags = {
    app     = "kiss-mail"
    env     = "production"
    managed = "terraform"
  }
}

# ----------------------------------------------------------------------------
# Network
# ----------------------------------------------------------------------------
resource "azurerm_virtual_network" "kiss_mail" {
  name                = "kiss-mail-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.kiss_mail.location
  resource_group_name = azurerm_resource_group.kiss_mail.name
}

resource "azurerm_subnet" "kiss_mail" {
  name                 = "kiss-mail-subnet"
  resource_group_name  = azurerm_resource_group.kiss_mail.name
  virtual_network_name = azurerm_virtual_network.kiss_mail.name
  address_prefixes     = ["10.0.1.0/24"]
}

# ----------------------------------------------------------------------------
# Public IP
# ----------------------------------------------------------------------------
resource "azurerm_public_ip" "kiss_mail" {
  name                = "kiss-mail-ip"
  location            = azurerm_resource_group.kiss_mail.location
  resource_group_name = azurerm_resource_group.kiss_mail.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

# ----------------------------------------------------------------------------
# Network Security Group
# ----------------------------------------------------------------------------
resource "azurerm_network_security_group" "kiss_mail" {
  name                = "kiss-mail-nsg"
  location            = azurerm_resource_group.kiss_mail.location
  resource_group_name = azurerm_resource_group.kiss_mail.name

  security_rule {
    name                       = "SSH"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "SMTP"
    priority                   = 1002
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "25"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "SMTP-Submission"
    priority                   = 1003
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "587"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "IMAP"
    priority                   = 1004
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "143"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "POP3"
    priority                   = 1005
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "110"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "HTTP"
    priority                   = 1006
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "HTTPS"
    priority                   = 1007
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# ----------------------------------------------------------------------------
# Network Interface
# ----------------------------------------------------------------------------
resource "azurerm_network_interface" "kiss_mail" {
  name                = "kiss-mail-nic"
  location            = azurerm_resource_group.kiss_mail.location
  resource_group_name = azurerm_resource_group.kiss_mail.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.kiss_mail.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.kiss_mail.id
  }
}

resource "azurerm_network_interface_security_group_association" "kiss_mail" {
  network_interface_id      = azurerm_network_interface.kiss_mail.id
  network_security_group_id = azurerm_network_security_group.kiss_mail.id
}

# ----------------------------------------------------------------------------
# Virtual Machine
# ----------------------------------------------------------------------------
resource "azurerm_linux_virtual_machine" "kiss_mail" {
  name                = "kiss-mail-vm"
  resource_group_name = azurerm_resource_group.kiss_mail.name
  location            = azurerm_resource_group.kiss_mail.location
  size                = var.vm_size
  admin_username      = var.admin_username

  network_interface_ids = [
    azurerm_network_interface.kiss_mail.id,
  ]

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.ssh_public_key != "" ? var.ssh_public_key : file("~/.ssh/id_rsa.pub")
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
    disk_size_gb         = var.disk_size
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }

  # Shared bootstrap script (cloud-init runs a custom_data that starts with
  # "#!" as a user script). The admin password is generated on the VM and
  # kept only in the root-only /opt/kiss-mail/credentials.txt.
  custom_data = base64encode(templatefile("${path.module}/../common/bootstrap.sh.tftpl", {
    provider_name = "azure"
    domain        = var.domain
    public_ip_cmd = "curl -s -H Metadata:true 'http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2021-02-01&format=text'"
  }))

  tags = {
    app     = "kiss-mail"
    env     = "production"
    managed = "terraform"
  }

  # The bootstrap script only runs on first boot; a template change must not
  # replace the VM (and its mail data).
  lifecycle {
    ignore_changes = [custom_data]
  }
}

# ----------------------------------------------------------------------------
# Outputs
# ----------------------------------------------------------------------------
output "public_ip" {
  description = "Public IP address"
  value       = azurerm_public_ip.kiss_mail.ip_address
}

output "web_admin_url" {
  description = "Web admin URL"
  value       = "http://${azurerm_public_ip.kiss_mail.ip_address}/admin"
}

output "ssh_command" {
  description = "SSH command"
  value       = "ssh ${var.admin_username}@${azurerm_public_ip.kiss_mail.ip_address}"
}

output "credentials_command" {
  description = "Show the generated credentials (admin password, API key)"
  value       = "ssh ${var.admin_username}@${azurerm_public_ip.kiss_mail.ip_address} sudo cat /opt/kiss-mail/credentials.txt"
}

output "dns_records" {
  description = "DNS records to configure"
  value       = <<-EOT
    
    Configure these DNS records for ${var.domain}:
    
    A     ${var.domain}              ${azurerm_public_ip.kiss_mail.ip_address}
    MX    ${var.domain}    10        ${var.domain}
    TXT   ${var.domain}              "v=spf1 ip4:${azurerm_public_ip.kiss_mail.ip_address} -all"
    
  EOT
}
