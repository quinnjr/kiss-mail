# KISS Mail - Microsoft Azure Deployment

Deploy KISS Mail on Microsoft Azure with Terraform.

## Quick Start

```bash
# 1. Login to Azure
az login

# 2. Deploy
cd deploy/azure
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars

terraform init
terraform apply
```

## Requirements

- [Terraform](https://terraform.io) >= 1.0
- [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/)
- Azure subscription

## What Gets Created

| Resource | Description | Cost |
|----------|-------------|------|
| Resource Group | Container for resources | Free |
| Virtual Network | Custom VNet | Free |
| Network Security Group | Firewall rules | Free |
| Public IP | Static IP address | ~$3/month |
| Virtual Machine | Standard_B1s (Ubuntu 24.04 LTS) | ~$8/month |

**Estimated Cost: ~$10-15/month**

## VM Sizes

| Size | vCPUs | RAM | Cost |
|------|-------|-----|------|
| Standard_B1s | 1 | 1GB | ~$8/month |
| Standard_B1ms | 1 | 2GB | ~$15/month |
| Standard_B2s | 2 | 4GB | ~$30/month |

## Admin Password

The admin password is not a Terraform variable: it is generated on the
server (so it never reaches Terraform state or instance metadata) and written
to the root-only `/opt/kiss-mail/credentials.txt` (`terraform output
credentials_command`). The server is provisioned by the shared bootstrap
script `deploy/common/bootstrap.sh.tftpl` on Ubuntu 24.04 LTS. The web admin
is reached through Nginx on port 80; the REST API is published on
`127.0.0.1` only (use `ssh -L 8025:127.0.0.1:8025 ...` for the remote CLI).
After `certbot --nginx`, switch the session cookie to Secure with
`upgrade.sh --no-pull --env KISS_MAIL_WEB_SECURE_COOKIE=true` (see the main
README).

azurerm 4.x requires a subscription: set `subscription_id` in
`terraform.tfvars` or export `ARM_SUBSCRIPTION_ID`.

## Access

```bash
# SSH
ssh azureuser@<public_ip>

# View credentials (admin password, API key)
sudo cat /opt/kiss-mail/credentials.txt

# View setup log / container logs
sudo cat /var/log/kiss-mail-setup.log
sudo docker logs kiss-mail
```

## Cleanup

```bash
terraform destroy
```
