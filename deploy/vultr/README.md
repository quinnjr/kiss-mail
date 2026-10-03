# KISS Mail - Vultr Deployment

Deploy KISS Mail on Vultr with Terraform.

## Quick Start

```bash
cd deploy/vultr
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars

terraform init
terraform apply
```

## Pricing

| Plan | RAM | Cost |
|------|-----|------|
| vc2-1c-1gb | 1GB | $5/month |
| vc2-1c-2gb | 2GB | $10/month |
| vc2-2c-4gb | 4GB | $20/month |

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

The startup script is a Vultr "boot" script: it runs on every boot but only
provisions once. The reserved IP is attached to the instance at creation.

## Cleanup

```bash
terraform destroy
```
