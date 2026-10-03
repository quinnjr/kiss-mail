# KISS Mail - Linode (Akamai) Deployment

Deploy KISS Mail on Linode with Terraform.

## Quick Start

```bash
cd deploy/linode
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your API token

terraform init
terraform apply
```

## Requirements

- [Terraform](https://terraform.io) >= 1.0
- [Linode API Token](https://cloud.linode.com/profile/tokens)

## Pricing

| Type | RAM | Cost |
|------|-----|------|
| g6-nanode-1 | 1GB | $5/month |
| g6-standard-1 | 2GB | $10/month |
| g6-standard-2 | 4GB | $20/month |

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

The instance uses `linode/ubuntu24.04`; the StackScript is the shared
bootstrap script rendered with your domain (no UDF fields).

## Cleanup

```bash
terraform destroy
```
