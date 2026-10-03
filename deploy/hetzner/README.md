# KISS Mail - Hetzner Cloud Deployment

Deploy KISS Mail on Hetzner Cloud with Terraform.

## Quick Start

```bash
cd deploy/hetzner
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars

terraform init
terraform apply
```

## Pricing (EU)

| Type | vCPU | RAM |
|------|------|-----|
| cx22 (default) | 2 | 4GB |
| cx32 | 4 | 8GB |

Check [current Hetzner pricing](https://www.hetzner.com/cloud/) - prices and
available server types change over time.

## What Gets Created

- A primary IPv4 address (kept on `terraform destroy` of the server only if you
  remove it from state; `auto_delete = false`), attached to the server at creation
- An Ubuntu 24.04 server whose user-data installs Docker and Nginx and starts KISS Mail
- A firewall allowing 22, 25, 587, 143, 110, 80, 443

The web admin and REST API are only published on `127.0.0.1` and reached
through Nginx on port 80.

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

To read it:

```bash
ssh root@<ip> cat /opt/kiss-mail/credentials.txt
```

## Cleanup

```bash
terraform destroy
```

## Server types and locations

The default `cx22` (shared Intel) type is only offered in the EU locations
`nbg1`, `fsn1` and `hel1`. In `ash`, `hil` (US) and `sin` (Singapore) use an
AMD type such as `cpx11` or `cpx21`; `terraform plan` fails with a clear
message otherwise.
