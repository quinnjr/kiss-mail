# KISS Mail - Digital Ocean Deployment

Deploy KISS Mail on Digital Ocean with a single command.

## Quick Start

```bash
# 1. Set your DO token
export DIGITALOCEAN_TOKEN="your-token"

# 2. Initialize Terraform
cd deploy/digitalocean
terraform init

# 3. Deploy
terraform apply -var="do_token=$DIGITALOCEAN_TOKEN"

# Or with custom domain
terraform apply \
  -var="do_token=$DIGITALOCEAN_TOKEN" \
  -var="domain=mail.yourdomain.com"
```

## Requirements

- [Terraform](https://terraform.io) >= 1.0
- [Digital Ocean account](https://digitalocean.com)
- [API Token](https://cloud.digitalocean.com/account/api/tokens)

## What Gets Created

| Resource | Description | Cost |
|----------|-------------|------|
| Droplet | s-1vcpu-1gb (Docker pre-installed) | $6/mo |
| Reserved IP | Static public IP | Free |
| Firewall | Ports 22, 25, 80, 110, 143, 443, 587 | Free |
| Project | Organization | Free |

**Total: ~$6/month**

## Configuration

Copy the example variables file:

```bash
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`:

```hcl
do_token       = "your-digitalocean-api-token"
region         = "nyc1"
droplet_size   = "s-1vcpu-1gb"
domain         = "mail.yourdomain.com"
```

### Available Regions

```bash
doctl compute region list
```

Common regions:
- `nyc1`, `nyc3` - New York
- `sfo3` - San Francisco
- `lon1` - London
- `ams3` - Amsterdam
- `sgp1` - Singapore

### Available Sizes

```bash
doctl compute size list
```

| Size | vCPUs | RAM | Cost |
|------|-------|-----|------|
| s-1vcpu-1gb | 1 | 1GB | $6/mo |
| s-1vcpu-2gb | 1 | 2GB | $12/mo |
| s-2vcpu-2gb | 2 | 2GB | $18/mo |
| s-2vcpu-4gb | 2 | 4GB | $24/mo |

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
The droplet uses the plain `ubuntu-24-04-x64` image; Docker is installed by the
bootstrap script.

## Access

After deployment, Terraform outputs:

```
reserved_ip    = "1.2.3.4"
web_admin_url  = "http://1.2.3.4/admin"
smtp_server    = "1.2.3.4:25"
```

### SSH Access

```bash
ssh root@<reserved_ip>
```

## DNS Configuration

Add these records to your domain:

```
A     mail.yourdomain.com         <reserved_ip>
MX    yourdomain.com       10     mail.yourdomain.com
TXT   yourdomain.com              "v=spf1 ip4:<reserved_ip> -all"
```

### Using Digital Ocean DNS

```hcl
# Add to main.tf
resource "digitalocean_domain" "main" {
  name = "yourdomain.com"
}

resource "digitalocean_record" "mail_a" {
  domain = digitalocean_domain.main.id
  type   = "A"
  name   = "mail"
  value  = digitalocean_reserved_ip.kiss_mail.ip_address
}

resource "digitalocean_record" "mx" {
  domain   = digitalocean_domain.main.id
  type     = "MX"
  name     = "@"
  value    = "mail.yourdomain.com."
  priority = 10
}
```

## SSL/TLS (Optional)

SSH into the droplet and run:

```bash
certbot --nginx -d mail.yourdomain.com
```

## One-Click Deploy (Alternative)

If you prefer the DO dashboard:

1. Go to [Digital Ocean Marketplace](https://marketplace.digitalocean.com)
2. Search for "Docker" and create a Droplet
3. SSH in and run:

```bash
curl -fsSL https://raw.githubusercontent.com/quinnjr/kiss-mail/main/deploy/scripts/install.sh | bash
```

## Cleanup

```bash
terraform destroy -var="do_token=$DIGITALOCEAN_TOKEN"
```

## Troubleshooting

### View setup logs
```bash
cat /var/log/kiss-mail-setup.log
```

### Check container status
```bash
docker ps
docker logs kiss-mail
```

### View credentials
```bash
cat /opt/kiss-mail/credentials.txt
```

### Restart KISS Mail
```bash
docker restart kiss-mail
```
