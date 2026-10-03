# KISS Mail - Google Cloud Platform Deployment

Deploy KISS Mail on Google Cloud Platform with Terraform.

## Quick Start

```bash
# 1. Authenticate with GCP
gcloud auth application-default login

# 2. Set your project
gcloud config set project YOUR_PROJECT_ID

# 3. Enable required APIs
gcloud services enable compute.googleapis.com

# 4. Deploy
cd deploy/gcp
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars

terraform init
terraform apply
```

## Requirements

- [Terraform](https://terraform.io) >= 1.0
- [Google Cloud SDK](https://cloud.google.com/sdk)
- GCP project with billing enabled

## What Gets Created

| Resource | Description | Cost |
|----------|-------------|------|
| Compute Instance | e2-micro (Ubuntu 24.04 LTS + Docker + Nginx, set up by the shared bootstrap script) | Free tier eligible |
| Static IP | External IP address | ~$3/month |
| VPC Network | Custom network | Free |
| Firewall Rules | Mail ports | Free |

**Estimated Cost: ~$3-10/month** (e2-micro is free tier eligible)

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `project_id` | (required) | GCP project ID |
| `region` | us-central1 | GCP region |
| `zone` | us-central1-a | GCP zone |
| `machine_type` | e2-micro | Instance type |
| `domain` | mail.example.com | Mail domain |
| `disk_size` | 20 | Boot disk GB |

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

## Access

```bash
# SSH via gcloud
gcloud compute ssh kiss-mail --zone us-central1-a

# View container logs
gcloud compute ssh kiss-mail --zone us-central1-a -- sudo docker logs kiss-mail

# Show generated credentials (admin password, API key)
gcloud compute ssh kiss-mail --zone us-central1-a -- sudo cat /opt/kiss-mail/credentials.txt

# Setup log (first boot)
gcloud compute ssh kiss-mail --zone us-central1-a -- sudo cat /var/log/kiss-mail-setup.log
```

## Cleanup

```bash
terraform destroy
```
