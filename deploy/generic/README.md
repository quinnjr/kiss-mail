# KISS Mail - Universal Cloud Deployment

Deploy KISS Mail on **any cloud provider** using cloud-init.

## Supported Providers

This cloud-init configuration works on any provider that supports cloud-init:

| Provider | Instructions |
|----------|--------------|
| **AWS** | Use as EC2 User Data |
| **GCP** | Use as Startup Script |
| **Azure** | Use as Custom Data |
| **Digital Ocean** | Use as User Data |
| **Linode** | Use as StackScript or cloud-init |
| **Vultr** | Use as Startup Script |
| **Hetzner** | Use as User Data |
| **OVH** | Use as cloud-init |
| **Scaleway** | Use as cloud-init |
| **Oracle Cloud** | Use as cloud-init |
| **Any VPS** | Copy and run setup script |

## Quick Start

### Option 1: Cloud-Init (Recommended)

1. **Copy `cloud-init.yml`** and customize the config section at the top:

```yaml
write_files:
  - path: /etc/kiss-mail.conf
    content: |
      DOMAIN=mail.yourdomain.com
      KISS_MAIL_API_KEY=
```

2. **Create a VM** with Ubuntu 24.04 LTS (or Debian 12 / RHEL family) and paste the cloud-init as user-data

3. **Wait** for setup to complete (2-5 minutes)

4. **Access** web admin at `http://YOUR_IP/admin`

### Option 2: Manual Script

If your provider doesn't support cloud-init, SSH into any Linux server and run:

```bash
curl -fsSL https://raw.githubusercontent.com/quinnjr/kiss-mail/main/deploy/scripts/install.sh | sudo bash
```

## Configuration

`/etc/kiss-mail.conf` is parsed as `KEY=VALUE` lines (it is never sourced) by
the setup script (`/opt/kiss-mail-setup.sh`) only - these are not environment
variables of the `kiss-mail` binary. Both files are deleted when setup
finishes:

| Variable | Description | Default |
|----------|-------------|---------|
| `DOMAIN` | Your mail domain (passed to the container as `KISS_MAIL_DOMAIN`) | mail.example.com |
| `KISS_MAIL_API_KEY` | REST API key (leave empty: the provider keeps a copy of user-data) | (auto-generated) |

The admin password is always generated on the VM and handed to the server on
stdin. It and the API key are written to the root-only
`/opt/kiss-mail/credentials.txt` (before the container starts, then updated).
The web admin is reached through Nginx (the SSO `/callback` too); the REST API
is published on `127.0.0.1` only and Nginx denies `/api` to remote clients
(remote CLI: `ssh -L 8025:127.0.0.1:8025 ...`). The firewall (ufw or firewalld) opens 22, 25, 587, 143, 110, 80
and 443.

## Post-Deployment

### View Credentials

```bash
sudo cat /opt/kiss-mail/credentials.txt
```

### Enable HTTPS

```bash
sudo certbot --nginx -d mail.yourdomain.com
# The container starts with KISS_MAIL_WEB_SECURE_COOKIE=false (plain HTTP).
# Once HTTPS works, recreate it with a Secure session cookie:
curl -fsSL https://raw.githubusercontent.com/quinnjr/kiss-mail/main/deploy/scripts/upgrade.sh \
  | sudo bash -s -- --no-pull --env KISS_MAIL_WEB_SECURE_COOKIE=true
```

### Configure DNS

Add these records:

```
A     mail.yourdomain.com         YOUR_SERVER_IP
MX    yourdomain.com       10     mail.yourdomain.com
TXT   yourdomain.com              "v=spf1 ip4:YOUR_SERVER_IP -all"
```

### View Logs

```bash
# Setup log
cat /var/log/kiss-mail-setup.log

# Container log
docker logs kiss-mail
```

## Minimum Requirements

- **OS**: Ubuntu 20.04+, Debian 11+, CentOS 8+, or any Linux with Docker
- **RAM**: 512MB minimum, 1GB recommended
- **Disk**: 10GB minimum
- **Ports**: 22, 25, 80, 110, 143, 443, 587

## Troubleshooting

### Container not running

```bash
docker ps -a
docker logs kiss-mail
docker start kiss-mail
```

### Nginx not working

```bash
nginx -t
systemctl status nginx
cat /var/log/nginx/error.log
```

### Can't receive email

1. Check MX records: `dig MX yourdomain.com`
2. Check port 25 is open
3. Check if ISP blocks port 25 (common on residential connections)
