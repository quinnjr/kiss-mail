# ============================================================================
# KISS Mail - AWS Terraform Configuration
# ============================================================================
# Deploy KISS Mail on AWS EC2 with a single command:
#   terraform init && terraform apply
# ============================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# ----------------------------------------------------------------------------
# Variables
# ----------------------------------------------------------------------------
variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
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

variable "ssh_key_name" {
  description = "SSH key pair name for EC2 access"
  type        = string
  default     = ""
}

variable "allowed_ssh_cidr" {
  description = "CIDR block allowed for SSH access"
  type        = string
  default     = "0.0.0.0/0"
}

variable "volume_size" {
  description = "EBS volume size in GB"
  type        = number
  default     = 20
}

variable "environment" {
  description = "Environment tag"
  type        = string
  default     = "production"
}

# ----------------------------------------------------------------------------
# Provider
# ----------------------------------------------------------------------------
provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "kiss-mail"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# ----------------------------------------------------------------------------
# Data Sources
# ----------------------------------------------------------------------------
data "aws_availability_zones" "available" {
  state = "available"
}

# Latest Ubuntu 24.04 LTS (Noble) AMI published by Canonical
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ----------------------------------------------------------------------------
# VPC & Networking
# ----------------------------------------------------------------------------
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "kiss-mail-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "kiss-mail-igw"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "kiss-mail-public"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "kiss-mail-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ----------------------------------------------------------------------------
# Security Group
# ----------------------------------------------------------------------------
resource "aws_security_group" "kiss_mail" {
  name        = "kiss-mail-sg"
  description = "Security group for KISS Mail server"
  vpc_id      = aws_vpc.main.id

  # SSH (optional)
  dynamic "ingress" {
    for_each = var.ssh_key_name != "" ? [1] : []
    content {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = [var.allowed_ssh_cidr]
      description = "SSH access"
    }
  }

  # SMTP
  ingress {
    from_port   = 25
    to_port     = 25
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SMTP"
  }

  # SMTP Submission
  ingress {
    from_port   = 587
    to_port     = 587
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SMTP Submission"
  }

  # IMAP
  ingress {
    from_port   = 143
    to_port     = 143
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "IMAP"
  }

  # POP3
  ingress {
    from_port   = 110
    to_port     = 110
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "POP3"
  }

  # SMTPS (submission, implicit TLS)
  ingress {
    from_port   = 465
    to_port     = 465
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SMTPS"
  }

  # IMAPS (IMAP over TLS)
  ingress {
    from_port   = 993
    to_port     = 993
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "IMAPS"
  }

  # POP3S (POP3 over TLS)
  ingress {
    from_port   = 995
    to_port     = 995
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "POP3S"
  }

  # Web Admin (HTTP)
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP (Web Admin)"
  }

  # Web Admin (HTTPS)
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS (Web Admin)"
  }

  # All outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = {
    Name = "kiss-mail-sg"
  }
}

# ----------------------------------------------------------------------------
# IAM Role for EC2
# ----------------------------------------------------------------------------
resource "aws_iam_role" "kiss_mail" {
  name = "kiss-mail-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.kiss_mail.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "kiss_mail" {
  name = "kiss-mail-profile"
  role = aws_iam_role.kiss_mail.name
}

# ----------------------------------------------------------------------------
# EC2 Instance
# ----------------------------------------------------------------------------
resource "aws_instance" "kiss_mail" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.kiss_mail.id]
  iam_instance_profile   = aws_iam_instance_profile.kiss_mail.name
  key_name               = var.ssh_key_name != "" ? var.ssh_key_name : null

  # IMDSv2 only, and a hop limit of 1 so containers cannot reach the
  # instance metadata (and the instance role credentials).
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size           = var.volume_size
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  # Shared bootstrap script. The admin password is generated on the VM and
  # kept only in the root-only /opt/kiss-mail/credentials.txt.
  user_data = base64encode(templatefile("${path.module}/../common/bootstrap.sh.tftpl", {
    provider_name = "aws"
    domain        = var.domain
    # IMDSv2 (session token required)
    public_ip_cmd = "t=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60'); curl -s -H \"X-aws-ec2-metadata-token: $t\" http://169.254.169.254/latest/meta-data/public-ipv4"
  }))

  tags = {
    Name = "kiss-mail"
  }

  lifecycle {
    ignore_changes = [ami, user_data]
  }
}

# ----------------------------------------------------------------------------
# Elastic IP
# ----------------------------------------------------------------------------
resource "aws_eip" "kiss_mail" {
  instance = aws_instance.kiss_mail.id
  domain   = "vpc"

  tags = {
    Name = "kiss-mail-eip"
  }
}

# ----------------------------------------------------------------------------
# Outputs
# ----------------------------------------------------------------------------
output "public_ip" {
  description = "Public IP address"
  value       = aws_eip.kiss_mail.public_ip
}

output "web_admin_url" {
  description = "Web admin URL"
  value       = "http://${aws_eip.kiss_mail.public_ip}/admin"
}

output "smtp_server" {
  description = "SMTP server address"
  value       = "${aws_eip.kiss_mail.public_ip}:25"
}

output "imap_server" {
  description = "IMAP server address"
  value       = "${aws_eip.kiss_mail.public_ip}:143"
}

output "pop3_server" {
  description = "POP3 server address"
  value       = "${aws_eip.kiss_mail.public_ip}:110"
}

output "dns_records" {
  description = "DNS records to configure"
  value       = <<-EOT
    
    Configure these DNS records for ${var.domain}:
    
    A     ${var.domain}              ${aws_eip.kiss_mail.public_ip}
    MX    ${var.domain}    10        ${var.domain}
    TXT   ${var.domain}              "v=spf1 ip4:${aws_eip.kiss_mail.public_ip} -all"
    
  EOT
}

output "ssh_command" {
  description = "SSH command (if key was provided)"
  value       = var.ssh_key_name != "" ? "ssh -i ~/.ssh/${var.ssh_key_name}.pem ubuntu@${aws_eip.kiss_mail.public_ip}" : "SSH not configured (no key provided)"
}

output "credentials_command" {
  description = "Show the generated credentials (admin password, API key)"
  value       = "aws ssm start-session --target ${aws_instance.kiss_mail.id} --document-name AWS-StartInteractiveCommand --parameters command='sudo cat /opt/kiss-mail/credentials.txt'"
}

output "ssm_command" {
  description = "AWS SSM Session Manager command"
  value       = "aws ssm start-session --target ${aws_instance.kiss_mail.id}"
}
