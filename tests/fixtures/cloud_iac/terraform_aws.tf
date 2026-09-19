# Insecure Terraform AWS Infrastructure Manifest for Cloud Posture Auditing
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# 1. Open Public S3 Bucket (CIS-2.1.5)
resource "aws_s3_bucket" "insecure_data_lake" {
  bucket = "revenant-audit-public-bucket"
  acl    = "public-read"

  tags = {
    Environment = "Dev"
    ManagedBy   = "Terraform"
  }
}

# 2. Overly Permissive Security Group Open to 0.0.0.0/0 on SSH port 22 (CIS-4.1)
resource "aws_security_group" "open_ssh" {
  name        = "open-ssh-ingress"
  description = "Allows unrestricted inbound SSH from the entire Internet"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 3. Wildcard Administrator IAM Policy (CIS-1.16)
resource "aws_iam_policy" "wildcard_admin" {
  name        = "revenant-wildcard-admin-policy"
  description = "Dangerous policy granting full wildcard administration"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}
