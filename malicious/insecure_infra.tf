# ============================================================
# TEST FILE: insecure_infra.tf
# Scanners targeted: IaC Scanner (Terraform rules)
# ============================================================

provider "aws" {
  region = "us-east-1"
}

# 1. Public S3 bucket ACL (CRITICAL)
resource "aws_s3_bucket" "public_data" {
  bucket = "my-public-bucket"
  acl    = "public-read-write"
}

# 2. Security group with open ingress from 0.0.0.0/0 (HIGH)
resource "aws_security_group" "open_sg" {
  name = "open-to-world"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
