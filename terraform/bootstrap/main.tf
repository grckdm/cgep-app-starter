# terraform/bootstrap/main.tf
#
# Creates the S3 bucket + DynamoDB lock table the main stack (../) uses
# as its remote backend. Deliberately a SEPARATE Terraform config with
# its own local state: the main stack can't create the backend it
# depends on to store its own state (chicken-and-egg), so this runs
# once, manually, before the main stack's backend block is configured.
#
# This module's own state stays local. These resources change rarely
# (essentially never, after initial creation), and bootstrapping the
# bootstrap's state into a remote backend has the same chicken-and-egg
# problem one level up, with no benefit at this scale.
#
# CI does NOT run this module. grc-gate.yml only ever applies ../ (the
# main stack) against the backend this module already created.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "acme-health-intake"
      ManagedBy = "terraform"
      Purpose   = "tfstate-backend"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "tfstate" {
  bucket = "cgep-capstone-tfstate-${random_id.suffix.hex}"
}

resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket                  = aws_s3_bucket.tfstate.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.tfstate.arn, "${aws_s3_bucket.tfstate.arn}/*"]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

resource "aws_dynamodb_table" "tflock" {
  name         = "cgep-capstone-tflock"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }
}

output "tfstate_bucket" {
  value       = aws_s3_bucket.tfstate.id
  description = "Bucket name for the main stack's backend \"s3\" block."
}

output "tflock_table" {
  value       = aws_dynamodb_table.tflock.name
  description = "DynamoDB table name for the main stack's backend \"s3\" block."
}
