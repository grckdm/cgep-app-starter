# terraform/evidence-vault.tf
#
# Object Lock evidence bucket, every signed pipeline run lands here.
# Adapted from the Lab 2.5 evidence-vault primitive: GOVERNANCE mode
# (decision: friendlier for a 30-day project than COMPLIANCE, a
# privileged caller can still bypass the lock if you need to clean up;
# defend this trade-off in WRITEUP.md), encrypted with the CMK from
# kms.tf instead of SSE-S3.

variable "lock_mode" {
  type        = string
  description = "Object Lock mode for the evidence vault."
  default     = "GOVERNANCE"
}

variable "retention_days" {
  type        = number
  description = "Default retention period for evidence objects."
  default     = 365
}

resource "aws_s3_bucket" "evidence_vault" {
  bucket              = "${local.name_prefix}-evidence-vault-${local.suffix}"
  object_lock_enabled = true # MUST be set at bucket creation
}

resource "aws_s3_bucket_versioning" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id
  versioning_configuration { status = "Enabled" } # Object Lock requires versioning
}

resource "aws_s3_bucket_object_lock_configuration" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id

  rule {
    default_retention {
      mode = var.lock_mode
      days = var.retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.evidence_vault]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.grc.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "evidence_vault" {
  bucket                  = aws_s3_bucket.evidence_vault.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyBucketDeletion"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:DeleteBucket"
        Resource  = aws_s3_bucket.evidence_vault.arn
        Condition = {
          StringNotEquals = {
            "aws:PrincipalArn" = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.evidence_vault.arn, "${aws_s3_bucket.evidence_vault.arn}/*"]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

output "evidence_vault_name" {
  value       = aws_s3_bucket.evidence_vault.id
  description = "EVIDENCE_VAULT repo variable for the GitHub Actions workflow."
}
