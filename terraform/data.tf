# terraform/data.tf
# Shared data sources used across the new GRC-layer files (kms.tf,
# evidence-vault.tf, cloudtrail.tf, oidc-trust.tf). Declared once here
# because Terraform errors on a duplicate data-source address within
# the same root module.

data "aws_caller_identity" "current" {}
