# terraform/backend_override.tf
#
# Remote state backend, added via override file rather than editing
# main.tf directly (same convention as the gap0*_override.tf files,
# main.tf stays exactly as the starter shipped it).
#
# Bucket + lock table created once by terraform/bootstrap/ (a separate
# config with its own local state, see its main.tf for why). This is
# what lets GitHub Actions' ephemeral runners share state with local
# applies instead of each starting from an empty state.
terraform {
  backend "s3" {
    bucket         = "cgep-capstone-tfstate-4821931c"
    key            = "cgep-capstone/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "cgep-capstone-tflock"
    encrypt        = true
  }
}
