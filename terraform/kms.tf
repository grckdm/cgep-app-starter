# terraform/kms.tf
#
# CMK(s) you own, for bringing the starter's data stores and the evidence
# vault under customer-managed encryption. Closes the "not under customer
# custody" half of GAP-01 / GAP-02 — the *wiring* of this key onto the
# starter's resources happens in hardening.tf, not here.

resource "aws_kms_key" "grc" {
  description             = "Acme Health capstone CMK — workload + evidence encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Purpose = "grc-capstone"
  }
}

resource "aws_kms_alias" "grc" {
  name          = "alias/${local.name_prefix}-grc-${local.suffix}"
  target_key_id = aws_kms_key.grc.key_id
}

output "kms_key_arn" {
  value       = aws_kms_key.grc.arn
  description = "CMK ARN — reference this from hardening.tf and the evidence vault."
}
