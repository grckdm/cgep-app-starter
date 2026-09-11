# terraform/gap02_dynamodb_override.tf
#
# GAP-02, DynamoDB submissions table: AWS-owned key, not your CMK.
# SOC 2: CC6.1
#
# server_side_encryption isn't a standalone resource type, so it can't be
# added the way GAP-01's S3 fix was. Terraform override files (name must
# end in _override.tf) merge into the resource of the same type+name in
# main.tf at plan time, so this adds the block without editing main.tf.
resource "aws_dynamodb_table" "intake" {
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.grc.arn
  }
}
