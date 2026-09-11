# terraform/gap07_iam_override.tf
#
# GAP-07, SOC 2 CC6.3. Replaces main.tf's dynamodb:* / s3:* wildcard
# actions with the specific actions handler.py actually calls
# (dynamodb.Table(...).put_item, s3.put_object), same resource scope
# main.tf already used.
resource "aws_iam_role_policy" "lambda_inline" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "dynamodb:PutItem"
        Resource = aws_dynamodb_table.intake.arn
      },
      {
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.uploads.arn}/*"
      }
    ]
  })
}
