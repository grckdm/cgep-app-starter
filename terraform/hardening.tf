# terraform/hardening.tf
#
# THIS FILE IS THE CAPSTONE. Everything above (kms.tf, evidence-vault.tf,
# cloudtrail.tf, oidc-trust.tf) is plumbing you could get from any of the
# labs. This is the part where you close GAP-01..08 from GAPS.md against
# your declared framework (SOC 2 TSC) and it's on you to write it —
# that's the actual grading surface for Layer 1 + half of Layer 2.
#
# Two mechanisms are available; the brief lets you mix them:
#
#   1. New resource, wired to the starter's resource by reference
#      (e.g. aws_s3_bucket_server_side_encryption_configuration whose
#      `bucket` argument points at aws_s3_bucket.uploads.id). This is
#      the only option when the fix is a resource type that doesn't
#      exist yet on the starter's object (GAP-01, GAP-03, GAP-04, GAP-06's
#      DLQ/reserved-concurrency).
#
#   2. A Terraform *override file* (a file whose name ends in
#      `_override.tf`) containing a resource block with the SAME
#      type + name as one in ../main.tf. Terraform merges it into the
#      original resource's config at plan time — this is how you add a
#      `vpc_config` block to `aws_lambda_function.intake` or tighten
#      `aws_iam_role_policy.lambda_inline` without hand-editing the
#      starter's main.tf (which the brief wants left runnable/intact).
#      See: https://developer.hashicorp.com/terraform/language/files/override
#
# For each gap below: decide new-resource vs override, then write it.
# Delete the TODO comment once the block is real. Cite the SOC 2 control
# in a comment above each fix — your OSCAL component and Rego policies
# need to point at the same control IDs, so decide the mapping here first.

######################################################################
# GAP-01 — S3 uploads bucket: SSE-S3 default, not SSE-KMS with your CMK.
# SOC 2: CC6.1
######################################################################
resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.grc.arn
    }
    bucket_key_enabled = true
  }
}

######################################################################
# GAP-02 — DynamoDB submissions table: AWS-owned key, not your CMK.
# SOC 2: CC6.1
#
# Implemented in gap02_dynamodb_override.tf (Terraform override files only
# merge if the file name ends in _override.tf, so this couldn't live here).
#
# Moving GAP-01/GAP-02 from AWS-owned keys to the CMK also means the
# Lambda role now needs explicit KMS permissions: unlike AWS-owned key
# encryption, a customer-managed key requires the calling principal to
# have kms:Decrypt / kms:GenerateDataKey on that key for both DynamoDB
# PutItem and S3 PutObject to succeed (found by testing after apply —
# the app returned 500s on AccessDeniedException: kms:Decrypt until
# this was added).
######################################################################

resource "aws_iam_role_policy" "lambda_kms_access" {
  name = "intake-kms-access"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.grc.arn
      }
    ]
  })
}

######################################################################
# GAP-03 — S3 uploads bucket: no deny-non-TLS bucket policy.
# SOC 2: CC6.7
######################################################################
resource "aws_s3_bucket_policy" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.uploads.arn, "${aws_s3_bucket.uploads.arn}/*"]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

######################################################################
# GAP-04 — S3 uploads bucket: no versioning.
# SOC 2: A1.2
######################################################################
resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  versioning_configuration {
    status = "Enabled"
  }
}

######################################################################
# GAP-05 — Lambda not deployed inside the starter's VPC.
# SOC 2: CC6.6
#
# The starter's private subnets have no route table at all — they fall
# back to the VPC's implicit default route table, which Gateway VPC
# endpoints can't be safely associated with here. So this creates an
# explicit private route table first, associates the private subnets
# to it, then associates the S3/DynamoDB Gateway endpoints to that same
# route table. Gateway endpoints are free and need no NAT gateway.
#
# Running in a VPC also requires the Lambda execution role to manage
# ENIs (CreateNetworkInterface / DescribeNetworkInterfaces /
# DeleteNetworkInterface) — the starter's role only has
# AWSLambdaBasicExecutionRole attached, which doesn't cover this.
######################################################################

resource "aws_iam_role_policy_attachment" "lambda_vpc_access" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "acme-health-intake-private-rt" }
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
}

resource "aws_security_group" "lambda" {
  name_prefix = "acme-health-intake-lambda-"
  vpc_id      = aws_vpc.main.id
  description = "Intake Lambda ENIs - HTTPS egress only, no inbound."

  egress {
    description = "HTTPS to AWS APIs (S3/DynamoDB Gateway endpoints route over this)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }
}

# GAP-05 continued: the Lambda's vpc_config (placing it in the private
# subnets behind the security group above) is implemented in
# gap05_06_lambda_override.tf — same naming-convention constraint as
# GAP-02. GAP-06's Lambda changes land in the same override file since
# both target aws_lambda_function.intake.

######################################################################
# GAP-06 — Lambda: no reserved concurrency, no DLQ, no X-Ray.
# SOC 2: CC7.2
#
# dead_letter_config / tracing_config additions to aws_lambda_function.
# intake live in gap05_06_lambda_override.tf alongside GAP-05's vpc_config,
# since both target the same resource. reserved_concurrent_executions is
# NOT set — this account's total Lambda concurrency limit is 10, below
# the threshold where any reservation is possible (AWS requires >=10
# unreserved account-wide). Documented as a known constraint in
# WRITEUP.md, not silently dropped.
######################################################################

resource "aws_sqs_queue" "intake_dlq" {
  name                      = "${local.name_prefix}-intake-dlq"
  message_retention_seconds = 1209600 # 14 days, SQS max
  kms_master_key_id         = aws_kms_key.grc.arn
}

resource "aws_iam_role_policy" "lambda_observability" {
  name = "intake-observability"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.intake_dlq.arn
      },
      {
        Effect   = "Allow"
        Action   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
        Resource = "*" # X-Ray write actions do not support resource-level scoping
      }
    ]
  })
}

######################################################################
# GAP-07 — Lambda IAM role: dynamodb:* and s3:* (over-broad).
# SOC 2: CC6.3
#
# Implemented in gap07_iam_override.tf (overrides aws_iam_role_policy.
# lambda_inline — same naming-convention constraint as GAP-02/05/06).
# handler.py only ever calls dynamodb:PutItem and s3:PutObject.
######################################################################

######################################################################
# GAP-08 — API Gateway: no access logging, no throttling, no WAF.
# SOC 2: CC7.2
#
# access_log_settings / default_route_settings on aws_apigatewayv2_stage.
# default live in gap08_apigw_override.tf (same naming-convention
# constraint as GAP-02/05/06/07).
#
# WAF is scoped out here (optional per GAPS.md) — record the reasoning
# for that call in WRITEUP.md, don't leave it undefended.
######################################################################

resource "aws_cloudwatch_log_group" "apigw_access" {
  name              = "/aws/apigateway/${local.name_prefix}-${local.suffix}"
  retention_in_days = 90
}

# HTTP API access logging requires the log group's resource policy to
# explicitly allow the API Gateway service principal to write to it —
# an IAM identity policy on the Lambda/account isn't sufficient here.
resource "aws_cloudwatch_log_resource_policy" "apigw_access" {
  policy_name = "${local.name_prefix}-apigw-access-logs"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "apigateway.amazonaws.com" }
        Action    = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource  = "${aws_cloudwatch_log_group.apigw_access.arn}:*"
      }
    ]
  })
}
