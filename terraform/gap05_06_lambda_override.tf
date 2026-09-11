# terraform/gap05_06_lambda_override.tf
#
# GAP-05 (SOC 2 CC6.6) — vpc_config places the Lambda in the private
# subnets behind aws_security_group.lambda (both defined in hardening.tf,
# along with the Gateway VPC endpoints this VPC placement depends on).
#
# GAP-06 (SOC 2 CC7.2) — dead_letter_config routes failed async
# invocations to aws_sqs_queue.intake_dlq (hardening.tf) instead of
# silently dropping them, tracing_config enables X-Ray.
#
# reserved_concurrent_executions is intentionally NOT set here: this
# account's total Lambda concurrency limit is 10 (a new/sandbox-account
# default), and AWS requires at least 10 unreserved account-wide — so
# reserving any amount for this function isn't possible without first
# requesting a Service Quotas increase. Documented as a known constraint
# in WRITEUP.md rather than left as a silent gap.
#
# Both gaps target aws_lambda_function.intake, so they're combined in one
# override file rather than risking merge-order ambiguity across two.
resource "aws_lambda_function" "intake" {
  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.intake_dlq.arn
  }

  tracing_config {
    mode = "Active"
  }
}
