# policies/cc6_3_iam_least_privilege.rego
# METADATA
# title: CC6.3 - Authorization (no wildcard actions in the Lambda's inline policy)
# description: >
#   GAP-07: aws_iam_role_policy.lambda_inline grants dynamodb:* and s3:*
#   on the workload's data stores instead of the specific actions
#   handler.py actually calls.
# custom:
#   framework: soc2
#   gap: GAP-07
#   controls: ["CC6.3"]
#   severity: critical
#   remediation: >
#     Override aws_iam_role_policy.lambda_inline to list explicit actions
#     (e.g. dynamodb:PutItem, s3:PutObject) instead of a service wildcard.
package compliance.soc2.cc6_3_iam_least_privilege

import rego.v1

# KNOWN LIMITATION: same as cc6_7_s3_tls_only.rego, this policy's IAM
# statement Actions are static strings, but the policy also embeds
# aws_dynamodb_table.intake.arn / aws_s3_bucket.uploads.arn, so the whole
# jsonencode() string is "known after apply" (absent from planned_values)
# on a from-scratch plan where those resources don't exist yet. Only
# evaluates correctly against a plan for an already-applied stack.
# Flagged in WRITEUP.md.

deny contains msg if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_iam_role_policy"
	r.name == "lambda_inline"
	policy := json.unmarshal(r.values.policy)
	some stmt in policy.Statement
	stmt.Effect == "Allow"
	action := wildcard_action(stmt.Action)
	msg := sprintf(
		"[CC6.3] %s: statement grants wildcard action %q, use the specific actions the handler calls instead of a service-level wildcard.",
		[r.address, action],
	)
}

wildcard_action(action) := action if {
	is_string(action)
	is_wildcard(action)
}

wildcard_action(action) := a if {
	is_array(action)
	some a in action
	is_wildcard(a)
}

is_wildcard(a) if endswith(a, ":*")

is_wildcard(a) if a == "*"
