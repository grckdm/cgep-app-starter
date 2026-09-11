# policies/cc6_1_dynamodb_cmk.rego
# METADATA
# title: CC6.1 - Logical access controls (DynamoDB table must use the CMK)
# description: >
#   GAP-02: aws_dynamodb_table.intake must set server_side_encryption
#   with a kms_key_arn pointing at our CMK, not the AWS-owned default key.
# custom:
#   framework: soc2
#   gap: GAP-02
#   controls: ["CC6.1"]
#   severity: high
#   remediation: >
#     Override aws_dynamodb_table.intake to add a server_side_encryption
#     block with enabled = true and kms_key_arn = aws_kms_key.grc.arn.
package compliance.soc2.cc6_1_dynamodb_cmk

import rego.v1

# Reads references via input.configuration rather than resolved values via
# input.planned_values: on a from-scratch plan (no prior applied state),
# kms_key_arn's actual ARN string is "known after apply" and omitted from
# planned_values entirely, which would make a value-based check false-fail.
# enabled is a plain literal either way, so constant_value is fine for it.
deny contains msg if {
	some r in input.configuration.root_module.resources
	r.type == "aws_dynamodb_table"
	not has_cmk_encryption(r)
	msg := sprintf(
		"[CC6.1] %s: server_side_encryption must be enabled with a customer-managed kms_key_arn (the AWS-owned default key does not satisfy this control).",
		[r.address],
	)
}

has_cmk_encryption(r) if {
	some sse in r.expressions.server_side_encryption
	sse.enabled.constant_value == true
	some ref in sse.kms_key_arn.references
	startswith(ref, "aws_kms_key.")
}
