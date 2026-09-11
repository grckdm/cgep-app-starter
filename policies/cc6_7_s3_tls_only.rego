# policies/cc6_7_s3_tls_only.rego
# METADATA
# title: CC6.7 - Transmission security (deny non-TLS access to the uploads bucket)
# description: >
#   GAP-03: aws_s3_bucket.uploads has no bucket policy denying requests
#   made over plain HTTP (no aws:SecureTransport deny statement).
# custom:
#   framework: soc2
#   gap: GAP-03
#   controls: ["CC6.7"]
#   severity: medium
#   remediation: >
#     Add an aws_s3_bucket_policy on aws_s3_bucket.uploads with a Deny
#     statement keyed on Bool { "aws:SecureTransport": "false" }.
package compliance.soc2.cc6_7_s3_tls_only

import rego.v1

# KNOWN LIMITATION: this reads planned_values.values.policy, the resolved
# JSON string, because the Deny/Condition content can only be inspected
# after jsonencode() has been evaluated — input.configuration only exposes
# a flat list of referenced addresses for a jsonencode() expression, not
# its structure. Since the policy embeds aws_s3_bucket.uploads.arn, the
# WHOLE jsonencode() string is "known after apply" (and absent from
# planned_values) on a from-scratch plan where the bucket doesn't exist
# yet — this policy can only evaluate against a plan for an
# already-applied stack. That matches this project's actual operating
# model (grc-gate.yml gates *changes* to a running stack; the initial
# bootstrap apply is run manually, not through the gate), but is a real
# gap if graded via a from-scratch plan. Flagged in WRITEUP.md.
deny contains msg if {
	uploads_bucket_exists
	not has_deny_insecure_transport
	msg := "[CC6.7] aws_s3_bucket.uploads must have a bucket policy denying requests where aws:SecureTransport is false."
}

uploads_bucket_exists if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	r.name == "uploads"
}

has_deny_insecure_transport if {
	addr := bucket_policy_address_for_uploads
	some pv in input.planned_values.root_module.resources
	pv.address == addr
	policy := json.unmarshal(pv.values.policy)
	some stmt in policy.Statement
	stmt.Effect == "Deny"
	stmt.Condition.Bool["aws:SecureTransport"] == "false"
}

bucket_policy_address_for_uploads := addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_policy"
	some ref in r.expressions.bucket.references
	references_uploads(ref)
	addr := sprintf("aws_s3_bucket_policy.%s", [r.name])
}

references_uploads(ref) if ref == "aws_s3_bucket.uploads"

references_uploads(ref) if ref == "aws_s3_bucket.uploads.id"

references_uploads(ref) if ref == "aws_s3_bucket.uploads.bucket"
