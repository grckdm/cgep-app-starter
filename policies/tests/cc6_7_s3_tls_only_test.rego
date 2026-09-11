# policies/tests/cc6_7_s3_tls_only_test.rego
package compliance.soc2.cc6_7_s3_tls_only_test

import rego.v1
import data.compliance.soc2.cc6_7_s3_tls_only

uploads_bucket_config := {"type": "aws_s3_bucket", "name": "uploads"}

bucket_policy_config := {
	"type": "aws_s3_bucket_policy",
	"name": "uploads",
	"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads", "aws_s3_bucket.uploads.id"]}},
}

bucket_policy_planned(policy_json) := {
	"address": "aws_s3_bucket_policy.uploads",
	"values": {"policy": policy_json},
}

input_with(config_resources, planned_resources) := {
	"configuration": {"root_module": {"resources": config_resources}},
	"planned_values": {"root_module": {"resources": planned_resources}},
}

deny_statement_json := `{"Version":"2012-10-17","Statement":[{"Sid":"DenyInsecureTransport","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::x","arn:aws:s3:::x/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`

allow_only_json := `{"Version":"2012-10-17","Statement":[{"Sid":"AllowSomething","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::x/*"}]}`

compliant_input := input_with(
	[uploads_bucket_config, bucket_policy_config],
	[bucket_policy_planned(deny_statement_json)],
)

noncompliant_wrong_statement_input := input_with(
	[uploads_bucket_config, bucket_policy_config],
	[bucket_policy_planned(allow_only_json)],
)

noncompliant_missing_input := input_with(
	[uploads_bucket_config],
	[],
)

test_compliant_passes if {
	count(cc6_7_s3_tls_only.deny) == 0 with input as compliant_input
}

test_noncompliant_wrong_statement_fails if {
	some msg in cc6_7_s3_tls_only.deny with input as noncompliant_wrong_statement_input
	contains(msg, "CC6.7")
}

test_noncompliant_missing_fails if {
	some msg in cc6_7_s3_tls_only.deny with input as noncompliant_missing_input
	contains(msg, "CC6.7")
}
