# policies/tests/cc6_1_s3_kms_test.rego
package compliance.soc2.cc6_1_s3_kms_test

import rego.v1
import data.compliance.soc2.cc6_1_s3_kms

uploads_bucket_config := {
	"type": "aws_s3_bucket",
	"name": "uploads",
	"address": "aws_s3_bucket.uploads",
}

sse_config(algorithm) := {
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"name": "uploads",
	"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
	"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads", "aws_s3_bucket.uploads.id"]}},
	"planned_values": {
		"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
		"values": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": algorithm}]}]},
	},
}

input_with(config_resources, planned_resources) := {
	"configuration": {"root_module": {"resources": config_resources}},
	"planned_values": {"root_module": {"resources": planned_resources}},
}

compliant_input := input_with(
	[uploads_bucket_config, sse_config("aws:kms")],
	[sse_config("aws:kms").planned_values],
)

noncompliant_wrong_algorithm_input := input_with(
	[uploads_bucket_config, sse_config("AES256")],
	[sse_config("AES256").planned_values],
)

noncompliant_missing_input := input_with(
	[uploads_bucket_config],
	[],
)

test_compliant_passes if {
	count(cc6_1_s3_kms.deny) == 0 with input as compliant_input
}

test_noncompliant_wrong_algorithm_fails if {
	some msg in cc6_1_s3_kms.deny with input as noncompliant_wrong_algorithm_input
	contains(msg, "CC6.1")
}

test_noncompliant_missing_fails if {
	some msg in cc6_1_s3_kms.deny with input as noncompliant_missing_input
	contains(msg, "CC6.1")
}
