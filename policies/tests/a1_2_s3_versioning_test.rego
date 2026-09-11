# policies/tests/a1_2_s3_versioning_test.rego
package compliance.soc2.a1_2_s3_versioning_test

import rego.v1
import data.compliance.soc2.a1_2_s3_versioning

uploads_bucket_config := {"type": "aws_s3_bucket", "name": "uploads"}

versioning_config := {
	"type": "aws_s3_bucket_versioning",
	"name": "uploads",
	"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads", "aws_s3_bucket.uploads.id"]}},
}

versioning_planned(status) := {
	"address": "aws_s3_bucket_versioning.uploads",
	"values": {"versioning_configuration": [{"status": status}]},
}

input_with(config_resources, planned_resources) := {
	"configuration": {"root_module": {"resources": config_resources}},
	"planned_values": {"root_module": {"resources": planned_resources}},
}

compliant_input := input_with(
	[uploads_bucket_config, versioning_config],
	[versioning_planned("Enabled")],
)

noncompliant_suspended_input := input_with(
	[uploads_bucket_config, versioning_config],
	[versioning_planned("Suspended")],
)

noncompliant_missing_input := input_with(
	[uploads_bucket_config],
	[],
)

test_compliant_passes if {
	count(a1_2_s3_versioning.deny) == 0 with input as compliant_input
}

test_noncompliant_suspended_fails if {
	some msg in a1_2_s3_versioning.deny with input as noncompliant_suspended_input
	contains(msg, "A1.2")
}

test_noncompliant_missing_fails if {
	some msg in a1_2_s3_versioning.deny with input as noncompliant_missing_input
	contains(msg, "A1.2")
}
