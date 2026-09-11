# policies/tests/cc6_1_dynamodb_cmk_test.rego
package compliance.soc2.cc6_1_dynamodb_cmk_test

import rego.v1
import data.compliance.soc2.cc6_1_dynamodb_cmk

table_config(sse) := {
	"address": "aws_dynamodb_table.intake",
	"type": "aws_dynamodb_table",
	"expressions": {"server_side_encryption": sse},
}

input_with(resources) := {"configuration": {"root_module": {"resources": resources}}}

compliant_input := input_with([table_config([{
	"enabled": {"constant_value": true},
	"kms_key_arn": {"references": ["aws_kms_key.grc.arn", "aws_kms_key.grc"]},
}])])

noncompliant_missing_input := input_with([table_config([])])

noncompliant_disabled_input := input_with([table_config([{
	"enabled": {"constant_value": false},
	"kms_key_arn": {"references": []},
}])])

test_compliant_passes if {
	count(cc6_1_dynamodb_cmk.deny) == 0 with input as compliant_input
}

test_noncompliant_missing_fails if {
	some msg in cc6_1_dynamodb_cmk.deny with input as noncompliant_missing_input
	contains(msg, "CC6.1")
}

test_noncompliant_disabled_fails if {
	some msg in cc6_1_dynamodb_cmk.deny with input as noncompliant_disabled_input
	contains(msg, "CC6.1")
}
