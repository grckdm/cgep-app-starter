# policies/tests/cc6_3_iam_least_privilege_test.rego
package compliance.soc2.cc6_3_iam_least_privilege_test

import rego.v1
import data.compliance.soc2.cc6_3_iam_least_privilege

policy_with(policy_json) := {
	"address": "aws_iam_role_policy.lambda_inline",
	"type": "aws_iam_role_policy",
	"name": "lambda_inline",
	"values": {"policy": policy_json},
}

input_with(resources) := {"planned_values": {"root_module": {"resources": resources}}}

compliant_json := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:PutItem","Resource":"x"},{"Effect":"Allow","Action":"s3:PutObject","Resource":"y"}]}`

noncompliant_wildcard_string_json := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:*","Resource":"x"}]}`

noncompliant_wildcard_array_json := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject","s3:*"],"Resource":"y"}]}`

compliant_input := input_with([policy_with(compliant_json)])

noncompliant_wildcard_string_input := input_with([policy_with(noncompliant_wildcard_string_json)])

noncompliant_wildcard_array_input := input_with([policy_with(noncompliant_wildcard_array_json)])

test_compliant_passes if {
	count(cc6_3_iam_least_privilege.deny) == 0 with input as compliant_input
}

test_noncompliant_wildcard_string_fails if {
	some msg in cc6_3_iam_least_privilege.deny with input as noncompliant_wildcard_string_input
	contains(msg, "CC6.3")
}

test_noncompliant_wildcard_array_fails if {
	some msg in cc6_3_iam_least_privilege.deny with input as noncompliant_wildcard_array_input
	contains(msg, "CC6.3")
}
