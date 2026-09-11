# policies/tests/cc6_6_lambda_vpc_test.rego
package compliance.soc2.cc6_6_lambda_vpc_test

import rego.v1
import data.compliance.soc2.cc6_6_lambda_vpc

lambda_config(vpc_config) := {
	"address": "aws_lambda_function.intake",
	"type": "aws_lambda_function",
	"name": "intake",
	"expressions": {"vpc_config": vpc_config},
}

input_with(resources) := {"configuration": {"root_module": {"resources": resources}}}

compliant_input := input_with([lambda_config([{"subnet_ids": {"references": ["aws_subnet.private"]}}])])

noncompliant_missing_input := input_with([lambda_config([])])

noncompliant_empty_refs_input := input_with([lambda_config([{"subnet_ids": {"references": []}}])])

test_compliant_passes if {
	count(cc6_6_lambda_vpc.deny) == 0 with input as compliant_input
}

test_noncompliant_missing_fails if {
	some msg in cc6_6_lambda_vpc.deny with input as noncompliant_missing_input
	contains(msg, "CC6.6")
}

test_noncompliant_empty_refs_fails if {
	some msg in cc6_6_lambda_vpc.deny with input as noncompliant_empty_refs_input
	contains(msg, "CC6.6")
}
