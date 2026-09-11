# policies/cc6_6_lambda_vpc.rego
# METADATA
# title: CC6.6 - Boundary protection (Lambda must run inside the VPC)
# description: >
#   GAP-05: aws_lambda_function.intake has no vpc_config block, so it
#   runs in the default Lambda environment instead of the starter's VPC.
# custom:
#   framework: soc2
#   gap: GAP-05
#   controls: ["CC6.6"]
#   severity: high
#   remediation: >
#     Override aws_lambda_function.intake to add a vpc_config block
#     referencing the private subnets and a hardened security group.
package compliance.soc2.cc6_6_lambda_vpc

import rego.v1

# Reads references via input.configuration rather than resolved values via
# input.planned_values: on a from-scratch plan, subnet_ids resolve from
# aws_subnet.private[*].id, which is "known after apply" for not-yet-created
# subnets and would be omitted from planned_values, false-failing this check.
deny contains msg if {
	some r in input.configuration.root_module.resources
	r.type == "aws_lambda_function"
	r.name == "intake"
	not has_vpc_config(r)
	msg := sprintf(
		"[CC6.6] %s: must have a vpc_config block with at least one subnet. Running in the default Lambda environment does not satisfy this control.",
		[r.address],
	)
}

has_vpc_config(r) if {
	some vc in r.expressions.vpc_config
	count(vc.subnet_ids.references) > 0
}
