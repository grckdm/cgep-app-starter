# policies/a1_2_s3_versioning.rego
# METADATA
# title: A1.2 - System availability (uploads bucket must have versioning enabled)
# description: >
#   GAP-04: aws_s3_bucket.uploads has no aws_s3_bucket_versioning
#   resource. PHI attachment overwrites are unrecoverable.
# custom:
#   framework: soc2
#   gap: GAP-04
#   controls: ["A1.2"]
#   severity: medium
#   remediation: >
#     Add aws_s3_bucket_versioning for aws_s3_bucket.uploads with
#     versioning_configuration { status = "Enabled" }.
package compliance.soc2.a1_2_s3_versioning

import rego.v1

deny contains msg if {
	uploads_bucket_exists
	not has_versioning_enabled
	msg := "[A1.2] aws_s3_bucket.uploads must have aws_s3_bucket_versioning with status \"Enabled\"."
}

uploads_bucket_exists if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	r.name == "uploads"
}

has_versioning_enabled if {
	addr := versioning_address_for_uploads
	some pv in input.planned_values.root_module.resources
	pv.address == addr
	some vc in pv.values.versioning_configuration
	vc.status == "Enabled"
}

versioning_address_for_uploads := addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_versioning"
	some ref in r.expressions.bucket.references
	references_uploads(ref)
	addr := sprintf("aws_s3_bucket_versioning.%s", [r.name])
}

references_uploads(ref) if ref == "aws_s3_bucket.uploads"

references_uploads(ref) if ref == "aws_s3_bucket.uploads.id"

references_uploads(ref) if ref == "aws_s3_bucket.uploads.bucket"
