# policies/cc6_1_s3_kms.rego
# METADATA
# title: CC6.1 - Logical access controls (S3 uploads bucket must use SSE-KMS with the CMK)
# description: >
#   GAP-01: aws_s3_bucket.uploads must have an
#   aws_s3_bucket_server_side_encryption_configuration whose sse_algorithm
#   is "aws:kms" referencing our CMK, not the SSE-S3 default.
# custom:
#   framework: soc2
#   gap: GAP-01
#   controls: ["CC6.1"]
#   severity: high
#   remediation: >
#     Add aws_s3_bucket_server_side_encryption_configuration for
#     aws_s3_bucket.uploads with sse_algorithm = "aws:kms" and
#     kms_master_key_id pointing at aws_kms_key.grc.
package compliance.soc2.cc6_1_s3_kms

import rego.v1

deny contains msg if {
	uploads_bucket_exists
	not has_kms_encryption
	msg := "[CC6.1] aws_s3_bucket.uploads must be encrypted with SSE-KMS using the customer CMK (aws_kms_key.grc). SSE-S3 or no encryption configuration does not satisfy this control."
}

uploads_bucket_exists if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	r.name == "uploads"
}

has_kms_encryption if {
	addr := sse_config_address_for_uploads
	some pv in input.planned_values.root_module.resources
	pv.address == addr
	some rule in pv.values.rule
	some conf in rule.apply_server_side_encryption_by_default
	conf.sse_algorithm == "aws:kms"
}

sse_config_address_for_uploads := addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_server_side_encryption_configuration"
	some ref in r.expressions.bucket.references
	references_uploads(ref)
	addr := sprintf("aws_s3_bucket_server_side_encryption_configuration.%s", [r.name])
}

references_uploads(ref) if ref == "aws_s3_bucket.uploads"

references_uploads(ref) if ref == "aws_s3_bucket.uploads.id"

references_uploads(ref) if ref == "aws_s3_bucket.uploads.bucket"
