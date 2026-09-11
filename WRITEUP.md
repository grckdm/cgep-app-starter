# Acme Health: GRC Engineering Capstone Write-up

## Primary framework

**SOC 2 Type II.** TODO: three sentences on why this fits Acme's
situation better than HIPAA or CMMC L2 — the companion's framing is that
SOC 2 fits because the evidence pipeline is fundamentally about proving
controls operate *continuously*, which is exactly what a signed bundle
on every push demonstrates. Make it your own argument, not this one.

## Control coverage

TODO: one row per gap in `GAPS.md`. For each: which SOC 2 criterion (and
which NIST 800-53 control-id, per the OSCAL crosswalk) it maps to, and
whether you closed it in Terraform, enforced it in policy, or both.

| Gap | SOC 2 criterion | NIST 800-53 ID | Closed in Terraform? | Enforced in policy? |
|---|---|---|---|---|
| GAP-01 (S3 SSE-KMS) | CC6.1 | TODO | TODO | `policies/cc6_1_s3_kms.rego` |
| GAP-02 (DynamoDB CMK) | CC6.1 | TODO | TODO | `policies/cc6_1_dynamodb_cmk.rego` |
| GAP-03 (S3 TLS-only) | CC6.7 | TODO | TODO | `policies/cc6_7_s3_tls_only.rego` |
| GAP-04 (S3 versioning) | A1.2 | TODO | TODO | `policies/a1_2_s3_versioning.rego` |
| GAP-05 (Lambda in VPC) | CC6.6 | TODO | TODO | `policies/cc6_6_lambda_vpc.rego` |
| GAP-06 (concurrency/DLQ/X-Ray) | CC7.2 | TODO | TODO | TODO — not yet policy-enforced, decide + defend |
| GAP-07 (IAM least privilege) | CC6.3 | TODO | TODO | `policies/cc6_3_iam_least_privilege.rego` |
| GAP-08 (API GW logging/throttle/WAF) | CC7.2 | TODO | TODO | TODO — not yet policy-enforced, decide + defend |

## Design decisions

Decided going in (record your reasoning, not just the choice):

- **AWS region:** `us-east-1`. TODO: reasoning (or "no data-residency
  driver for a sandbox, went with the default").
- **Object Lock mode:** `GOVERNANCE`. TODO: reasoning — trade-off is
  tamper-resistance (COMPLIANCE) vs. being able to clean up a 30-day
  sandbox project (GOVERNANCE).
- **Apply trigger:** auto-apply on merge to `main`. TODO: reasoning —
  trade-off is full continuity vs. a human-in-the-loop gate.
- **Account structure:** single AWS account. TODO: reasoning — brief
  calls this "acceptable for 30 days"; note what you'd change for
  production (separate evidence-vault account so a workload-account
  compromise can't rewrite evidence).
- **Terraform-vs-policy split:** TODO — which gaps you closed at the
  infrastructure layer vs. only gated in policy, and why a given gap
  belongs in one bucket over the other.

## How the pipeline produces evidence

TODO: trace one real run end to end — PR opened → grc-gate plan/policy
check → merge → apply → sign → upload. Name the actual GitHub Actions
run ID and the S3 key it landed at so an assessor can verify it
independently with `scripts/verify-evidence.sh <run_id> --vault <bucket>`.

## Trade-offs and what I'd do with another sprint

TODO. Be specific: what's shallow, what's a v1 that needs hardening,
what you'd automate next.

## What I didn't get to

TODO. Naming it costs nothing here and signals judgment — don't pad
this into a false "everything's done."
