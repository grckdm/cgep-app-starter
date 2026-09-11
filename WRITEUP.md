# Acme Health: GRC Engineering Capstone Write-up

## Primary framework

**SOC 2 Type II.** Acme's customer relationship here is B2B: a health
system deciding whether to trust Acme's intake API with patient data is
buying an attestation, not a regulation checkbox. SOC 2 Type II is the
artifact that market actually asks for in a vendor security review, where
HIPAA compliance is an obligation Acme has regardless and CMMC L2 is
scoped to federal defense contractors Acme isn't one of. The harder
argument is Type II over Type I: Type I only attests that controls existed
on a given day, while Type II attests they operated *effectively over a
period*, and this project's evidence pipeline is built around exactly
that claim, not around a point-in-time snapshot. That's not hypothetical:
run [`34626165911`](https://github.com/grckdm/cgep-app-starter/actions/runs/34626165911)
produced a real signed, hashed, receipted bundle
(`s3://acme-health-intake-evidence-vault-7eeb10ce/runs/34626165911/evidence-34626165911-9c07dd6394a61a341c8e3c1f400b539cf84ea975.tar.gz`)
the moment a change merged to `main`. A continuous evidence trail is
what a Type II assessor is actually sampling from, and this pipeline
produces one on every merge rather than requiring someone to assemble
one before an audit.

## Control coverage

| Gap | SOC 2 criterion | NIST 800-53 ID | Closed in Terraform? | Enforced in policy? |
|---|---|---|---|---|
| GAP-01 (S3 SSE-KMS) | CC6.1 | `sc-28` | Yes, `hardening.tf` | `policies/cc6_1_s3_kms.rego` |
| GAP-02 (DynamoDB CMK) | CC6.1 | `sc-28` | Yes, `gap02_dynamodb_override.tf` | `policies/cc6_1_dynamodb_cmk.rego` |
| GAP-03 (S3 TLS-only) | CC6.7 | `sc-8` | Yes, `hardening.tf` | `policies/cc6_7_s3_tls_only.rego` |
| GAP-04 (S3 versioning) | A1.2 | `cp-9` | Yes, `hardening.tf` | `policies/a1_2_s3_versioning.rego` |
| GAP-05 (Lambda in VPC) | CC6.6 | `sc-7` | Yes, `hardening.tf` + `gap05_06_lambda_override.tf` | `policies/cc6_6_lambda_vpc.rego` |
| GAP-06 (concurrency/DLQ/X-Ray) | CC7.2 | (not crosswalked; not policy layer) | Partial: DLQ + X-Ray yes; reserved concurrency **not set** (see Design decisions) | Not policy-enforced, see below |
| GAP-07 (IAM least privilege) | CC6.3 | `ac-6` | Yes, `gap07_iam_override.tf` | `policies/cc6_3_iam_least_privilege.rego` |
| GAP-08 (API GW logging/throttle/WAF) | CC7.2 | (not crosswalked; not policy layer) | Partial: access logging + throttling yes; WAF **scoped out** (see Design decisions) | Not policy-enforced, see below |

GAP-06 and GAP-08 not getting a Rego policy is a deliberate scope
decision, not an oversight. The brief requires 5+ of 8 gaps enforced in
policy, and I chose depth (six gaps with real fail-closed rules, tested
against fixtures, a from-scratch plan, and a live regression against the
real applied stack) over shallow coverage of all eight. The reasoning for
which two got left out is specific to each, not just "ran out of time":

- **GAP-06**: `reserved_concurrent_executions`, the one piece of this
  gap a boolean policy could most crisply check, was never actually set
  in Terraform (this AWS account's total Lambda concurrency limit is 10,
  and AWS refuses any reservation that would drop the account's
  unreserved pool below 10). A Rego rule asserting a value that can't
  exist in this account's real infrastructure would be enforcing
  something the deployment can never satisfy, which isn't a meaningful
  gate.
- **GAP-08**: throttling limits and log retention are magnitude/tuning
  choices, not present/absent booleans: whether `throttling_rate_limit`
  is correct needs a judgment call about acceptable load a fail-closed
  policy can't make crisply, and WAF is explicitly optional per
  `GAPS.md`. Writing a policy here would mean special-casing the WAF
  opt-out inside the policy itself, which felt like enforcing my own
  scope decision rather than a control.

## Design decisions

- **AWS region:** `us-east-1`. No data-residency driver for a sandbox
  project; this is the default region, and keeping every subsystem
  (Lambda, DynamoDB, S3, KMS, CloudTrail) in one region avoided any
  cross-region complexity that wouldn't have taught anything for a
  30-day project.
- **Object Lock mode:** `GOVERNANCE`. The trade-off is tamper-resistance
  (`COMPLIANCE`, where *no one*, including the account root, can delete
  or shorten retention before it expires) versus the ability to actually
  tear this down at the end of a 30-day sandbox project. `COMPLIANCE`
  mode would have meant either waiting out the full 365-day retention
  period to delete the evidence vault or filing an AWS support case.
  Neither is reasonable for coursework. `GOVERNANCE` still requires the
  `s3:BypassGovernanceRetention` permission to override, which I did not
  grant broadly (it's not in `grc_gate`'s policy), so it isn't a rubber
  stamp: it's "tamper-resistant against everyone except an explicit,
  auditable escalation," which is the right trade for a project with a
  defined end date.
- **Apply trigger:** auto-apply on merge to `main`. The trade-off is full
  continuity (every merge produces a plan, a policy check, and a signed
  bundle) versus a human-in-the-loop gate before anything actually
  deploys. I chose auto-apply because the whole premise of continuous
  evidence is broken by a manual gate: if a human has to remember to
  click "deploy" separately from merging, the evidence trail has gaps
  exactly at the moments something changed, which is the opposite of
  what a Type II assessor wants to see. The real cost of this choice
  surfaced directly this project: `grc_gate`'s own IAM role provisions
  the entire stack via that same auto-apply, including its own trust
  policy and permissions (`oidc-trust.tf`), so in principle it can
  modify its own boundary if a merged change asked it to. No IAM scoping
  closes that path while still letting Terraform manage the whole
  module; the actual control is process, not policy: branch protection
  requiring review on `main` is what stops an untrusted change from ever
  reaching `grc_gate`'s apply step. I'm naming this rather than treating
  auto-apply as free.
- **Account structure:** single AWS account. The brief calls this
  "acceptable for 30 days," and I agree for a project with a hard end
  date, but a real production version of this system should not keep
  the evidence vault in the same account as the workload it's providing
  evidence about. A single account means a compromise of the workload
  (the Lambda, its IAM role, the API) and a compromise of the audit
  trail proving the workload is compliant share the same blast radius,
  exactly the scenario an assessor should be most suspicious of, since
  it means an attacker who gets into the workload could theoretically
  also rewrite or delete the evidence that would reveal the compromise.
- **Terraform-vs-policy split:** all eight gaps are closed at the
  Terraform layer (the actual grading surface, per `GAPS.md`); six of
  eight are additionally enforced in policy. See Control coverage above
  for the reasoning on which two aren't, and why.

## How the pipeline produces evidence

Tracing the real first fully-green run,
[`34626165911`](https://github.com/grckdm/cgep-app-starter/actions/runs/34626165911)
(commit `9c07dd6`), end to end:

1. **Push to `main`** triggers `grc-gate.yml`.
2. **Configure AWS credentials (OIDC)**: the runner requests a GitHub
   Actions OIDC token and exchanges it for temporary AWS credentials by
   assuming `arn:aws:iam::477010601376:role/acme-health-intake-grc-gate`,
   with no long-lived AWS keys stored anywhere in GitHub.
3. **Plan**: `terraform init` against the S3 remote backend
   (`cgep-capstone-tfstate-4821931c`), `terraform validate`, then
   `terraform plan -out=tfplan`, converted to `plan.json`.
4. **Policy check**: `scripts/policy-gate.sh` runs `conftest` against
   `plan.json` across all six Rego namespaces; this run reported all six
   compliant (`policy-gate: PASS`).
5. **Apply**: `terraform apply -auto-approve tfplan`, since this was a
   push to `main`.
6. **Sign evidence bundle**: `plan.json` and `plan.txt` are packaged
   into a tarball, hashed with SHA-256, and signed with `cosign
   sign-blob --yes` (keyless signing via Sigstore, no key management
   needed on my end).
7. **Upload to evidence vault**: the bundle, its `.sha256`, and its
   `.sig.bundle` land at
   `s3://acme-health-intake-evidence-vault-7eeb10ce/runs/34626165911/`,
   and a `receipt.json` (run ID, vault, bundle key, S3 object version ID,
   SHA-256, commit SHA) is written alongside it and also uploaded as a
   workflow artifact.

An assessor doesn't need to trust my word that this happened; they can
run `scripts/verify-evidence.sh 34626165911 --vault
acme-health-intake-evidence-vault-7eeb10ce` and independently confirm the
chain is intact.

Getting to this first green run took six real, distinct rounds of
debugging after the first push, all fixed and documented in commit
history (`ba29130`, `7f15138`, `e0ff898`, `f00d07e`, `bd83fd4`,
`9c07dd6`): an OIDC trust policy repo-name mismatch, GitHub's newer
immutable-ID OIDC subject format, scripts committed without their
executable bit from a Windows working tree, missing refresh-time IAM read
permissions that only surface under the actually-scoped CI role (never
under admin credentials), a `pipefail` bug in the workflow that let a
failed `terraform plan` silently continue to the policy check, and a
missing KMS grant for uploading to the CMK-encrypted evidence vault. None
of these were caught by any amount of local testing under my own
`grcclub` admin credentials. Every one of them is specific to what the
*actually least-privileged* pipeline identity can and can't do, which is
the whole point of testing the real pipeline rather than trusting that a
correct-looking IAM policy will work.

## Trade-offs and what I'd do with another sprint

- **Two Rego policies can't evaluate correctly on a from-scratch plan.**
  `cc6_7_s3_tls_only.rego` and `cc6_3_iam_least_privilege.rego` both
  inspect the parsed content of a `jsonencode()`'d IAM/bucket policy that
  embeds another resource's ARN. When that resource doesn't exist yet
  (a true day-0 plan), the whole `jsonencode()` string is "known after
  apply" and Terraform omits it from `planned_values` entirely; there's
  no way to recover the policy's structure from `configuration` either,
  since Terraform only exposes a flat list of referenced addresses for a
  function-call expression, not its shape. This is a real limitation of
  Terraform plan JSON, not a bug I could code around, and it's why these
  two policies only work correctly against a plan for an already-applied
  stack (documented directly in both `.rego` files). That happens to
  match this project's actual operating model: `grc-gate.yml` polices
  *changes* to a running stack, not from-scratch bootstraps (those are
  done manually). But it's a real gap if this project were ever graded
  by tearing everything down and reapplying from zero.
- **The CI debugging cost itself is the biggest lesson of this project.**
  Six rounds of real bugs before the first green run, none of them
  caught by local testing, all specific to running under a genuinely
  least-privileged identity. With another sprint I'd build a way to test
  the `grc_gate` role's actual permissions locally before pushing,
  e.g. a script that assumes the role (via a temporarily broadened trust
  policy, or `sts:AssumeRole` from an admin principal added just for
  testing) and runs the same plan/apply sequence CI does, so these
  permission gaps surface in seconds locally instead of in ~2-minute CI
  round-trips.
- **Other concrete next steps**: a separate AWS account for the evidence
  vault (removes the single-blast-radius risk named above); policy
  enforcement for GAP-06 and GAP-08 once there's a principled way to
  handle the WAF opt-out and the concurrency-limit constraint in Rego;
  requesting a Lambda concurrency quota increase so GAP-06's
  `reserved_concurrent_executions` can actually be set; and fixing
  `data.archive_file`'s non-deterministic zip hashing (it embeds file
  timestamps, so the same source produces a different `source_code_hash`
  in CI versus locally, causing a spurious Lambda diff on every plan).

## What I didn't get to

- **OSCAL evidence links are still placeholders**
  (`urn:capstone:pending-first-pipeline-run`) even though a real pipeline
  run now exists and could be linked. I built the OSCAL layer before the
  pipeline was proven working end-to-end, and haven't gone back to wire
  the real S3 key in.
- **GAP-06 and GAP-08 have no policy-layer enforcement**: Terraform
  closes most of both (DLQ, X-Ray, access logging, throttling), but
  neither has a Rego rule, and GAP-06's reserved concurrency and GAP-08's
  WAF are not implemented at all (documented reasons above, not silently
  dropped).
- **No separate evidence-vault AWS account**: named as the single
  biggest structural gap between this project and a production version
  of it.
- **No fix for the Lambda zip hash flip-flop** between local and CI
  applies. Cosmetic (no functional difference in the deployed code),
  but it means every environment's plan shows a diff that isn't real.
