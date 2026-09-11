# policies/

SOC 2 Trust Services Criteria policy suite for the capstone. Six stub
policies below, one per gap in `GAPS.md` (that's 6, over the brief's
5-minimum floor — cut one if it's not adding signal, don't just leave
a hollow stub to hit a number).

Each stub has a filled-in `METADATA` block (title, SOC 2 control ID,
severity, remediation) and a `TODO` where the actual `deny` rule goes.
That's the part you write — it's graded Layer 2 content, not
boilerplate. `../../terraform/policies/sc28_encryption_aws.rego` and
`ac3_no_public_aws.rego` in the `cgep-labs` repo (Lab 3.3/3.4) are
worked examples of the same `input.configuration.root_module` /
`input.planned_values.root_module` shapes you'll need — adapt their
technique, not their control.

Each policy needs a `_test.rego` in `tests/` with a passing and a
failing fixture (`opa test ./policies` must pass). The grader
reintroduces a gap into a copy of the starter and checks your gate
fires — so the deny condition has to catch the *specific* misconfig,
not a generic "does this tag exist" check.

Run locally:

```bash
opa test ./policies
conftest test --policy ./policies --namespace compliance.soc2.cc6_1_s3_kms <path-to-plan.json>
```
