# OSCAL layer

`components/acme-health-capstone.json` and `profiles/acme-health-capstone-profile.json`
are stubs — real UUIDs, real structure, `TODO`s where the content has to be
yours: the NIST 800-53 crosswalk for your SOC 2 criteria, the implementation
descriptions, and the evidence links (which can't be real until the pipeline
has actually run once).

Author/validate with `trestle` (matches the Lab 6.1 workflow):

```bash
pip install compliance-trestle
mkdir -p .trestle-work && cd .trestle-work
trestle init
cp ../oscal/components/acme-health-capstone.json component-definitions/acme-health-capstone/component-definition.json
cp ../oscal/profiles/acme-health-capstone-profile.json profiles/acme-health-capstone-profile/profile.json
trestle validate -a component-definition -n acme-health-capstone
trestle validate -a profile -n acme-health-capstone-profile
```

Both must report `VALID` before submission. Copy the validated files back
over the committed ones in `../oscal/` if trestle reformats them.

Do not fill in the `control-id` fields with the raw `CC6.1`-style SOC 2
labels — those aren't NIST 800-53 IDs and `trestle validate` (and the
grader) expect real catalog control IDs from the `source` catalog. Put the
SOC 2 criteria in the `soc2-criteria` prop instead, as the stub already does.
