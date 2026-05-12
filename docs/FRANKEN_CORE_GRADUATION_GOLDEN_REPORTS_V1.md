# Franken-Core Graduation Golden Reports V1

Status: active
Primary bead: `bd-4w7h9.7`
Parent wave: `bd-4w7h9`
Machine-readable contract: `docs/franken_core_graduation_golden_reports_v1.json`
Golden JSON: `scripts/testdata/franken_core_graduation_golden_reports/reports.json`
Golden Markdown: `scripts/testdata/franken_core_graduation_golden_reports/reports.md.golden`

## Scope

This golden suite freezes the stable semantic fields from the IDEA-WIZARD-V
franken-core graduation reports:

- graduation contract
- API parity ledger
- validation impact planner
- status truth gate
- no-mock graduation drill
- staged-inclusion rehearsal
- one negative contradictory-doc fixture

The goldens intentionally omit timestamps, host-specific paths, temporary output
directories, and full command transcripts. They compare schema names, decisions,
reason codes, selected proof fields, risk identifiers, and required acceptance
references.

## Regeneration

Regeneration is explicit:

```bash
UPDATE_FRANKEN_CORE_GRADUATION_GOLDENS=1 bash scripts/e2e/franken_core_graduation_golden_reports_smoke.sh update
```

Review the diff before committing regenerated goldens. The update path is
docs/JSON/shell only; it does not run Cargo, run RCH, mutate workspace
membership, or edit root `Cargo.toml`.

## Validation

```bash
jq empty docs/franken_core_graduation_golden_reports_v1.json scripts/testdata/franken_core_graduation_golden_reports/reports.json
bash -n scripts/e2e/franken_core_graduation_golden_reports_smoke.sh
bash scripts/e2e/franken_core_graduation_golden_reports_smoke.sh check
git diff --check -- docs/FRANKEN_CORE_GRADUATION_GOLDEN_REPORTS_V1.md docs/franken_core_graduation_golden_reports_v1.json scripts/e2e/franken_core_graduation_golden_reports_smoke.sh scripts/testdata/franken_core_graduation_golden_reports/reports.json scripts/testdata/franken_core_graduation_golden_reports/reports.md.golden
```
