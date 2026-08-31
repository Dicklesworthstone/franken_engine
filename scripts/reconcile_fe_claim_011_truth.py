#!/usr/bin/env python3
from __future__ import annotations

import argparse
import difflib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

CANONICAL_PATH = Path("docs/claim_to_proof_matrix_v1.json")
MIRROR_PATH = Path("crates/franken-engine/docs/claim_to_proof_matrix_v1.json")
HUMAN_PATH = Path("docs/CLAIM_TO_PROOF_MATRIX_V1.md")
README_PATH = Path("README.md")
STATUS_PATH = Path("docs/evidence/FE-CLAIM-011/implementation_status_v1.json")
CHANGELOG_PATH = Path("CHANGELOG.md")

FE_011_DECISION = "stay_target_pending_current_100_trial_bundle"
FE_011_REASON = (
    "The executed comparator now feeds a receipt-bound producer that requires a "
    "complete 100-attempt matrix for every declared scenario under FrankenEngine, "
    "Node, and Bun. Aggregation independently re-hashes runtime executables, "
    "scenario scripts, manifests, witnesses, and transcripts; replay recomputes "
    "attempt counts from the source receipts; and the Rust "
    "franken_red_team_harness_gate consumes the exact harness schema before applying "
    "the product metric decision. Missing runtimes, blocked probes, mixed revisions, "
    "partial matrices, tampering, placeholders, and ambiguous dispositions fail "
    "closed. FE-CLAIM-011 remains target because no current non-fixture complete "
    "100-attempt-per-runtime-per-scenario bundle has yet been preserved and linked "
    "at the exact measured revision."
)
FE_014_DOWNGRADE = (
    "TARGETED: two independently observed features ship, but the three-feature floor "
    "is not met because FE-CLAIM-011 still lacks a current non-fixture complete "
    "100-attempt-per-runtime-per-scenario comparator bundle preserved at the exact "
    "measured revision."
)
FE_014_REASON = (
    "The catalog gate validates three bundle schemas and hashes, but the third named "
    "item is still a target metric outcome. The executed Node, Bun, and FrankenEngine "
    "lanes now feed a receipt-bound 100-attempt producer, full replay verifier, and "
    "Rust product gate, yet no current non-fixture complete FE-CLAIM-011 bundle is "
    "preserved and linked at the measured revision. Two independently observed "
    "features do not meet the three-feature floor."
)

README_REPLACEMENTS = (
    (
        "| Red-team compromise-rate comparison | TARGETED | The gate now executes the same declared scenarios under FrankenEngine, Node, and Bun and emits hash-bound runtime receipts, but no fresh non-fixture real-runtime bundle with a statistically adequate repeated-trial denominator has been committed. |",
        "| Red-team compromise-rate comparison | TARGETED | The executed comparator now feeds a receipt-bound 100-attempt producer, full replay verifier, and Rust product gate; promotion still waits on a current non-fixture complete 100-attempt-per-runtime-per-scenario bundle preserved and linked at the measured revision. |",
    ),
    (
        "| At-least-three production features impossible by default in Node/Bun | TARGETED | The catalog validates three named bundle shapes and hashes, but its third entry depends on FE-CLAIM-011, whose execution-capable comparator still lacks a fresh non-fixture real-runtime proof bundle; two independently observed features do not satisfy the three-feature floor. |",
        "| At-least-three production features impossible by default in Node/Bun | TARGETED | The catalog validates three named bundle shapes and hashes, but its third entry depends on FE-CLAIM-011, whose receipt-bound 100-attempt producer still lacks a current preserved non-fixture proof bundle; two independently observed features do not satisfy the three-feature floor. |",
    ),
)

HUMAN_REPLACEMENTS = (
    (
        "| `FE-CLAIM-011` | security | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:58` | `target` | all three runtime lanes now execute with hash-bound receipts and ambiguity blockers; promotion still waits on a fresh non-fixture real-runtime bundle with an adequate repeated-trial denominator | `bd-1vwza` |",
        "| `FE-CLAIM-011` | security | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:58` | `target` | executed lanes plus the receipt-bound 100-attempt producer, full replay verifier, and Rust product gate are live; promotion still waits on a current non-fixture complete bundle preserved and linked at the exact measured revision | `bd-1vwza` |",
    ),
    (
        "| `FE-CLAIM-014` | capability | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:61` | `target` | two independently observed features ship; the third catalog entry depends on FE-CLAIM-011, whose executed comparator still lacks a fresh non-fixture real-runtime proof bundle, so the three-feature floor is not met | `bd-cixqu.6.6` |",
        "| `FE-CLAIM-014` | capability | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:61` | `target` | two independently observed features ship; the third catalog entry depends on FE-CLAIM-011, whose receipt-bound 100-attempt producer still lacks a current preserved non-fixture proof bundle, so the three-feature floor is not met | `bd-cixqu.6.6` |",
    ),
)

IMPLEMENTATION_STATUS: dict[str, Any] = {
    "claim_id": "FE-CLAIM-011",
    "claim_state": "target",
    "comparator_contract": {
        "complete_matrix_required": True,
        "declared_runtimes": ["frankenengine", "node", "bun"],
        "failure_semantics": (
            "missing runtime, blocked probe, timeout, crash, malformed output, mixed "
            "revision, partial matrix, receipt tampering, placeholder data, or ambiguous "
            "disposition blocks the measurement and emits no favorable substitute rows"
        ),
        "identity_binding": [
            "runtime executable path and independently verified sha256",
            "runtime version command, exit code, stdout, and stderr",
            "scenario script path and independently verified sha256",
            "scenario manifest path and independently verified sha256",
            "per-attempt stdout, stderr, exit status, duration, and explicit disposition",
            "per-runtime transcript sha256",
            "per-scenario witness sha256",
            "aggregate transcript and witness sha256",
            "trial-index and measurement-details sha256",
        ],
        "minimum_trials_per_runtime_and_scenario": 100,
        "scenario_set": "red_team_security_critical_compromise_v1",
    },
    "implementation_commits": [
        "ca7fdd95b00b4c8438140c0b09c2c84cad8c2da0",
        "e6f2a7df4fa4570698d86ab45150f6c8c69a92de",
        "8078f78fc5c73fb4d6161131ad99b52cbd8d20b0",
        "5c7a551a01ac935b66681d009a45924a32485fc6",
        "844933b2104c06473e747b907012996dac6bab6d",
        "dc925cb1a4e02febd21ba9cf23c38b58cb63051c",
        "613e6fe78b220130b334f154f8d2bd2a4a445b3e",
        "68d551c718fe42d546fc9f19f497a8a698822748",
        "75321ba0db03752566bb91a618cd6d8167037eb3",
        "36dea62ab288d835fff072004d74fae1d5d95e9e",
        "a2bdfde392288c43e786089f197fc7d3577aaf20",
        "c16d70962c5327c23593f7b720b961a8a86ad2dd",
        "1c488965fc0332c69a42b82df34691d624a59ea0",
        "3622e772ddb1228a4737200d890147038c8a0119",
        "729db2daa7d2365cd4fc222f45c0fdc447a1fffd",
    ],
    "implementation_state": "receipt_bound_repeated_trial_producer_available",
    "measurement_state": "pending_current_real_100_trial_bundle",
    "operator_contract": "docs/RED_TEAM_REPEATED_TRIAL_HARNESS.md",
    "promotion_requirements": [
        "run the complete declared scenario set with identified FrankenEngine, Node, and Bun executables at one exact revision",
        "preserve at least 100 non-fixture hash-bound attempts for every runtime and scenario",
        "pass aggregate and source-receipt replay with no mixed revisions, partial matrices, ambiguity, or tampering",
        "pass the Rust franken_red_team_harness_gate metric decision",
        "demonstrate at least a 10x compromise-rate reduction against the conservative Node/Bun reference rate",
        "commit or otherwise permanently preserve the complete proof bundle and repro.lock at the exact measured revision",
        "link that bundle from the authoritative claim-to-proof matrix before promoting the claim",
    ],
    "schema_version": "franken-engine.fe-claim-011-implementation-status.v1",
    "verification_commands": [
        "python3 -m py_compile scripts/red_team_compromise_rate_metric.py scripts/red_team_trial_common.py scripts/red_team_trial_reader.py scripts/aggregate_red_team_trials.py",
        "bash scripts/e2e/red_team_compromise_rate_metric_comparator_smoke.sh",
        "bash scripts/e2e/red_team_repeated_trial_harness_smoke.sh",
        "cargo test --no-default-features -p frankenengine-engine --bin franken_red_team_harness_gate",
        "cargo test --no-default-features -p frankenengine-engine --test red_team_harness_gate_cli",
        "workflow_dispatch: .github/workflows/red-team-repeated-trial-measurement.yml",
    ],
}

CHANGELOG_HEADING = "## Post-Snapshot Update — Receipt-Bound Red-Team Measurement (2026-08-31)"
CHANGELOG_ANCHOR = "---\n\n## Post-Snapshot Update — Current window (2026-07-26 → 2026-08-19)"
CHANGELOG_SECTION = """## Post-Snapshot Update — Receipt-Bound Red-Team Measurement (2026-08-31)

This slice completes the missing measurement *producer* behind `FE-CLAIM-011`.
The claim remains **TARGETED**: the repository can now execute, aggregate,
replay, and evaluate the required 100-attempt denominator, but a current
non-fixture complete bundle has not yet been preserved and linked at the exact
measured revision.

### Delivered capability

- **Complete repeated-trial producer (`bd-1vwza`).**
  [`run_bd_28otw_attacker_harness.sh`](./scripts/run_bd_28otw_attacker_harness.sh)
  executes the full five-scenario matrix under Node, Bun, and FrankenEngine at
  least 100 times. A blocked or incomplete runtime probe aborts the campaign;
  it is never converted into a favorable containment result.
- **Receipt-bound aggregation and replay.**
  `aggregate_red_team_trials.py` independently re-hashes runtime executables,
  scenario scripts, manifests, witnesses, transcripts, aggregate receipts, and
  the trial index. It rejects mixed revisions, partial matrices, placeholders,
  negative fixtures, ambiguous dispositions, and source or aggregate tampering.
  Its output is the existing
  `franken-engine.red-team-harness-output.v1` schema.
- **One product interpretation of the metric.**
  The new `franken_red_team_harness_gate` binary deserializes that exact schema,
  converts it through `metric_input_from_harness_output`, and applies the
  existing Rust compromise-rate decision. Python owns execution receipts and
  replay; Rust owns the product metric contract.
- **Always-on and operator-triggered verification.**
  Main safety now runs a synthetic 100-trial shape plus aggregate-tamper,
  source-receipt-tamper, and insufficient-denominator drills. A focused Rust
  workflow checks conversion and pass/fail/invalid exit semantics. The manual
  measurement workflow pins comparator versions, builds the exact candidate,
  preserves the full bundle even on failure, and enforces the measured verdict
  only after artifact upload.
- **Agent-operable documentation.**
  [`RED_TEAM_REPEATED_TRIAL_HARNESS.md`](./docs/RED_TEAM_REPEATED_TRIAL_HARNESS.md)
  documents prerequisites, normal operation, replay, artifact anatomy,
  fail-closed conditions, exit codes, and the bounded claim posture.

### Truth posture

The implementation gap is closed, not the evidence gap. `FE-CLAIM-011` stays
TARGETED until a current non-fixture complete 100-attempt-per-runtime-per-scenario
bundle passes replay and the Rust gate, is permanently preserved with its
reproduction lock, and is linked from the authoritative claim-to-proof matrix.
`FE-CLAIM-014` consequently remains TARGETED as well.

### Representative commits

- [`ca7fdd95b`](https://github.com/Dicklesworthstone/franken_engine/commit/ca7fdd95b00b4c8438140c0b09c2c84cad8c2da0) — receipt and hash-verification primitives.
- [`8078f78fc`](https://github.com/Dicklesworthstone/franken_engine/commit/8078f78fc5c73fb4d6161131ad99b52cbd8d20b0) — complete aggregation and replay.
- [`5c7a551a0`](https://github.com/Dicklesworthstone/franken_engine/commit/5c7a551a01ac935b66681d009a45924a32485fc6) — 100-trial campaign runner.
- [`844933b21`](https://github.com/Dicklesworthstone/franken_engine/commit/844933b2104c06473e747b907012996dac6bab6d) — independent executable and scenario-input re-hashing.
- [`dc925cb1a`](https://github.com/Dicklesworthstone/franken_engine/commit/dc925cb1a4e02febd21ba9cf23c38b58cb63051c) — 100-trial replay and tamper drills.
- [`68d551c71`](https://github.com/Dicklesworthstone/franken_engine/commit/68d551c718fe42d546fc9f19f497a8a698822748) — Rust product-gate CLI.
- [`3622e772d`](https://github.com/Dicklesworthstone/franken_engine/commit/3622e772ddb1228a4737200d890147038c8a0119) — preserved real-measurement workflow.
- [`729db2daa`](https://github.com/Dicklesworthstone/franken_engine/commit/729db2daa7d2365cd4fc222f45c0fdc447a1fffd) — operator and contributor contract.
"""


class ReconciliationError(RuntimeError):
    pass


@dataclass(frozen=True)
class PlannedWrite:
    path: Path
    before: str | None
    after: str

    @property
    def changed(self) -> bool:
        return self.before != self.after


def load_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ReconciliationError(f"missing required file: {path}") from error
    except json.JSONDecodeError as error:
        raise ReconciliationError(f"invalid JSON in {path}: {error}") from error
    if not isinstance(value, dict):
        raise ReconciliationError(f"expected JSON object in {path}")
    return value


def find_claim(matrix: dict[str, Any], claim_id: str) -> dict[str, Any]:
    claims = matrix.get("claims")
    if not isinstance(claims, list):
        raise ReconciliationError("canonical matrix has no claims array")
    matches = [row for row in claims if isinstance(row, dict) and row.get("claim_id") == claim_id]
    if len(matches) != 1:
        raise ReconciliationError(f"expected exactly one {claim_id} row, found {len(matches)}")
    return matches[0]


def require_target_row(row: dict[str, Any], claim_id: str) -> None:
    if row.get("allowed_state") != "target" or row.get("actual_wording_state") != "target":
        raise ReconciliationError(
            f"{claim_id} reconciliation refuses to alter non-target state: "
            f"allowed={row.get('allowed_state')!r}, actual={row.get('actual_wording_state')!r}"
        )


def render_canonical(root: Path) -> str:
    matrix = load_json_object(root / CANONICAL_PATH)
    claim_011 = find_claim(matrix, "FE-CLAIM-011")
    require_target_row(claim_011, "FE-CLAIM-011")
    claim_011["decision"] = FE_011_DECISION
    claim_011["reason"] = FE_011_REASON

    claim_014 = find_claim(matrix, "FE-CLAIM-014")
    require_target_row(claim_014, "FE-CLAIM-014")
    claim_014["downgrade_text"] = FE_014_DOWNGRADE
    claim_014["reason"] = FE_014_REASON
    return json.dumps(matrix, indent=2, ensure_ascii=False) + "\n"


def replace_exact(text: str, replacements: Iterable[tuple[str, str]], path: Path) -> str:
    result = text
    for old, new in replacements:
        old_count = result.count(old)
        new_count = result.count(new)
        if old_count == 0 and new_count == 0:
            raise ReconciliationError(
                f"{path}: neither expected stale text nor reconciled text was found; refusing a fuzzy rewrite"
            )
        if old_count:
            result = result.replace(old, new)
    return result


def render_changelog(text: str) -> str:
    if CHANGELOG_HEADING in text:
        return text
    if text.count(CHANGELOG_ANCHOR) != 1:
        raise ReconciliationError(
            "CHANGELOG.md: expected one current-window insertion anchor; refusing a fuzzy rewrite"
        )
    replacement = f"---\n\n{CHANGELOG_SECTION}\n\n---\n\n## Post-Snapshot Update — Current window (2026-07-26 → 2026-08-19)"
    return text.replace(CHANGELOG_ANCHOR, replacement, 1)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise ReconciliationError(f"missing required file: {path}") from error


def plan(root: Path) -> list[PlannedWrite]:
    canonical_path = root / CANONICAL_PATH
    canonical_before = read_text(canonical_path)
    canonical_after = render_canonical(root)

    mirror_path = root / MIRROR_PATH
    mirror_before = read_text(mirror_path)

    human_path = root / HUMAN_PATH
    human_before = read_text(human_path)
    human_after = replace_exact(human_before, HUMAN_REPLACEMENTS, HUMAN_PATH)

    readme_path = root / README_PATH
    readme_before = read_text(readme_path)
    readme_after = replace_exact(readme_before, README_REPLACEMENTS, README_PATH)

    status_path = root / STATUS_PATH
    status_before = status_path.read_text(encoding="utf-8") if status_path.exists() else None
    status_after = json.dumps(IMPLEMENTATION_STATUS, indent=2, sort_keys=True) + "\n"

    changelog_path = root / CHANGELOG_PATH
    changelog_before = read_text(changelog_path)
    changelog_after = render_changelog(changelog_before)

    return [
        PlannedWrite(canonical_path, canonical_before, canonical_after),
        PlannedWrite(mirror_path, mirror_before, canonical_after),
        PlannedWrite(human_path, human_before, human_after),
        PlannedWrite(readme_path, readme_before, readme_after),
        PlannedWrite(status_path, status_before, status_after),
        PlannedWrite(changelog_path, changelog_before, changelog_after),
    ]


def print_diff(write: PlannedWrite) -> None:
    before_lines = [] if write.before is None else write.before.splitlines(keepends=True)
    after_lines = write.after.splitlines(keepends=True)
    sys.stdout.writelines(
        difflib.unified_diff(
            before_lines,
            after_lines,
            fromfile=f"a/{write.path}",
            tofile=f"b/{write.path}",
            n=3,
        )
    )


def write_atomic(write: PlannedWrite) -> None:
    write.path.parent.mkdir(parents=True, exist_ok=True)
    temporary = write.path.with_name(f".{write.path.name}.tmp")
    temporary.write_text(write.after, encoding="utf-8")
    temporary.replace(write.path)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Reconcile FE-CLAIM-011 implementation truth without promoting its evidence state."
    )
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--fix", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    root = args.root.resolve()
    try:
        writes = plan(root)
    except ReconciliationError as error:
        print(f"claim-truth reconciliation error: {error}", file=sys.stderr)
        return 2
    changed = [write for write in writes if write.changed]
    if args.check:
        if not changed:
            print("FE-CLAIM-011 truth surfaces are reconciled and remain target")
            return 0
        for write in changed:
            print_diff(write)
        print(
            "FE-CLAIM-011 truth surfaces are stale; run "
            "python3 scripts/reconcile_fe_claim_011_truth.py --fix",
            file=sys.stderr,
        )
        return 1
    for write in changed:
        write_atomic(write)
        print(f"updated {write.path.relative_to(root)}")
    if not changed:
        print("FE-CLAIM-011 truth surfaces already reconciled")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
