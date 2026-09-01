#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = ROOT / "docs/claim_to_proof_matrix_v1.json"
MATRIX_MIRROR_PATH = ROOT / "crates/franken-engine/docs/claim_to_proof_matrix_v1.json"
HUMAN_MATRIX_PATH = ROOT / "docs/CLAIM_TO_PROOF_MATRIX_V1.md"
README_PATH = ROOT / "README.md"
PLAN_PATH = ROOT / "docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md"
CHANGELOG_PATH = ROOT / "CHANGELOG.md"
STATUS_PATH = ROOT / "docs/FE_CLAIM_011_IMPLEMENTATION_STATUS.md"
CORPUS_PATH = ROOT / "docs/red_team_scenario_corpus_v2.json"

FE_011_DECISION = "stay_target_pending_current_v2_live_bundle"
FE_011_REASON = (
    "The exact v2 path now executes pinned FrankenEngine, Node, and Bun binaries over ten "
    "contract-declared security-critical scenarios, requires at least 100 receipt-bound "
    "stability/replay repetitions per runtime/scenario pair, rejects mixed outcomes and "
    "identity drift, and applies a one-scenario zero-cell guard before the sole Rust verdict "
    "gate computes the conservative corpus floor. The repetitions are stability evidence, "
    "not independent population samples. FE-CLAIM-011 remains target because no current "
    "non-fixture v2 campaign plus passing franken_red_team_harness_gate verdict is preserved "
    "and linked from this matrix."
)
FE_011_FRESHNESS_RATIONALE = (
    "exact red-team scenario-corpus comparison; the producer and verifier are stable, but "
    "the adversarial corpus and pinned runtime identities may evolve, so the evidence must "
    "not sit at the frozen window"
)
FE_011_VERIFY = (
    "cargo build --release --no-default-features -p frankenengine-engine --bin frankenctl "
    "--bin franken_red_team_harness_gate && "
    "FRANKENENGINE_BIN=$PWD/target/release/frankenctl "
    "./scripts/run_bd_28otw_attacker_harness.sh --trials 100 "
    "--artifact-root artifacts/red_team_scenario_corpus_measurement --run-id <run-id> "
    "--code-revision $(git rev-parse HEAD) --timeout-seconds 20 && "
    "./target/release/franken_red_team_harness_gate "
    "--input artifacts/red_team_scenario_corpus_measurement/<run-id>/aggregate/harness_output.json "
    "--output artifacts/red_team_scenario_corpus_measurement/<run-id>/claim_verdict.json "
    "--markdown artifacts/red_team_scenario_corpus_measurement/<run-id>/claim_verdict.md"
)
FE_014_DOWNGRADE = (
    "TARGETED: two independently observed features ship, but the three-feature floor is not "
    "met because FE-CLAIM-011 still lacks a current non-fixture v2 scenario-corpus campaign "
    "and passing linked Rust claim verdict."
)
FE_014_REASON = (
    "The catalog gate validates three bundle schemas and hashes, but the third named item is "
    "still a target metric outcome. The exact v2 Node/Bun/FrankenEngine producer, scoped "
    "replay verifier, ten-scenario contract, 100-repetition stability floor, one-scenario "
    "zero-cell guard, and sole Rust verdict gate now exist; however, no current non-fixture "
    "FE-CLAIM-011 campaign plus passing franken_red_team_harness_gate verdict is preserved "
    "and linked. Two independently observed features do not meet the three-feature floor."
)

HUMAN_FE_011 = (
    "| `FE-CLAIM-011` | security | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:58` | "
    "`target` | exact v2 producer, scoped replay, and sole Rust verdict path ship over ten "
    "contract-declared scenarios with 100 stability repetitions per runtime/scenario pair "
    "and a one-scenario zero-cell guard; promotion still waits on a current non-fixture v2 "
    "campaign plus passing linked verdict | `bd-1vwza` |"
)
HUMAN_FE_014 = (
    "| `FE-CLAIM-014` | capability | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:61` | "
    "`target` | two independently observed features ship; the third catalog entry depends "
    "on FE-CLAIM-011, whose exact v2 producer and verdict gate ship but still lack a current "
    "non-fixture campaign plus passing linked Rust verdict, so the three-feature floor is not "
    "met | `bd-cixqu.6.6` |"
)
README_FE_011 = (
    "| Red-team compromise-rate comparison | TARGETED | The exact v2 path executes ten "
    "contract-declared scenarios under pinned FrankenEngine, Node, and Bun binaries, requires "
    "100 receipt-bound stability/replay repetitions per pair, and applies a one-scenario "
    "zero-cell guard in the sole Rust verdict gate; no current non-fixture v2 campaign plus "
    "passing verdict is preserved and linked. |"
)
README_FE_014 = (
    "| At-least-three production features impossible by default in Node/Bun | TARGETED | The "
    "catalog validates three named bundle shapes and hashes, but its third entry depends on "
    "FE-CLAIM-011, whose exact v2 producer and verdict gate ship but still lack a current "
    "non-fixture campaign plus passing linked Rust verdict; two independently observed "
    "features do not satisfy the three-feature floor. |"
)
PLAN_FE_011 = (
    "- `>= 10x` reduction in successful red-team host compromise rate versus baseline "
    "Node/Bun default posture. **Target pending a current non-fixture v2 ten-scenario "
    "campaign, scoped replay, and passing Rust claim verdict.**"
)
CHANGELOG_HEADING = (
    "## Post-Snapshot Update — FE-CLAIM-011 Scenario-Corpus Truth Repair (2026-08-31)"
)
CHANGELOG_SECTION = f"""{CHANGELOG_HEADING}

The red-team compromise-rate lane was rebuilt around an exact machine contract
instead of allowing repeated deterministic executions to inflate the apparent
denominator. `docs/red_team_scenario_corpus_v2.json` now fixes ten distinct
security-critical scenarios, their attack classes, three runtime identities, a
100-repetition stability/replay floor per runtime/scenario pair, a one-scenario
zero-cell guard, and `franken_red_team_harness_gate` as the sole claim-verdict
producer.

### Delivered capability

- **Real comparator execution with receipt-bound identity.** Node, Bun, and
  FrankenEngine execute the same manifest-bound scenarios; executable, script,
  manifest, transcript, and witness identities are hash-bound.
- **Proof-class separation.** Each repetition is explicitly receipt-only, the
  aggregate is explicitly input-only, and neither may self-promote
  `FE-CLAIM-011`. Repetitions establish stability and replayability, not
  independent population confidence.
- **Conservative scenario-corpus metric.** The Rust verdict operates on ten
  distinct scenarios and treats a zero FrankenEngine cell as one hypothetical
  compromised scenario before checking the `>=10x` floor. A five-scenario
  zero-cell result therefore cannot manufacture an infinite or passing ratio.
- **Fail-closed scoped aggregation.** Exact scenario/class/runtime identity,
  complete matrices, stable outcomes, scoped replay commands, and hash rebinding
  are enforced; semantic finalization failure overwrites any lower-level stale
  success with `fail_closed`.
- **Focused and live workflows.** The focused gate exercises machine-contract,
  proof-class, receipt, replay, tamper, formatting, and Rust CLI drills. The
  live workflow pins Node/Bun, preserves the exact corpus contract and complete
  evidence bundle even on failure, and emits JSON/Markdown from the sole Rust
  verdict gate.

`FE-CLAIM-011` remains **TARGETED**. The producer/verifier system is implemented,
but no current non-fixture v2 campaign plus passing Rust verdict is yet preserved
and linked from the authoritative claim matrix. `FE-CLAIM-014` therefore also
remains TARGETED.

### Key files

- `docs/red_team_scenario_corpus_v2.json`
- `scripts/red_team_scenario_corpus_contract.py`
- `scripts/red_team_compromise_rate_corpus.py`
- `scripts/red_team_scenario_corpus_harness.py`
- `crates/franken-engine/src/bin/franken_red_team_harness_gate.rs`
- `docs/RED_TEAM_REPEATED_TRIAL_HARNESS.md`
- `docs/FE_CLAIM_011_IMPLEMENTATION_STATUS.md`

---
"""


class ReconcileError(RuntimeError):
    pass


def load_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ReconcileError(f"{path} must contain a JSON object")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def claim_by_id(matrix: dict[str, Any], claim_id: str) -> dict[str, Any]:
    claims = matrix.get("claims")
    if not isinstance(claims, list):
        raise ReconcileError("matrix claims must be an array")
    matches = [claim for claim in claims if isinstance(claim, dict) and claim.get("claim_id") == claim_id]
    if len(matches) != 1:
        raise ReconcileError(f"expected one {claim_id} row, found {len(matches)}")
    return matches[0]


def replace_prefixed_line(text: str, prefix: str, replacement: str, label: str) -> str:
    lines = text.splitlines()
    indexes = [index for index, line in enumerate(lines) if line.startswith(prefix)]
    if len(indexes) != 1:
        raise ReconcileError(f"expected one {label} line, found {len(indexes)}")
    lines[indexes[0]] = replacement
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def reconcile_matrix() -> None:
    matrix = load_json_object(MATRIX_PATH)
    fe_011 = claim_by_id(matrix, "FE-CLAIM-011")
    if fe_011.get("actual_wording_state") != "target" or fe_011.get("allowed_state") != "target":
        raise ReconcileError("FE-CLAIM-011 must remain target during reconciliation")
    fe_011["decision"] = FE_011_DECISION
    fe_011["reason"] = FE_011_REASON
    fe_011["freshness_tier_rationale"] = FE_011_FRESHNESS_RATIONALE
    fe_011["verification_command"] = FE_011_VERIFY

    fe_014 = claim_by_id(matrix, "FE-CLAIM-014")
    if fe_014.get("actual_wording_state") != "target" or fe_014.get("allowed_state") != "target":
        raise ReconcileError("FE-CLAIM-014 must remain target during reconciliation")
    fe_014["downgrade_text"] = FE_014_DOWNGRADE
    fe_014["reason"] = FE_014_REASON

    write_json(MATRIX_PATH, matrix)
    MATRIX_MIRROR_PATH.write_bytes(MATRIX_PATH.read_bytes())


def reconcile_markdown() -> None:
    human = HUMAN_MATRIX_PATH.read_text(encoding="utf-8")
    human = replace_prefixed_line(human, "| `FE-CLAIM-011` |", HUMAN_FE_011, "human FE-CLAIM-011")
    human = replace_prefixed_line(human, "| `FE-CLAIM-014` |", HUMAN_FE_014, "human FE-CLAIM-014")
    HUMAN_MATRIX_PATH.write_text(human, encoding="utf-8")

    readme = README_PATH.read_text(encoding="utf-8")
    readme = replace_prefixed_line(
        readme,
        "| Red-team compromise-rate comparison |",
        README_FE_011,
        "README FE-CLAIM-011",
    )
    readme = replace_prefixed_line(
        readme,
        "| At-least-three production features impossible by default in Node/Bun |",
        README_FE_014,
        "README FE-CLAIM-014",
    )
    README_PATH.write_text(readme, encoding="utf-8")

    plan = PLAN_PATH.read_text(encoding="utf-8")
    plan = replace_prefixed_line(plan, "- `>= 10x` reduction", PLAN_FE_011, "plan FE-CLAIM-011")
    PLAN_PATH.write_text(plan, encoding="utf-8")

    changelog = CHANGELOG_PATH.read_text(encoding="utf-8")
    if CHANGELOG_HEADING not in changelog:
        marker = "\n---\n\n## Post-Snapshot Update — Current window"
        if marker not in changelog:
            raise ReconcileError("CHANGELOG insertion marker not found")
        changelog = changelog.replace(marker, "\n---\n\n" + CHANGELOG_SECTION + "\n## Post-Snapshot Update — Current window", 1)
        CHANGELOG_PATH.write_text(changelog, encoding="utf-8")


def verify() -> None:
    required = [MATRIX_PATH, MATRIX_MIRROR_PATH, HUMAN_MATRIX_PATH, README_PATH, PLAN_PATH, CHANGELOG_PATH, STATUS_PATH, CORPUS_PATH]
    missing = [str(path.relative_to(ROOT)) for path in required if not path.is_file()]
    if missing:
        raise ReconcileError(f"required files missing: {missing}")
    if MATRIX_PATH.read_bytes() != MATRIX_MIRROR_PATH.read_bytes():
        raise ReconcileError("claim-matrix JSON mirrors are not byte-identical")

    matrix = load_json_object(MATRIX_PATH)
    fe_011 = claim_by_id(matrix, "FE-CLAIM-011")
    fe_014 = claim_by_id(matrix, "FE-CLAIM-014")
    expected_011 = {
        "actual_wording_state": "target",
        "allowed_state": "target",
        "decision": FE_011_DECISION,
        "reason": FE_011_REASON,
        "freshness_tier_rationale": FE_011_FRESHNESS_RATIONALE,
        "verification_command": FE_011_VERIFY,
    }
    expected_014 = {
        "actual_wording_state": "target",
        "allowed_state": "target",
        "downgrade_text": FE_014_DOWNGRADE,
        "reason": FE_014_REASON,
    }
    for field, expected in expected_011.items():
        if fe_011.get(field) != expected:
            raise ReconcileError(f"FE-CLAIM-011 {field} drift: {fe_011.get(field)!r}")
    for field, expected in expected_014.items():
        if fe_014.get(field) != expected:
            raise ReconcileError(f"FE-CLAIM-014 {field} drift: {fe_014.get(field)!r}")

    checks = {
        HUMAN_MATRIX_PATH: [HUMAN_FE_011, HUMAN_FE_014],
        README_PATH: [README_FE_011, README_FE_014],
        PLAN_PATH: [PLAN_FE_011],
        CHANGELOG_PATH: [CHANGELOG_HEADING],
    }
    for path, needles in checks.items():
        text = path.read_text(encoding="utf-8")
        for needle in needles:
            if needle not in text:
                raise ReconcileError(f"{path.relative_to(ROOT)} missing reconciled text: {needle[:80]!r}")

    status = STATUS_PATH.read_text(encoding="utf-8")
    if "**Public state:** **TARGETED**" not in status:
        raise ReconcileError("implementation status must keep FE-CLAIM-011 TARGETED")
    corpus = load_json_object(CORPUS_PATH)
    if corpus.get("corpus_id") != "red_team_security_critical_compromise_v2":
        raise ReconcileError("unexpected FE-CLAIM-011 corpus ID")
    if len(corpus.get("scenarios", [])) != 10:
        raise ReconcileError("FE-CLAIM-011 corpus must contain ten scenarios")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Reconcile FE-CLAIM-011/014 docs without promoting either claim")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.write:
            reconcile_matrix()
            reconcile_markdown()
        verify()
        print("fe_claim_011_docs_reconciliation=pass")
        return 0
    except (OSError, json.JSONDecodeError, ReconcileError) as error:
        print(f"FE-CLAIM-011 docs reconciliation blocked: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
