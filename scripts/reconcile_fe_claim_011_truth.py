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

FE_011_DECISION = "stay_target_pending_real_comparator_bundle"
FE_011_REASON = (
    "The gate now launches FrankenEngine, Node, and Bun for every declared scenario, "
    "requires an explicit per-runtime disposition, and emits hash-bound executable, "
    "transcript, script, manifest, and witness identities. Missing runtimes, crashes, "
    "timeouts, malformed output, and ambiguous dispositions produce a blocker rather "
    "than a favorable containment result. FE-CLAIM-011 remains target because no fresh "
    "non-fixture bundle from real installed runtimes with a statistically adequate "
    "repeated-trial denominator has been committed."
)
FE_014_DOWNGRADE = (
    "TARGETED: two independently observed features ship, but the three-feature floor "
    "is not met because FE-CLAIM-011 still lacks a fresh non-fixture observed "
    "Node/Bun/FrankenEngine comparator bundle."
)
FE_014_REASON = (
    "The catalog gate validates three bundle schemas and hashes, but the third named "
    "item is still a target metric outcome. Execution-capable Node, Bun, and "
    "FrankenEngine comparators now exist, yet no qualifying non-fixture FE-CLAIM-011 "
    "bundle demonstrates the >=10x reduction on real installed runtimes with a "
    "statistically adequate repeated-trial denominator. Two independently observed "
    "features do not meet the three-feature floor."
)

README_REPLACEMENTS = (
    (
        "| Red-team compromise-rate comparison | TARGETED | Live FrankenEngine adversarial probes exist, but the published gate hardcodes the Node/Bun baseline outcomes instead of executing comparable reference-runtime scenarios. |",
        "| Red-team compromise-rate comparison | TARGETED | The gate now executes the same declared scenarios under FrankenEngine, Node, and Bun and emits hash-bound runtime receipts, but no fresh non-fixture real-runtime bundle with a statistically adequate repeated-trial denominator has been committed. |",
    ),
    (
        "| At-least-three production features impossible by default in Node/Bun | TARGETED | The catalog validates three named bundle shapes and hashes, but its third entry is the unsupported Node/Bun compromise-rate comparison; two independently observed features do not satisfy the three-feature floor. |",
        "| At-least-three production features impossible by default in Node/Bun | TARGETED | The catalog validates three named bundle shapes and hashes, but its third entry depends on FE-CLAIM-011, whose execution-capable comparator still lacks a fresh non-fixture real-runtime proof bundle; two independently observed features do not satisfy the three-feature floor. |",
    ),
)

HUMAN_REPLACEMENTS = (
    (
        "| `FE-CLAIM-011` | security | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:58` | `target` | FrankenEngine probes execute, but Node/Bun baseline outcomes are hardcoded and no comparable reference-runtime receipts exist | `bd-1vwza` |",
        "| `FE-CLAIM-011` | security | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:58` | `target` | all three runtime lanes now execute with hash-bound receipts and ambiguity blockers; promotion still waits on a fresh non-fixture real-runtime bundle with an adequate repeated-trial denominator | `bd-1vwza` |",
    ),
    (
        "| `FE-CLAIM-014` | capability | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:61` | `target` | two independently observed features ship; the third catalog entry depends on FE-CLAIM-011's unexecuted Node/Bun comparison, so the three-feature floor is not met | `bd-cixqu.6.6` |",
        "| `FE-CLAIM-014` | capability | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:61` | `target` | two independently observed features ship; the third catalog entry depends on FE-CLAIM-011, whose executed comparator still lacks a fresh non-fixture real-runtime proof bundle, so the three-feature floor is not met | `bd-cixqu.6.6` |",
    ),
)

IMPLEMENTATION_STATUS: dict[str, Any] = {
    "claim_id": "FE-CLAIM-011",
    "claim_state": "target",
    "comparator_contract": {
        "declared_runtimes": ["frankenengine", "node", "bun"],
        "failure_semantics": (
            "missing runtime, timeout, crash, malformed output, or ambiguous disposition "
            "blocks the measurement and emits no placeholder scenario rows"
        ),
        "identity_binding": [
            "runtime executable path and sha256",
            "runtime version command and output",
            "scenario script path and sha256",
            "scenario manifest path and sha256",
            "stdout, stderr, exit status, and duration",
            "per-runtime transcript sha256",
            "per-scenario witness sha256",
        ],
        "scenario_set": "red_team_security_critical_compromise_v1",
    },
    "implementation_commits": [
        "173cc39c55cf1b224a564e58953804795f472c03",
        "2fe9d2ed117d410ae039491e7877156cbaa1e7a6",
        "6278ae25205d54356740fbfdd2afb9ad78e81117",
        "b03543d359c7e0cd3a9c8a1e4f0b9b058325f7e4",
        "ce31f684d8bf30a4b956c54c8816e30cfa415a29",
    ],
    "implementation_state": "executed_comparator_available",
    "measurement_state": "pending_fresh_real_non_fixture_bundle",
    "promotion_requirements": [
        "run the declared scenario set with real installed FrankenEngine, Node, and Bun executables",
        "preserve non-fixture hash-bound receipts for every runtime and scenario",
        "use a declared statistically adequate repeated-trial denominator rather than a single binary outcome per scenario",
        "demonstrate at least a 10x compromise-rate reduction against the conservative Node/Bun reference rate",
        "commit the complete proof bundle and repro.lock at the exact measured revision",
    ],
    "schema_version": "franken-engine.fe-claim-011-implementation-status.v1",
    "verification_commands": [
        "python3 -m py_compile scripts/red_team_compromise_rate_metric.py",
        "bash scripts/e2e/red_team_compromise_rate_metric_comparator_smoke.sh",
        "./scripts/run_red_team_compromise_rate_metric_gate.sh ci",
    ],
}


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

    return [
        PlannedWrite(canonical_path, canonical_before, canonical_after),
        PlannedWrite(mirror_path, mirror_before, canonical_after),
        PlannedWrite(human_path, human_before, human_after),
        PlannedWrite(readme_path, readme_before, readme_after),
        PlannedWrite(status_path, status_before, status_after),
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
