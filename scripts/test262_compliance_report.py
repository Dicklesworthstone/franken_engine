#!/usr/bin/env python3
"""Cross-harness ES2020 conformance compliance report generator.

Closes audit finding **FIND-20** (`bd-13rib`). Companion to
`scripts/test262_markdown_scoreboard.py` (FIND-6/16): the scoreboard
renders one gate run; this script renders the cross-harness
**compliance matrix** (every §-section the engine claims to cover,
every harness that anchors it, every test id) that downstream tooling
(matrix-promotion gates, audit reports, PR-comment bots) reads to
decide whether the engine ships.

Inputs
------
- The 11 `tests/*_test262_conformance.rs` harness files (read for
  `es_section` / `es2020_section` / `spec_section` tags + per-case ids
  + `RequirementLevel` annotations).
- (Optional) `--gate-manifest <path>` — if a gate run-manifest is
  provided, the report folds its per-run pass/fail/waived counts into
  the Summary section.

Outputs
-------
- Markdown to `--output <path>` (or stdout when `--output -`, the
  default).
- (Optional) `--json <path>` writes a machine-readable JSON sibling so
  the matrix-promotion gate / CI badges can consume it directly.

This script intentionally requires only the Python standard library so
it can run anywhere `python3` is on PATH. Run it from the repo root:

```
python3 scripts/test262_compliance_report.py \
    --tests-root crates/franken-engine/tests \
    --output     docs/conformance/COMPLIANCE_REPORT.md \
    --json       artifacts/test262_compliance_report.json
```
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import pathlib
import re
import sys
from typing import Any


# Field-name drift across harnesses (see FIND-12 `bd-cd0px`):
TAG_FIELD_NAMES: tuple[str, ...] = ("es_section", "es2020_section", "spec_section")

# ECMA-262 ES2020 budget sourced from
# `crates/franken-engine/docs/CONFORMANCE_HARNESS_MANIFEST.md`.
DEFAULT_MUST_BUDGET = 1847
DEFAULT_SHOULD_BUDGET = 423
PROMOTION_THRESHOLD = 0.95


def sec_key(section: str) -> tuple[Any, ...]:
    """Sort key for an ECMA-262 §-section identifier (numeric tuple)."""
    parts: list[tuple[int, int | str]] = []
    for component in section.split("."):
        try:
            parts.append((0, int(component)))
        except ValueError:
            parts.append((1, component))
    return tuple(parts)


def extract_harness_tags(harness_path: pathlib.Path) -> list[dict[str, str | None]]:
    """Scan one harness file for tagged test cases.

    Returns a list of `{section, test_id, level, field_name}` dicts —
    one per `es*_section` occurrence. `level` and `test_id` may be
    `None` when the extractor's 400-char window does not find a
    matching `RequirementLevel` or `id` field.
    """
    src = harness_path.read_text()
    cases: list[dict[str, str | None]] = []
    for field in TAG_FIELD_NAMES:
        for match in re.finditer(rf'{field}:\s*"([^"]*)"', src):
            section = match.group(1)
            if not section:
                continue
            window_start = max(0, match.start() - 400)
            window_end = min(len(src), match.end() + 400)
            window = src[window_start:window_end]
            level_match = re.search(
                r"requirement_level:\s*RequirementLevel::(\w+)", window
            )
            id_match = re.search(r'id:\s*"([^"]+)"', window)
            cases.append(
                {
                    "section": section,
                    "test_id": id_match.group(1) if id_match else None,
                    "level": level_match.group(1) if level_match else None,
                    "field_name": field,
                }
            )
    return cases


def build_matrix(tests_root: pathlib.Path) -> dict[str, Any]:
    harness_paths = sorted(
        p
        for p in tests_root.iterdir()
        if p.name.endswith(".rs")
        and "test262" in p.name
        and "conformance" in p.name
    )

    per_harness: dict[str, list[dict[str, str | None]]] = {}
    per_harness_fields: dict[str, set[str]] = {}
    section_index: dict[str, dict[str, list[dict[str, str | None]]]] = (
        collections.defaultdict(lambda: collections.defaultdict(list))
    )
    must_total = 0
    should_total = 0
    other_total = 0
    case_total = 0

    for path in harness_paths:
        short = path.name.removesuffix("_test262_conformance.rs")
        cases = extract_harness_tags(path)
        per_harness[short] = cases
        per_harness_fields[short] = {c["field_name"] for c in cases}
        for case in cases:
            section_index[case["section"]][short].append(case)
            case_total += 1
            if case["level"] == "Must":
                must_total += 1
            elif case["level"] == "Should":
                should_total += 1
            else:
                other_total += 1

    return {
        "harness_paths": [str(p.relative_to(tests_root.parent.parent.parent)) for p in harness_paths]
        if tests_root.parent.parent.parent
        else [p.name for p in harness_paths],
        "per_harness_case_count": {h: len(c) for h, c in per_harness.items()},
        "per_harness_fields": {h: sorted(f) for h, f in per_harness_fields.items()},
        "section_index": {
            sec: {h: [{"test_id": c["test_id"], "level": c["level"]} for c in cs] for h, cs in by_harness.items()}
            for sec, by_harness in section_index.items()
        },
        "totals": {
            "tagged_cases": case_total,
            "must_cases": must_total,
            "should_cases": should_total,
            "unresolved_level_cases": other_total,
            "distinct_sections": len(section_index),
            "harnesses_with_tags": sum(1 for cs in per_harness.values() if cs),
        },
    }


def maybe_load_gate_manifest(path: pathlib.Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        gate = json.loads(path.read_text())
    except FileNotFoundError:
        sys.exit(f"error: gate manifest not found: {path}")
    except json.JSONDecodeError as exc:
        sys.exit(f"error: malformed gate manifest JSON at {path}: {exc}")
    runner = gate.get("runner_artifacts") or {}
    runner_manifest_path = runner.get("runner_manifest")
    runner_data = None
    if runner_manifest_path:
        runner_data = json.loads(pathlib.Path(runner_manifest_path).read_text())
    return {"gate": gate, "runner": runner_data}


def build_markdown(matrix: dict[str, Any], gate: dict[str, Any] | None) -> str:
    totals = matrix["totals"]
    lines: list[str] = []
    lines.append("# ECMA-262 ES2020 Compliance Report")
    lines.append("")
    lines.append(
        "> Generated by `scripts/test262_compliance_report.py` — the"
        " load-bearing cross-harness compliance matrix the audit"
        " (`bd-85qfs`) flagged as missing in FIND-20 (`bd-13rib`)."
    )
    lines.append(
        "> See also: [`docs/ECMA262_CONFORMANCE_TARGET.md`](../ECMA262_CONFORMANCE_TARGET.md),"
        " [`docs/conformance/ECMA262_COVERAGE.md`](./ECMA262_COVERAGE.md),"
        " [`docs/conformance/SPEC_TO_TEST_TRACEABILITY.md`](./SPEC_TO_TEST_TRACEABILITY.md),"
        " [`docs/conformance/SHOULD_COVERAGE.md`](./SHOULD_COVERAGE.md)."
    )
    lines.append("")

    lines.append("## Headline counts")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| --- | ---: |")
    lines.append(f"| Harnesses with tagged cases | {totals['harnesses_with_tags']} |")
    lines.append(f"| Distinct §-sections covered | {totals['distinct_sections']} |")
    lines.append(f"| Tagged test cases | {totals['tagged_cases']} |")
    lines.append(f"| MUST-tier cases | {totals['must_cases']} |")
    lines.append(f"| SHOULD-tier cases | {totals['should_cases']} |")
    lines.append(f"| Unresolved-level cases | {totals['unresolved_level_cases']} |")
    lines.append("")

    if gate is not None:
        runner = gate.get("runner") or {}
        passed = runner.get("passed", 0)
        total = runner.get("total_profile_tests", 0)
        outcome = gate["gate"].get("outcome", "unknown")
        pass_rate = (passed / total) if total else None
        lines.append("## Latest gate run")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("| --- | --- |")
        lines.append(f"| Outcome | `{outcome}` |")
        lines.append(f"| Passed / total | {passed} / {total} |")
        if pass_rate is not None:
            lines.append(f"| Pass rate | {pass_rate * 100:.2f}% |")
            if pass_rate >= PROMOTION_THRESHOLD:
                lines.append(f"| 0.95 threshold | ✓ above |")
            else:
                lines.append(f"| 0.95 threshold | ✗ below |")
        lines.append("")

    lines.append("## Per-harness summary")
    lines.append("")
    lines.append("| Harness | Field name(s) | Tagged cases |")
    lines.append("| --- | --- | ---: |")
    for harness in sorted(matrix["per_harness_case_count"].keys()):
        count = matrix["per_harness_case_count"][harness]
        fields = matrix["per_harness_fields"][harness] or ["(none)"]
        lines.append(f"| `{harness}` | {' / '.join(fields)} | {count} |")
    lines.append("")

    lines.append("## §-section → covering harness/test ids")
    lines.append("")
    lines.append("| §-section | Harness | Level breakdown | Test ids |")
    lines.append("| --- | --- | --- | --- |")
    for sec in sorted(matrix["section_index"].keys(), key=sec_key):
        by_harness = matrix["section_index"][sec]
        for harness in sorted(by_harness.keys()):
            cases = by_harness[harness]
            levels: dict[str, int] = collections.Counter(c["level"] or "?" for c in cases)
            level_breakdown = " ".join(f"{lvl}×{cnt}" for lvl, cnt in sorted(levels.items()))
            test_ids = [c["test_id"] for c in cases if c["test_id"]]
            if not test_ids:
                ids_str = "(no resolved ids)"
            elif len(test_ids) <= 3:
                ids_str = "; ".join(f"`{tid}`" for tid in test_ids)
            else:
                ids_str = f"`{test_ids[0]}` + {len(test_ids) - 1} more"
            lines.append(f"| §{sec} | `{harness}` | {level_breakdown} | {ids_str} |")
    lines.append("")

    lines.append("## Notes for reviewers")
    lines.append("")
    lines.append(
        "- Field-name drift (`es_section` / `es2020_section` /"
        " `spec_section`) is the FIND-12 (`bd-cd0px`) tracking item."
    )
    lines.append(
        "- Cases with `?` in the Level column carry a §-section tag but"
        " the extractor did not find a `RequirementLevel` field within"
        " the 400-character window around the section — usually because"
        " the harness struct uses a different field layout. Pair-fix"
        " with FIND-12."
    )
    lines.append(
        "- This report is **the** compliance matrix — when a"
        " matrix-promotion gate asks 'what does the engine claim to"
        " cover?', this output is the authoritative answer until the"
        " per-harness `report` types start consuming"
        " `assert_report_round_trips` (FIND-22 `bd-wrmld`) and feeding"
        " into a per-harness aggregator."
    )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--tests-root",
        type=pathlib.Path,
        default=pathlib.Path("crates/franken-engine/tests"),
        help="Path to the directory containing `*_test262_conformance.rs` harnesses.",
    )
    parser.add_argument(
        "--gate-manifest",
        type=pathlib.Path,
        default=None,
        help="Optional path to a `scripts/run_test262_es2020_gate.sh` v2 run_manifest.json; fold its counts into the Summary section.",
    )
    parser.add_argument(
        "--output",
        default="-",
        help="Markdown output path (default: stdout).",
    )
    parser.add_argument(
        "--json",
        type=pathlib.Path,
        default=None,
        help="Optional machine-readable JSON sidecar path for matrix-promotion gates.",
    )
    args = parser.parse_args()

    tests_root = args.tests_root.resolve()
    if not tests_root.is_dir():
        sys.exit(f"error: tests root is not a directory: {tests_root}")

    matrix = build_matrix(tests_root)
    gate = maybe_load_gate_manifest(args.gate_manifest)
    markdown = build_markdown(matrix, gate)

    if args.output == "-":
        sys.stdout.write(markdown)
    else:
        output_path = pathlib.Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(markdown)
        print(f"wrote markdown → {output_path}", file=sys.stderr)

    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(matrix, indent=2, sort_keys=True))
        print(f"wrote json → {args.json}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
