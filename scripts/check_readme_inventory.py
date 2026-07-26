#!/usr/bin/env python3
"""Verify README's structural-inventory counts against the tree. Fail closed on drift.

Why (BRIDGE-00.8 item 3)
------------------------
The claim-to-proof matrix governs *capability* wording. Nothing governed *inventory*
wording, so the README architecture tables drifted for two months unnoticed: 495
modules against a real 615, `baseline_interpreter.rs` described as ~31,914 LoC against
a real 98,924, and three named source modules that do not exist at all. A reader who
followed the README to those filenames found nothing.

Regenerating the numbers once fixes the symptom, not the cause. Two days after the
last correction the tree had already moved again (integration tests 1,637 -> 1,649,
gate scripts 292 -> 293, docs 724 -> 726, beads 4,443 -> 4,447). Inventory truth needs
the same treatment as capability truth: enumerable, generated, and gated.

This is the gap-inventory pattern the runtime already uses for `parser_gap_inventory`
and `lowering_gap_inventory` — if something is claimed, it must be measurable, and the
gate must fail closed when the claim drifts from the measurement.

Exact equality is deliberate. A tolerance would mean choosing a threshold below which
the README is allowed to be wrong, and there is no such number for a count that a
generator can produce exactly.

`--fix` rewrites the numbers in place, so complying is one command rather than a
reason to bypass the gate. It only substitutes digits inside existing lines, never
adds or removes any, because `docs/claim_to_proof_matrix_v1.json` pins README claim
spans by line number and a reflow would silently shift every span below the edit.

Usage
-----
    python3 scripts/check_readme_inventory.py [--json PATH] [--fix]

Exit codes
----------
    0  every counted surface matches (or --fix applied the corrections)
    1  drift detected
    2  a README row could not be parsed (the format moved; the gate is not silently
       narrowing its own coverage)
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
README = REPO / "README.md"


@dataclass
class Surface:
    key: str
    # Regex with exactly one capture group holding the number to check. Anchored on
    # enough surrounding prose that it cannot match a different row by accident.
    pattern: str
    measure: str  # human description of how the truth is computed
    value: int
    # Advisory rows are reported and corrected by --fix but do not fail the gate.
    #
    # Reserved for counts that move through routine traffic rather than deliberate
    # engineering acts. The bead ledger is the only one: every `br update` across
    # every agent changes it, many times a day, so gating it hard would keep the
    # gate red for reasons no README edit can durably fix. A gate that is always
    # red gets bypassed, and then the eleven rows that DO track real structural
    # change stop being enforced too. Everything else here moves only when somebody
    # adds a module, script, doc, test, or fuzz target.
    advisory: bool = False


def _count_files(rel: str, pattern: str, maxdepth1: bool = True) -> int:
    base = REPO / rel
    if not base.is_dir():
        return 0
    globber = base.glob if maxdepth1 else base.rglob
    return sum(1 for p in globber(pattern) if p.is_file())


def measure() -> list[Surface]:
    src = REPO / "crates/franken-engine/src"
    lib_rs = src / "lib.rs"
    baseline = src / "baseline_interpreter.rs"

    pub_mod = 0
    if lib_rs.is_file():
        pub_mod = sum(
            1 for line in lib_rs.read_text().splitlines() if line.startswith("pub mod ")
        )

    baseline_loc = 0
    if baseline.is_file():
        baseline_loc = len(baseline.read_bytes().split(b"\n")) - 1

    beads = REPO / ".beads/issues.jsonl"
    bead_records = 0
    if beads.is_file():
        bead_records = sum(1 for line in beads.read_text().splitlines() if line.strip())

    docs = REPO / "docs"
    docs_top = 0
    if docs.is_dir():
        docs_top = sum(
            1 for p in docs.iterdir() if p.is_file() and p.suffix in (".md", ".json")
        )

    return [
        Surface(
            "src_modules",
            r"\| Source modules in `crates/franken-engine/src/` \| ([\d,]+) top-level",
            "top-level .rs files in crates/franken-engine/src/",
            _count_files("crates/franken-engine/src", "*.rs"),
        ),
        Surface(
            "pub_mod",
            r"top-level `\.rs` files / ([\d,]+) `pub mod` declarations",
            "lines starting `pub mod ` in lib.rs",
            pub_mod,
        ),
        Surface(
            "baseline_loc",
            r"`baseline_interpreter\.rs` alone is ~[\d.]+ MB / ([\d,]+) LoC",
            "line count of baseline_interpreter.rs",
            baseline_loc,
        ),
        Surface(
            "bin_files",
            r"\| Internal operator binaries in `crates/franken-engine/src/bin/` \| ([\d,]+) `\.rs` files",
            "top-level .rs files in crates/franken-engine/src/bin/",
            _count_files("crates/franken-engine/src/bin", "*.rs"),
        ),
        Surface(
            "integration_tests",
            r"\| Integration tests in `crates/franken-engine/tests/` \| ([\d,]+) top-level files",
            "top-level files in crates/franken-engine/tests/",
            sum(1 for p in (REPO / "crates/franken-engine/tests").iterdir() if p.is_file())
            if (REPO / "crates/franken-engine/tests").is_dir()
            else 0,
        ),
        Surface(
            "rgc_gate_tests",
            r"top-level files \(([\d,]+) are RGC gate tests\)",
            "crates/franken-engine/tests/rgc_*.rs",
            _count_files("crates/franken-engine/tests", "rgc_*.rs"),
        ),
        Surface(
            "gate_scripts",
            r"\| Operator gate scripts in `scripts/run_\*\.sh` \| ([\d,]+) ",
            "scripts/run_*.sh",
            _count_files("scripts", "run_*.sh"),
        ),
        Surface(
            "replay_wrappers",
            r"\| Replay wrappers in `scripts/e2e/\*_replay\.sh` \| ([\d,]+) ",
            "scripts/e2e/*_replay.sh",
            _count_files("scripts/e2e", "*_replay.sh"),
        ),
        Surface(
            "docs_top_level",
            r"\| Architecture / contract docs in `docs/` \| ([\d,]+) top-level files",
            "top-level *.md and *.json in docs/",
            docs_top,
        ),
        Surface(
            "bead_records",
            r"\| Tracked beads in `\.beads/issues\.jsonl` \| ([\d,]+) records",
            "non-blank lines in .beads/issues.jsonl",
            bead_records,
            advisory=True,
        ),
        Surface(
            "fuzz_top",
            r"across two trees: ([\d,]+) in top-level `fuzz/fuzz_targets/`",
            "fuzz/fuzz_targets/*.rs",
            _count_files("fuzz/fuzz_targets", "*.rs"),
        ),
        Surface(
            "fuzz_crate",
            r"\+ ([\d,]+) in `crates/franken-engine/fuzz/fuzz_targets/`",
            "crates/franken-engine/fuzz/fuzz_targets/*.rs",
            _count_files("crates/franken-engine/fuzz/fuzz_targets", "*.rs"),
        ),
    ]


def fmt(value: int) -> str:
    """Match the README's thousands separators so --fix is a pure digit swap."""
    return f"{value:,}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify README structural-inventory counts against the tree (BRIDGE-00.8)."
    )
    parser.add_argument("--json", dest="json_path", default="")
    parser.add_argument(
        "--fix",
        action="store_true",
        help="rewrite drifted numbers in place (line-count neutral)",
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    if not README.is_file():
        print("error: README.md not found", file=sys.stderr)
        return 2

    text = README.read_text()
    original_line_count = text.count("\n")
    surfaces = measure()

    rows, unparsed, drifted, advisory_drift = [], [], [], []
    for surface in surfaces:
        match = re.search(surface.pattern, text)
        if match is None:
            unparsed.append(surface.key)
            rows.append(
                {
                    "surface": surface.key,
                    "status": "unparsed",
                    "measured": surface.value,
                    "measure": surface.measure,
                }
            )
            continue

        claimed = int(match.group(1).replace(",", ""))
        matches = claimed == surface.value
        if not matches:
            if surface.advisory:
                advisory_drift.append(surface.key)
            else:
                drifted.append(surface.key)
            if args.fix:
                start, end = match.span(1)
                text = text[:start] + fmt(surface.value) + text[end:]
        rows.append(
            {
                "surface": surface.key,
                "status": "ok" if matches else ("advisory_drift" if surface.advisory else "drift"),
                "claimed": claimed,
                "measured": surface.value,
                "measure": surface.measure,
                "advisory": surface.advisory,
            }
        )

    if args.fix and (drifted or advisory_drift):
        if text.count("\n") != original_line_count:
            print(
                "error: --fix would change README line count; refusing, because "
                "docs/claim_to_proof_matrix_v1.json pins claim spans by line number",
                file=sys.stderr,
            )
            return 2
        README.write_text(text)

    report = {
        "schema_version": "franken-engine.readme-inventory-report.v1",
        "owning_bead": "bd-performance-conformance-bridge-tu32j.1.8",
        "summary": {
            "checked": len(rows),
            "ok": sum(1 for r in rows if r["status"] == "ok"),
            "drift": len(drifted),
            "advisory_drift": len(advisory_drift),
            "unparsed": len(unparsed),
            "fix_applied": bool(args.fix and (drifted or advisory_drift)),
        },
        "rows": rows,
    }

    if args.json_path:
        out = Path(args.json_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    if not args.quiet:
        s = report["summary"]
        print(
            f"readme_inventory=checked={s['checked']} ok={s['ok']} "
            f"drift={s['drift']} advisory_drift={s['advisory_drift']} "
            f"unparsed={s['unparsed']}" + (" fix_applied=1" if s["fix_applied"] else "")
        )
        for row in rows:
            if row["status"] in ("drift", "advisory_drift"):
                verb = "corrected" if args.fix else "README claims"
                tag = " [advisory]" if row["advisory"] else ""
                print(
                    f"  {row['surface']}{tag}: {verb} {row['claimed']:,}, measured "
                    f"{row['measured']:,} ({row['measure']})",
                    file=sys.stderr,
                )
            elif row["status"] == "unparsed":
                print(
                    f"  {row['surface']}: could not locate its README row -- the table "
                    f"format moved; update the pattern rather than dropping coverage",
                    file=sys.stderr,
                )

    # An unparsed row is exit 2, not 1: the gate cannot report drift it can no longer
    # see, and silently checking fewer surfaces is the failure mode this replaces.
    if unparsed:
        return 2
    if drifted and not args.fix:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
