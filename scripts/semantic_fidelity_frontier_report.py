#!/usr/bin/env python3
"""Render a scoped semantic-fidelity frontier ingest report."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


INGEST_SCHEMA_VERSION = "franken-engine.semantic-fidelity-frontier-ingest.v1"
ERROR_SCHEMA_VERSION = "franken-engine.semantic-fidelity-frontier-report-error.v1"
SCOPE = "semantic_fidelity_subset"
CLAIM_POLICY = "no_claim_promotion"

STATE_ORDER = [
    "accepted_external_oracle",
    "mismatch",
    "unsupported",
    "expected_unknown",
    "malformed",
    "declared_non_execution",
    "degraded",
]
COVERAGE_ORDER = [
    "eligible_subset_row",
    "non_passing_scoped_evidence",
    "fail_closed",
]


class ReportError(ValueError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def read_json(path: Path) -> dict[str, Any]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ReportError("missing_ingest_bundle", f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ReportError("malformed_ingest_bundle", f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ReportError("malformed_ingest_bundle", f"{path} must contain a JSON object")
    return loaded


def validate_bundle(bundle: dict[str, Any]) -> None:
    if bundle.get("schema_version") != INGEST_SCHEMA_VERSION:
        raise ReportError("schema_version_mismatch", "unexpected ingest schema_version")
    if bundle.get("scope") != SCOPE:
        raise ReportError("unsupported_scope", "ingest bundle is not semantic_fidelity_subset")
    if bundle.get("claim_policy") != CLAIM_POLICY:
        raise ReportError("claim_policy_violation", "ingest bundle may not promote claims")
    rows = bundle.get("rows")
    if not isinstance(rows, list) or not rows:
        raise ReportError("malformed_ingest_bundle", "ingest bundle rows must be non-empty")


def cell(value: Any) -> str:
    text = str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |"]
    lines.append("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        lines.append("| " + " | ".join(cell(value) for value in row) + " |")
    return lines


def sorted_unique(values: list[str]) -> list[str]:
    return sorted({value for value in values if value})


def counts_for(rows: list[dict[str, Any]], field: str, order: list[str]) -> list[list[Any]]:
    counts = Counter(str(row.get(field, "")) for row in rows)
    return [[name, counts.get(name, 0)] for name in order]


def cluster_rows(rows: list[dict[str, Any]]) -> list[list[Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[str(row["cluster_id"])].append(row)
    rendered: list[list[Any]] = []
    for cluster_id in sorted(groups):
        group = sorted(groups[cluster_id], key=lambda row: (row["vector_id"], row["route"]["route_id"]))
        rendered.append(
            [
                cluster_id,
                ", ".join(sorted_unique([str(row.get("semantic_family", "")) for row in group])),
                ", ".join(sorted_unique([str(row.get("route", {}).get("route_kind", "")) for row in group])),
                ", ".join(sorted_unique([str(row.get("oracle_mode", "")) for row in group])),
                ", ".join(sorted_unique([str(row.get("scope_state", "")) for row in group])),
                len(group),
                ", ".join(str(row["vector_id"]) for row in group),
            ]
        )
    return rendered


def non_passing_rows(rows: list[dict[str, Any]]) -> list[list[Any]]:
    selected = [
        row
        for row in rows
        if row.get("coverage_counting") != "eligible_subset_row"
        or row.get("scope_state") != "accepted_external_oracle"
    ]
    rendered: list[list[Any]] = []
    for row in sorted(selected, key=lambda item: (item["vector_id"], item["route"]["route_id"])):
        rendered.append(
            [
                row["vector_id"],
                row["route"]["route_id"],
                row["scope_state"],
                row.get("unsupported_reason"),
                row["coverage_counting"],
                ", ".join(row.get("related_bead_ids", [])),
            ]
        )
    return rendered


def render_report(bundle: dict[str, Any]) -> str:
    validate_bundle(bundle)
    rows = bundle["rows"]
    generated_from = bundle["generated_from"]
    related_beads = sorted_unique(
        [
            bead
            for row in rows
            for bead in row.get("related_bead_ids", [])
        ]
    )
    lines: list[str] = [
        "# Semantic Fidelity Frontier Subset Report",
        "",
        f"Scope: `{bundle['scope']}`",
        f"Claim policy: `{bundle['claim_policy']}`",
        f"Source bundle: `{generated_from['source_bundle_path']}`",
        f"Source suite: `{generated_from['source_suite_id']}`",
        f"Rows: {len(rows)}",
        "",
        "This report is scoped evidence for the semantic-fidelity subset only. It is not full E7 coverage, not a Test262 coverage percentage, and not claim-to-proof matrix promotion evidence.",
        "",
        "## Scope State Counts",
        "",
    ]
    lines.extend(table(["Scope state", "Rows"], counts_for(rows, "scope_state", STATE_ORDER)))
    lines.extend(["", "## Coverage Counting", ""])
    lines.extend(table(["Coverage class", "Rows"], counts_for(rows, "coverage_counting", COVERAGE_ORDER)))
    lines.extend(["", "## Clusters", ""])
    lines.extend(
        table(
            [
                "Cluster",
                "Semantic family",
                "Route kinds",
                "Oracle modes",
                "States",
                "Rows",
                "Vectors",
            ],
            cluster_rows(rows),
        )
    )
    lines.extend(["", "## Non-Passing Scoped Evidence", ""])
    non_passing = non_passing_rows(rows)
    if non_passing:
        lines.extend(
            table(
                ["Vector", "Route", "State", "Reason", "Coverage", "Related beads"],
                non_passing,
            )
        )
    else:
        lines.append("No non-passing scoped evidence rows are present.")
    lines.extend(["", "## Related Beads", ""])
    for bead in related_beads:
        lines.append(f"- `{bead}`")
    lines.extend(
        [
            "",
            "## Claim Hygiene",
            "",
            "Rows with `declared_non_execution`, `expected_unknown`, `unsupported`, `degraded`, `mismatch`, or `malformed` state cannot be counted as passing coverage. `accepted_external_oracle` rows are eligible only inside this `semantic_fidelity_subset` report.",
        ]
    )
    return "\n".join(lines) + "\n"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ingest", required=True, type=Path, help="Frontier ingest JSON bundle")
    parser.add_argument("--out", type=Path, help="Write report Markdown to this path")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    report = render_report(read_json(args.ingest))
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except ReportError as exc:
        error = {
            "schema_version": ERROR_SCHEMA_VERSION,
            "ok": False,
            "reason_code": exc.reason_code,
            "message": str(exc),
        }
        sys.stderr.write(json.dumps(error, sort_keys=True) + "\n")
        raise SystemExit(2)
