#!/usr/bin/env python3
"""Fail closed on unregistered ISA-specific code paths and on architecture
fingerprints leaking into content-hashed positions (BRIDGE-18.10).

Why
---
`bd-2noh9` was a real shipped defect in this repository: the SWAR lexer disagreed
with the scalar lexer on token output. An architecture-specific path silently
diverged from the portable one. The surviving control from that fix is
`find_mismatch(swar, scalar)` in `simd_lexer.rs`, and it must never be removed.

The surface is about to expand by an order of magnitude -- BRIDGE-10.2 adds
AArch64/NEON code shapes, BRIDGE-11.2 adds Zen4/Zen5 AVX-512 kernels, BRIDGE-07.20
adds guarded vectorization. Today there are ZERO real ISA-specific execution paths,
which is exactly when this gate is cheap to install. After twenty vectorized kernels
exist it is not.

What it checks
--------------
1. **Registration.** Any source file using an ISA-divergent construct (`core::arch`
   or `std::arch` intrinsics, `is_*_feature_detected!`, `std::simd`/`core::simd`)
   must be registered in `docs/isa_specific_path_inventory_v1.json`, which is where
   its portable counterpart and equivalence mechanism are declared. An unregistered
   ISA path fails closed.

2. **Fingerprint containment.** The architecture-fingerprint types
   (`ArchCapabilityProfile`, `ArchFamily`, `SwarDisableReason`, and the
   `*_available` capability flags) must not appear outside their declared owning
   files. Containment is what makes check 3 a complete argument rather than a
   spot check: a type that cannot leave its module cannot reach a hash elsewhere.

3. **Hash inputs are fingerprint-free.** `FE-CLAIM-023` claims cross-platform
   identical-hash reproducibility. If a detected CPU feature ever reaches a content
   hash, two machines produce different hashes for the same input and that claim is
   falsified -- not by a bug in the hash, but by feeding it a host fact. Host facts
   belong in `env.json`, never in an artifact content hash. So no function that
   feeds a hasher may reference an architecture symbol.

4. **cfg-site totals.** `#[cfg(target_arch)]` / `#[cfg(target_feature)]` sites are
   mostly platform plumbing rather than divergent execution, so requiring each to
   register would be noise. Their counts are gated against the inventory instead:
   adding one is a deliberate engineering act, and the inventory must acknowledge
   it. This is the same discipline `parser_gap_inventory` and `lowering_gap_inventory`
   apply -- if something is claimed, it must be measurable, and the gate must fail
   closed when the claim drifts from the measurement.

Usage
-----
    python3 scripts/check_isa_path_registration.py [--json PATH] [--repo-root DIR]

Negative drill: `scripts/e2e/isa_path_registration_drift.sh`.

Exit codes
----------
    0  every check passes
    1  a check failed (unregistered path, leaked fingerprint, or count drift)
    2  the inventory is missing or unparseable -- the gate cannot narrow its own
       coverage silently
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Constructs that create genuinely divergent machine behaviour between ISAs.
# `target_arch` cfg is deliberately NOT here: see check 4.
DIVERGENT_CONSTRUCTS = {
    "core_arch_intrinsics": r"core::arch::",
    "std_arch_intrinsics": r"std::arch::",
    "x86_feature_detection": r"is_x86_feature_detected",
    "aarch64_feature_detection": r"is_aarch64_feature_detected",
    "arm_feature_detection": r"is_arm_feature_detected",
    "portable_simd_std": r"std::simd",
    "portable_simd_core": r"core::simd",
}

# Types and fields that carry a *detected host capability*. Anything derived from
# these varies by machine and must stay out of content hashes.
FINGERPRINT_SYMBOLS = [
    "ArchCapabilityProfile",
    "ArchFamily",
    "SwarDisableReason",
    "avx2_available",
    "avx512f_available",
    "neon_available",
]

# Calls that feed bytes into a content hash or a content-derived identifier.
HASH_SINKS = [
    r"hasher\.update\(",
    r"Sha256::digest\(",
    r"::digest\(",
    r"derive_id\(",
]


def source_files(repo: Path) -> list[Path]:
    """Every crate source file, excluding tests, benches and fuzz trees.

    Tests are excluded on purpose: they legitimately construct synthetic
    `ArchCapabilityProfile`s for other architectures, which is how the parity
    control is exercised on a single host.
    """
    out: list[Path] = []
    crates = repo / "crates"
    if not crates.is_dir():
        return out
    for crate in sorted(crates.iterdir()):
        src = crate / "src"
        if not src.is_dir():
            continue
        out.extend(sorted(p for p in src.rglob("*.rs") if p.is_file()))
    return out


def _rel(repo: Path, path: Path) -> str:
    return path.relative_to(repo).as_posix()


def _hash_input_regions(text: str) -> list[tuple[int, str]]:
    """Bodies of functions that feed a hash sink, as (start_line, body).

    Brace-matched from the `fn` header rather than regex-extracted, so a nested
    closure or match arm inside the function is still covered.
    """
    regions: list[tuple[int, str]] = []
    for match in re.finditer(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+\w+", text, re.M):
        open_brace = text.find("{", match.end())
        if open_brace == -1:
            continue
        depth, index = 0, open_brace
        while index < len(text):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    break
            index += 1
        body = text[open_brace : index + 1]
        if any(re.search(sink, body) for sink in HASH_SINKS):
            regions.append((text.count("\n", 0, match.start()) + 1, body))
    return regions


def run_checks(repo: Path) -> tuple[list[dict], int, dict]:
    """Returns (findings, exit_code, coverage)."""
    inventory_path = repo / "docs/isa_specific_path_inventory_v1.json"
    if not inventory_path.is_file():
        return ([{"check": "inventory", "status": "unparseable",
                  "detail": f"{inventory_path} is missing"}], 2, {})
    try:
        inventory = json.loads(inventory_path.read_text())
    except json.JSONDecodeError as err:
        return ([{"check": "inventory", "status": "unparseable",
                  "detail": f"{inventory_path}: {err}"}], 2, {})

    for required in ("registered_paths", "totals", "fingerprint_owner_files"):
        if required not in inventory:
            return ([{"check": "inventory", "status": "unparseable",
                      "detail": f"inventory has no {required!r} key"}], 2, {})

    # A registered entry may name a file plus a parenthetical locator, e.g.
    # "src/simd_lexer.rs (arch_family reporting, lines ~1167-1205)"; and one entry
    # may brace-list sibling modules. Take every path-shaped token.
    registered: set[str] = set()
    for entry in inventory["registered_paths"]:
        raw = entry.get("path", "")
        brace = re.search(r"\{([^}]*)\}", raw)
        if brace:
            prefix = raw[: brace.start()]
            for name in brace.group(1).split(","):
                registered.add((prefix + name.strip()).strip())
        else:
            registered.add(raw.split(" ")[0].strip())

    owners = set(inventory["fingerprint_owner_files"])
    findings: list[dict] = []
    files = source_files(repo)

    # --- 1. registration -----------------------------------------------------
    construct_counts: dict[str, int] = {name: 0 for name in DIVERGENT_CONSTRUCTS}
    for path in files:
        text = path.read_text(errors="replace")
        hits = {}
        for name, pattern in DIVERGENT_CONSTRUCTS.items():
            found = len(re.findall(pattern, text))
            if found:
                hits[name] = found
                construct_counts[name] += found
        if hits and _rel(repo, path) not in registered:
            findings.append({
                "check": "registration",
                "status": "fail",
                "file": _rel(repo, path),
                "constructs": hits,
                "detail": "ISA-divergent construct in an unregistered file",
                "remedy": "register the path in docs/isa_specific_path_inventory_v1.json "
                          "with its portable counterpart and equivalence mechanism, or "
                          "remove the construct",
            })

    # --- 2. fingerprint containment -----------------------------------------
    for path in files:
        rel = _rel(repo, path)
        if rel in owners:
            continue
        text = path.read_text(errors="replace")
        leaked = [s for s in FINGERPRINT_SYMBOLS if s in text]
        if leaked:
            findings.append({
                "check": "fingerprint_containment",
                "status": "fail",
                "file": rel,
                "symbols": leaked,
                "detail": "architecture fingerprint symbol outside its declared owner",
                "remedy": "keep host capability facts inside the owning module, or add "
                          "the file to fingerprint_owner_files and prove it reaches no "
                          "content hash",
            })

    # --- 3. hash inputs are fingerprint-free --------------------------------
    # Coverage is counted and reported. A structural check like this fails open
    # if its extractor silently stops matching -- a change to how functions are
    # written, or a bad brace match, and it inspects nothing while still exiting
    # 0. Publishing the count makes that visible instead of invisible.
    hash_functions_scanned = 0
    for path in files:
        text = path.read_text(errors="replace")
        for line_number, body in _hash_input_regions(text):
            hash_functions_scanned += 1
            used = [s for s in FINGERPRINT_SYMBOLS if s in body]
            if used:
                findings.append({
                    "check": "fingerprint_in_hash",
                    "status": "fail",
                    "file": _rel(repo, path),
                    "line": line_number,
                    "symbols": used,
                    "detail": "a function feeding a content hash references an "
                              "architecture fingerprint; this falsifies FE-CLAIM-023 "
                              "cross-platform identical-hash reproducibility",
                    "remedy": "host facts belong in env.json, never in an artifact "
                              "content hash",
                })

    # --- 4. cfg-site totals --------------------------------------------------
    measured = {
        "target_arch_cfg_sites": 0,
        "target_feature_sites": 0,
        "core_arch_intrinsics": construct_counts["core_arch_intrinsics"],
        "std_arch_intrinsics": construct_counts["std_arch_intrinsics"],
        "std_simd_or_core_simd": (
            construct_counts["portable_simd_std"] + construct_counts["portable_simd_core"]
        ),
        "is_x86_feature_detected": construct_counts["x86_feature_detection"],
        "is_aarch64_feature_detected": construct_counts["aarch64_feature_detection"],
        "is_arm_feature_detected": construct_counts["arm_feature_detection"],
    }
    for path in files:
        text = path.read_text(errors="replace")
        measured["target_arch_cfg_sites"] += len(re.findall(r"target_arch", text))
        measured["target_feature_sites"] += len(re.findall(r"target_feature", text))

    for key, value in sorted(measured.items()):
        declared = inventory["totals"].get(key)
        if declared is None:
            findings.append({
                "check": "totals",
                "status": "fail",
                "metric": key,
                "measured": value,
                "detail": "inventory declares no total for this metric",
                "remedy": "add the metric to totals in the inventory",
            })
        elif declared != value:
            findings.append({
                "check": "totals",
                "status": "fail",
                "metric": key,
                "declared": declared,
                "measured": value,
                "detail": "inventory total disagrees with the tree",
                "remedy": "re-measure and update docs/isa_specific_path_inventory_v1.json; "
                          "a new architecture-specific site is a deliberate act and the "
                          "inventory must acknowledge it",
            })

    # A check that inspected nothing is not a passing check.
    if not files:
        findings.append({
            "check": "coverage",
            "status": "fail",
            "detail": "no source files were scanned; the gate would pass vacuously",
            "remedy": "check --repo-root; crates/*/src must exist",
        })
    elif hash_functions_scanned == 0:
        findings.append({
            "check": "coverage",
            "status": "fail",
            "detail": f"scanned {len(files)} source files but found 0 hash-input "
                      "functions; the fingerprint-in-hash check inspected nothing",
            "remedy": "the function-body extractor or HASH_SINKS list has stopped "
                      "matching; fix it rather than accepting a vacuous pass",
        })

    coverage = {
        "source_files_scanned": len(files),
        "hash_input_functions_scanned": hash_functions_scanned,
        "fingerprint_owner_files": sorted(owners),
        "registered_paths": len(registered),
    }
    return findings, (1 if findings else 0), coverage


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail closed on unregistered ISA paths and fingerprint-in-hash "
        "leaks (BRIDGE-18.10)."
    )
    parser.add_argument("--json", dest="json_path", default="")
    parser.add_argument(
        "--repo-root",
        default="",
        help="inspect this tree instead of the one containing this script "
        "(used by the negative drill)",
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    repo = Path(args.repo_root).resolve() if args.repo_root else Path(__file__).resolve().parent.parent
    findings, code, coverage = run_checks(repo)

    by_check: dict[str, int] = {}
    for finding in findings:
        by_check[finding["check"]] = by_check.get(finding["check"], 0) + 1

    report = {
        "schema_version": "franken-engine.isa-path-registration-report.v1",
        "owning_bead": "bd-performance-conformance-bridge-tu32j.19.10",
        "repo_root": str(repo),
        "summary": {
            "checks_run": 4,
            "findings": len(findings),
            "by_check": by_check,
            "verdict": "pass" if code == 0 else "fail_closed",
            "coverage": coverage,
        },
        "findings": findings,
    }

    if args.json_path:
        out = Path(args.json_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    if not args.quiet:
        print(
            f"isa_path_registration=verdict={report['summary']['verdict']} "
            f"findings={len(findings)} "
            f"files={coverage.get('source_files_scanned', 0)} "
            f"hash_fns={coverage.get('hash_input_functions_scanned', 0)} "
            + " ".join(f"{k}={v}" for k, v in sorted(by_check.items()))
        )
        for finding in findings:
            where = finding.get("file") or finding.get("metric") or "-"
            print(f"  [{finding['check']}] {where}: {finding['detail']}", file=sys.stderr)
            print(f"      remedy: {finding.get('remedy', '-')}", file=sys.stderr)

    return code


if __name__ == "__main__":
    sys.exit(main())
