#!/usr/bin/env python3
"""Fail closed when a `[patch.*]` entry substitutes an API-incompatible crate.

Why this exists (bd-h5cl7)
--------------------------
The workspace used to carry:

    [patch.crates-io]
    fsqlite = { path = "/dp/frankensqlite/crates/fsqlite" }

`sqlmodel-frankensqlite` declares `fsqlite = "0.1.18"`. Local `/dp/frankensqlite`
was `0.1.19`, and had shipped a breaking sync -> async API under that patch-level
bump. Under Cargo's 0.x rules `^0.1.18` admits `0.1.19`, so the substitution
applied *silently*: 33 sync call sites met Futures, the engine's default build
went red, and 7 of the 16 OBSERVED claims became unverifiable because their
verification commands are default-feature builds.

Nothing in the tree noticed. `test_standalone_build.sh` scans only
`crates/franken-engine/Cargo.toml`, so it never saw the root patch block;
`sqlite_policy_guard.rs` explicitly excludes `patch.crates-io`; and
`audit_external_deps.sh` sees the lines but never compares versions.

The rule
--------
For every patched crate, the substituted version must be EXACTLY the version each
consumer declares -- not merely semver-compatible with it.

Semver compatibility is deliberately not the test. A patch that points at a
development checkout can acquire unreleased breaking changes at any moment, which
is precisely what a version requirement cannot see. `^0.1.18` admitting `0.1.19`
is what let this failure through. Requiring exact equality turns a silent
mis-pairing into a loud one, and costs only an explicit version bump when a
sibling genuinely releases.

A requirement that cannot be reduced to a single exact version (a range such as
`>=0.1, <0.3`) is itself the ambiguity being guarded against, and fails closed.

Operation
---------
Patch tables are read straight from the manifests with `tomllib`, so the check
runs even when the tree does not compile -- which is the state it exists to
diagnose. `cargo metadata` is consulted only when at least one patch entry is
present; it resolves without compiling, and it is the only source that sees
consumers living outside this repository (the offending consumer was in
/dp/sqlmodel_rust). With no patch entries the check is instant and needs no cargo.

Usage
-----
    python3 scripts/check_patch_version_consistency.py [--json PATH] [--quiet]

Exit codes
----------
    0  every patched crate is exactly pinned to what its consumers declare
    1  skew detected (fail closed)
    2  usage / IO / cargo-metadata error
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# `--repo-root` exists so the negative drill can build a synthetic skewed
# workspace and prove this guard actually fires. A gate nobody has watched fail
# is not evidence. It defaults to the real repository, so the shipped invocation
# cannot be aimed somewhere harmless by accident.

# Manifests whose `[patch.*]` tables are load-bearing. Both are listed explicitly
# rather than globbed: the root and fuzz manifests carried byte-identical patch
# blocks and drifted apart unnoticed, so the guard names them and fails if one
# goes missing rather than silently checking fewer files.
PATCHED_MANIFESTS = (
    Path("Cargo.toml"),
    Path("crates/franken-engine/fuzz/Cargo.toml"),
)

# `0.1.18`, `^0.1.18`, `=0.1.18` -> an exact pin. Anything else is a range.
EXACT_REQ = re.compile(r"^[\^=]?(\d+)\.(\d+)\.(\d+)$")
# `0.1`, `^0.1` -> pins major.minor only.
PARTIAL_REQ = re.compile(r"^[\^=]?(\d+)\.(\d+)$")


@dataclass
class PatchEntry:
    """One `name = { ... }` line inside a `[patch.<registry>]` table."""

    manifest: str
    registry: str
    crate: str
    source_kind: str  # "path" | "git" | "version" | "unknown"
    source: str


@dataclass
class Finding:
    code: str
    crate: str
    detail: str
    remediation: str


@dataclass
class Report:
    schema_version: str = "franken-engine.patch-version-consistency.v1"
    owning_bead: str = "bd-h5cl7"
    patch_entries: list[dict] = field(default_factory=list)
    checked_pairs: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    decision: str = "pass"


def read_manifest(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def collect_patch_entries(repo: Path) -> tuple[list[PatchEntry], list[Finding]]:
    """Read every `[patch.<registry>]` table out of the declared manifests."""
    entries: list[PatchEntry] = []
    findings: list[Finding] = []

    for rel in PATCHED_MANIFESTS:
        manifest_path = repo / rel
        if not manifest_path.is_file():
            findings.append(
                Finding(
                    code="FE-PATCH-MANIFEST-MISSING",
                    crate="-",
                    detail=f"declared manifest {rel} does not exist",
                    remediation=(
                        "Update PATCHED_MANIFESTS in "
                        "scripts/check_patch_version_consistency.py if the "
                        "manifest moved, so the guard keeps covering it."
                    ),
                )
            )
            continue

        patch_table = read_manifest(manifest_path).get("patch", {})
        for registry, crates in patch_table.items():
            if not isinstance(crates, dict):
                continue
            for crate, spec in crates.items():
                if isinstance(spec, str):
                    kind, source = "version", spec
                elif isinstance(spec, dict):
                    for candidate in ("path", "git", "version"):
                        if candidate in spec:
                            kind, source = candidate, str(spec[candidate])
                            break
                    else:
                        kind, source = "unknown", json.dumps(spec, sort_keys=True)
                else:
                    kind, source = "unknown", repr(spec)
                entries.append(
                    PatchEntry(
                        manifest=str(rel),
                        registry=str(registry),
                        crate=str(crate),
                        source_kind=kind,
                        source=source,
                    )
                )

    return entries, findings


def load_cargo_metadata(repo: Path) -> dict:
    """Resolve the dependency graph without compiling anything."""
    completed = subprocess.run(
        ["cargo", "metadata", "--format-version", "1"],
        cwd=repo,
        capture_output=True,
        timeout=300,
        env={**_clean_env(), "RCH_CARGO_WRAPPER_BYPASS": "1"},
    )
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace")[-4000:]
        raise RuntimeError(f"cargo metadata failed:\n{stderr}")
    return json.loads(completed.stdout)


def _clean_env() -> dict[str, str]:
    import os

    env = dict(os.environ)
    # Inherited encoded flags confuse a bare `cargo metadata` invocation.
    env.pop("CARGO_ENCODED_RUSTFLAGS", None)
    return env


def exact_pin(req: str) -> tuple[str, str] | None:
    """Reduce a version requirement to the single version it pins, if it does.

    Returns (kind, pinned) where kind is "exact" (x.y.z) or "partial" (x.y).
    Returns None for anything that admits more than one release line.
    """
    req = req.strip()
    match = EXACT_REQ.match(req)
    if match:
        return "exact", ".".join(match.groups())
    match = PARTIAL_REQ.match(req)
    if match:
        return "partial", ".".join(match.groups())
    return None


def check(entries: list[PatchEntry], metadata: dict) -> tuple[list[dict], list[Finding]]:
    """Compare each patched crate's resolved version against every declared req."""
    packages = metadata.get("packages", [])
    patched_names = {entry.crate for entry in entries}

    # name -> the versions actually resolved into the graph
    resolved: dict[str, list[dict]] = {}
    for package in packages:
        name = package.get("name")
        if name in patched_names:
            resolved.setdefault(name, []).append(package)

    pairs: list[dict] = []
    findings: list[Finding] = []

    for name in sorted(patched_names):
        resolutions = resolved.get(name, [])
        if not resolutions:
            # The patch names a crate nothing in the graph depends on. Cargo warns
            # about this and ignores it; we record it because an unused patch is
            # dead weight that will silently start applying if a dep is added.
            findings.append(
                Finding(
                    code="FE-PATCH-UNUSED",
                    crate=name,
                    detail=(
                        f"`{name}` is patched but does not appear in the resolved "
                        f"graph, so the patch has no effect today"
                    ),
                    remediation=(
                        f"Drop the `{name}` entry from the `[patch.*]` table, or "
                        f"add the dependency the patch was meant to redirect."
                    ),
                )
            )
            continue

        for package in resolutions:
            version = package.get("version", "")
            for consumer in packages:
                for dep in consumer.get("dependencies", []):
                    if dep.get("name") != name:
                        continue
                    req = str(dep.get("req", ""))
                    pin = exact_pin(req)
                    pair = {
                        "crate": name,
                        "resolved_version": version,
                        "consumer": consumer.get("name"),
                        "consumer_version": consumer.get("version"),
                        "declared_req": req,
                        "dependency_kind": dep.get("kind") or "normal",
                    }

                    if pin is None:
                        pair["verdict"] = "unpinnable"
                        pairs.append(pair)
                        findings.append(
                            Finding(
                                code="FE-PATCH-REQ-NOT-EXACT",
                                crate=name,
                                detail=(
                                    f"{consumer.get('name')} declares `{name} = "
                                    f'"{req}"`, a range that does not reduce to one '
                                    f"version, so a patched substitution cannot be "
                                    f"verified"
                                ),
                                remediation=(
                                    f"Pin {consumer.get('name')}'s `{name}` "
                                    f"requirement to an exact version, or stop "
                                    f"patching `{name}`."
                                ),
                            )
                        )
                        continue

                    kind, pinned = pin
                    if kind == "exact":
                        matches = version == pinned
                        expected = pinned
                    else:
                        matches = ".".join(version.split(".")[:2]) == pinned
                        expected = f"{pinned}.x"

                    pair["verdict"] = "match" if matches else "skew"
                    pair["expected_version"] = expected
                    pairs.append(pair)

                    if not matches:
                        findings.append(
                            Finding(
                                code="FE-PATCH-VERSION-SKEW",
                                crate=name,
                                detail=(
                                    f"`[patch]` resolves `{name}` to {version}, but "
                                    f"{consumer.get('name')} "
                                    f"{consumer.get('version')} declares "
                                    f'`{name} = "{req}"` (expects {expected}). The '
                                    f"substituted crate may carry breaking changes "
                                    f"the requirement cannot express."
                                ),
                                remediation=(
                                    f"Either bump {consumer.get('name')} to declare "
                                    f"{version} and migrate its call sites, or remove "
                                    f"the `{name}` `[patch]` entry so it resolves to "
                                    f"the {expected} it was written against."
                                ),
                            )
                        )

    return pairs, findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Fail closed when a [patch.*] entry substitutes a crate whose version "
            "is not exactly what its consumers declare (bd-h5cl7)."
        )
    )
    parser.add_argument("--json", dest="json_path", default="", help="write the report here")
    parser.add_argument("--quiet", action="store_true", help="suppress the human summary")
    parser.add_argument(
        "--repo-root",
        default=str(REPO),
        help="workspace to inspect (defaults to this repository; used by the negative drill)",
    )
    args = parser.parse_args()

    repo = Path(args.repo_root).resolve()
    report = Report()

    try:
        entries, findings = collect_patch_entries(repo)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        print(f"error: could not read manifests: {exc}", file=sys.stderr)
        return 2

    report.patch_entries = [vars(entry) for entry in entries]

    if entries:
        try:
            metadata = load_cargo_metadata(repo)
        except (OSError, RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        pairs, skew_findings = check(entries, metadata)
        report.checked_pairs = pairs
        findings.extend(skew_findings)

    report.findings = [vars(finding) for finding in findings]
    report.decision = "fail_closed" if findings else "pass"

    if args.json_path:
        out = Path(args.json_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(vars(report), indent=2, sort_keys=True) + "\n")

    if not args.quiet:
        if not entries:
            print(
                "patch_version_consistency=pass patch_entries=0 "
                "(no [patch.*] table in any declared manifest)"
            )
        else:
            matched = sum(1 for p in report.checked_pairs if p.get("verdict") == "match")
            print(
                f"patch_version_consistency={report.decision} "
                f"patch_entries={len(entries)} pairs={len(report.checked_pairs)} "
                f"matched={matched} findings={len(findings)}"
            )
        for finding in findings:
            print(f"  [{finding.code}] {finding.crate}: {finding.detail}", file=sys.stderr)
            print(f"      remediation: {finding.remediation}", file=sys.stderr)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
