#!/usr/bin/env python3
"""Generate the BRIDGE tracker closeout manifest (v1) from one exact tracker snapshot.

Owning bead: bd-performance-conformance-bridge-tu32j.22.61
([BRIDGE-21.61] Enforce decomposed-parent closeout and exact required-child completion)

Reads `.beads/beads.db` READ-ONLY inside a single deferred transaction (one exact
snapshot), walks the `parent-child` dependency tree rooted at the program root,
applies the typed classifications fixed by the owning bead's description, and
emits a canonical, content-hashed JSON manifest.

Typed exception kinds (from the bead text):
  pre_harness_architecture - architecture/approval contract exempt from the
                             red-first harness ordering (explicitly NOT
                             implementation): BRIDGE-05.6.1 only.
  post_cert_research       - post-certification research that does NOT block its
                             production parent but is required by named
                             downstream nodes: BRIDGE-05.6.33 only.
  external_owner           - required node owned outside the agent fleet; the
                             manifest records the external owner role instead of
                             silently omitting it.

Stage/authority markers are metadata only (they document ordering intent);
closure ordering itself is enforced by requiring complete subtrees before any
decomposed parent closes.

Usage:
  python3 scripts/gen_bridge_closeout_manifest.py [--db PATH] [--out PATH] [--check]

--check re-runs generation and fails if the committed manifest differs (used by
the smoke drill to pin determinism).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = REPO_ROOT / ".beads" / "beads.db"
DEFAULT_OUT = REPO_ROOT / "docs" / "bridge_closeout_manifest_v1.json"

PROGRAM_ROOT = "bd-performance-conformance-bridge-tu32j"
SCHEMA_VERSION = "franken-engine.bridge-closeout-manifest.v1"
GATE_ID = "bridge_closeout"
GATE_LABEL = "bridge-manifest"
GATE_PROVIDER = "bridge-closeout-verifier"

# Typed exceptions fixed by the owning bead description. Keys are absolute IDs.
EXCEPTIONS: dict[str, dict] = {
    f"{PROGRAM_ROOT}.6.1": {
        "kind": "pre_harness_architecture",
        "blocks_parent": False,
        "note": "BRIDGE-05.6.1 is the sole architecture/approval pre-harness exception; explicitly not implementation.",
    },
    f"{PROGRAM_ROOT}.6.33": {
        "kind": "post_cert_research",
        "blocks_parent": False,
        "note": (
            "Post-cert research: depends on tu32j.22.11, does not block production "
            "epic/pack closure, and is required instead by BRIDGE-20.7 / BRIDGE-21.26 / frontier closure."
        ),
    },
    f"{PROGRAM_ROOT}.11.1": {
        "kind": "external_owner",
        "blocks_parent": True,
        "external_owner": "apple_adapter",
        "note": "External Apple adapter owner; requirement retained, ownership recorded.",
    },
    f"{PROGRAM_ROOT}.23.10": {
        "kind": "external_owner",
        "blocks_parent": True,
        "external_owner": "confidentiality_owner",
        "note": "External confidentiality owner; requirement retained, ownership recorded.",
    },
}

# Stage/authority/capstone markers: metadata documenting declared order roles.
STAGE_MARKERS: dict[str, dict] = {
    f"{PROGRAM_ROOT}.22.41": {"stage": "red_first_harness"},
    f"{PROGRAM_ROOT}.22.11": {"stage": "post_implementation_independent_verdict"},
    f"{PROGRAM_ROOT}.3.11": {"authority": "physical_executor"},
    f"{PROGRAM_ROOT}.6.6": {"capstone": "fixed_rco"},
    f"{PROGRAM_ROOT}.6.7": {"capstone": "cross_platform_product"},
}

# Cross-node requirements: closing KEY requires the listed beads closed normally.
CROSS_REQUIREMENTS: dict[str, list[str]] = {
    f"{PROGRAM_ROOT}.21.7": [f"{PROGRAM_ROOT}.6.33"],
    f"{PROGRAM_ROOT}.22.26": [f"{PROGRAM_ROOT}.6.33"],
}


def load_snapshot(db_path: Path) -> tuple[dict[str, dict], dict[str, list[str]]]:
    """Read issues + parent-child edges in ONE deferred transaction."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        conn.execute("BEGIN DEFERRED")
        issues: dict[str, dict] = {}
        for row in conn.execute(
            "SELECT id, title, status FROM issues WHERE deleted_at IS NULL"
        ):
            issues[row[0]] = {"id": row[0], "title": row[1], "status_at_gen": row[2]}
        children: dict[str, list[str]] = {}
        for parent, child in conn.execute(
            "SELECT depends_on_id, issue_id FROM dependencies WHERE type = 'parent-child'"
        ):
            children.setdefault(parent, []).append(child)
        conn.execute("COMMIT")
    finally:
        conn.close()
    for ids in children.values():
        ids.sort()
    return issues, children


def build_manifest(db_path: Path) -> dict:
    issues, children = load_snapshot(db_path)
    if PROGRAM_ROOT not in issues:
        raise SystemExit(f"program root {PROGRAM_ROOT} not found in tracker")

    nodes: dict[str, dict] = {}

    def visit(node_id: str) -> int:
        if node_id in nodes:
            return 0
        entry = issues.get(node_id)
        if entry is None:
            # Listed elsewhere by an edge but physically absent/deleted: keep a
            # placeholder so drift verification can name it.
            entry = {"id": node_id, "title": "<absent-at-generation>", "status_at_gen": "absent"}
        node = dict(entry)
        kids = sorted(children.get(node_id, []))
        node["children"] = kids
        if node_id in EXCEPTIONS:
            node["exception"] = EXCEPTIONS[node_id]
        if node_id in STAGE_MARKERS:
            node["markers"] = STAGE_MARKERS[node_id]
        if node_id in CROSS_REQUIREMENTS:
            node["requires_closed"] = CROSS_REQUIREMENTS[node_id]
        nodes[node_id] = node
        count = 1
        for kid in kids:
            count += visit(kid)
        return count

    total = visit(PROGRAM_ROOT)
    unknown_exc = sorted(set(EXCEPTIONS) - set(nodes))
    if unknown_exc:
        raise SystemExit(
            "exception IDs absent from the live tree (regenerate manually): "
            + ", ".join(unknown_exc)
        )

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "owning_bead": f"{PROGRAM_ROOT}.22.61",
        "generated_from_db": str(db_path),
        "program_root": PROGRAM_ROOT,
        "enforcement": {
            "policy_file": ".beads/policy.yaml",
            "gate_id": GATE_ID,
            "gate_label": GATE_LABEL,
            "gate_provider": GATE_PROVIDER,
            "allow_bypass": False,
        },
        "typed_exception_kinds": {
            "pre_harness_architecture": "architecture/approval contract exempt from red-first ordering; never implementation",
            "post_cert_research": "does not block production parent; required by explicitly listed downstream closures",
            "external_owner": "required node with recorded external owner; never silently omitted",
        },
        "nodes": {k: nodes[k] for k in sorted(nodes)},
        "stats": {
            "node_count": len(nodes),
            "reachable_node_count": total,
            "decomposed_parent_count": sum(1 for n in nodes.values() if n["children"]),
            "leaf_count": sum(1 for n in nodes.values() if not n["children"]),
            "exception_count": len(EXCEPTIONS),
        },
    }
    return manifest


def canonical_hash(manifest: dict) -> str:
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", type=Path, default=DEFAULT_DB)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument(
        "--check",
        action="store_true",
        help="verify the committed manifest matches regeneration exactly",
    )
    args = ap.parse_args()

    manifest = build_manifest(args.db)
    manifest.pop("generated_from_db", None)
    digest = canonical_hash(manifest)
    manifest["content_hash"] = digest

    if args.check:
        committed = json.loads(args.out.read_text())
        committed_cmp = dict(committed)
        committed_cmp.pop("generated_from_db", None)
        expected = dict(manifest)
        if committed_cmp == expected:
            print(f"OK manifest matches regeneration ({digest})")
            return 0
        print("FAIL committed manifest differs from regeneration", file=sys.stderr)
        return 1

    args.out.write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n")
    stats = manifest["stats"]
    print(
        f"wrote {args.out} ({digest})\n"
        f"  nodes={stats['node_count']} parents={stats['decomposed_parent_count']} "
        f"leaves={stats['leaf_count']} exceptions={stats['exception_count']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
