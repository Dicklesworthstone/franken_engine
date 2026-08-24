#!/usr/bin/env python3
"""Verify BRIDGE-manifest closure eligibility for one decomposed-parent bead.

Owning bead: bd-performance-conformance-bridge-tu32j.22.61

Reads `.beads/beads.db` READ-ONLY inside ONE deferred transaction (one exact
tracker snapshot) and checks, for `--issue`:

  1. The issue is manifest-listed and carries the enforcement label.
  2. Live parent-child edges match the manifest exactly for the target and,
     transitively, every manifest-listed descendant:
       - unmanifested child            -> fail_on_unmanifested_drift
       - listed child deleted/absent   -> tombstone_or_missing
       - listed child present, edge removed/moved -> reparented_or_edge_missing
  3. Exact required-child completion: every manifest-listed required node in the
     target's subtree is `closed` with a non-empty close reason and close time.
     Typed exceptions with `blocks_parent: false` are exempt for their own
     ancestor chain (post-cert research, pre-harness architecture contract).
  4. Cross-node requirements (`requires_closed`) hold for the target.
  5. No required node's closure rests on a break-glass gate pass
     (`provider LIKE 'breakglass:%'`): break-glass never counts as normal
     completion.

Exit codes: 0 eligible, 1 violations (each printed), 2 usage/environment error.
With `--json`, emits a machine-readable report instead.

The snapshot digest printed on success binds the verdict to one exact snapshot;
`scripts/run_bridge_closeout_gate.sh` records it in the gate note.
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
DEFAULT_MANIFEST = REPO_ROOT / "docs" / "bridge_closeout_manifest_v1.json"

ENFORCEMENT_LABEL = "bridge-manifest"


class Violations:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    def add(self, code: str, detail: dict) -> None:
        self.rows.append({"code": code, **detail})

    @property
    def ok(self) -> bool:
        return not self.rows


def load_manifest(path: Path) -> dict:
    manifest = json.loads(path.read_text())
    stored = manifest.get("content_hash")
    body = {k: v for k, v in manifest.items() if k != "content_hash"}
    body.pop("generated_from_db", None)
    digest = "sha256:" + hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if stored != digest:
        raise SystemExit(
            f"manifest content_hash mismatch ({stored} != {digest}); regenerate "
            "with scripts/gen_bridge_closeout_manifest.py before verifying"
        )
    return manifest


def snapshot(db_path: Path) -> tuple[dict[str, dict], dict[str, list[str]], dict[str, list[str]], list[tuple]]:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        conn.execute("BEGIN DEFERRED")
        issues: dict[str, dict] = {}
        for row in conn.execute(
            "SELECT id, status, coalesce(close_reason,''), closed_at, deleted_at FROM issues"
        ):
            issues[row[0]] = {
                "status": row[1],
                "close_reason": row[2],
                "closed_at": row[3],
                "deleted": row[4] is not None,
            }
        children: dict[str, list[str]] = {}
        for parent, child in conn.execute(
            "SELECT depends_on_id, issue_id FROM dependencies WHERE type='parent-child'"
        ):
            children.setdefault(parent, []).append(child)
        labels: dict[str, list[str]] = {}
        for issue_id, label in conn.execute("SELECT issue_id, label FROM labels"):
            labels.setdefault(issue_id, []).append(label)
        gates = list(
            conn.execute(
                "SELECT issue_id, gate, provider, passed FROM gate_result_history "
                "WHERE gate = 'bridge_closeout' AND passed = 1"
            )
        )
        conn.execute("COMMIT")
    finally:
        conn.close()
    for ids in children.values():
        ids.sort()
    return issues, children, labels, gates


def subtree(manifest_nodes: dict, root: str) -> list[str]:
    out, stack = [], [root]
    while stack:
        node = stack.pop()
        out.append(node)
        stack.extend(reversed(manifest_nodes[node]["children"]))
    return out



def verify(issue_id: str, manifest: dict, db_path: Path) -> tuple[bool, list[dict], str]:
    nodes = manifest["nodes"]
    issues, children, labels, breakglass_gates = snapshot(db_path)
    v = Violations()

    if issue_id not in nodes:
        v.add("not_manifest_listed", {"issue": issue_id})
        return False, v.rows, ""
    if ENFORCEMENT_LABEL not in labels.get(issue_id, []):
        v.add("missing_enforcement_label", {"issue": issue_id, "label": ENFORCEMENT_LABEL})

    # Edge-exactness for the target and every manifest-listed descendant parent.
    for node_id in subtree(nodes, issue_id):
        node = nodes[node_id]
        expected = set(node["children"])
        live = set(children.get(node_id, []))
        for kid in sorted(expected - live):
            if kid not in issues or issues[kid]["deleted"]:
                v.add("tombstone_or_missing", {"parent": node_id, "child": kid})
            else:
                v.add("reparented_or_edge_missing", {"parent": node_id, "child": kid})
        for kid in sorted(live - expected):
            v.add("fail_on_unmanifested_drift", {"parent": node_id, "child": kid})

    # Required-descendant completion. Typed exceptions with blocks_parent=False
    # are exempt from their own ancestor chain (post-cert research, pre-harness
    # architecture contract); everything else must be closed with evidence.
    exempt_roots = {
        nid
        for nid, n in nodes.items()
        if n.get("exception", {}).get("blocks_parent") is False
    }

    def exempt_from(node_id: str) -> bool:
        # Walk from the node toward the program root. The target is always an
        # ancestor-or-self of the node (the node sits in the target's subtree).
        # The node is exempt iff an exempt root appears on that walk BEFORE the
        # target is reached — i.e. the target does not sit inside the exempt
        # chain.
        cursor, seen = node_id, set()
        while cursor in nodes and cursor not in seen:
            if cursor == issue_id:
                return False
            if cursor in exempt_roots:
                return True
            seen.add(cursor)
            cursor = next(
                (
                    p
                    for p, kids in ((k, w["children"]) for k, w in nodes.items())
                    if cursor in kids
                ),
                None,
            )
        return False

    for node_id in subtree(nodes, issue_id):
        if node_id == issue_id:
            continue
        if node_id in exempt_roots and exempt_from(node_id):
            continue
        state = issues.get(node_id)
        if state is None or state["deleted"]:
            v.add("required_node_missing", {"issue": node_id})
            continue
        if state["status"] != "closed":
            v.add(
                "required_child_not_closed",
                {"issue": node_id, "status": state["status"]},
            )
        elif not state["close_reason"].strip() or not state["closed_at"]:
            v.add(
                "closure_evidence_missing",
                {
                    "issue": node_id,
                    "has_reason": bool(state["close_reason"].strip()),
                    "has_closed_at": bool(state["closed_at"]),
                },
            )

    # Cross-node requirements declared on the target.
    for req in nodes[issue_id].get("requires_closed", []):
        state = issues.get(req)
        if state is None or state["deleted"]:
            v.add("cross_requirement_missing", {"issue": req})
        elif state["status"] != "closed":
            v.add(
                "cross_requirement_not_closed",
                {"issue": req, "status": state["status"]},
            )

    # Gate-pass provenance: only the sanctioned verifier and signed break-glass
    # providers may back a closure. Any other recorded pass is flagged.
    sanctioned = manifest["enforcement"]["gate_provider"]
    unsanctioned = {
        row[0]
        for row in breakglass_gates
        if row[3] and row[1] == "bridge_closeout" and row[2] != sanctioned
        and not row[2].startswith("breakglass:")
    }
    if unsanctioned:
        for node_id in subtree(nodes, issue_id):
            if node_id in unsanctioned:
                v.add(
                    "unsanctioned_gate_pass",
                    {"issue": node_id, "detail": "bridge_closeout pass recorded by a non-sanctioned provider"},
                )

    # Break-glass passes never count as normal completion.
    bg_ids = {row[0] for row in breakglass_gates if row[3] and row[2].startswith("breakglass:")}
    if bg_ids:
        for node_id in subtree(nodes, issue_id):
            if node_id in bg_ids:
                v.add(
                    "breakglass_not_normal_completion",
                    {"issue": node_id, "detail": "closure rests on signed break-glass, not verified completion"},
                )

    # Snapshot digest over the exact rows this verdict saw.
    reach = subtree(nodes, issue_id)
    digest_payload = {
        "target": issue_id,
        "subtree_states": [
            [nid, issues[nid]["status"], issues[nid]["closed_at"]]
            for nid in sorted(reach)
            if nid in issues
        ],
        "edges": {n: nodes[n]["children"] for n in sorted(reach)},
    }
    digest = hashlib.sha256(
        json.dumps(digest_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16]

    return v.ok, v.rows, f"snapshot:{digest}"

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--issue", required=True)
    ap.add_argument("--db", type=Path, default=DEFAULT_DB)
    ap.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args()

    manifest = load_manifest(args.manifest)
    ok, rows, digest = verify(args.issue, manifest, args.db)

    if args.as_json:
        print(json.dumps({"ok": ok, "violations": rows, "snapshot_digest": digest}, indent=2))
    elif ok:
        print(f"ELIGIBLE {args.issue} {digest}")
    else:
        print(f"DENIED {args.issue} ({len(rows)} violation(s)) {digest}")
        for r in rows:
            print(f"  [{r['code']}]", json.dumps({k: val for k, val in r.items() if k != 'code'}, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
