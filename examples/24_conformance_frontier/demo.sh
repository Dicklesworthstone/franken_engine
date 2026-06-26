#!/usr/bin/env bash
# Conformance Frontier demo (E7.DOC, bd-fqlfw.7.7).
#
# Runs the `franken_coverage_frontier` operator binary over the hermetic
# `franken-engine` <-> `franken-core` differential-oracle seed corpus (no Test262
# checkout, no network, no real bead filing) and walks the four read modes:
#
#   1. --rank             the impact-ranked worklist (what to fix first)
#   2. --coverage-summary the six weighted ES2020 views + headline + floor view
#   3. --file-beads       the gated, plan-only auto-bead-filing plan + E4 scaffold
#   4. dedup + determinism: the plan is byte-identical across runs, and a cluster
#                           already in the dedup ledger is skipped (idempotent)
#
# Nothing here mutates the real bead tracker: --file-beads is plan-only (no
# --execute), and the dedup step seeds a throwaway ledger under out/.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
cd "$repo_root"

# Locate the binary (prefer $FRONTIER_BIN, then release, then debug).
bin=""
if [[ -n "${FRONTIER_BIN:-}" && -x "${FRONTIER_BIN}" ]]; then
  bin="${FRONTIER_BIN}"
elif [[ -x target/release/franken_coverage_frontier ]]; then
  bin="target/release/franken_coverage_frontier"
elif [[ -x target/debug/franken_coverage_frontier ]]; then
  bin="target/debug/franken_coverage_frontier"
else
  echo "franken_coverage_frontier not found. Build it first:" >&2
  echo "  cargo build --release -p frankenengine-engine --bin franken_coverage_frontier" >&2
  exit 2
fi

out="${script_dir}/out"
rm -rf "$out"
mkdir -p "$out"

src=(--engine-core-oracle)   # hermetic in-process seed corpus

echo "== 1. Ranked worklist (impact = failing_count × usage × locality) =="
"$bin" "${src[@]}" --rank --out "$out/rank.json" >/dev/null
python3 - "$out/rank.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(f"  {d['cluster_count']} cluster(s); digest {d['report_digest'][:16]}…")
for c in d["ranked"][:3]:
    s = c["score"]
    print(f"  #{c['rank']} {c['construct']:<14} impact={s['impact_millionths']/1_000_000:.6f}  ({c['source']})")
    print(f"     {s['explanation']}")
PY

echo
echo "== 2. Weighted ES2020 coverage summary (six views + headline + floor) =="
"$bin" "${src[@]}" --coverage-summary --out "$out/summary.json" >/dev/null
python3 - "$out/summary.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
hp = d["observable_surface_executed_millionths"] / 10_000.0
fp = d["floor_view_executed_millionths"] / 10_000.0
print(f"  headline executed = {hp:.4f}%  ({d['in_scope_passed']}/{d['in_scope_total']} in-scope)")
print(f"  floor view '{d['floor_view']}' = {fp:.4f}%  (the weakest view — a single number cannot hide it)")
for v in d["views"]:
    print(f"    {v['view']:<22} {v['executed_millionths']/10_000.0:7.4f}%  ({v['passed']}/{v['total']})")
if d["in_scope_total"] == 0:
    print("  NOTE: the headline figure is a *Test262-surface* measure, so the hermetic")
    print("        oracle source above contributes 0 surface records — this run shows the")
    print("        SHAPE (six views + floor), not a populated figure. Feed a Test262 source")
    print("        (--report <conformance.json> / --run-suite <tc39/test262>) for real numbers.")
print("  'executed' = evaluated without an engine error / correctly rejected; assertion")
print("  outcomes are NOT verified -> execution coverage, not a conformance pass-rate.")
print("  The full-corpus figure (~13.05%, weakest view 'builtin' ~1.67%) is published as")
print("  FE-CLAIM-026 (TARGETED); the stricter conformance pass-rate is far lower (~0.25%).")
PY

echo
echo "== 3. Auto-bead-filing PLAN (plan-only; nothing is filed) =="
"$bin" "${src[@]}" --file-beads --out "$out/plan_a.json" >/dev/null
python3 - "$out/plan_a.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(f"  considered={d['considered_count']} proposals={d['proposal_count']} "
      f"skipped={d['skipped_count']}; plan digest {d['plan_digest'][:16]}…")
for p in d["proposals"][:2]:
    print(f"  - {p['title']}")
    print(f"    scaffold_kind={p['scaffold_kind']}  priority={p['priority']}  labels={p['labels']}")
    print(f"    reviewable command: {p['br_create_command'][:72]}…")
PY

echo
echo "== 4. Determinism + idempotent dedup (no real beads filed) =="
"$bin" "${src[@]}" --file-beads --out "$out/plan_b.json" >/dev/null
if diff -q "$out/plan_a.json" "$out/plan_b.json" >/dev/null; then
  echo "  determinism: plan_a == plan_b (byte-identical across runs) ✓"
else
  echo "  determinism: plan_a != plan_b — UNEXPECTED" >&2
  exit 1
fi

# Seed a throwaway dedup ledger from plan_a's proposals, then re-run: every seeded
# cluster must be skipped. This proves idempotency WITHOUT touching the real tracker.
python3 - "$out/plan_a.json" "$out/seeded_ledger.json" <<'PY'
import json, sys
plan = json.load(open(sys.argv[1]))
records = {
    p["cluster_id"]: {
        "cluster_id": p["cluster_id"],
        "bead_id": f"bd-demo-{i:04d}",
        "construct": p["construct"],
        "note": "seeded by examples/24_conformance_frontier/demo.sh to show dedup",
    }
    for i, p in enumerate(plan["proposals"], start=1)
}
json.dump(
    {"schema_version": "franken-engine.coverage-frontier-filed-ledger.v1", "records": records},
    open(sys.argv[2], "w"),
    indent=2,
)
print(f"  seeded a throwaway ledger with {len(records)} already-filed cluster(s)")
PY
"$bin" "${src[@]}" --file-beads --ledger "$out/seeded_ledger.json" --out "$out/plan_dedup.json" >/dev/null
python3 - "$out/plan_dedup.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(f"  re-run with seeded ledger: proposals={d['proposal_count']} skipped={d['skipped_count']}")
for s in d["skipped"][:3]:
    print(f"    skipped {s['construct']} ({s['cluster_id'][:12]}…): {s['reason']}")
assert d["proposal_count"] == 0, "expected all seeded clusters to be skipped"
print("  idempotent: an already-filed cluster is never re-proposed ✓")
PY

echo
echo "== 5. Truth gate (cross-reference vs parser/lowering gap inventories) =="
set +e
"$bin" "${src[@]}" --cross-reference --out "$out/xref.json" >/dev/null 2>&1
xref_exit=$?
set -e
python3 - "$out/xref.json" "$xref_exit" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
ec = sys.argv[2]
gate = "PASS" if d["truth_gate_pass"] else "FAIL (undocumented gap -> exit 3, fail-closed)"
print(f"  {d['total_clusters']} clusters -> {d['reconciled_count']} reconciled, "
      f"{d['undocumented_count']} undocumented; gate {gate}; exit={ec}")
print("  (exit 3 here is the gate doing its job: a failure with no inventory entry is")
print("   surfaced rather than allowed to grow the frontier silently.)")
PY

echo
echo "Done. Reports under examples/24_conformance_frontier/out/ (rank/summary/plan/xref)."
echo "Operator runbook: runbooks/dw_conformance_frontier.md"
echo "Full gate:        ./scripts/run_dw_conformance_frontier.sh ci"
