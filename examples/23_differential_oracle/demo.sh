#!/usr/bin/env bash
# Differential Oracle demo (E2.DOC, bd-fqlfw.2.9).
#
# Runs a tiny corpus through `frankenctl oracle run` across the two hermetic
# in-process lanes (franken-engine + franken-core), emits a content-addressed
# bundle (manifest.json + report.json + repro.lock) per case, and re-verifies each
# bundle byte-identically with `frankenctl oracle report`. Then it demonstrates the
# fail-closed DEGRADED path when a requested reference runtime is unavailable.
#
# No node/bun is required: the consensus corpus uses the in-process lanes, and the
# degraded demonstration points --node-bin at a non-existent binary deliberately.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
cd "$repo_root"

# Locate frankenctl (prefer $FRANKENCTL_BIN, then release, then debug).
bin=""
if [[ -n "${FRANKENCTL_BIN:-}" && -x "${FRANKENCTL_BIN}" ]]; then
  bin="${FRANKENCTL_BIN}"
elif [[ -x target/release/frankenctl ]]; then
  bin="target/release/frankenctl"
elif [[ -x target/debug/frankenctl ]]; then
  bin="target/debug/frankenctl"
else
  echo "frankenctl not found. Build it first:" >&2
  echo "  cargo build --release -p frankenengine-engine --bin frankenctl" >&2
  exit 2
fi

out="${script_dir}/out"
rm -rf "$out"
mkdir -p "$out"

verdict_of() {  # read --json summary from stdin, print a one-line verdict
  python3 -c "import sys,json
d=json.load(sys.stdin)
print('  integrity=%s verdict=%s degraded=%s exit=%s'
      % (d.get('integrity','-'), d['semantic_verdict'], d['degraded'], d['exit_code']))" 2>/dev/null \
    || echo "  (could not parse summary)"
}

echo "== Differential oracle: franken-engine <-> franken-core (hermetic) =="
for case in "${script_dir}"/corpus/*.js; do
  name="$(basename "${case%.js}")"
  echo "--- ${name}: $(cat "$case") ---"
  "$bin" oracle run "$case" --engines franken,core --bundle "$out/$name" --json | verdict_of
  echo "  re-verify (byte-identical):"
  "$bin" oracle report "$out/$name" --json | verdict_of
  echo "  bundle: examples/23_differential_oracle/out/${name}/ (manifest.json + report.json + repro.lock)"
done

echo
echo "== Fail-closed DEGRADED path (requested reference runtime unavailable) =="
echo "--- franken,node with a non-existent node binary ---"
if "$bin" oracle run "${script_dir}/corpus/arith_sum.js" --engines franken,node \
     --node-bin /nonexistent/franken_oracle_demo_node \
     --bundle "$out/degraded" --json | verdict_of; then :; fi
if [[ -f "$out/degraded/degraded_receipt.json" ]]; then
  echo "  degraded receipt written: examples/23_differential_oracle/out/degraded/degraded_receipt.json"
  python3 -c "import json;d=json.load(open('$out/degraded/degraded_receipt.json'));print('  error_code=%s verdict=%s' % (d['error_code'], d['verdict']))" 2>/dev/null || true
fi

echo
echo "Done. Inspect a repro.lock with:  jq . examples/23_differential_oracle/out/arith_sum/repro.lock"
echo "Operator runbook: docs/DW_DIFFERENTIAL_ORACLE_V1.md"
