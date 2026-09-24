#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

RCH_BIN="${RCH_BIN:-rch}"
RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
CARGO_TARGET_DIR="${QUARANTINE_MESH_DEMO_CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_quarantine_mesh_demo}"

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
  echo "Required rch binary not found: $RCH_BIN" >&2
  exit 2
fi

log_path="$(mktemp "${TMPDIR:-/tmp}/quarantine-mesh-demo.XXXXXX.log")"
json_path="$(mktemp "${TMPDIR:-/tmp}/quarantine-mesh-demo.XXXXXX.json")"
trap 'rm -f "$log_path" "$json_path"' EXIT

set +e
remote_env=(
  "RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN"
  "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS"
)
if [[ -n "$CARGO_TARGET_DIR" ]]; then
  remote_env+=("CARGO_TARGET_DIR=$CARGO_TARGET_DIR")
fi
"$RCH_BIN" exec -- env \
  "${remote_env[@]}" \
  cargo run --quiet -p frankenengine-engine --bin franken-quarantine-mesh-demo > "$json_path" 2> "$log_path"
status=$?
set -e
cat "$log_path" >&2

if grep -Eiq 'falling back to local|local fallback|running locally|\[RCH\] local \(|Dependency preflight blocked remote execution|RCH-E326' "$log_path" "$json_path"; then
  echo "rch reported local fallback; refusing local execution" >&2
  exit 125
fi
if [[ "$status" -ne 0 ]]; then
  exit "$status"
fi

cat "$json_path"

# The property this demo claims (bd-9vouw.20): every instance applied the
# revocation and checkpointed a quarantine decision within the bounded SLO.
if ! jq -e '
  (.instances | length) == 3
  and all(.instances[]; .target_revoked and .resolved_action == "quarantine" and .within_bounded_slo)
  and .fleet_convergence.within_bounded_slo
' "$json_path" > /dev/null; then
  echo "FAIL: quarantine did not converge on every instance within the bounded SLO" >&2
  exit 1
fi
echo "verified: 3/3 instances revoked and checkpointed quarantine within the bounded SLO" >&2
