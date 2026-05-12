#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
tmp_root="${TMPDIR:-/tmp}/franken-engine-lib-unit-smoke-gate-${timestamp}-$$"
good_dir="${tmp_root}/good"
bad_dir="${tmp_root}/bad"
mkdir -p "$good_dir" "$bad_dir"

cat >"${good_dir}/cargo-output.log" <<'GOOD_LOG'
INFO rch::transfer: Syncing /data/projects/franken_engine/crates/franken-engine-test-support -> /data/projects/franken_engine/crates/franken-engine-test-support on worker
   Compiling frankenengine-extension-host v0.1.0 (/data/projects/franken_engine/crates/franken-extension-host)
   Compiling frankenengine-engine v0.1.0 (/data/projects/franken_engine/crates/franken-engine)
GOOD_LOG

cat >"${bad_dir}/cargo-output.log" <<'BAD_LOG'
   Compiling frankenengine-test-support v0.1.0 (/data/projects/franken_engine/crates/franken-engine-test-support)
BAD_LOG

cat >"${good_dir}/wrapped.sh" <<'GOOD_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
RCH_BIN="${RCH_BIN:-rch}"
"$RCH_BIN" exec -- env \
  "CARGO_TARGET_DIR=/tmp/rch_target_good" \
  cargo test -p frankenengine-engine --lib some::unit::test --no-run
GOOD_SCRIPT

cat >"${bad_dir}/bare.sh" <<'BAD_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
cargo test -p frankenengine-engine --lib some::unit::test --no-run
BAD_SCRIPT

"${repo_root}/scripts/rch_engine_lib_unit_smoke_gate.sh" --scan-log "${good_dir}/cargo-output.log" >/dev/null
"${repo_root}/scripts/rch_engine_lib_unit_smoke_gate.sh" --check-script "${good_dir}/wrapped.sh" >/dev/null

if ! "${repo_root}/scripts/rch_engine_lib_unit_smoke_gate.sh" --print-command | grep -q 'rch exec -- env'; then
  echo "expected printed command to use rch exec -- env" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

if "${repo_root}/scripts/rch_engine_lib_unit_smoke_gate.sh" --scan-log "${bad_dir}/cargo-output.log" >"${tmp_root}/bad-log.stdout" 2>"${tmp_root}/bad-log.stderr"; then
  echo "expected forbidden support dependency fixture to fail" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

if ! grep -q 'forbidden_support_dependency' "${tmp_root}/bad-log.stdout"; then
  echo "expected support dependency diagnostic not found" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

if "${repo_root}/scripts/rch_engine_lib_unit_smoke_gate.sh" --check-script "${bad_dir}/bare.sh" >"${tmp_root}/bad-script.stdout" 2>"${tmp_root}/bad-script.stderr"; then
  echo "expected bare cargo fixture to fail" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

if ! grep -q 'bare Cargo command must be routed through rch exec' "${tmp_root}/bad-script.stderr"; then
  echo "expected bare cargo diagnostic not found" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

echo "rch engine lib-unit smoke gate smoke passed"
echo "smoke artifacts: ${tmp_root}"
