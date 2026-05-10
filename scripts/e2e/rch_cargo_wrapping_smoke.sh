#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
tmp_root="${TMPDIR:-/tmp}/franken-engine-rch-cargo-wrapping-smoke-${timestamp}-$$"
good_dir="${tmp_root}/good"
bad_dir="${tmp_root}/bad"
mkdir -p "$good_dir" "$bad_dir"

cat > "${good_dir}/wrapped.sh" <<'GOOD'
#!/usr/bin/env bash
set -euo pipefail
RCH_BIN="${RCH_BIN:-rch}"
"$RCH_BIN" exec -- env \
  "CARGO_TARGET_DIR=/tmp/rch_target_good" \
  cargo test -p frankenengine-engine --lib
GOOD

cat > "${good_dir}/fixture.sh" <<'FIXTURE'
#!/usr/bin/env bash
set -euo pipefail
printf 'negative fixture: cargo test -p frankenengine-engine --lib\n'
FIXTURE

cat > "${bad_dir}/bare.sh" <<'BAD'
#!/usr/bin/env bash
set -euo pipefail
cargo test -p frankenengine-engine --lib
BAD

"${repo_root}/scripts/check_rch_cargo_wrapping.sh" --strict --root "$tmp_root" good >/dev/null

if "${repo_root}/scripts/check_rch_cargo_wrapping.sh" --strict --root "$tmp_root" bad >"${tmp_root}/bad.stdout" 2>"${tmp_root}/bad.stderr"; then
  echo "expected bare cargo fixture to fail" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

if ! grep -q 'bare Cargo command must be routed through rch exec' "${tmp_root}/bad.stderr"; then
  echo "expected failure diagnostic not found" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

echo "rch cargo wrapping smoke passed"
echo "smoke artifacts: ${tmp_root}"
