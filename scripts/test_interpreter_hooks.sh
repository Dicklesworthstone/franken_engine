#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
artifact_dir="$repo_root/artifacts/interpreter_hooks/$timestamp"
target_dir="$repo_root/target_rch_interpreter_hooks"

mkdir -p "$artifact_dir"

events_file="$artifact_dir/events.jsonl"
manifest_file="$artifact_dir/run_manifest.json"
commands_file="$artifact_dir/commands.txt"
log_file="$artifact_dir/rch-test.log"

command=(
  rch exec --
  env
  RUSTUP_TOOLCHAIN=nightly
  "CARGO_TARGET_DIR=$target_dir"
  cargo
  test
  -p
  frankenengine-engine
  --lib
  interpreter_hook
  --
  --nocapture
)

cat >"$manifest_file" <<EOF
{
  "suite": "interpreter_hooks",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "repo_root": "$repo_root",
  "artifact_dir": "$artifact_dir",
  "target_dir": "$target_dir"
}
EOF

printf '%s\n' \
  "{\"suite\":\"interpreter_hooks\",\"phase\":\"started\",\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
  >>"$events_file"

printf '%q ' "${command[@]}" >"$commands_file"
printf '\n' >>"$commands_file"

set +e
"${command[@]}" 2>&1 | tee "$log_file"
status=${PIPESTATUS[0]}
set -e

printf '%s\n' \
  "{\"suite\":\"interpreter_hooks\",\"phase\":\"completed\",\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"exit\":$status}" \
  >>"$events_file"

exit "$status"
