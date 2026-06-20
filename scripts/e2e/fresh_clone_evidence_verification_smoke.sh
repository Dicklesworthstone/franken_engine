#!/usr/bin/env bash
# CEI B.4 (bd-sde5e.2.4): fresh-clone committed-evidence verification.
#
# Proves the "No artifact, no claim" guarantee (FE-CLAIM-009) holds for an
# EXTERNAL verifier: a clone that has only the committed git tree — no
# git-ignored artifacts/ directory and none of the working tree's uncommitted
# edits — can re-verify every OBSERVED claim's evidence offline.
#
# We simulate the fresh clone with `git worktree add --detach HEAD` into a temp
# dir (a clean checkout of the current commit; artifacts/ is git-ignored so it is
# absent, and no in-flight WIP leaks in). franken_evidence_manifest resolves its
# repo root from the current directory, so the *prebuilt* binary verifies the
# worktree without a cold rebuild. The gate fails closed if any OBSERVED claim is
# unverifiable offline.
#
# Honors FRANKEN_EVIDENCE_MANIFEST_BIN to skip the build.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for the fresh-clone evidence verification smoke" >&2
  exit 2
fi
if ! command -v git >/dev/null 2>&1; then
  echo "git is required for the fresh-clone evidence verification smoke" >&2
  exit 2
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
artifact_root="${FRESH_CLONE_EVIDENCE_ARTIFACT_ROOT:-${root_dir}/artifacts/fresh_clone_evidence_verification}"
run_dir="${FRESH_CLONE_EVIDENCE_RUN_DIR:-${artifact_root}/${timestamp}}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
verify_log="${run_dir}/verify.log"
mkdir -p "$run_dir"
: >"$events_path"
: >"$commands_path"

trace_id="trace-fresh-clone-evidence-${timestamp}"
schema_ns="franken-engine.fresh-clone-evidence-verification"

append_event() {
  jq -nc \
    --arg schema_version "${schema_ns}.event.v1" \
    --arg trace_id "${trace_id}" \
    --arg event "$1" \
    --arg outcome "$2" \
    --arg detail "$3" \
    '{schema_version:$schema_version,trace_id:$trace_id,event:$event,outcome:$outcome,detail:(if $detail=="" then null else $detail end)}' \
    >>"$events_path"
}

append_event "smoke.start" "info" "timestamp=${timestamp}"

# ---------------------------------------------------------------------------
# Step 0 — locate or build the verifier binary (prefer a prebuilt one)
# ---------------------------------------------------------------------------
bin="${FRANKEN_EVIDENCE_MANIFEST_BIN:-}"
if [[ -z "$bin" ]]; then
  for cand in \
    "target_icydeer/debug/franken_evidence_manifest" \
    "target/debug/franken_evidence_manifest" \
    "target/release/franken_evidence_manifest"; do
    if [[ -x "$cand" ]]; then bin="${root_dir}/${cand}"; break; fi
  done
fi
if [[ -z "${bin:-}" ]]; then
  echo "building franken_evidence_manifest ..." >&2
  printf 'cargo build -p frankenengine-engine --bin franken_evidence_manifest\n' >>"$commands_path"
  cargo build -p frankenengine-engine --bin franken_evidence_manifest >&2
  bin="${root_dir}/target/debug/franken_evidence_manifest"
fi
append_event "smoke.bin" "ok" "bin=${bin}"

# ---------------------------------------------------------------------------
# Step 1 — materialize a fresh clone (clean checkout of HEAD, no artifacts/)
# ---------------------------------------------------------------------------
head_commit="$(git rev-parse HEAD)"
clone_dir="$(mktemp -d "${TMPDIR:-/tmp}/fe_fresh_clone.XXXXXX")"
cleanup() {
  git worktree remove --force "$clone_dir" >/dev/null 2>&1 || rm -rf "$clone_dir" 2>/dev/null || true
  git worktree prune >/dev/null 2>&1 || true
}
trap cleanup EXIT

printf 'git worktree add --detach %s %s\n' "$clone_dir" "$head_commit" >>"$commands_path"
git worktree add --detach "$clone_dir" "$head_commit" >/dev/null 2>&1
append_event "smoke.fresh_clone" "ok" "commit=${head_commit} dir=${clone_dir}"

# The "No artifact, no claim" guarantee is meaningless if verification secretly
# reaches into the git-ignored, timestamped gate-output bundles the working tree
# accumulates under artifacts/<gate>/<ts>/. A clean checkout of HEAD carries none
# of those (they are git-ignored, so absent) nor any uncommitted WIP — prove it.
# (Committed docs such as artifacts/*/README.md may exist; they are not evidence
# the verifier depends on.)
stray="$(cd "$clone_dir" && git status --porcelain --ignored 2>/dev/null | head -3 | tr '\n' ';')"
if [[ -n "$stray" ]]; then
  echo "FAIL: fresh checkout is not a clean committed-only tree: ${stray}" >&2
  append_event "smoke.clean_checkout" "fail" "stray=${stray}"
  exit 1
fi
# Defensive: no committed evidence bundle should itself be a timestamped gate run
# dir under artifacts/ (verification must source only docs/evidence/).
if (cd "$clone_dir" && git ls-files 'artifacts/**/run_manifest.json' 'artifacts/**/*Z/*' | grep -q .); then
  echo "FAIL: a timestamped gate-output bundle is committed under artifacts/" >&2
  append_event "smoke.clean_checkout" "fail" "committed gate bundle under artifacts/"
  exit 1
fi
append_event "smoke.clean_checkout" "ok" "fresh checkout is committed-only; no git-ignored bundles or WIP"

# ---------------------------------------------------------------------------
# Step 2 — verify every OBSERVED claim offline, from committed evidence only
# ---------------------------------------------------------------------------
printf '(cd %s && %s verify)\n' "$clone_dir" "$bin" >>"$commands_path"
set +e
( cd "$clone_dir" && "$bin" verify ) >"$verify_log" 2>&1
verify_exit=$?
set -e
cat "$verify_log"

# franken_evidence_manifest verify prints "verify: <ok> ok, <failed> failed (of <n>)".
summary_line="$(grep -E '^verify: [0-9]+ ok, [0-9]+ failed' "$verify_log" | tail -1)"
ok_count="$(sed -E 's/^verify: ([0-9]+) ok.*/\1/' <<<"$summary_line")"
failed_count="$(sed -E 's/.* ([0-9]+) failed.*/\1/' <<<"$summary_line")"

if [[ "$verify_exit" -ne 0 || "${failed_count:-1}" -ne 0 ]]; then
  echo "FAIL: ${failed_count:-?} OBSERVED claim(s) unverifiable offline from the committed tree" >&2
  append_event "smoke.verify" "fail" "exit=${verify_exit} ok=${ok_count:-0} failed=${failed_count:-?}"
  verdict="fail"
else
  append_event "smoke.verify" "pass" "exit=0 ok=${ok_count} failed=0"
  verdict="pass"
fi

# ---------------------------------------------------------------------------
# Step 3 — content-addressed run manifest
# ---------------------------------------------------------------------------
verify_sha="$(sha256sum "$verify_log" | cut -d' ' -f1)"
events_sha="$(sha256sum "$events_path" | cut -d' ' -f1)"
jq -n \
  --arg schema_version "${schema_ns}.run-manifest.v1" \
  --arg verdict "$verdict" \
  --arg head_commit "$head_commit" \
  --argjson verify_exit_code "$verify_exit" \
  --argjson observed_ok "${ok_count:-0}" \
  --argjson observed_failed "${failed_count:-0}" \
  --arg trace_id "$trace_id" \
  --arg owning_bead "bd-sde5e.2.4" \
  --arg verify_log_sha256 "$verify_sha" \
  --arg events_sha256 "$events_sha" \
  '{schema_version:$schema_version,verdict:$verdict,head_commit:$head_commit,
    verify_exit_code:$verify_exit_code,observed_ok:$observed_ok,observed_failed:$observed_failed,
    fresh_clone:{method:"git worktree add --detach HEAD",artifacts_tree_present:false},
    trace_id:$trace_id,owning_bead:$owning_bead,
    artifacts:{verify_log:"verify.log",events:"events.jsonl",commands:"commands.txt"},
    content_hashes:{"verify.log":$verify_log_sha256,"events.jsonl":$events_sha256}}' \
  >"$manifest_path"

append_event "smoke.end" "$verdict" "run_dir=${run_dir}"

echo "fresh_clone_evidence_verification_manifest=${manifest_path}"
echo "fresh_clone_evidence_verification_verdict=${verdict}"
echo "fresh_clone_evidence_verification_observed=${ok_count:-0} verified, ${failed_count:-0} unverifiable"

[[ "$verdict" == "pass" ]] || exit 1
