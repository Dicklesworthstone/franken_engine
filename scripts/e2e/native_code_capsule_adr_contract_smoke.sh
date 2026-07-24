#!/usr/bin/env bash
set -euo pipefail
shopt -s inherit_errexit

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repo_root="$(cd "${script_dir}/../.." && pwd)"
readonly repo_root
node_repo="${FRANKEN_NODE_REPO:-${repo_root}/../franken_node}"
readonly node_repo
gate="${repo_root}/scripts/run_native_code_capsule_adr_gate.sh"
readonly gate

output_root="${repo_root}/artifacts/native_code_capsule_adr_e2e"
seed="${NATIVE_CAPSULE_ADR_SEED:-1001001}"
verify_sources=false
require_authorized=false
owner_anchor=""

usage() {
  printf '%s\n' \
    "usage: $0 [options]" \
    "" \
    "  --output-root PATH" \
    "  --seed VALUE" \
    "  --verify-sources-online" \
    "  --require-authorized" \
    "  --owner-anchor PATH" \
    "  -h, --help"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-root)
      output_root="${2:?--output-root requires a path}"
      shift 2
      ;;
    --seed)
      seed="${2:?--seed requires a value}"
      shift 2
      ;;
    --verify-sources-online)
      verify_sources=true
      shift
      ;;
    --require-authorized)
      require_authorized=true
      shift
      ;;
    --owner-anchor)
      owner_anchor="${2:?--owner-anchor requires a path}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

log() {
  printf '[native-code-capsule-adr-e2e] %s\n' "$*" >&2
}

fail() {
  log "FAIL: $*"
  exit 1
}

declare -a common_args=(
  --repo-root "$repo_root"
  --node-repo "$node_repo"
  --seed "$seed"
)
if [[ "$verify_sources" == true ]]; then
  common_args+=(--verify-sources-online)
fi
if [[ "$require_authorized" == true ]]; then
  common_args+=(--require-authorized)
fi
if [[ -n "$owner_anchor" ]]; then
  common_args+=(--owner-anchor "$owner_anchor")
fi

log "phase=producer: snapshotting inputs and generating an immutable candidate"
producer_stderr="$(mktemp)"
if ! ci_result="$(
  bash "$gate" ci --output-root "$output_root" "${common_args[@]}" \
    2>"$producer_stderr"
)"; then
  log "producer stderr follows"
  sed -n '1,240p' "$producer_stderr" >&2
  fail "strict candidate producer failed; retained stderr=${producer_stderr}"
fi
log "producer stderr retained at ${producer_stderr}"

if ! bundle_dir="$(
  python3 -c '
import json
import sys
value = json.load(sys.stdin)
path = value.get("candidate_dir")
if value.get("outcome") != "candidate" or not isinstance(path, str) or not path:
    raise SystemExit(1)
print(path)
' <<<"$ci_result"
)"; then
  fail "producer output did not identify one candidate directory"
fi
[[ -d "$bundle_dir" && ! -L "$bundle_dir" ]] \
  || fail "candidate is absent or a symlink: ${bundle_dir}"

snapshot_validator="${bundle_dir}/inputs/strict_validator.py"
[[ -f "$snapshot_validator" && ! -L "$snapshot_validator" ]] \
  || fail "snapshotted independent validator is absent or a symlink"

log "phase=verifier: rerunning contract, repository, source, event, and tamper checks"
declare -a finalizer_args=(
  finalize-candidate
  --repo-root "$repo_root"
  --node-repo "$node_repo"
  --candidate "$bundle_dir"
  --seed "$seed"
)
if [[ "$require_authorized" == true ]]; then
  finalizer_args+=(--require-authorized)
fi
if [[ -n "$owner_anchor" ]]; then
  finalizer_args+=(--owner-anchor "$owner_anchor")
fi
verifier_stderr="$(mktemp)"
if ! verifier_result="$(
  python3 "$snapshot_validator" "${finalizer_args[@]}" 2>"$verifier_stderr"
)"; then
  log "verifier stderr follows"
  sed -n '1,240p' "$verifier_stderr" >&2
  fail "independent E2E verifier rejected the candidate; retained stderr=${verifier_stderr}"
fi
log "verifier stderr retained at ${verifier_stderr}"

manifest="${bundle_dir}/run_manifest.json"
[[ -s "$manifest" && ! -L "$manifest" ]] \
  || fail "run_manifest.json was not published last"

log "phase=independent-shell-closure: checking sealed bytes, modes, and exact inventory"
python3 - "$bundle_dir" <<'PY' \
  || fail "independent shell-level publication closure check failed"
import hashlib
import json
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])

def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result

manifest_path = root / "run_manifest.json"
manifest = json.loads(
    manifest_path.read_text(encoding="utf-8"),
    object_pairs_hook=reject_duplicates,
    parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
)
assert manifest["schema_version"] == "franken-engine.native-code-capsule-adr-run-manifest.v2"
assert manifest["complete"] is True
assert manifest["validation_outcome"] == "pass"
assert manifest["self_test_outcome"] == "pass"
assert manifest["e2e_outcome"] == "pass"
assert manifest["publication_phase"] == "independently-verified-final"
assert manifest["decision_status"] in {"proposed", "accepted"}
assert manifest["implementation_authorized"] is (manifest["decision_status"] == "accepted")

records = manifest["artifacts"]
paths = [record["path"] for record in records]
assert paths == sorted(paths)
assert len(paths) == len(set(paths))
expected = set(paths) | {"run_manifest.json"}
actual = set()
for directory, directory_names, file_names in os.walk(root, followlinks=False):
    directory_path = pathlib.Path(directory)
    assert not directory_path.is_symlink()
    assert stat.S_IMODE(directory_path.stat().st_mode) == 0o500
    for name in directory_names:
        child = directory_path / name
        assert not child.is_symlink()
    for name in file_names:
        child = directory_path / name
        assert not child.is_symlink() and child.is_file()
        relative = child.relative_to(root).as_posix()
        assert ".." not in pathlib.PurePosixPath(relative).parts
        actual.add(relative)
assert actual == expected, (sorted(expected - actual), sorted(actual - expected))

for record in records:
    assert set(record) == {"path", "sha256", "bytes", "mode"}
    path = root / record["path"]
    body = path.read_bytes()
    assert len(body) == record["bytes"]
    assert hashlib.sha256(body).hexdigest() == record["sha256"]
    assert record["mode"] == stat.S_IMODE(path.stat().st_mode) == 0o400

assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o400
assert not (root / "failure.json").exists()
assert not (root / "e2e_failure.json").exists()
receipt = json.loads((root / "e2e_receipt.json").read_text(encoding="utf-8"))
assert receipt["artifact_closure_outcome"] == "pass"
assert receipt["bundle_mutation_outcome"] == "pass"
assert receipt["bundle_mutation_test_count"] >= 10
events = (root / "events.jsonl").read_bytes().splitlines()
assert len(events) >= 30
print(json.dumps({"sealed_artifacts": len(records), "events": len(events)}, sort_keys=True))
PY

if [[ "$require_authorized" == false ]]; then
  log "phase=negative-authorization: proving proposed state cannot authorize implementation"
  authorization_stderr="$(mktemp)"
  if bash "$gate" check \
      --repo-root "$repo_root" \
      --node-repo "$node_repo" \
      --seed "$seed" \
      --require-authorized \
      >"/dev/null" 2>"$authorization_stderr"; then
    fail "proposed decision unexpectedly passed --require-authorized"
  fi
  python3 - "$authorization_stderr" <<'PY' \
    || fail "authorization refusal lacks NCC-AUTHORIZATION-REQUIRED"
import json
import pathlib
import sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert value["outcome"] == "fail"
assert value["error"]["code"] == "NCC-AUTHORIZATION-REQUIRED"
PY
  log "negative authorization stderr retained at ${authorization_stderr}"
fi

log "PASS: two-phase candidate, independent replay, tamper suite, and sealed closure are coherent"
log "bundle=${bundle_dir}"
printf '%s\n' "$verifier_result"
