#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
sample_path="${script_dir}/sample_checkpoint.json"
replay_path="${script_dir}/replay_checkpoint.json"
sample_norm="$(mktemp)"
replay_norm="$(mktemp)"
trap 'rm -f "${sample_norm}" "${replay_norm}"' EXIT

jq -e '
  has("checkpoint_id")
  and has("policy_version")
  and has("parent_checkpoint_id")
  and has("freshness_proof_hash")
  and has("signature_hex")
  and has("rollback_resistance_witness")
  and (.checkpoint_id | type == "string" and length > 0)
  and (.parent_checkpoint_id | type == "string" and length > 0)
  and (.parent_checkpoint_id != .checkpoint_id)
  and (.signature_hex | type == "string" and test("^[0-9a-f]{64}$"))
' "${sample_path}" > /dev/null

jq -S . "${sample_path}" > "${sample_norm}"
jq -S . "${replay_path}" > "${replay_norm}"
diff -u "${sample_norm}" "${replay_norm}" > /dev/null

echo "verified signed checkpoint fixture: parent linkage is non-self-referential and replay is stable"
