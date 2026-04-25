#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
before_path="${script_dir}/before_promotion.json"
after_path="${script_dir}/after_promotion.json"
receipt_path="${script_dir}/lineage_receipt.json"

delegate_hash="$(jq -r '.impl_hash' "${before_path}")"
native_hash="$(jq -r '.impl_hash' "${after_path}")"

jq -e --arg delegate_hash "${delegate_hash}" --arg native_hash "${native_hash}" '
  has("delegate_hash")
  and has("native_hash")
  and has("promoted_at")
  and has("signature_hex")
  and has("evidence_chain")
  and (.delegate_hash == $delegate_hash)
  and (.native_hash == $native_hash)
  and (.delegate_hash | type == "string" and length > 0)
  and (.native_hash | type == "string" and length > 0)
  and (.promoted_at | type == "string" and length > 0)
  and (.signature_hex | type == "string" and test("^[0-9a-f]{64}$"))
  and (.evidence_chain | type == "array" and length > 0 and all(.[]; type == "string"))
' "${receipt_path}" > /dev/null

echo "verified lineage receipt: ${delegate_hash} -> ${native_hash}"
