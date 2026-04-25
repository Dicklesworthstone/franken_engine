#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
input_path="${script_dir}/confidential_input.txt"
receipt_path="${script_dir}/sample_declassification_receipt.json"

expected_hash="$(sha256sum "${input_path}" | awk '{print $1}')"

jq -e --arg expected_hash "${expected_hash}" '
  .data_hash == $expected_hash
  and .label_before == "Confidential"
  and .label_after == "Public"
  and (.authorized_by | type == "string" and length > 0)
  and (.justification | type == "string" and length > 0)
  and (.signature_hex | test("^[0-9a-f]{64}$"))
' "${receipt_path}" > /dev/null

printf 'verified declassification receipt for %s\n' "${input_path}"
cat "${receipt_path}"
