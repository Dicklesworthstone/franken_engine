#!/usr/bin/env bash
#
# rgc_compounding_red_team_replay.sh — deterministic-replay verifier for the
# Track U.4 compounding red-team gate (bd-cixqu.21.4).
#
# Runs `frankenctl gates compounding-red-team` twice over identical inputs and
# asserts the produced bundle is byte-identical — the audit-verification property
# the gate depends on.
#
# Environment overrides:
#   CRT_CONFIG        optional campaign config TOML
#   CARGO_TARGET_DIR  cargo target dir (default: <repo>/target)
#   RUSTUP_TOOLCHAIN  toolchain (default: nightly-x86_64-unknown-linux-gnu)
#   CARGO_BIN         cargo binary (default: cargo)
#
# Exit codes: 0 identical, 2 setup error, 3 divergence.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CARGO_BIN="${CARGO_BIN:-cargo}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly-x86_64-unknown-linux-gnu}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${REPO_ROOT}/target}"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/crt_replay.XXXXXX")"
trap 'rm -rf "${TMP}"' EXIT

cd "${REPO_ROOT}"
if ! "${CARGO_BIN}" build -p frankenengine-engine --bin frankenctl >"${TMP}/build.log" 2>&1; then
  echo "❌ failed to build frankenctl (see ${TMP}/build.log)" >&2
  cat "${TMP}/build.log" >&2 || true
  exit 2
fi
FRANKENCTL="${CARGO_TARGET_DIR}/debug/frankenctl"

CONFIG_ARGS=()
if [[ -n "${CRT_CONFIG:-}" ]]; then
  CONFIG_ARGS=(--config "${CRT_CONFIG}")
fi

"${FRANKENCTL}" gates compounding-red-team --out-dir "${TMP}/a" "${CONFIG_ARGS[@]}" >/dev/null
"${FRANKENCTL}" gates compounding-red-team --out-dir "${TMP}/b" "${CONFIG_ARGS[@]}" >/dev/null

if cmp -s "${TMP}/a/compounding_red_team_bundle.json" "${TMP}/b/compounding_red_team_bundle.json"; then
  digest="$(grep -o '"bundle_digest": *"[^"]*"' "${TMP}/a/compounding_red_team_bundle.json" | head -1)"
  echo "✅ compounding-red-team bundle is deterministic (byte-identical replay)"
  echo "   ${digest}"
  exit 0
else
  echo "❌ compounding-red-team bundle diverged across identical runs" >&2
  diff "${TMP}/a/compounding_red_team_bundle.json" "${TMP}/b/compounding_red_team_bundle.json" | head -40 >&2 || true
  exit 3
fi
