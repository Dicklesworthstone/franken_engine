#!/usr/bin/env bash
#
# Lean 4 toolchain doctor + installer (bd-cixqu.7.17.3).
#
# Track-G FE-CLAIM-016 depends on running `lake build` over `proofs/lean4/` and
# emitting a machine-checkable proof bundle (see `run_lean_proof_check.sh`).
# `lake` requires the Lean 4 toolchain, which is installed via the `elan`
# version manager. This script is the reproducible install/detect doctor:
#
#   detect   — print which tools are on PATH and at which versions (default
#              if no mode is given)
#   install  — install elan (and the Lean toolchain pinned by
#              `proofs/lean4/lean-toolchain`) if absent; idempotent
#   selftest — verify the script's structure + that `proofs/lean4/` is sane,
#              without invoking `cargo`, `elan`, or `lake`
#
# Idempotent install path: elan is installed under `~/.elan/`, `lake` is added
# to PATH via `~/.elan/bin/lake`. The script never invokes `sudo`; if `curl` or
# `bash` is missing it fails closed with an actionable hint, and if `elan` is
# already present it does NOT reinstall.
#
# Refusal modes (fail-closed, exit 2):
#   - No internet (curl returns non-zero on the elan installer URL)
#   - $HOME is not writable
#   - lean-toolchain file at proofs/lean4/lean-toolchain is missing
#   - elan installer downloads but the install step exits non-zero
#
# Output:
#   stdout — human-readable status lines (`[lean-doctor] ...`)
#   exit 0 — all required tools present (after the requested mode runs)
#   exit 1 — required tool absent (in `detect` mode only — install with
#            `$0 install`)
#   exit 2 — refusal / structural failure (see above)
#
# Usage:
#   $0 [detect|install|selftest]
#
# Mode defaults to `detect` so a bare `./install_lean_toolchain.sh` is safe.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_DIR}"

readonly BEAD="bd-cixqu.7.17.3"
readonly LEAN_PROOFS_DIR="${PROJECT_DIR}/proofs/lean4"
readonly LEAN_TOOLCHAIN_FILE="${LEAN_PROOFS_DIR}/lean-toolchain"
readonly ELAN_BIN_DIR="${HOME}/.elan/bin"
readonly ELAN_INSTALLER_URL="https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh"

MODE="${1:-detect}"

log() {
    printf '[lean-doctor] %s\n' "$*"
}

err() {
    printf '[lean-doctor] ERROR: %s\n' "$*" >&2
}

refuse() {
    err "$*"
    exit 2
}

#------------------------------------------------------------------------
# selftest — structural only, no cargo/elan/lake invocation
#------------------------------------------------------------------------
if [[ "$MODE" == "selftest" || "$MODE" == "--self-check" ]]; then
    log "selftest: starting (no external commands invoked)"
    [[ -d "$LEAN_PROOFS_DIR" ]] || refuse "proofs/lean4/ directory missing"
    [[ -f "$LEAN_TOOLCHAIN_FILE" ]] || refuse "proofs/lean4/lean-toolchain file missing"
    [[ -f "$LEAN_PROOFS_DIR/lakefile.lean" ]] || refuse "proofs/lean4/lakefile.lean missing"
    pinned_toolchain="$(tr -d '[:space:]' < "$LEAN_TOOLCHAIN_FILE")"
    if [[ -z "$pinned_toolchain" ]]; then
        refuse "lean-toolchain file is empty"
    fi
    log "selftest: proofs/lean4/ is structurally sane (toolchain pin: ${pinned_toolchain})"
    log "selftest: PASS"
    exit 0
fi

#------------------------------------------------------------------------
# Detect — present in both modes
#------------------------------------------------------------------------
detect_tool() {
    local tool="$1"
    if command -v "$tool" >/dev/null 2>&1; then
        local v
        v="$("$tool" --version 2>&1 | head -1 || true)"
        log "$tool: $(command -v "$tool")  (${v})"
        return 0
    fi
    # Fall back to elan's bin directory in case PATH was not refreshed yet.
    if [[ -x "${ELAN_BIN_DIR}/${tool}" ]]; then
        local v
        v="${ELAN_BIN_DIR}/${tool} --version 2>&1 | head -1"
        v="$(eval "$v" || true)"
        log "$tool: ${ELAN_BIN_DIR}/${tool}  (${v}; not on PATH)"
        return 0
    fi
    log "$tool: NOT FOUND"
    return 1
}

elan_present=0
lake_present=0
lean_present=0

detect_tool elan && elan_present=1 || true
detect_tool lake && lake_present=1 || true
detect_tool lean && lean_present=1 || true

case "$MODE" in
    detect)
        if [[ -f "$LEAN_TOOLCHAIN_FILE" ]]; then
            pinned_toolchain="$(tr -d '[:space:]' < "$LEAN_TOOLCHAIN_FILE")"
            log "proofs/lean4/lean-toolchain pin: ${pinned_toolchain}"
        else
            log "proofs/lean4/lean-toolchain pin: <file missing>"
        fi
        if (( elan_present == 1 && lake_present == 1 && lean_present == 1 )); then
            log "ready: elan + lake + lean all on PATH"
            exit 0
        fi
        log "missing tools — run \`$0 install\` to install via elan"
        exit 1
        ;;
    install)
        ;;
    *)
        refuse "unknown mode: ${MODE} (expected: detect | install | selftest)"
        ;;
esac

#------------------------------------------------------------------------
# Install path (MODE == install)
#------------------------------------------------------------------------
log "install: starting"
[[ -d "$LEAN_PROOFS_DIR" ]] || refuse "proofs/lean4/ directory missing"
[[ -f "$LEAN_TOOLCHAIN_FILE" ]] || refuse "proofs/lean4/lean-toolchain file missing"
[[ -w "$HOME" ]] || refuse "\$HOME (${HOME}) is not writable"
command -v curl >/dev/null 2>&1 || refuse "curl is required to fetch the elan installer; install curl first"

if (( elan_present == 0 )); then
    log "fetching elan installer from ${ELAN_INSTALLER_URL}"
    tmp_installer="$(mktemp -t elan-init.XXXXXXXX.sh)"
    trap 'rm -f "$tmp_installer"' EXIT
    if ! curl --fail --silent --show-error --location "$ELAN_INSTALLER_URL" -o "$tmp_installer"; then
        refuse "failed to download elan installer; check network connectivity"
    fi
    log "running elan installer in non-interactive mode (-y, --default-toolchain none)"
    if ! bash "$tmp_installer" -y --default-toolchain none; then
        refuse "elan installer exited non-zero"
    fi
    log "elan installed under ~/.elan/"
else
    log "elan already present; skipping installer download"
fi

# Add elan bin to PATH for this script run; the user must add it to their
# shell rc themselves for future shells.
if ! command -v elan >/dev/null 2>&1; then
    if [[ -x "${ELAN_BIN_DIR}/elan" ]]; then
        export PATH="${ELAN_BIN_DIR}:${PATH}"
        log "added ${ELAN_BIN_DIR} to PATH for this run"
    else
        refuse "elan binary still not found after install at ${ELAN_BIN_DIR}/elan"
    fi
fi

pinned_toolchain="$(tr -d '[:space:]' < "$LEAN_TOOLCHAIN_FILE")"
log "ensuring Lean toolchain ${pinned_toolchain} is installed"
if ! elan toolchain install "$pinned_toolchain"; then
    refuse "elan toolchain install ${pinned_toolchain} failed"
fi

log "verifying tools after install"
detect_tool elan || refuse "elan not detectable after install"
detect_tool lake || refuse "lake not detectable after install"
detect_tool lean || refuse "lean not detectable after install"

log ""
log "install: COMPLETE"
log "add this to your shell rc to keep elan on PATH:"
log "    export PATH=\"\$HOME/.elan/bin:\$PATH\""
log ""
log "next: run scripts/run_lean_proof_check.sh ci to build proofs/lean4/ and"
log "      emit artifacts/rgc_theorem_backed_compiler_inputs/FE-CLAIM-016.proof.json"
log "      (bead ${BEAD})"
