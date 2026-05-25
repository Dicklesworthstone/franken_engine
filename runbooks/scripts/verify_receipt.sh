#!/usr/bin/env bash
# verify_receipt.sh — operator-friendly wrapper around `frankenctl verify receipt`.
#
# Track A / FE-CLAIM-004, bead bd-cixqu.1.7 (A.7 operator runbook).
#
# Wraps the signed-decision-receipt verifier with incident-triage output:
#   - renders the three verification layers (signature / transparency / attestation)
#     in plain English with PASS/FAIL and the failing layer's error code;
#   - --show-posterior-path  surfaces the decision posterior snapshot the receipt binds;
#   - --show-evidence-chain  surfaces the transparency-log inclusion + consistency proof
#     checks and the trace -> decision -> policy provenance chain;
#   - on failure, prints failure-class-specific remediation, including what
#     "attestation degraded to safe-mode" means operationally.
#
# Verifier verdict shape (UnifiedReceiptVerificationVerdict, flattened):
#   receipt_id, trace_id, decision_id, policy_id, verification_timestamp_ns,
#   passed(bool), failure_class(Signature|Transparency|Attestation|StaleData|null),
#   exit_code, signature/transparency/attestation: {passed, error_code, checks:[{check,outcome,error_code,detail}]},
#   warnings[], logs[].
# Verifier input shape (ReceiptVerifierCliInput):
#   { "receipts": { "<id>": { trace_id, decision_id, policy_id, receipt:{posterior_snapshot:{...}}, ... } } }
#
# Per bd-cixqu.45 logging discipline: set -euo pipefail, ISO-8601 timestamped log
# lines on stderr, fails closed (never silent success). `selftest` exercises the
# rendering/extraction against built-in fixtures with no frankenctl dependency.

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"

log() { printf '%s [%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$SCRIPT_NAME" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

usage() {
    cat <<'EOF'
verify_receipt.sh — operator wrapper around `frankenctl verify receipt`

USAGE:
    verify_receipt.sh --input <verifier_input.json> --receipt-id <id> [options]
    verify_receipt.sh selftest

OPTIONS:
    --input <path>          Verifier input JSON (ReceiptVerifierCliInput). Required.
    --receipt-id <id>       Receipt id to verify. Required.
    --show-posterior-path   Print the decision posterior snapshot the receipt binds.
    --show-evidence-chain   Print transparency-log inclusion/consistency proof checks
                            and the trace -> decision -> policy provenance chain.
    --summary               Pass --summary through to frankenctl (human verdict).
    --frankenctl <path>     Path to the frankenctl binary (default: $FRANKENCTL, then
                            target/release|debug/frankenctl, then `cargo run --bin frankenctl`).
    --verdict-json <path>   Render/triage a pre-computed verdict JSON instead of invoking
                            frankenctl (useful when the engine is not built).
    -h, --help              This help.

EXIT CODES:
    0  receipt verified (verdict.passed == true)
    1  usage / environment error (missing args, jq, or frankenctl)
    2  verifier ran but the receipt FAILED verification (see failure class)
EOF
}

require_jq() {
    command -v jq >/dev/null 2>&1 || die "jq is required but not found on PATH"
}

# --- frankenctl discovery (fail-closed) ------------------------------------
resolve_frankenctl() {
    if [ -n "${FRANKENCTL_BIN:-}" ]; then printf '%s' "$FRANKENCTL_BIN"; return; fi
    local root; root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
    for cand in "$root/target/release/frankenctl" "$root/target/debug/frankenctl"; do
        if [ -x "$cand" ]; then printf '%s' "$cand"; return; fi
    done
    printf 'cargo run -q --bin frankenctl --'  # last resort; requires the engine to build
}

run_frankenctl_verify() {
    # args: input receipt_id summary(0/1) out_json
    local input="$1" rid="$2" summary="$3" out="$4" bin
    bin="${FRANKENCTL_OVERRIDE:-$(resolve_frankenctl)}"
    local -a cmd
    # shellcheck disable=SC2206
    cmd=($bin verify receipt --input "$input" --receipt-id "$rid" --output "$out")
    [ "$summary" = "1" ] && cmd+=(--summary)
    log "invoking: ${cmd[*]}"
    if ! "${cmd[@]}"; then
        die "frankenctl verify receipt failed to run (engine built? receipt-id present in input?)"
    fi
    [ -f "$out" ] || die "frankenctl did not produce verdict json at $out"
}

# --- rendering -------------------------------------------------------------
render_verdict() {
    local verdict="$1"
    local passed failure exit_code rid
    passed="$(jq -r '.passed' "$verdict")"
    failure="$(jq -r '.failure_class // "none"' "$verdict")"
    exit_code="$(jq -r '.exit_code' "$verdict")"
    rid="$(jq -r '.receipt_id' "$verdict")"
    echo "=================================================================="
    if [ "$passed" = "true" ]; then
        echo "  RECEIPT $rid: VERIFIED ✓"
    else
        echo "  RECEIPT $rid: FAILED ✗   (failure_class=$failure, exit_code=$exit_code)"
    fi
    echo "------------------------------------------------------------------"
    for layer in signature transparency attestation; do
        local lp lerr
        lp="$(jq -r ".${layer}.passed" "$verdict")"
        lerr="$(jq -r ".${layer}.error_code // \"-\"" "$verdict")"
        printf "  %-13s %s   (error_code=%s)\n" "$layer" \
            "$([ "$lp" = "true" ] && echo PASS || echo FAIL)" "$lerr"
    done
    local nwarn; nwarn="$(jq -r '.warnings | length' "$verdict")"
    [ "$nwarn" != "0" ] && jq -r '.warnings[] | "  warning: " + .' "$verdict"
    echo "=================================================================="
}

show_posterior_path() {
    local input="$1" rid="$2"
    echo "--- posterior path (decision the receipt binds) ------------------"
    if ! jq -e --arg id "$rid" '.receipts[$id].receipt.posterior_snapshot' "$input" >/dev/null 2>&1; then
        echo "  (no posterior_snapshot present in input for receipt $rid)"
        return
    fi
    jq -r --arg id "$rid" '
        .receipts[$id] as $r
        | "  trace_id   : " + ($r.trace_id // "-"),
          "  decision_id: " + ($r.decision_id // "-"),
          "  policy_id  : " + ($r.policy_id // "-"),
          "  posterior_snapshot:",
          ( $r.receipt.posterior_snapshot
            | to_entries[]
            | "    " + .key + " = " + (.value|tostring) )
    ' "$input"
}

show_evidence_chain() {
    local verdict="$1"
    echo "--- evidence chain (transparency log + signature) ----------------"
    jq -r '
        "  provenance: trace=" + .trace_id + "  decision=" + .decision_id + "  policy=" + .policy_id,
        "  transparency layer (" + (if .transparency.passed then "PASS" else "FAIL" end) + "):",
        ( .transparency.checks[]? | "    [" + .outcome + "] " + .check + " — " + .detail ),
        "  signature layer (" + (if .signature.passed then "PASS" else "FAIL" end) + "):",
        ( .signature.checks[]? | "    [" + .outcome + "] " + .check + " — " + .detail )
    ' "$verdict"
}

print_triage() {
    local verdict="$1" failure
    failure="$(jq -r '.failure_class // "none"' "$verdict")"
    [ "$failure" = "none" ] && return
    echo "--- incident triage (failure_class=$failure) ---------------------"
    case "$failure" in
        Signature)
            echo "  The receipt's threshold signature did not validate."
            echo "  -> Confirm the verifier has the correct signer verification keys."
            echo "  -> A genuine mismatch means the receipt was not produced by the"
            echo "     attested signing quorum: treat the decision as UNTRUSTED."
            ;;
        Transparency)
            echo "  The transparency-log inclusion and/or consistency proof failed."
            echo "  -> --show-evidence-chain shows which MMR proof check failed."
            echo "  -> Inclusion fail: the receipt is not in the published log (possible"
            echo "     equivocation/omission). Consistency fail: the log was forked or"
            echo "     rewritten between checkpoints. Escalate to log-operator on-call."
            ;;
        Attestation)
            echo "  The TEE attestation quote could not be validated."
            echo "  -> The runtime has degraded to SAFE-MODE: it continues only under the"
            echo "     restricted capability posture (no attested-only operations), because"
            echo "     it can no longer prove it is running inside a trusted enclave."
            echo "  -> Check tee_attestation_policy freshness/measurement; a stale or"
            echo "     mismatched measurement is the usual cause. Re-attest before"
            echo "     promoting any decision that requires a trusted enclave."
            ;;
        StaleData)
            echo "  Verifier input is stale (timestamp/epoch outside the accepted window)."
            echo "  -> Re-export a fresh verifier_input.json for this receipt and re-run."
            ;;
        *)
            echo "  Unrecognised failure class: $failure"
            ;;
    esac
}

# --- selftest (no frankenctl / no engine build required) -------------------
selftest() {
    require_jq
    local td; td="$(mktemp -d)"
    cat > "$td/input.json" <<'JSON'
{
  "receipts": {
    "rcpt-001": {
      "trace_id": "trace-aaa",
      "decision_id": "dec-bbb",
      "policy_id": "pol-ccc",
      "verification_timestamp_ns": 1716000000000000000,
      "receipt": {
        "posterior_snapshot": {
          "point_estimate": 0.873,
          "confidence_interval_95_lower": 0.81,
          "confidence_interval_95_upper": 0.92
        }
      }
    }
  }
}
JSON
    cat > "$td/verdict_pass.json" <<'JSON'
{
  "receipt_id": "rcpt-001", "trace_id": "trace-aaa", "decision_id": "dec-bbb",
  "policy_id": "pol-ccc", "verification_timestamp_ns": 1716000000000000000,
  "passed": true, "failure_class": null, "exit_code": 0,
  "signature": {"passed": true, "error_code": null, "checks": [{"check":"threshold_signature","outcome":"pass","error_code":null,"detail":"3/3 signers"}]},
  "transparency": {"passed": true, "error_code": null, "checks": [{"check":"mmr_inclusion","outcome":"pass","error_code":null,"detail":"leaf 41 under root r9"},{"check":"mmr_consistency","outcome":"pass","error_code":null,"detail":"c0->c1 consistent"}]},
  "attestation": {"passed": true, "error_code": null, "checks": []},
  "warnings": [], "logs": []
}
JSON
    cat > "$td/verdict_attest_fail.json" <<'JSON'
{
  "receipt_id": "rcpt-001", "trace_id": "trace-aaa", "decision_id": "dec-bbb",
  "policy_id": "pol-ccc", "verification_timestamp_ns": 1716000000000000000,
  "passed": false, "failure_class": "Attestation", "exit_code": 2,
  "signature": {"passed": true, "error_code": null, "checks": []},
  "transparency": {"passed": true, "error_code": null, "checks": []},
  "attestation": {"passed": false, "error_code": "ATTEST_STALE", "checks": [{"check":"quote_freshness","outcome":"fail","error_code":"ATTEST_STALE","detail":"quote older than max age"}]},
  "warnings": ["attestation degraded; running in safe-mode"], "logs": []
}
JSON

    local fail=0
    # Capture output into variables before grepping: piping a long producer into
    # `grep -q` under `set -o pipefail` makes grep close the pipe on first match,
    # SIGPIPE-killing the producer and flipping the pipeline status to failure.
    local out
    log "selftest: render PASS verdict"
    out="$(render_verdict "$td/verdict_pass.json")"
    grep -q "VERIFIED" <<<"$out" || { log "FAIL: pass render"; fail=1; }
    log "selftest: posterior path extraction"
    out="$(show_posterior_path "$td/input.json" "rcpt-001")"
    grep -q "point_estimate = 0.873" <<<"$out" || { log "FAIL: posterior"; fail=1; }
    log "selftest: evidence chain extraction"
    out="$(show_evidence_chain "$td/verdict_pass.json")"
    grep -q "mmr_inclusion" <<<"$out" || { log "FAIL: evidence chain"; fail=1; }
    grep -q "mmr_consistency" <<<"$out" || { log "FAIL: consistency check"; fail=1; }
    log "selftest: attestation-failure triage mentions safe-mode"
    out="$(print_triage "$td/verdict_attest_fail.json")"
    grep -qi "SAFE-MODE" <<<"$out" || { log "FAIL: safe-mode triage"; fail=1; }
    out="$(render_verdict "$td/verdict_attest_fail.json")"
    grep -q "FAILED" <<<"$out" || { log "FAIL: fail render"; fail=1; }

    # Cleanup (non-recursive; leaking a /tmp dir on failure is harmless).
    rm -f "$td"/*.json 2>/dev/null || true
    rmdir "$td" 2>/dev/null || true
    if [ "$fail" = "0" ]; then log "selftest: ALL CHECKS PASSED"; echo "selftest OK"; return 0; fi
    die "selftest had failures"
}

# --- main ------------------------------------------------------------------
main() {
    [ "$#" -eq 0 ] && { usage; exit 1; }
    if [ "$1" = "selftest" ]; then selftest; exit $?; fi

    local input="" rid="" summary=0 show_post=0 show_evid=0 verdict_json=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -h|--help) usage; exit 0 ;;
            --input) input="${2:-}"; shift 2 ;;
            --receipt-id) rid="${2:-}"; shift 2 ;;
            --summary) summary=1; shift ;;
            --show-posterior-path) show_post=1; shift ;;
            --show-evidence-chain) show_evid=1; shift ;;
            --frankenctl) FRANKENCTL_OVERRIDE="${2:-}"; export FRANKENCTL_OVERRIDE; shift 2 ;;
            --verdict-json) verdict_json="${2:-}"; shift 2 ;;
            *) die "unknown argument: $1 (try --help)" ;;
        esac
    done

    require_jq
    [ -n "$rid" ] || die "--receipt-id is required"

    local verdict
    if [ -n "$verdict_json" ]; then
        [ -f "$verdict_json" ] || die "--verdict-json not found: $verdict_json"
        verdict="$verdict_json"
    else
        [ -n "$input" ] || die "--input is required (or pass --verdict-json)"
        [ -f "$input" ] || die "--input not found: $input"
        verdict="$(mktemp)"
        # Guard with ${verdict:-} so the EXIT trap is set -u safe if the local is
        # out of scope when the trap fires.
        trap 'rm -f "${verdict:-}"' EXIT
        run_frankenctl_verify "$input" "$rid" "$summary" "$verdict"
    fi

    render_verdict "$verdict"
    [ "$show_post" = "1" ] && [ -n "$input" ] && show_posterior_path "$input" "$rid"
    [ "$show_evid" = "1" ] && show_evidence_chain "$verdict"
    print_triage "$verdict"

    local passed; passed="$(jq -r '.passed' "$verdict")"
    [ "$passed" = "true" ] && exit 0 || exit 2
}

main "$@"
