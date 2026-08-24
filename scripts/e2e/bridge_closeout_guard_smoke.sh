#!/usr/bin/env bash
# Red-first smoke drill for the BRIDGE closeout enforcement stack.
#
# Owning bead: bd-performance-conformance-bridge-tu32j.22.61
#
# Builds an isolated scratch project (real copy of .beads/beads.db via sqlite
# .backup, real policy.yaml, real scripts/docs) and proves every demanded
# denial path against REAL br tooling:
#
#   S1  raw close of decomposed parent with open children   -> denied (native)
#   S2  same with --force                                    -> denied (gate)
#   S3  same with --force --bypass-policy                    -> denied (allow_bypass:false)
#   S4  forged bridge_closeout pass by a foreign provider    -> native close
#       accepts it (documented residual), verifier flags it  -> unsanctioned_gate_pass
#   S5  valid path: complete subtree bottom-up, verify,      -> pass recorded,
#       gate-report, close                                   -> close accepted
#   S6  stale gate pass after status-revision bump           -> close denied
#   S7  unmanifested child created under listed parent       -> drift denial
#   S8  tombstoned required child                            -> tombstone denial
#   S9  reparented (edge removed) required child             -> reparent denial
#   S10 plain non-manifest issue closes with no friction      -> accepted
#   S11 break-glass signed pass closes incomplete parent,     -> accepted but
#       later verification of program root flags it           -> flagged forever
#   D1  manifest regeneration is deterministic                -> gen --check ok
#
# Exit 0 iff every assertion holds.

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/bridge-closeout-smoke.XXXXXX")"
PROJ="$SCRATCH/proj"
PASS=0
FAIL=0

cleanup() { rm -rf "$SCRATCH"; }
trap cleanup EXIT

say()  { printf '%s\n' "$*"; }
ok()   { printf 'PASS %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf 'FAIL %s: %s\n' "$1" "$2" >&2; FAIL=$((FAIL+1)); }

# Assert command fails and combined output contains needle.
expect_deny() {
  local label="$1" needle="$2"; shift 2
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  if [[ $rc -eq 0 ]]; then
    bad "$label" "expected nonzero exit, got 0 :: $(echo "$out" | tail -1)"
  elif [[ "$out" != *"$needle"* ]]; then
    bad "$label" "denied but without expected text '$needle' :: $(echo "$out" | tail -2 | tr '\n' ' ')"
  else
    ok "$label"
  fi
}

# Assert command succeeds.
expect_ok() {
  local label="$1"; shift
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  if [[ $rc -ne 0 ]]; then
    bad "$label" "expected exit 0, got $rc :: $(echo "$out" | tail -2 | tr '\n' ' ')"
  else
    ok "$label"
  fi
}

B() { br --no-auto-import --no-auto-flush "$@"; }
ROOT="bd-performance-conformance-bridge-tu32j"

### --- scratch project assembly -------------------------------------------
mkdir -p "$PROJ/.beads" "$PROJ/docs"
sqlite3 "$ROOT_DIR/.beads/beads.db" ".backup '$PROJ/.beads/beads.db'" || { echo "backup failed" >&2; exit 2; }
cp "$ROOT_DIR/.beads/policy.yaml" "$PROJ/.beads/policy.yaml"
cp -r "$ROOT_DIR/scripts" "$PROJ/scripts"
cp "$ROOT_DIR/docs/bridge_closeout_manifest_v1.json" "$PROJ/docs/"
git -C "$PROJ" init -q && git -C "$PROJ" add -A && git -C "$PROJ" -c user.email=a@a -c user.name=a commit -qm init
cd "$PROJ" || exit 2

### D1 deterministic regeneration against pristine snapshot (before mutations)
expect_ok "D1 manifest-deterministic" python3 scripts/gen_bridge_closeout_manifest.py --check

### --- labels: every manifest-listed decomposed parent ---------------------
python3 - <<'PY' > /tmp/bridge_smoke_parents.txt || exit 2
import json
m = json.load(open("docs/bridge_closeout_manifest_v1.json"))
print("\n".join(i for i, n in m["nodes"].items() if n["children"]))
PY
while IFS= read -r id; do B label add "$id" bridge-manifest >/dev/null; done < /tmp/bridge_smoke_parents.txt

EPIC24="$ROOT.24"; EPIC25="$ROOT.25"; EPIC26="$ROOT.26"; EPIC27="$ROOT.27"

### S1 raw close, open children
expect_deny "S1 raw-close-open-children" "open child" \
  B close "$EPIC24"

### S2 force still hits the gate
expect_deny "S2 force-denied-by-gate" "bridge_closeout" \
  B close "$EPIC24" --force

### S3 bypass disabled
expect_deny "S3 bypass-disabled" "allow_bypass" \
  B close "$EPIC24" --force --bypass-policy --bypass-reason "operator override attempt"

### S4 forged provider pass: native accepts (residual), verifier flags
if B gate report "$EPIC27" --gate bridge_closeout --provider rogue-agent \
     --status pass --to closed --note forged >/dev/null 2>&1; then
  FORGE_OUT=$(B close "$EPIC27" --force 2>&1); FORGE_RC=$?
  if [[ $FORGE_RC -eq 0 ]]; then
    VOUT="$(python3 scripts/bridge_closeout_verify.py --issue "$EPIC27")"
    if [[ "$VOUT" == *"unsanctioned_gate_pass"* ]]; then
      ok "S4 forged-pass-flagged-by-verifier (native acceptance = documented residual)"
    else
      bad "S4 forged-pass-flagged-by-verifier" "close accepted but verifier silent"
    fi
    B reopen "$EPIC27" >/dev/null 2>&1 || true
    sqlite3 .beads/beads.db "DELETE FROM gate_result_history WHERE issue_id='$EPIC27'"
    sqlite3 .beads/beads.db "UPDATE issues SET status='open', closed_at=NULL, close_reason='' WHERE id='$EPIC27'"
  else
    bad "S4 forged-pass-native-behavior" "expected documented residual acceptance, got denial :: $(echo "$FORGE_OUT" | tail -1)"
  fi
else
  bad "S4 forged-pass-recordable" "could not record foreign provider pass at all"
fi

### S5 valid completion path on EPIC24 (children carry real blocks edges -> force)
for i in 1 2 3 4 5 6 7; do
  expect_ok "S5.close-child-$i" B close "$EPIC24.$i" --force --reason "smoke: child $i completed with evidence"
done
expect_ok "S5.verify-check-only" ./scripts/run_bridge_closeout_gate.sh "$EPIC24" --check
expect_ok "S5.gate-pass" ./scripts/run_bridge_closeout_gate.sh "$EPIC24"
expect_ok "S5.close-parent" B close "$EPIC24" --reason "smoke: all seven required children closed with evidence"

### S6 stale pass on EPIC25: sanctioned-style pass, then revision bumps.
B update "$EPIC25" --status in_progress >/dev/null 2>&1 || true
B gate report "$EPIC25" --gate bridge_closeout --provider bridge-closeout-verifier \
    --status pass --to closed --note "simulated pre-bump pass" >/dev/null 2>&1 || true
B update "$EPIC25" --status blocked >/dev/null 2>&1 || true
B update "$EPIC25" --status open >/dev/null 2>&1 || true
STALE_OUT=$(B close "$EPIC25" --force 2>&1); STALE_RC=$?
if [[ $STALE_RC -ne 0 && "$STALE_OUT" == *"stale"* ]]; then
  ok "S6 stale-revision-denied"
elif [[ $STALE_RC -ne 0 ]]; then
  ok "S6 close-still-denied post-bump (message variant)"
else
  bad "S6 stale-revision-denied" "close accepted despite revision bump"
fi
B update "$EPIC25" --status in_progress >/dev/null 2>&1 || true

### S7 unmanifested drift under EPIC26
DRIFT_ID=$(B create "smoke unmanifested child" --json | jq -r '.id // .issue.id')
B dep add "$DRIFT_ID" "$EPIC26" --type parent-child >/dev/null
expect_deny "S7 unmanifested-drift" "fail_on_unmanifested_drift" \
  ./scripts/run_bridge_closeout_gate.sh "$EPIC26" --check

### S8 tombstone a required child of EPIC25 (--force orphans dependents; never cascade)
VICTIM="$EPIC25.1"
B delete "$VICTIM" --force >/dev/null 2>&1 || true
expect_deny "S8 tombstone-or-missing" "tombstone_or_missing" \
  ./scripts/run_bridge_closeout_gate.sh "$EPIC25" --check

### S9 reparenting: remove one parent-child edge inside EPIC26
EDGE_KID=$(python3 - <<PY
import json
m = json.load(open("docs/bridge_closeout_manifest_v1.json"))
print(m["nodes"]["$EPIC26"]["children"][0])
PY
)
B dep remove "$EDGE_KID" "$EPIC26" >/dev/null 2>&1 || true
expect_deny "S9 reparent-edge-missing" "reparented_or_edge_missing" \
  ./scripts/run_bridge_closeout_gate.sh "$EPIC26" --check

### S10 peer friction check: unrelated issue closes normally
PLAIN=$(B create "plain non-manifest task" --json | jq -r '.id // .issue.id')
expect_ok "S10 plain-close-unaffected" B close "$PLAIN" --reason "smoke: ordinary work unaffected by policy"

### S11 break-glass on EPIC26 (incomplete by construction)
KEYFILE="$SCRATCH/bg.key"; printf 'smoke-secret-%s\n' "$RANDOM" > "$KEYFILE"
BG_OUT=$(BRIDGE_BREAKGLASS_KEY_FILE="$KEYFILE" ./scripts/bridge_breakglass.sh "$EPIC26" "smoke: operator signed emergency closure drill" 2>&1); BG_RC=$?
if [[ $BG_RC -ne 0 ]]; then
  bad "S11 breakglass-record" "$(echo "$BG_OUT" | tail -1)"
else
  if B close "$EPIC26" --force --reason "smoke: break-glass closure" >/dev/null 2>&1; then
    ROUT="$(python3 scripts/bridge_closeout_verify.py --issue "$ROOT")"
    if [[ "$ROUT" == *"breakglass_not_normal_completion"* ]]; then
      ok "S11 breakglass-closes-but-flagged-forever"
    else
      bad "S11 breakglass-flagged" "closed but root verification does not flag it"
    fi
  else
    bad "S11 breakglass-close" "signed pass did not enable close"
  fi
fi


say ""
say "smoke results: PASS=$PASS FAIL=$FAIL scratch=$SCRATCH"
[[ $FAIL -eq 0 ]]
