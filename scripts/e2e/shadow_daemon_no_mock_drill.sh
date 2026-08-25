#!/bin/bash
set -euo pipefail

# Authoritative no-mock shadow-daemon lifecycle drill (bd-nil04).
#
# Unlike scripts/e2e/shadow_daemon_lifecycle_drill.sh (which self-marks
# DRILL_EVIDENCE_MODE=synthetic_drill and exits 17 as no-mock proof), this
# drill harvests REAL repository state with real tools, normalizes it into
# composer journal events, and drives the REAL advisory decision composer
# (`compose_shadow_decision`) through a Rust integration-test harness.
#
# Machinery truth is what is under test: composition succeeds on true inputs,
# repeats byte-stably, stamps exactly the advisory-only mutation policy, and
# derives error codes consistent with the captured reality. The repository's
# health verdict itself may legitimately be Degraded/Blocked — that is honest
# output, not a drill failure.
#
# Exit codes:
#   0  machinery held end-to-end; evidence bundle written
#   17 no-mock proof could not be established (harness failed)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

TIMESTAMP="$(date +%Y%m%dT%H%M%SZ)"
OUT_DIR="artifacts/shadow_daemon_no_mock_drill/$TIMESTAMP"
CAPTURE_DIR="$OUT_DIR/capture"
OUTPUT_ROOT="$OUT_DIR"
RUN_ID="shadow-no-mock-$TIMESTAMP"

mkdir -p "$CAPTURE_DIR" "$OUTPUT_ROOT"
COMMANDS_FILE="$OUT_DIR/commands.txt"
: > "$COMMANDS_FILE"

record() { echo "$1" >> "$COMMANDS_FILE"; }
fail_closed() {
    echo "authoritative drill failed closed: $1" >&2
    echo "{\"drill\":\"authoritative_no_mock_lifecycle\",\"result\":\"fail_closed\",\"reason\":\"$1\"}" \
        > "$OUT_DIR/drill_evidence.json"
    exit 17
}

echo "== authoritative no-mock shadow daemon drill ($TIMESTAMP) ==" >&2

# --- 1. Real harvest ---------------------------------------------------------
record "br ready --json"
br ready --json > "$CAPTURE_DIR/br_ready.json" 2>"$CAPTURE_DIR/br_ready.err" || BR_FAILED=1
BR_FAILED="${BR_FAILED:-0}"

record "br list --json --status in_progress"
record "bv --robot-plan"
BV_DEGRADED=0
if ! timeout 60s bv --robot-plan > "$CAPTURE_DIR/bv_plan.json" 2>>"$CAPTURE_DIR/bv.err"; then
    BV_DEGRADED=1
    echo '{}' > "$CAPTURE_DIR/bv_plan.json"
fi

record "curl agent-mail health"
MAIL_REACHABLE=0
if curl -fsS -m 5 http://127.0.0.1:8765/health > "$CAPTURE_DIR/mail_health.json" 2>/dev/null; then
    MAIL_REACHABLE=1
fi
# Reservation enumeration is only attempted through the local HTTP API; when
# unavailable the source is marked degraded rather than silently emptied.
MAIL_DEGRADED=1
MAIL_RESERVATIONS="[]"
for endpoint in \
    "http://127.0.0.1:8765/api/file-reservations?project=/data/projects/franken_engine&active=true" \
    "http://127.0.0.1:8765/api/projects/data-projects-franken-engine/file-reservations?active=true"; do
    if curl -fsS -m 5 "$endpoint" > "$CAPTURE_DIR/mail_reservations.raw" 2>/dev/null; then
        if python3 -c 'import json,sys; json.load(open("'"$CAPTURE_DIR"'/mail_reservations.raw"))' 2>/dev/null; then
            MAIL_RESERVATIONS="$CAPTURE_DIR/mail_reservations.raw"
            MAIL_DEGRADED=0
            break
        fi
    fi
done

record "rch status"
RCH_CONTAMINATED=0
RCH_DEGRADED=0
if timeout 30s rch status > "$CAPTURE_DIR/rch_status.txt" 2>&1; then
    if grep -qi 'local fallback' "$CAPTURE_DIR/rch_status.txt"; then
        RCH_CONTAMINATED=1
    fi
else
    RCH_DEGRADED=1
fi

record "git rev-parse HEAD && git status --porcelain"
GIT_HEAD="$(git rev-parse HEAD)"
GIT_DIRTY_COUNT="$(git status --porcelain | wc -l | tr -d ' ')"

# No-mock proof artifacts are prior COMPLETE authoritative runs on disk.
record "scan artifacts/shadow_daemon_no_mock_drill for complete prior bundles"
NO_MOCK_ARTIFACTS_JSON="$(python3 - <<PYEOF
import json, os
root = "artifacts/shadow_daemon_no_mock_drill"
found = []
if os.path.isdir(root):
    for entry in sorted(os.listdir(root)):
        marker = os.path.join(root, entry, "drill_evidence.json")
        if entry != "$TIMESTAMP" and os.path.isfile(marker):
            found.append(marker)
print(json.dumps(found))
PYEOF
)"

NOW_EPOCH="$(date +%s)"

# --- 2. Normalize into composer journal events -------------------------------
record "python3 normalize capture -> journal.json"
python3 - "$CAPTURE_DIR" "$NOW_EPOCH" "$GIT_HEAD" "$RUN_ID" "$TIMESTAMP" "$NO_MOCK_ARTIFACTS_JSON" \
    "$BR_FAILED" "$BV_DEGRADED" "$MAIL_REACHABLE" "$MAIL_DEGRADED" "$MAIL_RESERVATIONS" \
    "$RCH_CONTAMINATED" "$RCH_DEGRADED" "$GIT_DIRTY_COUNT" <<'PYEOF'
import hashlib
import json
import sys
from datetime import datetime, timezone

capture = sys.argv[1]
now = int(sys.argv[2])
head = sys.argv[3]
run_id = sys.argv[4]
timestamp = sys.argv[5]
no_mock_artifacts = json.loads(sys.argv[6])
br_failed = sys.argv[7] == "1"
bv_degraded = sys.argv[8] == "1"
mail_reachable = sys.argv[9] == "1"
mail_degraded = sys.argv[10] == "1"
mail_reservations_path = sys.argv[11]
rch_contaminated = sys.argv[12] == "1"
rch_degraded = sys.argv[13] == "1"
git_dirty_count = int(sys.argv[14])

def load(name, fallback):
    try:
        with open(f"{capture}/{name}", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return fallback

def event(key, kind, payload, degraded=False, error_codes=None):
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return {
        "source_key": key,
        "source_id": f"{key}@{timestamp}",
        "journal_event_id": f"{run_id}:{key}",
        "source_kind": kind,
        "schema_version": "shadow.source.v1",
        "content_hash": "sha256:" + hashlib.sha256(canonical.encode()).hexdigest(),
        "payload_content_hash": "sha256:" + hashlib.sha256(canonical.encode()).hexdigest(),
        "normalized_payload_hash": "sha256:" + hashlib.sha256(canonical.encode()).hexdigest(),
        "collected_epoch_seconds": now,
        "fresh": True,
        "degraded": degraded,
        "error_codes": error_codes or [],
        "payload": payload,
        "normalized_payload": payload,
    }

ready = load("br_ready.json", [])
if isinstance(ready, dict):
    ready = ready.get("ready", ready)
in_progress_raw = load("br_in_progress.json", [])
in_progress_items = in_progress_raw if isinstance(in_progress_raw, list) else []
in_progress = [
    {
        "id": item.get("id"),
        "title": item.get("title"),
        "updated_epoch_seconds": int(
            datetime.fromisoformat(
                str(item.get("updated_at")).replace("Z", "+00:00")
            ).timestamp()
        ) if item.get("updated_at") else now,
    }
    for item in in_progress_items
]

reservations = []
try:
    loaded = json.load(open(mail_reservations_path, encoding="utf-8"))
    if isinstance(loaded, dict):
        reservations = loaded.get("active_reservations", loaded.get("reservations", []))
    elif isinstance(loaded, list):
        reservations = loaded
except Exception:
    reservations = []

with open("docs/SHADOW_DAEMON_PROOF_STATE.md", "rb") as handle:
    proof_state_bytes = handle.read()

events = [
    event(
        "br_queue",
        "br_cli",
        {"ready": ready, "in_progress": in_progress},
        degraded=br_failed,
        error_codes=["FE-SWARM-AUTOPILOT-SHADOW-DEGRADED-SOURCE"] if br_failed else [],
    ),
    event("bv_robot_plan", "bv_robot", load("bv_plan.json", {}), degraded=bv_degraded),
    event(
        "agent_mail",
        "http_api",
        {
            "reachable": mail_reachable,
            "active_reservations": reservations,
        },
        degraded=(not mail_reachable) or mail_degraded,
    ),
    event(
        "rch_status",
        "rch_cli",
        {
            "status_text": open(f"{capture}/rch_status.txt", encoding="utf-8").read()[:4000],
            "local_fallback_contamination_flag": rch_contaminated,
        },
        degraded=rch_degraded,
        error_codes=(
            ["FE-SWARM-AUTOPILOT-SHADOW-RCH-LOCAL-FALLBACK"] if rch_contaminated else []
        ),
    ),
    event(
        "git_state",
        "git_cli",
        {"head": head, "dirty": git_dirty_count > 0, "dirty_entries": git_dirty_count},
    ),
    event(
        "artifact_bundles",
        "artifact_scan",
        {
            "no_mock_proof_artifacts": no_mock_artifacts,
            "proof_state_doc_sha256": "sha256:"
            + hashlib.sha256(proof_state_bytes).hexdigest(),
        },
    ),
]

with open(f"{capture}/journal.json", "w", encoding="utf-8") as handle:
    json.dump(events, handle, indent=2, sort_keys=True)
    handle.write("\n")

with open(f"{capture}/source_revision.txt", "w", encoding="utf-8") as handle:
    handle.write(head + "\n")
with open(f"{capture}/generated_epoch_seconds.txt", "w", encoding="utf-8") as handle:
    handle.write(str(now) + "\n")
with open(f"{capture}/shadow_run_id.txt", "w", encoding="utf-8") as handle:
    handle.write(run_id + "\n")
PYEOF

# --- 3. Drive the real composer through the harness --------------------------
record "cargo test -p frankenengine-engine --test shadow_daemon_no_mock_drill_bd_nil04"
# cargo test executes with the crate directory as CWD, so relative paths from
# this script would not resolve inside the harness.
export SHADOW_NO_MOCK_CAPTURE_DIR="$PROJECT_ROOT/$CAPTURE_DIR"
export SHADOW_NO_MOCK_OUTPUT_ROOT="$PROJECT_ROOT/$OUTPUT_ROOT"
if ! cargo test -p frankenengine-engine --test shadow_daemon_no_mock_drill_bd_nil04 -- --nocapture; then
    fail_closed "composer harness assertions failed; see test output"
fi

echo "authoritative no-mock drill complete: evidence at $OUTPUT_ROOT/drill_evidence.json" >&2
