# Swarm Proof Request Capture

`bd-ua5n2.2`

`scripts/swarm_proof_request_capture.sh` normalizes proof intent from br, Agent
Mail, git status, and RCH command summaries into evidence-linked proof request
rows for the proof broker. It never runs Cargo or RCH.

## Inputs

The script accepts a single fixture case with `--fixture-json`, or separate
source snapshots:

- `--br-json`
- `--agent-mail-json`
- `--git-status-json`
- `--rch-summary-json`
- repeated `--claimed-path`

When br or git snapshots are omitted, the script can read the local br
in-progress list and git porcelain status as a lightweight fallback. Agent Mail
context is explicit evidence: if it is missing, capture fails closed.

## Output Rows

Successful capture emits `proof_requests.jsonl`. Every row includes:

- `trace_id`
- `proof_request_id`
- `bead_id`
- `agent`
- normalized proof `command`
- `request_kind`
- `captured_at`
- `source_revision`
- `source_evidence` pointers for br, Agent Mail, git, and RCH snapshots

## Fail-Closed Rules

Capture fails closed for:

- missing Agent Mail message/reservation context
- stale br/bv snapshot
- dirty git paths outside the claimed lane
- ambiguous or missing proof command text
- RCH local fallback contamination

The script writes `proof_request_capture.json`, `run_manifest.json`,
`events.jsonl`, `commands.txt`, and `report.md` for both passing and fail-closed
runs.

## Validation

```bash
jq empty scripts/testdata/swarm_proof_request_capture/cases.json
bash -n scripts/swarm_proof_request_capture.sh
bash -n scripts/e2e/swarm_proof_request_capture_smoke.sh
bash scripts/e2e/swarm_proof_request_capture_smoke.sh check
bash scripts/e2e/swarm_proof_request_capture_smoke.sh selftest
git diff --check -- scripts/swarm_proof_request_capture.sh docs/SWARM_PROOF_REQUEST_CAPTURE.md scripts/testdata/swarm_proof_request_capture/cases.json scripts/e2e/swarm_proof_request_capture_smoke.sh
```
