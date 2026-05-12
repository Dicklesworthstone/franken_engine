# Swarm Continuity Doctor

Bead: `bd-bahyn`

`scripts/swarm_continuity_doctor.sh` builds a fixture-fed continuity evidence
bundle from preserved br, Agent Mail, git, reservation, and rch snapshots. It
reuses `scripts/swarm_agent_mail_outage_continuity_bridge.sh` for mail outage
continuity and records the bridge output under `mail_outage_bridge/`.

The doctor is advisory-only. It never repairs the Agent Mail database, sends
Agent Mail, mutates br, releases reservations, runs Cargo, invokes rch, mutates
git, changes queue policy, or touches worker state.

## Usage

```bash
./scripts/swarm_continuity_doctor.sh \
  --br-ready-json /path/to/br-ready.json \
  --br-in-progress-json /path/to/br-in-progress.json \
  --mail-health-json /path/to/mail-health.json \
  --agent-profiles-json /path/to/agent-profiles.json \
  --git-status-json /path/to/git-status.json \
  --file-reservations-json /path/to/file-reservations.json \
  --rch-status-json /path/to/rch-status.json \
  --rch-queue-json /path/to/rch-queue.json \
  --output-dir /tmp/swarm-continuity-doctor
```

## Artifacts

- `run_manifest.json`
- `swarm_continuity_doctor_report.json`
- `events.jsonl`
- `commands.txt`
- `report.md`
- `mail_outage_bridge/mail_outage_continuity_bridge.json`

## Decisions

- `healthy`: no continuity findings were produced.
- `degraded`: one or more advisory findings are present, such as red/corrupt
  Agent Mail, degraded rch evidence, dirty paths, missing reservation snapshots,
  or partial mail reads.
- `blocked`: a fail-closed finding is present, such as local rch fallback
  contamination or reservation conflicts.

Red or corrupt Agent Mail is always represented as degraded evidence, even when
partial reads such as agent profiles are still available.

## Validation

```bash
jq empty docs/swarm_continuity_doctor_contract_v1.json scripts/testdata/swarm_continuity_doctor/cases.json
bash -n scripts/swarm_continuity_doctor.sh scripts/e2e/swarm_continuity_doctor_smoke.sh
bash scripts/e2e/swarm_continuity_doctor_smoke.sh check
bash scripts/e2e/swarm_continuity_doctor_smoke.sh selftest
git diff --check -- scripts/swarm_continuity_doctor.sh scripts/e2e/swarm_continuity_doctor_smoke.sh scripts/testdata/swarm_continuity_doctor/cases.json docs/swarm_continuity_doctor_contract_v1.json docs/SWARM_CONTINUITY_DOCTOR.md
```
