# IDEA-WIZARD-IV Coordination Health Packet

`bd-o9wbd` adds an IDEA-WIZARD-IV adapter around the existing
`swarm_agent_mail_outage_continuity_bridge` surface. It emits
`coordination_health_packet.json`, a compact advisory packet that future agents
can attach to bead comments when Agent Mail is red, degraded, unavailable, or
malformed.

The packet is advisory only. It never runs `am doctor repair`, never repairs
the mailbox database, never sends Agent Mail, never claims or closes beads, and
never releases reservations.

## Inputs

```bash
./scripts/idea_wizard_iv_coordination_health_packet.sh \
  --mail-health-json /path/to/agent-mail-health.json \
  --br-in-progress-json /path/to/br-in-progress.json \
  --output-dir /tmp/franken-engine-iw4-coordination-health
```

Optional inputs:

- `--mail-bootstrap-json FILE`
- `--agent-profiles-json FILE`
- `--git-status-json FILE`
- `--file-reservations-json FILE`
- `--source-revision REV`
- `--generated-epoch-seconds N`

## Outputs

- `coordination_health_packet.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `report.md`
- `agent_mail_outage_bridge/mail_outage_continuity_bridge.json`

## Decisions

| Bridge decision | Packet decision | Meaning |
| --- | --- | --- |
| `healthy` | `healthy` | Mail evidence is available and no degraded reason was found |
| `degraded` | `degraded` | Coordination evidence is available but not green; use br fallback |
| `blocked` | `fail_closed` | Mail is unavailable and fallback evidence is insufficient |
| malformed input | `fail_closed` | The packet cannot trust the supplied health evidence |

## Validation

```bash
bash -n scripts/idea_wizard_iv_coordination_health_packet.sh
bash -n scripts/e2e/idea_wizard_iv_coordination_health_packet_smoke.sh
bash scripts/e2e/idea_wizard_iv_coordination_health_packet_smoke.sh check
git diff --check -- docs/IDEA_WIZARD_IV_COORDINATION_HEALTH_PACKET.md scripts/idea_wizard_iv_coordination_health_packet.sh scripts/e2e/idea_wizard_iv_coordination_health_packet_smoke.sh docs/idea_wizard_iv_saturation_convergence_v1.json
```
