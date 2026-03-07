# RGC Hindsight Boundary Capture V1

Status: active  
Primary bead: `bd-1lsy.9.11.1`  
Machine-readable contract: `docs/rgc_hindsight_boundary_capture_v1.json`

## Purpose

This contract defines the minimal hindsight boundary capture substrate for
FrankenEngine. The objective is to record only the small set of
nondeterministic or externally shaped facts that actually matter for replay,
audit, and escalation.

The contract is deliberately fail-closed:

- missing required minimal fields invalidate a capture
- unexpected extra fields are rejected from the minimal envelope
- richer capture is requested through explicit escalation reasons rather than
  silently widening the logging surface

## Boundary Taxonomy

The substrate enumerates these boundary classes:

- `clock_read`
- `randomness_draw`
- `filesystem_input`
- `network_response`
- `module_resolution`
- `scheduling_decision`
- `controller_override`
- `external_policy_read`
- `hardware_surface_read`

Each class has:

- a stable nondeterminism tag
- a minimal field set required for replay
- a list of escalation cases
- field-level privacy and redaction metadata

## Correlation Key Contract

Every capture record derives a stable `correlation_key` from:

- boundary class
- capture sequence
- `trace_id`
- `decision_id`
- component name
- virtual timestamp

The key is content-addressed so downstream replay, evidence-ledger, and support
surfaces can join on one deterministic identifier without reinterpreting raw
payloads.

## Minimal Replay Input Rules

Minimal inputs are sufficient only when:

- every required field for the boundary class is present
- no unexpected field is smuggled into the minimal envelope
- the capture does not declare an escalation reason

If a capture declares an escalation reason, the record remains valid but is
classified as `needs_escalation` so downstream consumers know the minimal
envelope is not the whole story.

## Privacy And Redaction

Redaction happens at capture time, not as an afterthought.

The machine-readable contract assigns every minimal field one of:

- `public_metadata`
- `path_digest`
- `secret_digest`
- `policy_digest`
- `hardware_fingerprint`

and one treatment:

- `plaintext`
- `digest_only`
- `omit`

This lets support, release, replay, and evidence-ledger consumers reuse the
same privacy posture without inventing their own field policies.

## Artifact Contract

The deterministic scenario script for this bead emits:

- `hindsight_boundary_catalog.json`
- `minimal_replay_input_schema.json`
- `boundary_capture_log.jsonl`
- `boundary_redaction_map.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`

Artifacts live under:

`artifacts/rgc_hindsight_boundary_capture/<UTC_TIMESTAMP>/`

## Operator Verification

```bash
jq empty docs/rgc_hindsight_boundary_capture_v1.json
cargo test -p frankenengine-engine --test rgc_hindsight_boundary_capture
./scripts/run_rgc_hindsight_boundary_capture.sh ci
./scripts/e2e/rgc_hindsight_boundary_capture_replay.sh ci
```
