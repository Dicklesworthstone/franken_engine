# Proof-Economy Control Surface Inventory

Bead: `bd-nil8a`

This inventory maps the existing swarm, proof, rch, and operator surfaces that
should be reused before building the operator proof-economy control tower. The
machine-readable companion is
`docs/proof_economy_control_surface_inventory_v1.json`.

## Operator Map

| Surface | Owner | Input schema | Emitted artifacts | Replay command |
| --- | --- | --- | --- | --- |
| Proof reuse cache planner | `scripts/proof_reuse_cache_planner.sh` | `franken-engine.proof-evidence-query.v1`, `franken-engine.proof-freshness-decay-report.v1` | `proof_cache_plan.json`, `events.jsonl`, `commands.txt`, `report.md`, classifier JSONL rows | `./scripts/proof_reuse_cache_planner.sh --proof-index-json <proof_index.json> --freshness-report <freshness.json> --expected-source-revision <rev> --changed-path <path> --output-dir <dir>` |
| Proof-economy replay trace normalizer | `scripts/proof_economy_replay_trace_normalizer.sh` | br snapshots plus optional mail, lease, proof-cache, resident-bundle, and no-mock drill snapshots | `replay_trace.normalized.json`, `events.jsonl`, `commands.txt`, `report.md` | `./scripts/proof_economy_replay_trace_normalizer.sh --br-ready-json <ready.json> --br-in-progress-json <in_progress.json> --output-dir <dir>` |
| Proof queue brownout detector | `scripts/proof_queue_brownout_starvation_detector.sh` | `franken-engine.proof-economy-replay-trace.v1`, optional `franken-engine.proof-economy-counterfactual-replay-report.v1` | `brownout_report.json`, `events.jsonl`, `commands.txt`, `report.md` | `./scripts/proof_queue_brownout_starvation_detector.sh --replay-trace-json <trace.json> --counterfactual-report-json <counterfactual.json> --output-dir <dir>` |
| Starvation rescue planner | `scripts/swarm_starvation_rescue_planner.sh` | `franken-engine.swarm-starvation-rescue-input.v1`, `franken-engine.swarm-starvation-rescue-scenario-matrix-report.v1` | `swarm_starvation_rescue_plan.json`, `events.jsonl`, `commands.txt`, `report.md` | `./scripts/swarm_starvation_rescue_planner.sh --starvation-rescue-input-json <input.json> --scenario-matrix-report-json <matrix.json> --output-dir <dir>` |
| Starvation rescue conformance gate | `scripts/swarm_starvation_rescue_conformance_gate.sh` | rescue plan plus resolved rescue input and scenario matrix reports | `swarm_starvation_rescue_conformance_report.json`, `events.jsonl`, `commands.txt`, `report.md`, gate JSONL rows | `./scripts/swarm_starvation_rescue_conformance_gate.sh --starvation-rescue-plan-json <plan.json> --output-dir <dir>` |
| Agent Mail outage continuity bridge | `scripts/swarm_agent_mail_outage_continuity_bridge.sh` | br in-progress snapshot plus optional mail health/bootstrap/profiles, git status, and reservation snapshots | `mail_outage_continuity_bridge.json`, `soft_lock_receipts.jsonl`, `events.jsonl`, `commands.txt`, `report.md` | `./scripts/swarm_agent_mail_outage_continuity_bridge.sh --br-in-progress-json <in_progress.json> --mail-health-json <mail_health.json> --output-dir <dir>` |
| Swarm ops state snapshot | `scripts/swarm_ops_state_snapshot_capture.sh` | br/bv/mail/rch/git snapshots or live read-only local CLI capture | `swarm_ops_state_snapshot.json`, `raw/`, `events.jsonl`, `commands.txt`, `report.md` | `./scripts/swarm_ops_state_snapshot_capture.sh --br-ready-json <ready.json> --br-in-progress-json <in_progress.json> --rch-status-json <rch_status.json> --git-status-txt <git_status.txt> --output-dir <dir>` |
| Agent causal trace graph | `scripts/swarm_agent_causal_trace_graph.sh` | `franken-engine.swarm-agent-causal-trace-event-set.v1` | `swarm_agent_causal_trace_graph.json`, `swarm_agent_causal_trace_anomalies.json`, `events.jsonl`, `commands.txt`, `report.md` | `./scripts/swarm_agent_causal_trace_graph.sh --normalized-events-json <events.json> --output-dir <dir>` |
| Swarm execution queue runner | `crates/franken-engine/src/swarm_execution_queue_runner.rs`, `crates/franken-engine/src/bin/franken_swarm_execution_queue.rs` | `franken-engine.swarm-execution-queue-input.v1` | `run_manifest.json`, `events.jsonl`, `commands.txt`, `execution_queue_artifact.json`, `risk_budget_receipt.json`, `bottleneck_report.json`, `operator_summary.md` | `rch exec -- env CARGO_TARGET_DIR=<target-dir> cargo run -p frankenengine-engine --bin franken_swarm_execution_queue -- --normalized-input-json <input.json> --output-dir <dir>` |
| Workload preflight doctor | `crates/franken-engine/src/workload_preflight_doctor.rs` | `WorkloadPreflightDoctorInput` | serialized `WorkloadPreflightDoctorReport`, text summary | `rch exec -- env CARGO_TARGET_DIR=<target-dir> cargo test -p frankenengine-engine workload_preflight_doctor` |
| Tail-latency control plane | `crates/franken-engine/src/tail_latency_control_plane.rs`, `crates/franken-engine/src/bin/franken_tail_latency_control_plane.rs` | `StressProfile`, epoch | `run_manifest.json`, `events.jsonl`, `commands.txt`, `trace_ids.json`, `latency_control_plane_report.json`, `admission_publication_bundle.json`, `summary.md`, `env.json`, `repro.lock`, `step_logs/` | `rch exec -- env CARGO_TARGET_DIR=<target-dir> cargo run -p frankenengine-engine --bin franken_tail_latency_control_plane -- --out-dir <dir> --profile synthetic-contention --epoch <n> --emit-artifact-stream` |
| Promotion gate runner | `crates/franken-engine/src/promotion_gate_runner.rs` | `GateRunnerConfig`, `GateRunnerInput` | `GateRunnerOutput`, `EvidenceArtifactBundle`, `GateRunnerLogEvent` when serialized by callers | `rch exec -- env CARGO_TARGET_DIR=<target-dir> cargo test -p frankenengine-engine promotion_gate_runner` |
| Remote-proof control surface catalog | `scripts/swarm_control_surface_catalog_normalizer.sh` | remote-proof surface manifest or `source_inventory` array | `swarm_control_surface_catalog.json`, `catalog_findings.json`, `events.jsonl`, `commands.txt`, `report.md` | `./scripts/swarm_control_surface_catalog_normalizer.sh --source-manifest-json <manifest.json> --output-dir <dir>` |

## Pipeline Shape

The proof queue path is already mostly present as a replayable pipeline:

1. `proof_reuse_cache_planner` classifies reusable, refresh-required, and invalid proof artifacts.
2. `proof_economy_replay_trace_normalizer` turns br/mail/rch/proof snapshots into a scheduler replay trace.
3. `proof_queue_brownout_starvation_detector` detects all-workers-busy, unfair agent share, low-priority starvation, and counterfactual brownout.
4. `swarm_starvation_rescue_planner` proposes bounded advisory rescue actions.
5. `swarm_starvation_rescue_conformance_gate` fails closed on stale, contradictory, ungrounded, or locally contaminated rescue evidence.

The coordination path is also present but split:

1. `swarm_ops_state_snapshot_capture` captures broad br/bv/mail/rch/git state, either from fixtures or live read-only local CLIs.
2. `swarm_agent_mail_outage_continuity_bridge` converts preserved snapshots into soft-lock continuity receipts without sending mail, repairing the DB, mutating br, invoking rch, or changing worker state.
3. `swarm_agent_causal_trace_graph` explains one normalized event set, but it is not yet a run-wide bead/mail/commit/rch evidence index.

## Overlaps

| Overlap | Surfaces | Resolution |
| --- | --- | --- |
| Coordination health | `swarm_ops_state_snapshot_capture`, `swarm_agent_mail_outage_continuity_bridge` | Use the snapshot surface for broad state capture and the bridge for mail-outage continuity receipts. |
| Proof queue rescue | replay trace normalizer, brownout detector, rescue planner, conformance gate | Treat them as one staged pipeline, not competing detectors. |
| Evidence graph scope | causal trace graph, remote-proof catalog | Catalog validates surface metadata; causal trace explains one run/event set. A future index should join bead, mail, commit, rch, and artifact edges. |
| Artifact envelopes | execution queue runner, tail-latency control plane, proof reuse planner, brownout detector | Later work should normalize `run_manifest.json`, `events.jsonl`, `commands.txt`, `trace_ids.json`, and report paths across surfaces. |

## Gap Table

| Gap | Category | Finding | Feeds |
| --- | --- | --- | --- |
| G1 | Missing CLI exposure | No single existing operator entry point composes swarm health, proof reuse, rch pressure, Agent Mail continuity, causal trace, and rescue recommendations. | `bd-bahyn`, `bd-i36b4` |
| G2 | Missing no-mock drill | Existing smoke/no-mock coverage is per-surface or per-family; no drill runs the whole proof-economy control tower from preserved real snapshots. | `bd-ksuqm` |
| G3 | Weak replay proof | Artifact envelopes differ. Several scripts emit `events.jsonl`, `commands.txt`, and `report.md` but no `run_manifest.json` or `trace_ids.json`. | `bd-bahyn`, `bd-es4nn` |
| G4 | Missing admission integration | Proof reuse planning is classifier-only and is not yet wired into rch proof admission. | `bd-yb8kk` |
| G5 | Mail degraded state | Agent Mail corruption can still leave partial reads available; red/corrupt health must remain explicit evidence, not success. | `bd-bahyn`, `bd-es4nn` |
| G6 | Library-only surface | `workload_preflight_doctor` and `promotion_gate_runner` have strong Rust tests but no proof-economy operator artifact bridge. | `bd-i36b4` |
| G7 | Evidence index scope | `swarm_agent_causal_trace_graph` is event-set scoped and does not index bead, mail, commit, rch, and artifact edges across a run. | `bd-es4nn` |
| G8 | Live capture boundary | `swarm_ops_state_snapshot_capture` supports live local CLI capture when fixtures are omitted, while downstream continuity work should be replay-first and explicit about live read-only capture boundaries. | `bd-bahyn`, `bd-ksuqm` |

## Validation

This bead is docs and JSON only. Source-only validation is:

```bash
jq empty docs/proof_economy_control_surface_inventory_v1.json
git diff --check -- docs/proof_economy_control_surface_inventory_v1.json docs/PROOF_ECONOMY_CONTROL_SURFACE_INVENTORY.md
```

No Cargo is required for this inventory. Any future Rust validation named above
must use `rch exec -- env CARGO_TARGET_DIR=<target-dir> ...`.
