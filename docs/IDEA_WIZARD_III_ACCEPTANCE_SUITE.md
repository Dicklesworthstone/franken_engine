# IDEA-WIZARD-III Acceptance Suite

This suite is the top-level source-only acceptance wrapper for the
IDEA-WIZARD-III proof-economy and degraded-coordination wave.

It verifies that every child contract and fixture bundle is present, tracked,
and JSON-valid; runs the cheap fixture/selftest gates; captures `br show`
closeout evidence for every child bead; emits a preserved degraded-coordination
bundle; and replays that bundle without rerunning component commands.

The suite does not run Cargo, start `rch`, mutate `br`, send Agent Mail, repair
Agent Mail, query live workers, or mutate remote workers. Rust validation is
therefore marked `not_required_source_only_surface` unless a future child
contract adds an explicit Rust test requirement; any such future Rust command
must be RCH-wrapped.

## Outputs

- `run_manifest.json`
- `acceptance_manifest.json`
- `events.jsonl`
- `commands.txt`
- `step_results.jsonl`
- `br_closeout_evidence.jsonl`
- `preserved/degraded_coordination/run_manifest.json`
- `preserved/degraded_coordination/drill_report.json`

Replay mode validates the emitted suite bundle without rerunning the child
selftests, `br show`, or degraded-coordination fixture generation.
