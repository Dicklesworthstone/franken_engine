# RGC Continuation Cliff Atlas v1

Status: active
Primary bead: `bd-1lsy.7.19`
Track id: `RGC-619`
Machine-readable contract: `docs/rgc_continuation_cliff_atlas_v1.json`

## Scope

`RGC-619` defines a deterministic continuation cliff atlas for runtime
performance and tail-risk neighborhoods. The atlas is the local source of truth
for whether a claimed win is robust, near a cliff, already beyond a cliff, or
not sampled at all.

## Cliff Band Contract

Every evaluated threat or workload neighborhood must emit exactly one margin
certificate with one of these bands:

1. `stable`
2. `near_cliff`
3. `beyond_cliff`
4. `missing_neighborhood`

The certificate must include explicit CVaR margin, e-value margin, and
observation margin fields. Missing neighborhoods are not advisory; they are a
fail-closed state.

## Witness and Escape Contract

Every non-stable band must emit a cliff witness with:

1. `threat_class_id`
2. `cliff_band`
3. `campaign_id` when a sampled campaign exists
4. `max_payoff_millionths`
5. `worst_exploit`
6. `escape_action`
7. `rationale`

`missing_neighborhood` witnesses must route to a deterministic safe fallback.
`near_cliff` and `beyond_cliff` witnesses must carry a deterministic rollback or
safe-lane routing action.

## Failure Policy

The continuation cliff atlas fails closed when:

1. Any declared neighborhood has no observations.
2. Any neighborhood crosses the CVaR budget or e-value alarm boundary.
3. Any neighborhood is within the configured near-cliff margin and the caller
   attempts to treat the result as globally robust without preserving the
   warning witness.

## Deterministic Replay

Primary replay entrypoint:

```bash
./scripts/run_rgc_continuation_cliff_atlas_suite.sh ci
```

Supported modes:

- `check`
- `test`
- `clippy`
- `ci`

All heavy cargo work in the gate runner must execute via `rch`.

## Evidence Pack

Every run emits:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`

Under:

`artifacts/rgc_continuation_cliff_atlas/<UTC_TIMESTAMP>/`

## Operator Verification

1. Run the replay command in `ci` mode.
2. Inspect the emitted manifest, events, and commands.
3. Confirm the continuation cliff atlas includes margin certificates for every
   declared neighborhood.
4. Confirm any non-stable neighborhood has a witness and deterministic
   `escape_action`.
