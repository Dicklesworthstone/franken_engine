# E8 Non-Use / Use Certificate Bundle — Audit Summary

**Certificate status: uncertified** (refusal ledger `e8-preflight-de928b0d9e7bd060477d81b5e23bcf3823245d8c8b263b55fb5a5fbc1833ee48`, result class `uncertified`).

## Scope

Under engine version `0.3.0`, policy `default-policy` at security epoch 1, the declared host boundary (1 sink(s)), input binding `support-ticket-batch` of contract `contract-smuggle` (contract hash `35d81555453be4ab6646a445da2c1f6808d5a93723b7c803198e5e1dd8b18b49`), and replay artifact `cadc328d5c74614f41f0f46a359af0726fb91807264906392621b28886713a25`, the flows and capability uses enumerated below were absent or present as stated.

Threat model: **EXPLICIT-FLOW ONLY** (`explicit_flow_ifc_v1`); covert channels, timing channels, and control-flow implicit channels are out of scope (see `docs/E8_NON_USE_CERTIFICATE_THREAT_MODEL_V1.md`). Analysis posture: `conservative_ingress_over_approximation_v1` — every declared sink is treated as a potential destination of the ingress label; certification additionally requires the bd-fqlfw.8.4 analyzed-subset scan to place every construct of the run inside the analyzed explicit-flow subset.

### Declared host boundary

| sink | clearance | location |
|---|---|---|
| `audited-summary-report` | AuditedSink | report://weekly-summary |

## Requested output claims

| claim id | evaluation | detail |
|---|---|---|
| `no-secret-open-sink` | holds_within_analyzed_scope | no declared sink of clearance OpenSink exists in the host boundary; undeclared sinks are fail-closed by the membrane |
| `no-process-spawn` | holds_within_analyzed_scope | capability ProcessSpawn was granted by neither the contract envelope nor the runtime profile; the hostcall membrane denies ungranted capabilities fail-closed |
| `no-network-egress` | holds_within_analyzed_scope | capability NetworkEgress was granted by neither the contract envelope nor the runtime profile; the hostcall membrane denies ungranted capabilities fail-closed |

## Recorded flow edges

| event id | source label | sink ceiling | decision |
|---|---|---|---|
| `dc-ingress-contract-smuggle-support-ticket-batch-audited-summary-report` | confidential | confidential | allowed |

## Capability and declassification evidence

- capability trace records: 11 (see `capability_trace.jsonl`)
- declassification receipts consumed: 0 (see `declassification_receipts.jsonl`)
- contract capability envelope respected by runtime profile: false
- instructions executed: 295
- console entries: 0

## Verification

1. Verify both certificate signature envelopes against the runtime identity from an independently authenticated trust registry or recorded-run input. Never trust the verification key embedded in the claimant artifact as its own anchor.
2. Replay the run: `frankenctl replay run --trace <nondeterminism-trace.json> --mode strict` and confirm the trace content hash `cadc328d5c74614f41f0f46a359af0726fb91807264906392621b28886713a25`.
3. Re-emit the bundle from the same fixed inputs and confirm byte-identical files (digests in `repro.lock`).

## Honesty boundary

This bundle never asserts a negative claim beyond its analyzed scope: verdicts are limited to `holds_within_analyzed_scope`, `contradicted`, `not_assertable_conservative`, and `unanalyzed_fail_closed`. The certificate status (`uncertified`) is derived, never asserted — it requires an empty, scan-backed `certifiable_subset` refusal ledger AND every requested claim to hold within the analyzed explicit-flow subset; any unanalyzed construct keeps the run `uncertified` (bd-fqlfw.8.4). Payload bytes never appear in the trace — only lengths and content hashes.
