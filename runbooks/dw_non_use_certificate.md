# Runbook: Non-Use / Non-Exfiltration Certificate (E8 Integrator Guide & Threat-Model Boundary)

> Operator & integrator runbook per DW.DOCS (`bd-fqlfw.12`). Capability beads:
> `bd-fqlfw.8` (epic), `bd-fqlfw.8.1` (data contract), `bd-fqlfw.8.2` (runtime
> label ingress + purpose metadata), `bd-fqlfw.8.3` (six-file certifier bundle),
> `bd-fqlfw.8.4` (analyzed-subset soundness + refusal ledger), `bd-fqlfw.8.5`
> (`agent-sandbox` + MCP tool-runner shim), `bd-fqlfw.8.6` (four-act demo),
> `bd-fqlfw.8.7` (capstone verification + third-party verifier), `bd-fqlfw.8.8`
> (integrator guide + doc-drift guard), `bd-fqlfw.8.9` (trusted-surface red-team).

## What this does (one paragraph)

An E8 run executes untrusted extension or agent-generated JavaScript/TypeScript
under a machine-readable `DataContract` (`franken-engine.data-contract.v1`) and
emits a six-file signed evidence bundle stating what the run **did not do** with
labeled inputs (`non_use_certificate.json`, `use_certificate.json`,
`declassification_receipts.jsonl`, `capability_trace.jsonl`, `repro.lock`, and
`audit.md`). Certification is derived mechanically from the preflight
analyzed-subset refusal ledger (`e8_analyzed_subset.rs`), runtime IFC provenance,
verified `DeclassificationReceipt` records, and hostcall capability traces, and
is signed with an Ed25519 `RuntimeEvidenceAuthority` (`franken-engine.e8-certifier`)
so an external verifier (`third_party_verifier::verify_non_use_certificate_claim`)
can check origin, file digests, trace bytes, and refusal-ledger consistency
against an independently pinned `EvidenceVerificationIdentity`.

## Explicit Threat-Model & Analyzed-Subset Boundary (Read First)

An E8 certificate is **explicit-flow only** (`threat_model_scope = "explicit_flow_ifc_v1"`,
canonical spec: [`docs/E8_NON_USE_CERTIFICATE_THREAT_MODEL_V1.md`](../docs/E8_NON_USE_CERTIFICATE_THREAT_MODEL_V1.md)).
It is **never a noninterference proof over arbitrary JavaScript** and **never
covers covert, timing, control-flow-implicit, or hardware side channels**:

| Boundary | Behavior |
|---|---|
| **Analyzed explicit-flow subset** (literals, lexical bindings, arithmetic/logical/bitwise ops, property get/set/delete/accessors, direct/method/constructor/callback calls, arrays/objects/templates, `try`/`catch`/`finally`/`throw`, capability-gated hostcalls) | Eligible for `certified_within_analyzed_scope` when the refusal ledger is empty and every requested claim evaluates `holds_within_analyzed_scope`. |
| **Unproven JS constructs** (`await`, `yield`, async/generator creation, `for..in` / `for..of` / `iterator_close`, `import` / `export` module edges, dynamic `require(...)`, native `.node` addons, `eval`, ambient `process` / `fetch`) | Emits `unproven_ifc_propagation` with `<file>:<line>:<col>` span provenance (plus `missing_source_span` when spanless), sets `must_block_certificate = true`, and downgrades the bundle to `certificate_status = "uncertified"` (output-independence claims evaluate `unanalyzed_fail_closed`). |
| **Covert / timing / implicit branch channels** | Outside `explicit_flow_ifc_v1`; `RequestedOutputClaim` cannot express covert/timing claims, and `out_of_scope_covert_channel` / `out_of_scope_timing_channel` remain pinned fail-closed refusal codes. |
| **Runtime IFC violation (`Secret -> OpenSink / NeverSink`)** | Aborts execution fail-closed before leak (`ifc runtime guard blocked execution`); no positive certificate bundle is emitted. |

## Authoring a `DataContract` (`franken-engine.data-contract.v1`)

A contract declares five sections:

1. **`input_bindings`**: each binding names `binding_id`, `object_ref`, `path`
   (hash-bound against the exact `run_input` bytes; mismatch triggers
   `run_input_hash_mismatch`), sensitivity `label` (`Public`, `Internal`,
   `Confidential`, `Secret`, `TopSecret`, or custom), `owner`, `role`
   (`run_input` or `auxiliary_input`), and `allowed_purposes`.
2. **`allowed_purposes`** & **`allowed_capabilities`**: explicit purpose list
   (for example `["runtime_execution"]`) and `RuntimeCapability` ceiling
   (for example `["VmDispatch", "HeapAllocate", "Builtin", "Console"]`).
3. **`allowed_sinks`**: sink descriptors with `sink_id`, `clearance`
   (`OpenSink`, `AuditedSink`, `SealedSink`, `NeverSink`), `location`, and
   `allowed_labels`.
4. **`required_declassification_routes`**: cross-label routes requiring a signed
   `DeclassificationReceipt` in `declassification_receipts.jsonl`.
5. **`requested_output_claims`**: closed enum of negative claims:
   - `{"claim_type": "no_flow", "claim_id": "...", "source_label": "Secret", "sink_clearance": "OpenSink"}`
   - `{"claim_type": "output_independent_of", "claim_id": "...", "source_label": "Secret"}`
   - `{"claim_type": "capability_not_used", "claim_id": "...", "capability": "NetworkEgress"}`

## Preflight & Normal Use

### 1. Deterministic certifier key initialization + `frankenctl run`

Pinning an explicit `franken-engine.e8-certifier` signing seed makes two
independent CLI runs emit byte-identical certificate bundles and lets third
parties verify against `trust.json`:

```bash
# 1) Initialize an explicit E8 certifier key + pinned public trust snapshot
TRUST_DIGEST=$(frankenctl evidence init \
  --producer-id franken-engine.e8-certifier \
  --key-out ./artifacts/e8.seed \
  --trust-out ./artifacts/e8.trust.json \
  --epoch 1 | jq -r .evidence_trust_snapshot_digest)

# 2) Execute under the data contract, emitting run report, trace, explain bundle, and E8 bundle
frankenctl run \
  --input ./examples/26_non_exfiltration_certificate/out/agent_honest.js \
  --extension-id agent-support-summarizer \
  --data-contract ./contract.json \
  --evidence-key-file ./artifacts/e8.seed \
  --evidence-producer-id franken-engine.e8-certifier \
  --trust-snapshot ./artifacts/e8.trust.json \
  --expected-trust-digest "$TRUST_DIGEST" \
  --emit-trace ./artifacts/nondeterminism_trace.json \
  --explain --explain-out ./artifacts/explain.json \
  --certificate-out ./artifacts/certificate_bundle \
  --out ./artifacts/run_report.json

# 3) Re-execute recorded inputs under strict authenticated replay (non-self-fed)
frankenctl replay run \
  --trace ./artifacts/run_report.json \
  --mode strict \
  --trust-snapshot ./artifacts/e8.trust.json \
  --expected-trust-digest "$TRUST_DIGEST" \
  --out ./artifacts/replay_report.json
```

### 2. Agent-sandbox & MCP / tool-runner shim (`frankenctl agent-sandbox`)

Agent frameworks execute model-generated code under a manifest
(`franken-engine.agent-sandbox-manifest.v1`) declaring `agent_id`, `tool_grants`
(each mapped to a typed `RuntimeCapability`; unknown capability tags fail closed),
`denied_capability_tags`, and `purpose`:

```bash
frankenctl agent-sandbox \
  --manifest ./sandbox_manifest.json \
  --input ./generated_step.js \
  --data-contract ./contract.json \
  --certificate-out ./artifacts/sandbox_certificate_bundle \
  --out ./artifacts/sandbox_report.json
```

Programmatic Rust / MCP tool-runner consumers drive `agent_sandbox::McpToolRunnerShim`
directly so tool calls pass through the hostcall capability membrane and guardplane
containment thresholds (`allow` / `challenge` / `sandbox` / `suspend` / `terminate` /
`quarantine`). Note that CLI `frankenctl agent-sandbox` without an explain-bundle
provenance surface stays honestly `uncertified` rather than overclaiming.

### 3. Capstone gate, replay wrapper, and four-act demo

```bash
# Run the full E8 soundness capstone gate (routes Cargo through rch by default)
./scripts/run_dw_non_use_certificate.sh ci
DW_RUN_LOCAL=1 ./scripts/run_dw_non_use_certificate.sh ci   # local fallback

# Verify a preserved capstone bundle or re-run into replay root
./scripts/e2e/dw_non_use_certificate_replay.sh bundle artifacts/dw_non_use_certificate/<ts>
./scripts/e2e/dw_non_use_certificate_replay.sh rerun

# Run the interactive four-act demo once frankenctl is built
./examples/26_non_exfiltration_certificate/demo.sh
```

## Reading the Six-File Bundle & Third-Party Verification

| File | Answers |
|---|---|
| `non_use_certificate.json` | Schema `franken-engine.non-use-certificate.v2`: `certificate_status` (`certified_within_analyzed_scope` vs `uncertified`), `scope` (`explicit_flow_ifc_v1`, `replay_trace_content_hash_hex`), `refusal_ledger_content_hash_hex`, per-claim verdicts (`holds_within_analyzed_scope`, `contradicted`, `not_assertable_conservative`, `unanalyzed_fail_closed`), and `signature_envelope` (`EvidenceSignatureEnvelope`). |
| `use_certificate.json` | Schema `franken-engine.use-certificate.v2`: conservative over-approximation of labels bound, capabilities granted/invoked, sinks reached, and declassifications applied, signed under the same `EvidenceSignatureEnvelope`. |
| `declassification_receipts.jsonl` | One signed `DeclassificationReceipt` JSON object per line (`verify()` checked during third-party verification) for every cross-label flow authorized during the run. |
| `capability_trace.jsonl` | Ordered `CapabilityTraceRecord` entries (`grant`, `host_effect` with length + SHA-256 rather than raw payload bytes, and `console_summary`). |
| `repro.lock` | Schema `franken-engine.repro-lock.v2`: exact SHA-256 + byte lengths of all five sibling bundle files plus `replay_pointer` matching `sha256sum` of the `--emit-trace` JSON file (`allow_randomness = false`). |
| `audit.md` | Human-readable summary table including the explicit-flow scope boundary, claim verdicts, refusal codes/spans, and replay pointer. |

External verifiers construct `third_party_verifier::NonUseCertificateClaimBundle`
with their pinned `EvidenceVerificationIdentity`, the six bundle files, the
`E8RefusalLedgerReceipt` from the run report, and the emitted trace bytes, then
call `verify_non_use_certificate_claim(&claim_bundle)`. Any claimant-key
substitution, payload edit, `repro.lock` mismatch, tampered trace byte, broken
declassification receipt signature, or certification status contradicting
`refusal_receipt.must_block_certificate` returns `VerificationVerdict::Failed`.

## Exit Codes & Failure Triage

| Symptom / Exit | Meaning | Recovery |
|---|---|---|
| `frankenctl run` exits `0`, `certificate_status == "certified_within_analyzed_scope"` | Source stayed inside the analyzed explicit-flow subset, refusal ledger is empty, and every requested claim held. | Attach the six-file bundle + `--emit-trace` file + `trust.json` for downstream verification. |
| `frankenctl run` exits `0`, `certificate_status == "uncertified"` | Run completed safely, but an unproven JS construct (`unproven_ifc_propagation` at `<file>:<line>:<col>`) or missing explain/provenance evidence blocked certification. | Inspect `refusal_codes` in `audit.md` or the preflight receipt in `run_report.json`; rewrite the unanalyzed construct (`for..of` -> indexed `for`, remove dynamic `require` / async generator) if positive certification is required. |
| `frankenctl run` exits non-zero with `ifc runtime guard blocked execution` | Disallowed explicit flow (e.g., `Secret -> NeverSink / OpenSink`) or contract purpose/hash mismatch was caught before leak. | No certificate bundle is written; fix the illegal flow or declare an authorized `AuditedSink` / verified declassification route. |
| `frankenctl agent-sandbox` exits non-zero with `unknown capability tag` | Manifest requested a tool capability tag outside the closed `RuntimeCapability` vocabulary. | Map the tool grant to a valid capability tag (`console`, `fs_read`, `fs_write`, `network`, `process_spawn`, `timer`, `crypto`, etc.). |
| `verify_non_use_certificate_claim` returns `Failed` on `non_use_certificate_signature` or `trace_digest_parity` | Signer identity does not match the pinned `EvidenceVerificationIdentity`, or the `--emit-trace` file does not match `scope.replay_trace_content_hash_hex`. | Verify `--evidence-key-file` / `trust.json` pairing and ensure the unmodified `--emit-trace` file from the same run is supplied. |

## Claim-State Disclosure (Binding)

In [`docs/claim_to_proof_matrix_v1.json`](../docs/claim_to_proof_matrix_v1.json):
- Deterministic IFC confinement with signed declassification receipts (`FE-CLAIM-015`),
  compile-time ambient-authority hostcall/import rejection (`FE-CLAIM-006`),
  deterministic replay for declared security-critical decisions (`FE-CLAIM-013`),
  and signed decision receipts (`FE-CLAIM-004`) are **OBSERVED**.
- Live hardware TEE quote binding (`FE-CLAIM-004-TEE`) and end-to-end machine-checked
  theorem proofs for all security decision algorithms (`FE-CLAIM-016`) remain
  **HYPOTHESIS**.
- Describe E8 certificates strictly as **signed, replay-verifiable explicit-flow
  non-use certificates within the v1 analyzed subset**, bounded by
  [`docs/E8_NON_USE_CERTIFICATE_THREAT_MODEL_V1.md`](../docs/E8_NON_USE_CERTIFICATE_THREAT_MODEL_V1.md).
