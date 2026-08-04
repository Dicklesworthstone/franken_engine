# E8 Analyzed-Subset Refusal Ledger

This document is the source-grounded inventory for
`bd-fqlfw.8.4.1.1`. It defines the denominator and refusal vocabulary
for E8 non-use certificate work before the full certifier exists.

## Boundary

The refusal ledger is not a non-use certificate. It is the artifact that
prevents an unanalyzed run from being promoted into one.

E8 v1 remains scoped to explicit-flow IFC. Covert channels, timing
channels, and resource side channels are out of scope and must be named as
out-of-scope refusals rather than silently approved.

## Current Source Hooks

| Surface | Current hook | Role in the refusal ledger |
| --- | --- | --- |
| Data contract binding | `crates/franken-engine/src/data_contract.rs` | Binds a run input, purpose, source hash, allowed capabilities, sinks, labels, declassification routes, requested output claims, and the live E8 preflight refusal receipt, including typed adversarial refusal fixtures. |
| CLI run/explain bundle | `crates/franken-engine/src/bin/frankenctl.rs` | Loads `--data-contract`, binds it to the run, emits the E8 preflight receipt, and links both artifacts into the runtime explain bundle. |
| Parser unsupported diagnostics | `crates/franken-engine/src/parser.rs` | Provides fail-closed unsupported-syntax diagnostics and grammar coverage status that can become unanalyzed-surface evidence. |
| Flow envelope | `crates/franken-engine/src/flow_envelope.rs` | Represents required flows, discovery methods, proof obligations, fallback status, and proof-artifact hashes. |
| IFC artifact model | `crates/franken-engine/src/ifc_artifacts.rs` | Defines labels, clearances, flow rules, declassification receipts, flow proofs, and confinement claims. |
| Interpreter labels | `crates/franken-engine/src/baseline_interpreter.rs` | Holds register labels, pending exception labels, intrinsic IFC propagation, and runtime label checks. |
| External trust UX | `docs/EXTERNAL_TRUST_ARTIFACT_UX_CONTRACT_V1.md` | Explains claim/certificate/bundle evidence to auditors and must distinguish missing E8 evidence from explicit uncertified refusal. |

## Denominator

An E8 run can only be considered inside the analyzed subset when all of
these conditions are true:

1. The run has a valid data-contract binding for the source, purpose, and
   extension id, plus the generated E8 preflight refusal receipt.
2. The run source has a stable source hash and, where available, source
   span/provenance references.
3. Parser and lowering surfaces either produce supported IR or emit a
   stable unsupported-surface diagnostic.
4. Every requested flow claim maps to a flow requirement, proof obligation,
   declassification receipt, or explicit refusal reason.
5. Runtime label propagation evidence is present for dynamic edges used by
   the claim.
6. The explain/replay bundle links the data-contract binding, source, run
   report, and any flow/proof evidence needed by the claim.

If any item is missing, the result is not a successful non-use claim. It
is `uncertified` or `fail_closed`, depending on whether the evidence is
incomplete but well-formed or contaminated/malformed.

## Refusal Vocabulary

| Code | Class | Meaning | Expected remediation |
| --- | --- | --- | --- |
| `missing_data_contract_binding` | `missing_evidence` | The run did not bind a data contract. | Run with `--data-contract` and a valid purpose. |
| `missing_run_input_hash` | `missing_evidence` | The contract declares a source hash but the run did not provide one. | Hash the actual run input and bind it. |
| `run_input_hash_mismatch` | `fail_closed` | The contract source hash differs from the executed source. | Fix the contract or rerun against the intended source. |
| `unsupported_syntax_surface` | `uncertified` | Parser or lowering rejected syntax that E8 cannot analyze. | Reduce the program or add analyzed support with tests. |
| `unproven_ifc_propagation` | `uncertified` | A runtime or intrinsic path lacks proof that labels propagate correctly. | Add IFC propagation proof or fail-closed fixture coverage. |
| `missing_flow_proof_obligation` | `missing_evidence` | A requested flow claim has no matching proof obligation. | Emit or link a `FlowProofObligation`. |
| `fallback_flow_envelope` | `degraded` | Flow envelope came from fallback or partial analysis. | Rerun with sufficient budget or mark the claim uncertified. |
| `missing_declassification_receipt` | `fail_closed` | A cross-label flow needs declassification but no receipt is linked. | Add a signed declassification receipt or deny the claim. |
| `missing_source_span` | `degraded` | The refusal has no precise source span/provenance. | Thread span/provenance from parser/lowering into the receipt. |
| `missing_explain_or_replay_bundle` | `missing_evidence` | The run cannot be replayed or externally inspected. | Emit the explain/replay bundle before certification. |
| `out_of_scope_covert_channel` | `out_of_scope` | The claim depends on covert-channel reasoning. | State the boundary; do not certify under E8 v1. |
| `out_of_scope_timing_channel` | `out_of_scope` | The claim depends on timing-channel reasoning. | State the boundary; do not certify under E8 v1. |

## Result Classes

| Result | Use when | Claim-language rule |
| --- | --- | --- |
| `certifiable_subset` | All required explicit-flow evidence is present and no refusal reason exists. | May feed the certifier, but is still not itself a certificate. |
| `uncertified` | Evidence is well-formed but an analyzed-subset gap exists. | Must not be phrased as non-use success. |
| `degraded` | Evidence exists but is incomplete, fallback-derived, or missing precision. | Must require remediation before promotion. |
| `fail_closed` | Evidence is malformed, contradictory, tampered, or missing a required safety receipt. | Must block certification. |
| `out_of_scope` | The requested guarantee depends on covert/timing/resource-channel semantics. | Must state E8 v1 cannot certify the claim. |

## Operator Runbook

Use this sequence when authoring or reviewing an E8 refusal-ledger artifact:

1. Inspect `schema_version`, `ledger_id`, `run_id`, and
   `threat_model_scope`. The schema version must be
   `franken-engine.e8-refusal-ledger.v1`, and the threat model must be
   `explicit_flow_ifc_v1`.
2. Treat `ledger_id` as content-addressed refusal identity, not a display id.
   Live preflight receipts must bind at least the run id, contract id, contract
   content hash, run-input binding id, actual run-input content hash, explain
   bundle path, and adversarial fixture set. Two receipts that differ in any of
   those inputs must not share a `ledger_id`.
3. Verify the source references first. Every refusal code must point at a
   declared `source_refs[].id`; a missing reference means the artifact is
   degraded at minimum and may need to fail closed.
4. Check `positive_non_use_claim_allowed`. It must be `false` for every
   current fixture and for any runtime receipt that carries refusal evidence.
5. Check `certifier_input_allowed` and `must_block_certificate` together.
   Any `uncertified`, `degraded`, `fail_closed`, or `out_of_scope` result
   must set `certifier_input_allowed=false` and
   `must_block_certificate=true`.
6. Compare every `refusal_codes[].code` and `refusal_codes[].class` with the
   vocabulary above and with `docs/e8_refusal_ledger_schema_v1.json`.
   Unknown codes are not warnings; they are unreviewed claim language.
7. Preserve the remediation text when feeding an external trust explainer.
   Operators and auditors need to see why a run is uncertified, not just
   that the positive certificate was withheld.

The current no-Cargo smoke gate is:

```bash
scripts/e2e/e8_refusal_ledger_smoke.sh check
```

This gate is intentionally limited to schema, inventory, fixture, and
vocabulary drift. It does not prove that live `frankenctl run` emits the
receipt; that remains `bd-fqlfw.8.4.1.3`.

## Truth-Gate Capstone Contract

The E8 capstone must prove the absence of false positive non-use claims, not
just the presence of well-formed JSON. A capstone run is acceptable only when
all of these inputs exist:

1. The static inventory in this document and
   `docs/e8_analyzed_subset_refusal_ledger_v1.json`.
2. The machine-readable schema in `docs/e8_refusal_ledger_schema_v1.json`.
3. Deterministic fixture ledgers under `scripts/testdata/e8_refusal_ledger/`.
4. A live data-contract preflight receipt emitted by the E8 run path.
5. Adversarial unsupported-surface fixtures, including at least one
   Secret-to-sink-like case whose analyzed subset is intentionally incomplete.
   In code, these fixtures enter through
   `E8AdversarialRefusalFixture` and
   `DataContractRunBinding::uncertified_preflight_receipt_with_adversarial_fixtures`.
6. External-trust explainer output that distinguishes explicit refusal from
   missing, stale, or degraded evidence.

The capstone must assert these invariants:

- If any refusal code is present, no successful non-use certificate is
  emitted.
- If a Secret-to-sink-like fixture crosses an unanalyzed surface, the result
  is `uncertified` or `fail_closed`, never `certifiable_subset`.
- If source hash or source provenance disagrees with the run input, the
  result is `fail_closed`.
- If contract content or actual run-input content differs, the preflight
  receipt must produce a different `ledger_id`.
- If flow evidence comes from fallback or partial analysis, the result is
  `degraded` and cannot feed the certifier.
- If the requested guarantee depends on covert or timing channels, the result
  is `out_of_scope` with E8 v1 boundary language.
- If an external explainer consumes the ledger, human and machine output must
  preserve the refusal code, class, source reference, and remediation.

Future Cargo-backed validation must be offloaded through `rch` with a unique
target directory. Use command shapes like these, replacing the timestamp and
test target with the landed test names:

```bash
RCH_REQUIRE_REMOTE=1 RCH_EXEC_TIMEOUT_SECONDS=2400 \
  rch exec --json --no-self-healing -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
    CARGO_ENCODED_RUSTFLAGS=-Clinker=cc \
    CARGO_TARGET_DIR=/tmp/rch_target_brownwolf_bd_fqlfw_8_4_1_4_fixtures_<ts> \
    cargo test -p frankenengine-engine --test data_contract_integration \
      adversarial_unsupported_surface_fixtures_refuse_e8_certification -- --nocapture
```

```bash
RCH_REQUIRE_REMOTE=1 RCH_EXEC_TIMEOUT_SECONDS=3600 \
  rch exec --json --no-self-healing -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
    CARGO_ENCODED_RUSTFLAGS=-Clinker=cc \
    CARGO_TARGET_DIR=/tmp/rch_target_brownwolf_bd_fqlfw_8_4_1_6_capstone_<ts> \
    cargo test -p frankenengine-engine --test e8_non_use_certificate_capstone -- --nocapture
```

Do not close the runbook/capstone bead from transport evidence alone. The
closeout must include a real Cargo verdict for the focused tests once those
tests exist, plus the shell/JQ smoke result above.

## Downstream Work

The current bead chain turns this inventory into shipped behavior:

| Bead | Purpose |
| --- | --- |
| `bd-fqlfw.8.4.1.2` | Define the schema and deterministic fixture corpus. |
| `bd-fqlfw.8.4.1.3` | Emit a preflight refusal receipt from data-contract runs. |
| `bd-fqlfw.8.4.1.4` | Add adversarial unsupported-surface fixtures. |
| `bd-fqlfw.8.4.1.5` | Feed refusal evidence into external trust explainers. |
| `bd-fqlfw.8.4.1.6` | Add the runbook and truth-gate capstone. |
| `bd-fqlfw.8.7` | Consume the capstone before E8.TEST can pass. |

## Acceptance Notes

Any future E8 certificate path must prove that refusal reasons are absent
before producing a positive non-use claim. A positive claim with any
refusal reason is a bug, even when the run result itself is otherwise
successful.
