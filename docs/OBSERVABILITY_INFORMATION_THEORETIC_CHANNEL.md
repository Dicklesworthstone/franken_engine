# Observability Information-Theoretic Channel Contract

## Scope

This contract captures the FRX-17 observability design:

- `observability_channel_model.rs`: rate-distortion envelopes and channel constitutions
- `observability_probe_design.rs`: budget-constrained probe selection and multimode schedules
- `entropy_evidence_compressor.rs`: entropy-bound compression certificates
- `observability_quality_sentinel.rs`: fail-closed quality monitoring and deterministic demotion

## Deterministic Invariants

1. Every evidence family has an explicit distortion metric and a bounded rate-distortion envelope.
2. Lossless-only channels (replay, security, legal provenance) reject lossy emissions.
3. Probe schedules are selected from a declared objective under explicit latency/memory/count budgets.
4. Compression artifacts use the versioned, canonical codec contract below before production code emits a certificate.
5. Sentinel quality breaches deterministically produce degradation artifacts and demotion receipts.

## Evidence Families and Distortion Policy

Required evidence families:

- `decision`
- `replay`
- `optimization`
- `security`
- `legal_provenance`

Lossless constraints:

- `replay`: `max_distortion_millionths = 0`, `lossy_permitted = false`
- `security`: `max_distortion_millionths = 0`, `lossy_permitted = false`
- `legal_provenance`: `max_distortion_millionths = 0`, `lossy_permitted = false`

## Probe Objective Contract

Probe selection is not heuristic. It must be explainable by:

- Utility term: forensic utility (`forensic_utility_millionths`)
- Resource constraints: latency, memory, probe count
- Coverage term: event-space coverage in millionths
- Mode-aware budgets: `normal`, `degraded`, `incident`

Expected monotonic behavior:

- `incident` mode must provide coverage greater than or equal to `normal` mode
- schedule hashes and multimode manifest hashes must be deterministic for the same universe

## Compression Certificate Contract

### Lossless codec boundary

`franken-engine.entropy-evidence-compressor.v2` is a static-model, 32-bit
E1/E2/E3 arithmetic codec. Its lossless claim is deliberately narrow: given
the exact serialized `ArithmeticCoder` model and `CompressedEvidence`
artifact, decoding restores the derived `u32` symbol stream byte-for-byte in
canonical big-endian symbol order. A valid artifact binds:

- exact symbol count, compressed byte count, and valid bit count
- the original symbol-stream content hash
- the exact canonical frequency-model hash
- zero-valued final-byte padding and a bounded canonical payload length
- schema, original-size estimate, and compression-ratio metadata

Decode validates the model and all framing metadata before allocating the
bounded output, restores the declared number of symbols, verifies the content
hash, and then requires a byte-for-byte canonical re-encode. Truncation,
extension, bit corruption, non-zero padding, wrong models, malformed frequency
tables, and non-canonical encodings fail closed. Production certificate
issuance uses `CompressionCertificate::build_verified`, which performs this
decode and also requires the restored histogram to match the estimator.

This is **not** a claim that the current orchestrator persists a lossless copy
of a complete `EvidenceEntry`. `build_evidence_symbols` is a many-to-one
observability sketch, and the current orchestrator retains only its certificate
metadata, not the coder/artifact pair. Full evidence serialization, durable
artifact retention, and replay-bundle integration remain separate work. The
infallible `CompressionCertificate::build` constructor is an unchecked
structural helper and must not be used by production emission paths.

### Certificate fields

Required certificate fields:

- `entropy_millibits_per_symbol`
- `shannon_lower_bound_bits`
- `achieved_bits`
- `overhead_ratio_millionths`
- `kraft_sum_millionths`
- `kraft_satisfied`
- `certificate_hash`

Gate semantics:

- the legacy Kraft-named field records canonical model probability-mass
  normalization (`sum(frequency) / total_frequency`), not sequence-level
  prefix-freeness or a substitute for decode verification
- normalized mass must be satisfied (`kraft_sum_millionths <= 1_000_000 + tolerance`)
- Overhead ratio checks must fail closed when lower bounds are degenerate
- Shannon fields compare achieved length with the module's empirical entropy
  estimate; they are not, by themselves, a source-distribution proof

## Quality Sentinel Contract

Signal quality dimensions:

- `signal_fidelity`
- `blind_spot_ratio`
- `reconstruction_ambiguity`
- `tail_undercoverage`
- `evidence_staleness`

Fail-closed behavior:

- quality breaches produce deterministic degradation artifacts
- matching demotion rules produce deterministic demotion receipts
- severe fidelity degradation triggers `full_replay_capture`
- gate fails when sentinel reports degraded state

## Verification and Artifacts

Run the FRX-17 gate script:

```bash
./scripts/run_observability_information_theoretic_gate.sh ci
```

Operational contract:

- heavy Cargo lanes are executed via `rch` only (no local fallback acceptance)
- default target dir is repo-local `.rch_target/observability_information_theoretic_<timestamp>`
- `RCH_EXEC_TIMEOUT_SECONDS` can be set to tune remote timeout bounds

Artifacts are emitted under:

- `artifacts/observability_information_theoretic/<timestamp>/run_manifest.json`
- `artifacts/observability_information_theoretic/<timestamp>/events.jsonl`
- `artifacts/observability_information_theoretic/<timestamp>/commands.txt`

Primary integration test:

- `crates/franken-engine/tests/observability_channel_model.rs`
- `crates/franken-engine/tests/entropy_evidence_compressor_integration.rs`

Bead reference:

- `bd-mjh3.17`
