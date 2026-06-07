# ADR-0009: Runtime Explain Bundle as an Artifact Index

- Status: Accepted
- Date: 2026-06-07
- Owners: FrankenEngine maintainers + E3 flight-recorder maintainers
- Plan references: Evidence Flight Recorder, `frankenctl run --explain`
- Related beads: `bd-fqlfw.3.1`, `bd-fqlfw.3.2`, `bd-fqlfw.3.3`

## Context

The E3 flight-recorder lane adds a runtime explanation surface for operator and
auditor workflows. The repository already has several serialized surfaces with
overlapping concepts:

- `crates/franken-engine/src/incident_replay_bundle.rs` owns portable incident
  archives, `BundleManifest`, trace records, evidence entries, optimization
  receipts, quorum checkpoints, nondeterminism logs, counterfactual results,
  policy snapshots, Merkle roots, and bundle signatures.
- `crates/franken-engine/src/runtime_diagnostics_cli.rs` owns runtime
  diagnostics output, evidence exports, support bundle indexes, redaction audit
  output, preflight doctor reports, onboarding scorecards, rollout artifacts,
  and GA evidence packages.
- `crates/franken-engine/src/forensic_query_api.rs` owns causal query requests
  and results, including causal explanations, influence analysis,
  counterfactual analysis, timeline reconstruction, query metadata, and error
  status.

`runtime_explain_bundle.rs` was introduced in `bd-fqlfw.3.1` as a thin index
over existing artifacts. Without an explicit decision record, later CLI work
could accidentally copy fields from those surfaces into a fourth truth model,
creating incompatible schemas for the same facts.

## Decision

`RuntimeExplainBundle` is the canonical explain index format, not a canonical
payload format.

It may serialize only:

- the explain index schema version
- run and source-revision identity
- required explanation roles
- artifact references containing bundle-local id, kind, schema id, stable
  source reference, content hash, producer, logical epoch, roles, and
  non-authoritative display/provenance metadata
- typed links between referenced artifacts
- bundle-level non-authoritative metadata

It must not copy authoritative payload fields from existing bundlers. In
particular, it must not serialize trace maps, evidence-entry maps, support
bundle file contents, diagnostic payload records, causal subgraph nodes, ranked
influence lists, counterfactual result payloads, policy snapshots, Merkle proof
material, or signatures that are owned by another surface.

The owning surface remains responsible for its own validation and integrity
model:

| Owning surface | Canonical ownership | Explain-bundle relationship |
| --- | --- | --- |
| `incident_replay_bundle` | incident archive payloads, manifest inventory, Merkle/signature checks, replay verification | referenced by `artifact_id`, `schema_id`, `stable_ref`, and `content_hash`; explain links may point from IR/evidence decisions to the archive or manifest |
| `runtime_diagnostics_cli` | diagnostics outputs, evidence exports, support bundle index/files, redaction/privacy verification | referenced as operator-support artifacts; the explain bundle may link decisions to the support bundle index but does not include support files |
| `forensic_query_api` | structured causal query request/result payloads and query metadata | referenced as causal explanation artifacts linked to source evidence, decisions, or counterfactual inputs |
| parser/IR/evidence/guardplane modules | their own schema constants and payload records | referenced directly when the source artifact has a stable store key and content hash |

If a future explain workflow needs a field from an owning surface, it should
reference that surface's artifact and schema, not duplicate the field.

## Implementation Rules

1. `runtime_explain_bundle.rs` may add artifact kinds, roles, or link
   relations when they improve navigation across existing artifacts.
2. It may add metadata keys for provenance, display labels, or CLI hints, but
   metadata is never authoritative and must not be required to reconstruct the
   source payload.
3. Any field that changes replay semantics, redaction semantics, causal query
   semantics, evidence validity, content integrity, or signature verification
   belongs in the owning surface, not in the explain index.
4. Validation remains fail-closed against a caller-supplied
   `RuntimeArtifactCatalog`. Missing, stale, or schema-mismatched artifacts are
   diagnostics; validation must not synthesize missing artifacts.
5. CLI work in `bd-fqlfw.3.3` should emit an explain bundle beside the existing
   owning artifacts and use `RuntimeArtifactRef` entries to connect them.

## Migration Guidance

Existing producers should populate these provenance metadata keys when indexing
artifacts from another surface:

- `origin_surface`: owning module or surface name, for example
  `incident_replay_bundle`, `runtime_diagnostics_cli`, or `forensic_query_api`
- `origin_schema`: owning schema/version string
- `origin_artifact`: owning record type or exported file name

These keys are hints for rendering and debugging. The stable reference and
content hash are the binding contract.

## Consequences

Positive:

- The explain surface can connect parser, IR, capability, IFC, guardplane,
  replay, diagnostics, evidence, and forensic query artifacts without forcing a
  schema fork.
- Existing integrity models stay authoritative: incident replay keeps its
  Merkle/signature checks, diagnostics keeps redaction/privacy checks, and
  forensic queries keep their causal-result contract.
- Later `frankenctl run --explain` work can emit stable JSON without choosing
  between copying every payload and losing navigability.

Negative:

- Consumers need the referenced artifact catalog to fully inspect payloads.
- Explain bundles cannot be used as standalone incident archives; that remains
  the job of `IncidentReplayBundle`.
- Producers must maintain stable refs and content hashes for every artifact
  they want the explain index to navigate.

## Validation

This ADR is backed by `runtime_explain_bundle_integration` coverage that creates
references to incident replay, runtime diagnostics, and forensic query surfaces
and asserts that the explain bundle serializes only artifact references and
links, not the payload fields owned by those surfaces.
