# FrankenEngine Data Provenance Bundle

- **Report ID:** `FKTR-2026-004`
- **Tracking Bead:** `bd-2501`
- **Status:** Draft skeleton
- **Scope:** Evidence lineage for reproducible FrankenEngine research artifacts.

This bundle defines the minimum provenance record required before benchmark data,
compatibility traces, replay captures, or safety evaluation artifacts can be cited
from a technical report. It is intentionally fail-closed: unknown origin,
unbounded capture windows, missing signatures, or ambiguous replay rights keep an
artifact in draft status.

## Source Attribution

Every referenced dataset, trace, benchmark run, or generated artifact must name
its source system, source commit, capture operator, and transformation path.

| Field | Required Evidence |
| --- | --- |
| Source system | Repository, corpus, benchmark harness, or external feed name |
| Source revision | Commit SHA, content-addressed snapshot, release tag, or immutable archive ID |
| Capture operator | Human or automation identity responsible for capture |
| Transform path | Ordered list of normalization, filtering, aggregation, or export steps |
| License posture | Redistribution, citation, and retention constraints |

## Hash Chain

Each artifact bundle must publish a deterministic hash chain from raw inputs to
final report outputs.

1. Record raw input digests before normalization.
2. Record normalized-input digests after each deterministic transformation.
3. Record generated output digests for reports, tables, charts, and manifests.
4. Store chain links as `(parent_digest, transform_id, child_digest)` tuples.
5. Treat any missing parent or child digest as a provenance validation failure.

## Temporal Bounds

Every provenance entry must state the exact collection and validity window.

| Bound | Meaning |
| --- | --- |
| `capture_started_at` | First instant included in the captured evidence |
| `capture_ended_at` | Last instant included in the captured evidence |
| `source_valid_from` | Earliest source revision or corpus date represented |
| `source_valid_until` | Latest source revision or corpus date represented |
| `embargo_until` | Optional publication or disclosure hold date |

Temporal bounds must use UTC RFC 3339 timestamps. Open-ended windows are not
acceptable for publishable artifacts.

## Signature Manifest

The signature manifest binds provenance records to responsible parties and
verification keys.

| Manifest Item | Requirement |
| --- | --- |
| Signer identity | Stable team, operator, or automation identity |
| Signing key reference | Public key fingerprint or key registry URI |
| Signed payload | Canonical manifest digest, not ad hoc file contents |
| Verification command | Reproducible command or script path |
| Rotation notes | Key replacement, revocation, or expiry metadata |

Unsigned bundles may be used for local development, but they cannot satisfy a
publishable-report gate.

## Replay Access Rights

Replay rights describe who can rerun the evidence pipeline and under what
constraints.

| Access Tier | Expected Rights |
| --- | --- |
| Maintainer replay | Full raw inputs, transforms, manifests, and generated outputs |
| External reviewer replay | Redacted or synthetic inputs plus deterministic transforms |
| Public replay | Open artifacts, hashes, manifests, and reproduction instructions |
| Restricted replay | Documented legal, privacy, or embargo restrictions |

Artifacts without replay-access documentation must remain advisory-only and must
not be promoted as independently reproducible claims.

## Initial Provenance Entry

| Entry ID | Artifact | Source Attribution | Hash Chain | Temporal Bounds | Signature Manifest | Replay Access Rights |
| --- | --- | --- | --- | --- | --- | --- |
| `data-provenance-bundle-0001` | `DATA_PROVENANCE_BUNDLE.md` | FrankenEngine docs skeleton authored under `bd-2501` | Pending first signed bundle manifest | Draft window: `2026-04-20T00:00:00Z` to `2026-04-20T23:59:59Z` | Pending key registry integration | Maintainer replay via repository history; public replay after report bundle publication |
