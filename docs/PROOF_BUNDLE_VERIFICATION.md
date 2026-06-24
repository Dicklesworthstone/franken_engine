# Proof Bundle Verification — Downstream Consumer Guide

> Track Y (`bd-cixqu.25`). Operator surface: `bd-cixqu.25.4` (Y.4).
> Producer: Y.1 [`scripts/export_proof_bundle.sh`](../scripts/export_proof_bundle.sh).
> Clean-room checker: Y.2 [`docker/y2_proof_bundle_verifier/`](../docker/y2_proof_bundle_verifier/).
> Operator wrapper: [`runbooks/scripts/verify_proof_bundle.sh`](../runbooks/scripts/verify_proof_bundle.sh).

This document is for **downstream consumers** (for example `/dp/franken_node`,
sibling repos, or any third party) who receive a FrankenEngine release proof
bundle and want to verify it **without the FrankenEngine source tree present**.

The proof bundle *is* the trust artifact. If verifying it is hard, the trust
property collapses — so the whole procedure is a single command, re-checkable on
a laptop with nothing but `python3`, and a clean-room docker path for the
strongest isolation.

---

## What the proof bundle is

A release ships a `proof_bundle.tar.gz` (deterministically packed) containing:

| Entry | What it is |
|---|---|
| `proof_source/<FE-CLAIM-NNN>.proof.json` | The theorem-backed-compiler proof artifacts (schema `franken-engine.theorem-backed-compiler.proof.v1`), plus any `*.lean` / `*.v` proof sources present. |
| `proof_assistant_versions.json` | The pinned Lean 4 / Coq versions and recheck-tool reference a verifier reproduces. |
| `recheck_expected.sha256` | The **trust anchor**: the expected recheck digest (bare lowercase hex sha256). |
| `bundle_manifest.json` | Schema `franken-engine.proof-bundle.v1` — per-proof content hashes, the recheck digest, the claim inventory, and the recheck instructions. |

The **recheck digest** is `sha256` over the sorted JSON array of
`[claim_id, sha256(canonical proof body), stated_verdict]` for every proof. It is
a pure function of the proof-source bytes, so it reproduces identically across
machines and is **independent of wall-clock freshness and of the proof-assistant
version**. A verifier re-derives it from the bundled `proof_source/` and confirms
it equals `recheck_expected.sha256`. Any post-export edit of a proof body that is
not re-signed into its `content_hash` breaks the match (tamper-evident).

> **Pinned proof assistant.** Per [ADR-0007](./adr/ADR-0007-proof-assistant-selection.md),
> FrankenEngine's primary proof assistant is **Lean 4**. The operative version a
> given bundle was built against is recorded in its own
> `proof_assistant_versions.json` (the authoritative pin for *that* bundle), not
> hard-coded in this document — read the pin from the bundle you received.

---

## What you need

- **`python3`** (3.8+). That alone is enough for the local path.
- *Optional:* **docker** for the clean-room path (strongest isolation: the
  checker runs in an image with no FrankenEngine source on it).
- *Optional:* a **Lean 4 / Coq toolchain** matching the bundle's pin — only if
  you additionally want to re-run the underlying proof sources yourself. The
  recheck digest does **not** require it.

---

## Verify in one command

```bash
# Auto path: docker clean-room when a tar + reachable daemon are present,
# otherwise local python3. Writes a classified verdict and a logged run bundle.
runbooks/scripts/verify_proof_bundle.sh verify path/to/proof_bundle.tar.gz
```

Force a path explicitly:

```bash
# Strongest: clean-room docker image (no engine source consulted).
runbooks/scripts/verify_proof_bundle.sh verify proof_bundle.tar.gz --via docker

# No docker needed (laptop-friendly).
runbooks/scripts/verify_proof_bundle.sh verify proof_bundle.tar.gz --via local
```

### Expected output (a healthy bundle)

```
[proof_bundle_operator_verify] classification : verified
[proof_bundle_operator_verify] recheck verdict : pass
[proof_bundle_operator_verify] version status  : aligned        # or "absent"
[proof_bundle_operator_verify] action          : VERIFIED: the recheck digest matches the trust anchor; N proof(s) intact and proven.
[proof_bundle_operator_verify] verdict json    : artifacts/proof_bundle_operator_verify/<ts>/operator_verdict.json
```

Exit code `0`. The machine-readable verdict is
`artifacts/proof_bundle_operator_verify/<ts>/operator_verdict.json`
(schema `franken-engine.proof-bundle-operator-verdict.v1`).

---

## The three outcomes (and exactly what to do)

The wrapper separates two **independent** failure dimensions so you always know
whether to fix *your environment* or *escalate to the maintainers*. This split
is possible precisely because the recheck digest is version-independent: a
proof-assistant version difference can never, by construction, cause the recheck
to fail.

| `classification` | Exit | Meaning | Your action |
|---|---|---|---|
| `verified` | `0` | The recheck digest equals the trust anchor; every proof is intact and proven. Toolchain aligned or simply absent. | Rely on the release under its stated inputs. |
| `version_drift` | `0` (advisory) / `2` (`--strict-version`) | The recheck **still holds** — the content is intact — but your local Lean/Coq version differs from the bundle's pin (or a `--expected-*` pin you asserted). | **Update your toolchain** to the bundle's `proof_assistant_versions.json` pin before re-running the underlying proofs. The release itself is fine. |
| `proof_regression` | `1` | The recheck digest does **not** reproduce the trust anchor (a proof body/verdict changed, a proof is not `proven`, or the bundle is incomplete). | **Escalate to the FrankenEngine maintainers.** Do not treat the release as verified. Attach the verdict JSON — `failing_claims` and `recheck.reasons` name the specific proof(s). |

### Why this distinction matters

The original worry these bundles answer is: *"my verification failed — is it my
fault or theirs?"*

- A **proof-assistant version drift** is *your* environment. Updating the
  toolchain (or pinning to the bundle's recorded version) resolves it. It never
  invalidates the bundle's content, because the trust anchor is computed over
  proof bytes, not over a Lean/Coq build.
- A **proof regression** is *theirs*: the proof content no longer matches what
  the release claims. That is a real integrity signal and belongs in the
  maintainers' hands, with the verdict JSON attached as evidence.

The wrapper makes the call for you and prints the recommended action verbatim.

---

## Reading a recheck failure

On a `proof_regression`, the operator verdict JSON pinpoints the cause:

```bash
jq '{classification, failing_claims, reasons: .recheck.reasons}' \
  artifacts/proof_bundle_operator_verify/<ts>/operator_verdict.json
```

- `failing_claims` — the `claim_id`s whose proof was tampered, not `proven`, or
  off-schema.
- `recheck.reasons` — the underlying Y.2 checker's fail-closed reasons, e.g.
  `recheck digest mismatch vs trust anchor: recomputed <a> != expected <b>`,
  `tampered proof (content_hash mismatch): FE-CLAIM-019`, or
  `manifest declares bundle_status='incomplete'`.
- `recheck.proofs[]` — the per-proof breakdown (`integrity`, `proven`,
  `schema_ok`, `recomputed_hash` vs `content_hash`).

A digest mismatch with **all** per-proof entries `intact` usually means the
manifest's `recheck_digest_sha256` or the `recheck_expected.sha256` trust anchor
was altered; a single `tampered`/`not proven` entry isolates the exact proof.

---

## Manual verification (no wrapper)

The wrapper only orchestrates; the trust math is small enough to run by hand.

**Clean-room docker (the Y.2 checker, no engine source on the image):**

```bash
docker run --rm --network=none \
  -v "$PWD/proof_bundle.tar.gz:/input/proof_bundle.tar.gz:ro" \
  frankenengine/y2-proof-bundle-verifier:bd-cixqu.25.2 \
  verify-proof-bundle /input/proof_bundle.tar.gz
```

**Local python3 (same standalone checker):**

```bash
python3 docker/y2_proof_bundle_verifier/verify_proof_bundle.py \
  verify-proof-bundle proof_bundle.tar.gz
```

Both print a typed verdict (`franken-engine.proof-bundle-verifier-verdict.v1`)
and exit `0` (pass) or `1` (fail-closed). Re-derive the digest yourself from the
unpacked `proof_source/` with the recipe printed in
`bundle_manifest.json → recheck_instructions`, and confirm it equals
`recheck_expected.sha256`.

---

## How verification fits the release

```
Y.1 export_proof_bundle.sh   ──▶  proof_bundle.tar.gz  (trust anchor inside)
                                        │
Y.2 docker/y2_proof_bundle_verifier ◀───┤  clean-room recheck (no engine source)
                                        │
Y.3 ga_exit_evidence_package.rs    ◀────┤  records the bundle + verify command
                                        │
Y.4 verify_proof_bundle.sh (this) ◀─────┘  operator/consumer surface + drift split
```

The GA-exit evidence package (`ProofBundleReference`) records the bundle path,
the trust-anchor digest, and the exact `verify_command` — so the package itself
tells you how to re-check it.

---

## Reference

| Surface | Path |
|---|---|
| Operator wrapper (this guide's command) | `runbooks/scripts/verify_proof_bundle.sh` |
| Composition gate (proves the surface end-to-end) | `scripts/run_y4_proof_bundle_operator_surface.sh ci` |
| Y.1 bundle exporter | `scripts/export_proof_bundle.sh` |
| Y.2 clean-room checker (image) | `docker/y2_proof_bundle_verifier/`, `scripts/run_y2_proof_bundle_verifier.sh` |
| Y.3 GA-exit integration | `crates/franken-engine/src/ga_exit_evidence_package.rs` |
| Proof-assistant selection | `docs/adr/ADR-0007-proof-assistant-selection.md` |
| Gate catalogue entry | `docs/operator-gates/RGC_GATES_REFERENCE.md` → *Proof Bundle Verification Operator Surface (Y.4)* |

> **Operators (FrankenEngine-internal):** a per-release verification-history
> panel (`ProofBundleStatusPanel`,
> `crates/franken-engine/src/proof_bundle_status_panel.rs`) is available for the
> frankentui operator console. It is operator-facing only and not part of this
> public consumer surface.
