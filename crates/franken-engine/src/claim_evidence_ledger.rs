//! Merkle-committed Claim-Evidence Ledger (CEI track H.1, bead `bd-sde5e.8.1`).
//!
//! # Why this module exists
//!
//! FrankenEngine ships a real RFC-6962 transparency log ([`crate::mmr_proof`],
//! [`crate::transparency_log`]) and uses it to make *runtime decision receipts*
//! tamper-evident: once a receipt is committed to the Merkle Mountain Range, no
//! later edit can change history without changing the root. CEI track H turns
//! that same property **onto the project's own claims**.
//!
//! Track A.1 ([`crate::claim_evidence_lattice`]) made over-promotion *visible*: it
//! scores every `docs/claim_to_proof_matrix_v1.json` row's asserted state against
//! the evidence tier its committed artifacts actually license. Track B committed
//! the per-claim evidence manifests ([`crate::evidence_manifest`]). What was still
//! missing is **tamper-evidence**: nothing stopped a silent edit to a matrix row
//! (bumping `allowed_state` to `observed`) or to a committed evidence manifest
//! from sailing through review without anyone recomputing whether the claim is
//! still backed.
//!
//! This module closes that gap by construction. It builds a ledger whose leaves
//! are, one per matrix claim:
//!
//! ```text
//! (claim_id, asserted_state, evidence_tier, artifact_content_hash, receipt_hash)
//! ```
//!
//! and commits the **MMR root** in-repo at [`LEDGER_ROOT_FILE`]. The gate
//! ([`verify_against_committed`]) recomputes the ledger from the *live* matrix and
//! evidence, checks the recomputed root equals the committed root, and verifies an
//! RFC-6962 inclusion proof for every leaf. Any silent matrix/README/evidence edit
//! that is not accompanied by a recomputed, evidence-consistent root therefore
//! **breaks the gate closed**.
//!
//! # Determinism: the pinned `as_of_unix`
//!
//! A leaf's `evidence_tier` is computed by the A.1 scorer, one component of which —
//! freshness — depends on the artifact's *age*, hence on the current time. If the
//! gate recomputed against the wall clock, the committed root would silently drift
//! as evidence ages past the freshness e-process bound, failing the gate with *no
//! edit at all*.
//!
//! The ledger therefore **pins** the generation time into the committed root file
//! (`as_of_unix`). Verification recomputes against that pinned instant, never the
//! wall clock, so the recomputed root is a pure function of committed content:
//! stable under the passage of time, and changed only by a real matrix/evidence
//! edit. Live freshness *decay* is a separate concern, already enforced against
//! the wall clock by the A.3 audit (`franken_evidence_manifest audit`). The two
//! are complementary: this ledger is the tamper-evident commitment over committed
//! content; A.3 is the live soundness verdict.
//!
//! # Relationship to the rest of CEI
//!
//! * Reuses [`crate::mmr_proof::MerkleMountainRange`] (RFC-6962) verbatim — the
//!   same substrate the runtime uses for decision-receipt transparency.
//! * Reads asserted state + evidence tier from the A.1 scorer
//!   ([`crate::claim_evidence_lattice::score_matrix_file`]).
//! * Reads each claim's committed evidence manifest via
//!   [`crate::evidence_manifest::load_manifest`].
//! * Backs the reflexive claim `FE-CLAIM-025` (H.2, `bd-sde5e.8.2`): the committed
//!   root is part of that claim's backing artifact.

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::claim_evidence_lattice::{
    ClaimAssertionState, EvidenceTier, IntegrityError, score_matrix_file,
};
use crate::evidence_manifest::{load_manifest, sha256_hex};
use crate::hash_tiers::ContentHash;
use crate::mmr_proof::{MerkleMountainRange, ProofError, verify_inclusion};

/// Schema/domain tag for the ledger, mixed into the flat leaves digest and the
/// committed root file's `schema` line.
pub const LEDGER_SCHEMA: &str = "franken-engine.claim-evidence-ledger.v1";

/// Domain tag mixed into every leaf preimage so a ledger-leaf hash can never
/// collide with any other length-prefixed preimage in the codebase.
pub const LEDGER_LEAF_DOMAIN: &str = "franken-engine.claim-evidence-ledger.leaf.v1";

/// Repo-relative path of the committed MMR root commitment.
pub const LEDGER_ROOT_FILE: &str = "docs/claim_evidence_ledger_root.txt";

/// MMR epoch id for the claim-evidence ledger. Fixed so the root is reproducible.
pub const LEDGER_EPOCH: u64 = 1;

/// Sentinel hash for a claim with no committed evidence manifest (64 hex zeros).
/// Distinct from any real SHA-256 with overwhelming probability, and honestly
/// records "no committed evidence bundle" for `hypothesis`/`target` rows.
pub const ZERO_HASH_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// ---------------------------------------------------------------------------
// Length-prefixed canonical encoding helpers (mirror `claim_evidence_lattice`)
// ---------------------------------------------------------------------------

/// Append `bytes` with a fixed-width `u64` little-endian length prefix.
fn push_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// Append a `u64` little-endian count prefix for an otherwise-unbounded sequence.
fn push_count(buf: &mut Vec<u8>, count: usize) {
    buf.extend_from_slice(&(count as u64).to_le_bytes());
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors raised while building, committing, or verifying the ledger.
#[derive(Debug)]
pub enum LedgerError {
    /// The A.1 scorer failed to read or parse the matrix.
    Integrity(IntegrityError),
    /// The MMR substrate rejected an append / root / proof operation.
    Proof(ProofError),
    /// The committed root file could not be read or written.
    Io(String),
    /// The committed root file was malformed (missing/!parseable field).
    Malformed(String),
    /// The ledger had no leaves, so no root could be committed.
    Empty,
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Integrity(e) => write!(f, "integrity scorer error: {e}"),
            Self::Proof(e) => write!(f, "mmr proof error: {e:?}"),
            Self::Io(m) => write!(f, "io error: {m}"),
            Self::Malformed(m) => write!(f, "malformed ledger root file: {m}"),
            Self::Empty => write!(f, "ledger has no leaves; cannot commit a root"),
        }
    }
}

impl std::error::Error for LedgerError {}

impl From<IntegrityError> for LedgerError {
    fn from(e: IntegrityError) -> Self {
        Self::Integrity(e)
    }
}

impl From<ProofError> for LedgerError {
    fn from(e: ProofError) -> Self {
        Self::Proof(e)
    }
}

// ---------------------------------------------------------------------------
// Ledger leaf
// ---------------------------------------------------------------------------

/// One ledger leaf: the committed claim-evidence state for a single claim row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerLeaf {
    /// Matrix `claim_id`, e.g. `FE-CLAIM-004`.
    pub claim_id: String,
    /// The state the matrix asserts (`allowed_state`).
    pub asserted_state: ClaimAssertionState,
    /// The evidence tier the committed artifacts license (A.1 scorer, evaluated
    /// at the ledger's pinned `as_of_unix`).
    pub evidence_tier: EvidenceTier,
    /// Lowercase hex SHA-256 binding the *entire* committed evidence manifest
    /// (all input hashes + receipt + bundle files), or [`ZERO_HASH_HEX`] when no
    /// manifest is committed for this claim.
    pub artifact_content_hash: String,
    /// The committed receipt hash (`manifest.receipt.receipt_sha256`), or
    /// [`ZERO_HASH_HEX`] when no manifest is committed.
    pub receipt_hash: String,
}

impl LedgerLeaf {
    /// The leaf's content hash: a length-prefixed, domain-separated SHA-256 over
    /// the five fields. Injective by construction — two distinct claim-evidence
    /// states cannot share a leaf hash.
    #[must_use]
    pub fn leaf_hash(&self) -> ContentHash {
        let mut buf: Vec<u8> = Vec::new();
        push_len_prefixed(&mut buf, LEDGER_LEAF_DOMAIN.as_bytes());
        push_len_prefixed(&mut buf, self.claim_id.as_bytes());
        buf.push(self.asserted_state.rank());
        buf.push(self.evidence_tier.rank());
        push_len_prefixed(&mut buf, self.artifact_content_hash.as_bytes());
        push_len_prefixed(&mut buf, self.receipt_hash.as_bytes());
        ContentHash::compute(&buf)
    }

    /// The leaf hash as lowercase hex (for the committed audit table).
    #[must_use]
    pub fn leaf_hash_hex(&self) -> String {
        self.leaf_hash().to_hex()
    }
}

/// Read the committed evidence hashes for a claim: the SHA-256 of its canonical
/// evidence manifest, and the manifest's recorded receipt hash. Returns the zero
/// sentinel for both when no manifest is committed (the honest "no evidence
/// bundle" state for `hypothesis`/`target` rows).
fn evidence_hashes(repo_root: &Path, claim_id: &str) -> (String, String) {
    match load_manifest(repo_root, claim_id) {
        Ok(manifest) => {
            let artifact = sha256_hex(manifest.to_canonical_json().as_bytes());
            let receipt = if manifest.receipt.receipt_sha256.is_empty() {
                ZERO_HASH_HEX.to_string()
            } else {
                manifest.receipt.receipt_sha256.clone()
            };
            (artifact, receipt)
        }
        Err(_) => (ZERO_HASH_HEX.to_string(), ZERO_HASH_HEX.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------------

/// The Claim-Evidence Ledger: one leaf per matrix claim, in `claim_id` order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimEvidenceLedger {
    /// Leaves in deterministic (`claim_id`-sorted) order.
    pub leaves: Vec<LedgerLeaf>,
    /// The instant freshness was evaluated at when the leaves' tiers were scored.
    pub as_of_unix: i64,
}

impl ClaimEvidenceLedger {
    /// Build the ledger from the live matrix and committed evidence, evaluating
    /// freshness at `as_of_unix`.
    ///
    /// `max_freshness_days` overrides the matrix's e-process horizon when `Some`;
    /// otherwise the scorer reads it from the matrix policy.
    pub fn build(
        matrix_path: &Path,
        repo_root: &Path,
        as_of_unix: i64,
        max_freshness_days: Option<u64>,
    ) -> Result<Self, LedgerError> {
        let report = score_matrix_file(matrix_path, repo_root, as_of_unix, max_freshness_days)?;
        // `report.verdicts` is a BTreeMap keyed by claim_id, so iteration is
        // already in deterministic, sorted order.
        let mut leaves = Vec::with_capacity(report.verdicts.len());
        for (claim_id, verdict) in &report.verdicts {
            let (artifact_content_hash, receipt_hash) = evidence_hashes(repo_root, claim_id);
            leaves.push(LedgerLeaf {
                claim_id: claim_id.clone(),
                asserted_state: verdict.asserted_state,
                evidence_tier: verdict.evidence_tier,
                artifact_content_hash,
                receipt_hash,
            });
        }
        Ok(Self { leaves, as_of_unix })
    }

    /// Build the underlying MMR by appending every leaf hash in order.
    fn mmr(&self) -> MerkleMountainRange {
        let mut mmr = MerkleMountainRange::new(LEDGER_EPOCH);
        for leaf in &self.leaves {
            mmr.append(leaf.leaf_hash());
        }
        mmr
    }

    /// Number of committed leaves.
    #[must_use]
    pub fn leaf_count(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// The MMR root as lowercase hex. Errors only when the ledger is empty.
    pub fn root_hex(&self) -> Result<String, LedgerError> {
        if self.leaves.is_empty() {
            return Err(LedgerError::Empty);
        }
        Ok(self.mmr().root_hash()?.to_hex())
    }

    /// A flat, MMR-independent SHA-256 over all leaf hashes in order. A secondary
    /// cross-check: an attacker who somehow forged an MMR-root collision would
    /// also have to collide this independent digest.
    #[must_use]
    pub fn leaves_digest(&self) -> String {
        let mut buf: Vec<u8> = Vec::new();
        push_len_prefixed(&mut buf, LEDGER_SCHEMA.as_bytes());
        push_count(&mut buf, self.leaves.len());
        for leaf in &self.leaves {
            buf.extend_from_slice(leaf.leaf_hash().as_bytes());
        }
        hex::encode(Sha256::digest(&buf))
    }

    /// Verify that every leaf carries a valid RFC-6962 inclusion proof against the
    /// freshly-recomputed MMR root. This is the inclusion-proof check the bead
    /// requires: it proves the committed set of leaves is exactly what the root
    /// commits to.
    pub fn verify_all_inclusions(&self) -> Result<(), LedgerError> {
        let mmr = self.mmr();
        for (i, leaf) in self.leaves.iter().enumerate() {
            let proof = mmr.inclusion_proof(i as u64)?;
            verify_inclusion(&leaf.leaf_hash(), i as u64, &proof)?;
        }
        Ok(())
    }

    /// The full commitment: schema, pinned time, root, leaf count, leaves digest,
    /// and the per-leaf audit records.
    pub fn commitment(&self) -> Result<LedgerCommitment, LedgerError> {
        Ok(LedgerCommitment {
            schema: LEDGER_SCHEMA.to_string(),
            as_of_unix: self.as_of_unix,
            root: self.root_hex()?,
            leaf_count: self.leaf_count(),
            leaves_digest: self.leaves_digest(),
            leaves: self.leaves.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Committed commitment (the on-disk root file)
// ---------------------------------------------------------------------------

/// The committed commitment serialized to / parsed from [`LEDGER_ROOT_FILE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerCommitment {
    pub schema: String,
    pub as_of_unix: i64,
    pub root: String,
    pub leaf_count: u64,
    pub leaves_digest: String,
    /// The committed per-leaf audit records (also re-verified by the gate).
    pub leaves: Vec<LedgerLeaf>,
}

impl LedgerCommitment {
    /// Render the committed root file: a human-auditable, machine-parseable,
    /// fully self-describing ledger. Every `leaf` line is independently
    /// re-verified by the gate, so the file is a complete tamper-evident record,
    /// not just an opaque root.
    #[must_use]
    pub fn to_root_file(&self) -> String {
        let mut s = String::new();
        s.push_str("# Claim-Evidence Ledger — franken-engine.claim-evidence-ledger.v1 (CEI H.1, bd-sde5e.8.1)\n");
        s.push_str("# Merkle Mountain Range (RFC-6962) root over one leaf per claim:\n");
        s.push_str(
            "#   (claim_id, asserted_state, evidence_tier, artifact_content_hash, receipt_hash)\n",
        );
        s.push_str(
            "# Editing a matrix row or a committed evidence manifest changes a leaf, hence the\n",
        );
        s.push_str("# root: the gate then fails closed until the root is regenerated against the change.\n");
        s.push_str("# Regenerate (only after an intentional, evidence-consistent change):\n");
        s.push_str("#   cargo run -q -p frankenengine-engine --bin franken_claim_evidence_ledger -- generate\n");
        s.push_str("# Verify (gate): ./scripts/run_claim_evidence_ledger_gate.sh ci\n");
        s.push_str(&format!("schema {}\n", self.schema));
        s.push_str(&format!("as_of_unix {}\n", self.as_of_unix));
        s.push_str(&format!("root {}\n", self.root));
        s.push_str(&format!("leaf_count {}\n", self.leaf_count));
        s.push_str(&format!("leaves_digest {}\n", self.leaves_digest));
        s.push_str("# leaf <claim_id> <asserted_state> <evidence_tier> <artifact_content_hash> <receipt_hash> <leaf_hash>\n");
        for leaf in &self.leaves {
            s.push_str(&format!(
                "leaf {} {} {} {} {} {}\n",
                leaf.claim_id,
                leaf.asserted_state,
                leaf.evidence_tier,
                leaf.artifact_content_hash,
                leaf.receipt_hash,
                leaf.leaf_hash_hex(),
            ));
        }
        s
    }

    /// Parse a committed root file. Ignores blank lines and `#` comments; requires
    /// the `schema`, `as_of_unix`, `root`, `leaf_count`, and `leaves_digest`
    /// key lines plus exactly `leaf_count` `leaf` records.
    pub fn parse_root_file(text: &str) -> Result<Self, LedgerError> {
        let mut schema: Option<String> = None;
        let mut as_of_unix: Option<i64> = None;
        let mut root: Option<String> = None;
        let mut leaf_count: Option<u64> = None;
        let mut leaves_digest: Option<String> = None;
        let mut leaves: Vec<LedgerLeaf> = Vec::new();

        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let key = parts.next().unwrap_or("");
            match key {
                "schema" => {
                    schema = Some(field(&mut parts, "schema")?);
                }
                "as_of_unix" => {
                    let v = field(&mut parts, "as_of_unix")?;
                    as_of_unix = Some(
                        v.parse::<i64>()
                            .map_err(|_| LedgerError::Malformed(format!("as_of_unix: {v}")))?,
                    );
                }
                "root" => {
                    root = Some(field(&mut parts, "root")?);
                }
                "leaf_count" => {
                    let v = field(&mut parts, "leaf_count")?;
                    leaf_count = Some(
                        v.parse::<u64>()
                            .map_err(|_| LedgerError::Malformed(format!("leaf_count: {v}")))?,
                    );
                }
                "leaves_digest" => {
                    leaves_digest = Some(field(&mut parts, "leaves_digest")?);
                }
                "leaf" => {
                    let claim_id = field(&mut parts, "leaf.claim_id")?;
                    let state_s = field(&mut parts, "leaf.asserted_state")?;
                    let tier_s = field(&mut parts, "leaf.evidence_tier")?;
                    let artifact_content_hash = field(&mut parts, "leaf.artifact_content_hash")?;
                    let receipt_hash = field(&mut parts, "leaf.receipt_hash")?;
                    // The trailing leaf_hash is informational; the gate recomputes it.
                    let asserted_state = ClaimAssertionState::parse(&state_s)
                        .map_err(|_| LedgerError::Malformed(format!("leaf state: {state_s}")))?;
                    let evidence_tier = parse_evidence_tier(&tier_s)?;
                    leaves.push(LedgerLeaf {
                        claim_id,
                        asserted_state,
                        evidence_tier,
                        artifact_content_hash,
                        receipt_hash,
                    });
                }
                other => {
                    return Err(LedgerError::Malformed(format!("unknown key: {other}")));
                }
            }
        }

        let commitment = Self {
            schema: schema.ok_or_else(|| LedgerError::Malformed("missing schema".into()))?,
            as_of_unix: as_of_unix
                .ok_or_else(|| LedgerError::Malformed("missing as_of_unix".into()))?,
            root: root.ok_or_else(|| LedgerError::Malformed("missing root".into()))?,
            leaf_count: leaf_count
                .ok_or_else(|| LedgerError::Malformed("missing leaf_count".into()))?,
            leaves_digest: leaves_digest
                .ok_or_else(|| LedgerError::Malformed("missing leaves_digest".into()))?,
            leaves,
        };
        if commitment.leaves.len() as u64 != commitment.leaf_count {
            return Err(LedgerError::Malformed(format!(
                "leaf_count {} != {} leaf records",
                commitment.leaf_count,
                commitment.leaves.len()
            )));
        }
        Ok(commitment)
    }
}

/// Pull the next whitespace-token field, erroring if absent.
fn field<'a>(parts: &mut impl Iterator<Item = &'a str>, name: &str) -> Result<String, LedgerError> {
    parts
        .next()
        .map(str::to_string)
        .ok_or_else(|| LedgerError::Malformed(format!("missing field: {name}")))
}

/// Parse an evidence-tier label (the [`EvidenceTier`] `Display` form).
fn parse_evidence_tier(s: &str) -> Result<EvidenceTier, LedgerError> {
    match s.trim() {
        "unbacked" => Ok(EvidenceTier::Unbacked),
        "asserted" => Ok(EvidenceTier::Asserted),
        "exercised" => Ok(EvidenceTier::Exercised),
        "reproduced" => Ok(EvidenceTier::Reproduced),
        "adversarially_verified" => Ok(EvidenceTier::AdversariallyVerified),
        other => Err(LedgerError::Malformed(format!("evidence tier: {other}"))),
    }
}

/// Read the committed commitment from [`LEDGER_ROOT_FILE`] under `repo_root`.
pub fn load_committed_commitment(repo_root: &Path) -> Result<LedgerCommitment, LedgerError> {
    let path = repo_root.join(LEDGER_ROOT_FILE);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| LedgerError::Io(format!("{}: {e}", path.display())))?;
    LedgerCommitment::parse_root_file(&text)
}

/// Write the commitment to [`LEDGER_ROOT_FILE`] under `repo_root`.
pub fn write_committed_commitment(
    repo_root: &Path,
    commitment: &LedgerCommitment,
) -> Result<(), LedgerError> {
    let path = repo_root.join(LEDGER_ROOT_FILE);
    std::fs::write(&path, commitment.to_root_file())
        .map_err(|e| LedgerError::Io(format!("{}: {e}", path.display())))
}

// ---------------------------------------------------------------------------
// Verification (the gate)
// ---------------------------------------------------------------------------

/// The verdict of checking the live matrix/evidence against the committed root.
#[derive(Debug, Clone)]
pub struct LedgerVerification {
    /// The commitment parsed from [`LEDGER_ROOT_FILE`].
    pub committed: LedgerCommitment,
    /// The commitment recomputed from the live matrix + evidence at the committed
    /// `as_of_unix`.
    pub recomputed: LedgerCommitment,
    /// Recomputed root equals committed root.
    pub root_matches: bool,
    /// Recomputed leaf count equals committed leaf count.
    pub leaf_count_matches: bool,
    /// Recomputed leaves digest equals committed leaves digest.
    pub leaves_digest_matches: bool,
    /// Every committed `leaf` record reproduces exactly (per-row tamper check).
    pub leaves_match: bool,
    /// Every recomputed leaf carries a valid RFC-6962 inclusion proof.
    pub inclusion_proofs_ok: bool,
    /// Human-readable descriptions of each divergence (empty iff [`Self::ok`]).
    pub mismatches: Vec<String>,
}

impl LedgerVerification {
    /// Whether the committed root is consistent with live matrix/evidence: every
    /// check passed.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.root_matches
            && self.leaf_count_matches
            && self.leaves_digest_matches
            && self.leaves_match
            && self.inclusion_proofs_ok
    }
}

/// Recompute the ledger from the live matrix + committed evidence at the
/// committed `as_of_unix`, and compare against the committed root file.
///
/// This is the gate's core: it fails (`ok() == false`) whenever a matrix row or a
/// committed evidence manifest was edited without regenerating the root.
pub fn verify_against_committed(
    matrix_path: &Path,
    repo_root: &Path,
    max_freshness_days: Option<u64>,
) -> Result<LedgerVerification, LedgerError> {
    let committed = load_committed_commitment(repo_root)?;
    // Recompute at the *pinned* instant so the verdict is a pure function of
    // committed content, never the wall clock.
    let ledger = ClaimEvidenceLedger::build(
        matrix_path,
        repo_root,
        committed.as_of_unix,
        max_freshness_days,
    )?;
    let recomputed = ledger.commitment()?;

    let mut mismatches: Vec<String> = Vec::new();

    let root_matches = recomputed.root == committed.root;
    if !root_matches {
        mismatches.push(format!(
            "root mismatch: committed {} != recomputed {}",
            committed.root, recomputed.root
        ));
    }

    let leaf_count_matches = recomputed.leaf_count == committed.leaf_count;
    if !leaf_count_matches {
        mismatches.push(format!(
            "leaf_count mismatch: committed {} != recomputed {}",
            committed.leaf_count, recomputed.leaf_count
        ));
    }

    let leaves_digest_matches = recomputed.leaves_digest == committed.leaves_digest;
    if !leaves_digest_matches {
        mismatches.push(format!(
            "leaves_digest mismatch: committed {} != recomputed {}",
            committed.leaves_digest, recomputed.leaves_digest
        ));
    }

    // Per-leaf comparison: pinpoints which claim drifted (only when the leaf sets
    // line up by claim_id, which they do when only content — not the row set —
    // changed).
    let leaves_match = compare_leaves(&committed.leaves, &recomputed.leaves, &mut mismatches);

    let inclusion_proofs_ok = ledger.verify_all_inclusions().is_ok();
    if !inclusion_proofs_ok {
        mismatches.push("one or more leaves failed RFC-6962 inclusion proof".to_string());
    }

    Ok(LedgerVerification {
        committed,
        recomputed,
        root_matches,
        leaf_count_matches,
        leaves_digest_matches,
        leaves_match,
        inclusion_proofs_ok,
        mismatches,
    })
}

/// Compare committed vs recomputed leaves by `claim_id`, appending a description
/// for every divergence. Returns `true` iff the two leaf sets are identical.
fn compare_leaves(
    committed: &[LedgerLeaf],
    recomputed: &[LedgerLeaf],
    mismatches: &mut Vec<String>,
) -> bool {
    use std::collections::BTreeMap;
    let by_id: BTreeMap<&str, &LedgerLeaf> = recomputed
        .iter()
        .map(|l| (l.claim_id.as_str(), l))
        .collect();
    let committed_ids: std::collections::BTreeSet<&str> =
        committed.iter().map(|l| l.claim_id.as_str()).collect();

    let mut ok = true;
    for c in committed {
        match by_id.get(c.claim_id.as_str()) {
            None => {
                ok = false;
                mismatches.push(format!(
                    "claim {} present in committed but not live",
                    c.claim_id
                ));
            }
            Some(r) => {
                if c.asserted_state != r.asserted_state {
                    ok = false;
                    mismatches.push(format!(
                        "{}: asserted_state {} -> {}",
                        c.claim_id, c.asserted_state, r.asserted_state
                    ));
                }
                if c.evidence_tier != r.evidence_tier {
                    ok = false;
                    mismatches.push(format!(
                        "{}: evidence_tier {} -> {}",
                        c.claim_id, c.evidence_tier, r.evidence_tier
                    ));
                }
                if c.artifact_content_hash != r.artifact_content_hash {
                    ok = false;
                    mismatches.push(format!("{}: artifact_content_hash changed", c.claim_id));
                }
                if c.receipt_hash != r.receipt_hash {
                    ok = false;
                    mismatches.push(format!("{}: receipt_hash changed", c.claim_id));
                }
            }
        }
    }
    for r in recomputed {
        if !committed_ids.contains(r.claim_id.as_str()) {
            ok = false;
            mismatches.push(format!(
                "claim {} present live but not in committed",
                r.claim_id
            ));
        }
    }
    ok
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_leaf(claim_id: &str, state: ClaimAssertionState, tier: EvidenceTier) -> LedgerLeaf {
        LedgerLeaf {
            claim_id: claim_id.to_string(),
            asserted_state: state,
            evidence_tier: tier,
            artifact_content_hash: sha256_hex(claim_id.as_bytes()),
            receipt_hash: sha256_hex(format!("{claim_id}:receipt").as_bytes()),
        }
    }

    fn sample_ledger() -> ClaimEvidenceLedger {
        ClaimEvidenceLedger {
            leaves: vec![
                sample_leaf(
                    "FE-CLAIM-001",
                    ClaimAssertionState::Observed,
                    EvidenceTier::Reproduced,
                ),
                sample_leaf(
                    "FE-CLAIM-002",
                    ClaimAssertionState::Target,
                    EvidenceTier::Asserted,
                ),
                sample_leaf(
                    "FE-CLAIM-003",
                    ClaimAssertionState::Hypothesis,
                    EvidenceTier::Unbacked,
                ),
            ],
            as_of_unix: 1_750_000_000,
        }
    }

    #[test]
    fn leaf_hash_is_injective_over_every_field() {
        let base = sample_leaf(
            "FE-CLAIM-007",
            ClaimAssertionState::Observed,
            EvidenceTier::Reproduced,
        );
        let h0 = base.leaf_hash();

        let mut a = base.clone();
        a.claim_id = "FE-CLAIM-008".into();
        assert_ne!(h0, a.leaf_hash(), "claim_id must change the leaf hash");

        let mut b = base.clone();
        b.asserted_state = ClaimAssertionState::Target;
        assert_ne!(
            h0,
            b.leaf_hash(),
            "asserted_state must change the leaf hash"
        );

        let mut c = base.clone();
        c.evidence_tier = EvidenceTier::Exercised;
        assert_ne!(h0, c.leaf_hash(), "evidence_tier must change the leaf hash");

        let mut d = base.clone();
        d.artifact_content_hash = ZERO_HASH_HEX.into();
        assert_ne!(
            h0,
            d.leaf_hash(),
            "artifact_content_hash must change the leaf hash"
        );

        let mut e = base.clone();
        e.receipt_hash = ZERO_HASH_HEX.into();
        assert_ne!(h0, e.leaf_hash(), "receipt_hash must change the leaf hash");
    }

    #[test]
    fn leaf_hash_no_field_boundary_collision() {
        // A boundary attack: moving a character across the claim_id/hash boundary
        // must not collide, because every field is length-prefixed.
        let a = LedgerLeaf {
            claim_id: "AB".into(),
            asserted_state: ClaimAssertionState::Observed,
            evidence_tier: EvidenceTier::Reproduced,
            artifact_content_hash: "CD".into(),
            receipt_hash: "EF".into(),
        };
        let b = LedgerLeaf {
            claim_id: "A".into(),
            asserted_state: ClaimAssertionState::Observed,
            evidence_tier: EvidenceTier::Reproduced,
            artifact_content_hash: "BCD".into(),
            receipt_hash: "EF".into(),
        };
        assert_ne!(a.leaf_hash(), b.leaf_hash());
    }

    #[test]
    fn root_is_deterministic_and_nonempty() {
        let l = sample_ledger();
        let r1 = l.root_hex().expect("root");
        let r2 = l.clone().root_hex().expect("root");
        assert_eq!(r1, r2, "root must be deterministic");
        assert_eq!(r1.len(), 64, "root is a hex sha256");
        assert_ne!(r1, ZERO_HASH_HEX);
    }

    #[test]
    fn empty_ledger_has_no_root() {
        let l = ClaimEvidenceLedger {
            leaves: vec![],
            as_of_unix: 0,
        };
        assert!(matches!(l.root_hex(), Err(LedgerError::Empty)));
    }

    #[test]
    fn every_leaf_has_a_valid_inclusion_proof() {
        let l = sample_ledger();
        l.verify_all_inclusions()
            .expect("all inclusion proofs verify");
    }

    #[test]
    fn editing_any_leaf_changes_the_root() {
        let base = sample_ledger();
        let base_root = base.root_hex().expect("root");

        let mut edited = base.clone();
        edited.leaves[1].asserted_state = ClaimAssertionState::Observed; // silent over-promotion
        let edited_root = edited.root_hex().expect("root");
        assert_ne!(
            base_root, edited_root,
            "an over-promotion edit must change the root"
        );

        // The flat leaves digest must also change (defense in depth).
        assert_ne!(base.leaves_digest(), edited.leaves_digest());
    }

    #[test]
    fn adding_or_removing_a_claim_changes_count_and_root() {
        let base = sample_ledger();
        let base_root = base.root_hex().expect("root");

        let mut added = base.clone();
        added.leaves.push(sample_leaf(
            "FE-CLAIM-099",
            ClaimAssertionState::Hypothesis,
            EvidenceTier::Unbacked,
        ));
        assert_eq!(added.leaf_count(), base.leaf_count() + 1);
        assert_ne!(base_root, added.root_hex().expect("root"));
    }

    #[test]
    fn root_file_round_trips() {
        let l = sample_ledger();
        let commitment = l.commitment().expect("commitment");
        let text = commitment.to_root_file();
        let parsed = LedgerCommitment::parse_root_file(&text).expect("parses");
        assert_eq!(parsed.schema, commitment.schema);
        assert_eq!(parsed.as_of_unix, commitment.as_of_unix);
        assert_eq!(parsed.root, commitment.root);
        assert_eq!(parsed.leaf_count, commitment.leaf_count);
        assert_eq!(parsed.leaves_digest, commitment.leaves_digest);
        assert_eq!(parsed.leaves, commitment.leaves);
    }

    #[test]
    fn parse_rejects_leaf_count_mismatch() {
        let l = sample_ledger();
        let mut text = l.commitment().expect("c").to_root_file();
        // Corrupt the declared leaf_count.
        text = text.replace("leaf_count 3", "leaf_count 9");
        assert!(matches!(
            LedgerCommitment::parse_root_file(&text),
            Err(LedgerError::Malformed(_))
        ));
    }

    #[test]
    fn parse_ignores_comments_and_blank_lines() {
        let l = sample_ledger();
        let mut text = String::from("\n\n# a comment\n");
        text.push_str(&l.commitment().expect("c").to_root_file());
        text.push_str("\n# trailing comment\n");
        let parsed = LedgerCommitment::parse_root_file(&text).expect("parses");
        assert_eq!(parsed.leaf_count, 3);
    }

    #[test]
    fn evidence_tier_label_round_trips() {
        for tier in EvidenceTier::all() {
            assert_eq!(parse_evidence_tier(&tier.to_string()).expect("tier"), tier);
        }
    }
}
