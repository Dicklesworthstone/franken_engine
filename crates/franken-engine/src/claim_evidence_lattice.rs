//! Claim ⇄ evidence soundness lattice (CEI track A.1, bead `bd-sde5e.1.1`).
//!
//! # Why this module exists
//!
//! FrankenEngine's constitutional thesis (`docs/RUNTIME_CHARTER.md` §7) is that a
//! claim's *stated strength* may never exceed its *evidence*. The historical
//! claim-to-proof gate (`scripts/run_claim_to_proof_matrix_gate.sh`) only enforces
//! **one** direction of that contract:
//!
//! ```text
//! README wording state  ≤  matrix.allowed_state          (already enforced)
//! ```
//!
//! It treats `matrix.allowed_state` as a *trusted oracle* and never checks the
//! other direction:
//!
//! ```text
//! matrix.allowed_state  ≤  evidence actually committed     (NOT enforced — the gap)
//! ```
//!
//! The 2026-06-18 reality check found exactly this drift: rows marked `observed`
//! whose proof bundles are git-ignored (a fresh clone has *zero* evidence),
//! carry `verification_result = pending` from a backfill script, and advertise a
//! fictional `freshness_days = 1` when the real artifact age is weeks.
//!
//! This module closes the missing direction *by construction*. It defines two
//! finite, totally-ordered lattices and a **monotone** map `tier` from
//! machine-checkable facts to an evidence tier, a total `ceiling` from evidence
//! tier to the maximum honestly-assertable claim state, and the soundness
//! predicate `state(claim) ≤ ceiling(tier(claim))`. The fraction of rows that
//! satisfy the predicate is the **claim-integrity-coverage** — a single number
//! that can only rise as real, committed, freshly-verified evidence lands.
//!
//! # The two lattices
//!
//! Claim-assertion state (mirrors `docs/claim_to_proof_matrix_v1.json` `state_order`):
//!
//! ```text
//! Hypothesis  <  Target  <  Observed
//! ```
//!
//! Evidence tier (computed only from facts a machine can re-derive):
//!
//! ```text
//! Unbacked  <  Asserted  <  Exercised  <  Reproduced  <  AdversariallyVerified
//! ```
//!
//! Both are *chains* (total orders), hence lattices with `join = max` and
//! `meet = min`. The lattice laws (idempotence, commutativity, associativity,
//! absorption) and the monotonicity of `tier` / `ceiling` are proven by the unit
//! tests at the bottom of this file.
//!
//! # Scope of A.1
//!
//! This bead delivers the pure scorer plus a fact collector that reads the real
//! repository (git-tracked status, manifest `verification_result`, freshness).
//! Turning the advisory coverage metric into a *blocking* gate is deferred to
//! A.3 (`bd-sde5e.1.3`), which depends on track B committing the evidence first;
//! enforcing it before then would brick the gate against every currently-drifted
//! row. The full e2e runner + replay wrapper belong to A.6 (`bd-sde5e.1.6`).

use std::fmt;
use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Schema/domain tag mixed into the content-addressed coverage digest so a digest
/// for this report can never be confused with any other length-prefixed preimage.
pub const COVERAGE_DIGEST_DOMAIN: &str = "franken-engine.claim-evidence-integrity.v1";

// ---------------------------------------------------------------------------
// Length-prefixed canonical encoding helpers
// ---------------------------------------------------------------------------
//
// These mirror `push_len_prefixed` / `push_count` in `semantic_cover_schema`
// and the project-wide determinism discipline: every variable-length field is
// length-prefixed before concatenation so two distinct reports can never share
// a preimage (injectivity).

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
// Claim-assertion state lattice: Hypothesis < Target < Observed
// ---------------------------------------------------------------------------

/// How strongly a README sentence / matrix row *asserts* a capability.
///
/// Declaration order is ascending, so the derived `Ord` is the lattice order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimAssertionState {
    /// Projected / optional behaviour; must not be read as shipped proof.
    Hypothesis,
    /// A documented design goal or SLO; a roadmap commitment, not a guarantee.
    Target,
    /// Current artifacts and a verification command are linked. Strongest wording.
    Observed,
}

impl ClaimAssertionState {
    /// Numeric rank within the chain (0 = weakest).
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Self::Hypothesis => 0,
            Self::Target => 1,
            Self::Observed => 2,
        }
    }

    /// Lattice join (least upper bound) — the stronger of two states.
    #[must_use]
    pub fn join(self, other: Self) -> Self {
        if self >= other { self } else { other }
    }

    /// Lattice meet (greatest lower bound) — the weaker of two states.
    #[must_use]
    pub fn meet(self, other: Self) -> Self {
        if self <= other { self } else { other }
    }

    /// Parse a matrix state string (`hypothesis` / `target` / `observed`).
    ///
    /// Matching is case-insensitive and tolerant of surrounding whitespace.
    pub fn parse(s: &str) -> Result<Self, IntegrityError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "hypothesis" => Ok(Self::Hypothesis),
            "target" => Ok(Self::Target),
            "observed" => Ok(Self::Observed),
            other => Err(IntegrityError::UnknownClaimState(other.to_string())),
        }
    }

    /// All states, ascending — used by lattice-law property tests.
    #[must_use]
    pub fn all() -> [Self; 3] {
        [Self::Hypothesis, Self::Target, Self::Observed]
    }
}

impl fmt::Display for ClaimAssertionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Hypothesis => "hypothesis",
            Self::Target => "target",
            Self::Observed => "observed",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// Evidence-tier lattice: Unbacked < Asserted < Exercised < Reproduced < AdversariallyVerified
// ---------------------------------------------------------------------------

/// The strength of evidence a claim row can actually stand on, derived purely
/// from machine-checkable facts. Declaration order is ascending.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceTier {
    /// No committed artifact at all (git-ignored or absent). "No artifact, no claim."
    Unbacked,
    /// A committed, git-tracked artifact exists but has not been exercised
    /// (verification pending / backfilled, or no zero-exit run receipt).
    Asserted,
    /// The verifying gate ran and passed with a committed zero-exit run receipt,
    /// but the bundle is not reproducible (no committed `repro.lock`) or is stale.
    Exercised,
    /// Exercised *and* reproducible: a git-tracked `repro.lock` partner plus a
    /// freshness within the matrix window.
    Reproduced,
    /// Reproduced *and* additionally backed by the adversarial / metamorphic
    /// self-audit corpus (set by A.5 / track H; default `false` in A.1).
    AdversariallyVerified,
}

impl EvidenceTier {
    /// Numeric rank within the chain (0 = weakest).
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Self::Unbacked => 0,
            Self::Asserted => 1,
            Self::Exercised => 2,
            Self::Reproduced => 3,
            Self::AdversariallyVerified => 4,
        }
    }

    /// Lattice join (least upper bound).
    #[must_use]
    pub fn join(self, other: Self) -> Self {
        if self >= other { self } else { other }
    }

    /// Lattice meet (greatest lower bound).
    #[must_use]
    pub fn meet(self, other: Self) -> Self {
        if self <= other { self } else { other }
    }

    /// All tiers, ascending — used by lattice-law and monotonicity tests.
    #[must_use]
    pub fn all() -> [Self; 5] {
        [
            Self::Unbacked,
            Self::Asserted,
            Self::Exercised,
            Self::Reproduced,
            Self::AdversariallyVerified,
        ]
    }
}

impl fmt::Display for EvidenceTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Unbacked => "unbacked",
            Self::Asserted => "asserted",
            Self::Exercised => "exercised",
            Self::Reproduced => "reproduced",
            Self::AdversariallyVerified => "adversarially_verified",
        };
        write!(f, "{label}")
    }
}

/// Total map from an evidence tier to the **maximum** claim state it can honestly
/// license. Monotone (non-decreasing in tier) — proven by [`tests`].
///
/// The boundary at `Reproduced → Observed` encodes the project's reproducibility
/// contract (`bd-cixqu.4.3`): an `observed` row must carry a committed,
/// freshly-verified `repro.lock`, not merely a passing one-shot gate.
#[must_use]
pub fn ceiling(tier: EvidenceTier) -> ClaimAssertionState {
    match tier {
        EvidenceTier::Unbacked => ClaimAssertionState::Hypothesis,
        // A committed-but-unexercised artifact can back a roadmap goal, not a guarantee.
        EvidenceTier::Asserted | EvidenceTier::Exercised => ClaimAssertionState::Target,
        // Reproducible (and stronger) evidence licenses the strongest wording.
        EvidenceTier::Reproduced | EvidenceTier::AdversariallyVerified => {
            ClaimAssertionState::Observed
        }
    }
}

// ---------------------------------------------------------------------------
// Machine-checkable evidence facts
// ---------------------------------------------------------------------------

/// The finite set of machine-checkable facts that `tier` consumes. Every field
/// is a *positive* fact (true = stronger evidence) so the dominance order and
/// monotonicity are unambiguous; freshness is reduced to the boolean `fresh`
/// for the lattice while `freshness_days` is retained for reporting only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceFacts {
    /// `git ls-files` reports the declared artifact path as tracked.
    pub artifact_git_tracked: bool,
    /// Manifest `outputs.verification_result == "passed"` AND not backfill-generated.
    pub verification_passed: bool,
    /// A committed run receipt records a zero exit status (e.g. `repro.lock`
    /// `expected_outputs.exit_code == 0`).
    pub receipt_exit_zero: bool,
    /// A git-tracked `repro.lock` partner exists for the bundle.
    pub repro_lock_present: bool,
    /// The artifact's real age is within the matrix freshness window.
    pub fresh: bool,
    /// The claim is additionally backed by the adversarial / metamorphic corpus.
    pub adversarially_verified: bool,

    // --- reporting-only fields (NOT part of the monotone lattice) ---
    /// Real artifact age in days, if it could be computed from the manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freshness_days: Option<u64>,
    /// Human-readable provenance notes (e.g. "verification_result=pending").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl EvidenceFacts {
    /// Componentwise dominance over the six monotone facts: `self` is at least as
    /// strong as `other` in every positive fact. Used to prove `tier` monotone.
    #[must_use]
    pub fn dominates(&self, other: &Self) -> bool {
        (self.artifact_git_tracked || !other.artifact_git_tracked)
            && (self.verification_passed || !other.verification_passed)
            && (self.receipt_exit_zero || !other.receipt_exit_zero)
            && (self.repro_lock_present || !other.repro_lock_present)
            && (self.fresh || !other.fresh)
            && (self.adversarially_verified || !other.adversarially_verified)
    }
}

/// Monotone map from machine-checkable facts to an evidence tier.
///
/// Built as a ladder of cumulative conjunctive gates, so strengthening any single
/// fact can only move a row *up* the ladder — never down. This is the structural
/// guarantee that honesty "can only rise with committed evidence."
#[must_use]
pub fn tier(facts: &EvidenceFacts) -> EvidenceTier {
    let committed = facts.artifact_git_tracked;
    let exercised = committed && facts.verification_passed && facts.receipt_exit_zero;
    let reproduced = exercised && facts.repro_lock_present && facts.fresh;
    let adversarial = reproduced && facts.adversarially_verified;

    if adversarial {
        EvidenceTier::AdversariallyVerified
    } else if reproduced {
        EvidenceTier::Reproduced
    } else if exercised {
        EvidenceTier::Exercised
    } else if committed {
        EvidenceTier::Asserted
    } else {
        EvidenceTier::Unbacked
    }
}

// ---------------------------------------------------------------------------
// Per-claim verdict and whole-matrix integrity report
// ---------------------------------------------------------------------------

/// A minimal view of one claim-to-proof matrix row: what it asserts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimRow {
    /// Matrix `claim_id`, e.g. `FE-CLAIM-004`.
    pub claim_id: String,
    /// The state the matrix asserts (`allowed_state`).
    pub asserted_state: ClaimAssertionState,
    /// The machine-checkable evidence facts gathered for this row.
    pub facts: EvidenceFacts,
}

/// The scored verdict for one claim row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimVerdict {
    pub claim_id: String,
    pub asserted_state: ClaimAssertionState,
    pub evidence_tier: EvidenceTier,
    pub ceiling: ClaimAssertionState,
    /// `asserted_state ≤ ceiling` — the soundness predicate for this row.
    pub sound: bool,
    /// Reporting-only provenance notes copied from the facts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl ClaimVerdict {
    /// Score a single row against the lattice soundness predicate.
    #[must_use]
    pub fn score(row: &ClaimRow) -> Self {
        let evidence_tier = tier(&row.facts);
        let ceiling = ceiling(evidence_tier);
        let sound = row.asserted_state <= ceiling;
        Self {
            claim_id: row.claim_id.clone(),
            asserted_state: row.asserted_state,
            evidence_tier,
            ceiling,
            sound,
            notes: row.facts.notes.clone(),
        }
    }
}

/// Fixed-point scale for the coverage ratio (`1_000_000 = 1.0`). `f64` is
/// forbidden in this hashed position per the determinism discipline.
pub const COVERAGE_SCALE: u64 = 1_000_000;

/// The whole-matrix integrity report: per-row verdicts plus the content-addressed
/// claim-integrity-coverage scalar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityReport {
    /// Verdicts keyed by `claim_id`, sorted (BTree iteration) for determinism.
    pub verdicts: std::collections::BTreeMap<String, ClaimVerdict>,
    /// Number of rows scored.
    pub total_rows: u64,
    /// Rows whose asserted state is within its evidence ceiling.
    pub sound_rows: u64,
    /// `sound_rows / total_rows` in millionths (`1_000_000 = 1.0`).
    pub coverage_millionths: u64,
    /// Lowercase hex SHA-256 of the canonical, length-prefixed report preimage.
    pub coverage_digest: String,
}

impl IntegrityReport {
    /// Score every row and compute the content-addressed coverage metric.
    #[must_use]
    pub fn score(rows: &[ClaimRow]) -> Self {
        let mut verdicts = std::collections::BTreeMap::new();
        let mut sound_rows: u64 = 0;
        for row in rows {
            let verdict = ClaimVerdict::score(row);
            if verdict.sound {
                sound_rows = sound_rows.saturating_add(1);
            }
            verdicts.insert(row.claim_id.clone(), verdict);
        }
        let total_rows = verdicts.len() as u64;
        // Integer fixed-point: exactly COVERAGE_SCALE iff all rows are sound.
        let coverage_millionths = if total_rows == 0 {
            COVERAGE_SCALE
        } else {
            (sound_rows.saturating_mul(COVERAGE_SCALE)) / total_rows
        };
        let coverage_digest = Self::compute_digest(&verdicts, coverage_millionths);
        Self {
            verdicts,
            total_rows,
            sound_rows,
            coverage_millionths,
            coverage_digest,
        }
    }

    /// Whether the matrix is internally sound: every asserted state is within its
    /// evidence ceiling. This is the predicate A.3 will enforce as blocking.
    #[must_use]
    pub fn is_sound(&self) -> bool {
        self.sound_rows == self.total_rows
    }

    /// The rows that over-promote (asserted state exceeds their evidence ceiling).
    #[must_use]
    pub fn unsound(&self) -> Vec<&ClaimVerdict> {
        self.verdicts.values().filter(|v| !v.sound).collect()
    }

    /// Canonical, length-prefixed SHA-256 over the (sorted) verdicts and the
    /// coverage scalar. Deterministic and injective: distinct reports cannot
    /// share a digest.
    fn compute_digest(
        verdicts: &std::collections::BTreeMap<String, ClaimVerdict>,
        coverage_millionths: u64,
    ) -> String {
        let mut buf: Vec<u8> = Vec::new();
        push_len_prefixed(&mut buf, COVERAGE_DIGEST_DOMAIN.as_bytes());
        push_count(&mut buf, verdicts.len());
        for (claim_id, v) in verdicts {
            push_len_prefixed(&mut buf, claim_id.as_bytes());
            buf.push(v.asserted_state.rank());
            buf.push(v.evidence_tier.rank());
            buf.push(v.ceiling.rank());
            buf.push(u8::from(v.sound));
        }
        buf.extend_from_slice(&coverage_millionths.to_le_bytes());
        let digest = Sha256::digest(&buf);
        hex::encode(digest)
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors raised while scoring or collecting facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityError {
    /// A matrix state string was not `hypothesis` / `target` / `observed`.
    UnknownClaimState(String),
    /// The matrix file could not be read.
    MatrixRead(String),
    /// The matrix JSON was malformed or missing required fields.
    MatrixParse(String),
}

impl fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownClaimState(s) => write!(f, "unknown claim state: {s:?}"),
            Self::MatrixRead(s) => write!(f, "could not read matrix: {s}"),
            Self::MatrixParse(s) => write!(f, "could not parse matrix: {s}"),
        }
    }
}

impl std::error::Error for IntegrityError {}

// ---------------------------------------------------------------------------
// Fact collection (machine-checkable, reads the real repository)
// ---------------------------------------------------------------------------

/// Returns `true` if `rel_path` is tracked by git under `repo_root`.
///
/// Uses `git ls-files --error-unmatch`, which exits non-zero for untracked or
/// ignored paths. A directory is considered tracked iff it contains ≥1 tracked
/// file (`git ls-files <dir>` prints at least one line).
#[must_use]
pub fn git_path_tracked(repo_root: &Path, rel_path: &str) -> bool {
    if rel_path.is_empty() {
        return false;
    }
    let out = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .arg("ls-files")
        .arg("--")
        .arg(rel_path)
        .output();
    match out {
        Ok(o) if o.status.success() => !o.stdout.is_empty(),
        _ => false,
    }
}

/// Parse an ISO-8601 / RFC-3339 timestamp into a unix-seconds value.
fn parse_unix_seconds(ts: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(ts.trim())
        .ok()
        .map(|dt| dt.timestamp())
}

/// Gather [`EvidenceFacts`] for one claim row from the real repository.
///
/// Reads:
/// * `git ls-files` for the declared artifact path and any `repro.lock` partner;
/// * the bundle `manifest.json` `outputs.verification_result` and
///   `provenance.generated_by` (a `backfill`-generated bundle is never "passed");
/// * `repro.lock` `expected_outputs.exit_code` for the run receipt;
/// * the manifest `generated_at_utc` to derive real freshness vs `now_unix`.
///
/// `now_unix` and `max_freshness_days` are passed in (never read from the wall
/// clock here) so the collector is deterministic and unit-testable.
#[must_use]
pub fn collect_evidence_facts(
    repo_root: &Path,
    artifact_path: &str,
    now_unix: i64,
    max_freshness_days: u64,
) -> EvidenceFacts {
    let mut facts = EvidenceFacts::default();

    facts.artifact_git_tracked = git_path_tracked(repo_root, artifact_path);
    if !facts.artifact_git_tracked {
        facts
            .notes
            .push(format!("artifact not git-tracked: {artifact_path}"));
    }

    let bundle_dir = repo_root.join(artifact_path);
    let manifest_path = bundle_dir.join("manifest.json");
    let repro_lock_rel = format!("{}/repro.lock", artifact_path.trim_end_matches('/'));

    // repro.lock must be *committed* to count.
    facts.repro_lock_present = git_path_tracked(repo_root, &repro_lock_rel);

    if let Ok(text) = std::fs::read_to_string(&manifest_path) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
            let verification_result = json
                .get("outputs")
                .and_then(|o| o.get("verification_result"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let generated_by = json
                .get("provenance")
                .and_then(|p| p.get("generated_by"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let backfilled = generated_by.to_ascii_lowercase().contains("backfill");
            facts.verification_passed =
                verification_result.eq_ignore_ascii_case("passed") && !backfilled;
            if verification_result != "passed" {
                facts
                    .notes
                    .push(format!("verification_result={verification_result}"));
            }
            if backfilled {
                facts
                    .notes
                    .push(format!("backfill provenance: {generated_by}"));
            }

            // Freshness from the manifest generation timestamp.
            let generated = json
                .get("generated_at_utc")
                .or_else(|| json.get("generated_utc"))
                .and_then(|v| v.as_str())
                .and_then(parse_unix_seconds);
            if let Some(gen_unix) = generated {
                let age_days = ((now_unix - gen_unix).max(0) / 86_400) as u64;
                facts.freshness_days = Some(age_days);
                facts.fresh = age_days <= max_freshness_days;
                if !facts.fresh {
                    facts
                        .notes
                        .push(format!("stale: {age_days}d > {max_freshness_days}d window"));
                }
            } else {
                facts.notes.push("no parseable generation timestamp".into());
            }
        } else {
            facts.notes.push("manifest.json not valid JSON".into());
        }
    } else if facts.artifact_git_tracked {
        facts.notes.push("manifest.json missing".into());
    }

    // Run receipt: zero exit recorded in the committed repro.lock.
    if facts.repro_lock_present {
        let repro_lock_path = bundle_dir.join("repro.lock");
        if let Ok(text) = std::fs::read_to_string(&repro_lock_path) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                let exit = json
                    .get("expected_outputs")
                    .and_then(|o| o.get("exit_code"))
                    .and_then(serde_json::Value::as_i64);
                facts.receipt_exit_zero = exit == Some(0);
                if exit != Some(0) {
                    facts.notes.push(format!("repro.lock exit_code={exit:?}"));
                }
            }
        }
    }

    facts
}

/// Score the live claim-to-proof matrix JSON file against committed evidence.
///
/// Reads `matrix_path`, collects facts for each claim from `repo_root`, and
/// returns the [`IntegrityReport`]. `now_unix` / `max_freshness_days` are passed
/// in for determinism; `max_freshness_days` falls back to the matrix's own
/// `max_observed_freshness_days` when `None`.
pub fn score_matrix_file(
    matrix_path: &Path,
    repo_root: &Path,
    now_unix: i64,
    max_freshness_days: Option<u64>,
) -> Result<IntegrityReport, IntegrityError> {
    let text = std::fs::read_to_string(matrix_path)
        .map_err(|e| IntegrityError::MatrixRead(e.to_string()))?;
    let json: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| IntegrityError::MatrixParse(e.to_string()))?;

    let window = max_freshness_days.unwrap_or_else(|| {
        json.get("max_observed_freshness_days")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(30)
    });

    let claims = json
        .get("claims")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| IntegrityError::MatrixParse("missing `claims` array".into()))?;

    let mut rows = Vec::with_capacity(claims.len());
    for claim in claims {
        let claim_id = claim
            .get("claim_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| IntegrityError::MatrixParse("claim missing `claim_id`".into()))?
            .to_string();
        let allowed = claim
            .get("allowed_state")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                IntegrityError::MatrixParse(format!("{claim_id} missing `allowed_state`"))
            })?;
        let asserted_state = ClaimAssertionState::parse(allowed)?;
        let artifact_path = claim
            .get("artifact_path")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let facts = collect_evidence_facts(repo_root, artifact_path, now_unix, window);
        rows.push(ClaimRow {
            claim_id,
            asserted_state,
            facts,
        });
    }

    Ok(IntegrityReport::score(&rows))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Lattice laws for a finite chain -----------------------------------

    fn claim_law_check<F>(join: bool, op: F)
    where
        F: Fn(ClaimAssertionState, ClaimAssertionState) -> ClaimAssertionState,
    {
        let all = ClaimAssertionState::all();
        // Idempotence.
        for a in all {
            assert_eq!(op(a, a), a, "idempotence failed for {a}");
        }
        // Commutativity.
        for a in all {
            for b in all {
                assert_eq!(op(a, b), op(b, a), "commutativity {a},{b}");
            }
        }
        // Associativity.
        for a in all {
            for b in all {
                for c in all {
                    assert_eq!(op(op(a, b), c), op(a, op(b, c)), "assoc {a},{b},{c}");
                }
            }
        }
        // Join/meet agree with max/min on a chain.
        for a in all {
            for b in all {
                let expect = if join { a.max(b) } else { a.min(b) };
                assert_eq!(op(a, b), expect);
            }
        }
    }

    #[test]
    fn claim_state_join_meet_satisfy_lattice_laws() {
        claim_law_check(true, ClaimAssertionState::join);
        claim_law_check(false, ClaimAssertionState::meet);
        // Absorption: a ∨ (a ∧ b) = a  and  a ∧ (a ∨ b) = a.
        for a in ClaimAssertionState::all() {
            for b in ClaimAssertionState::all() {
                assert_eq!(a.join(a.meet(b)), a, "absorb-join {a},{b}");
                assert_eq!(a.meet(a.join(b)), a, "absorb-meet {a},{b}");
            }
        }
    }

    fn tier_law_check<F>(join: bool, op: F)
    where
        F: Fn(EvidenceTier, EvidenceTier) -> EvidenceTier,
    {
        let all = EvidenceTier::all();
        for a in all {
            assert_eq!(op(a, a), a, "idempotence {a}");
        }
        for a in all {
            for b in all {
                assert_eq!(op(a, b), op(b, a), "commutativity {a},{b}");
            }
        }
        for a in all {
            for b in all {
                for c in all {
                    assert_eq!(op(op(a, b), c), op(a, op(b, c)), "assoc {a},{b},{c}");
                }
            }
        }
        for a in all {
            for b in all {
                let expect = if join { a.max(b) } else { a.min(b) };
                assert_eq!(op(a, b), expect);
            }
        }
    }

    #[test]
    fn evidence_tier_join_meet_satisfy_lattice_laws() {
        tier_law_check(true, EvidenceTier::join);
        tier_law_check(false, EvidenceTier::meet);
        for a in EvidenceTier::all() {
            for b in EvidenceTier::all() {
                assert_eq!(a.join(a.meet(b)), a, "absorb-join {a},{b}");
                assert_eq!(a.meet(a.join(b)), a, "absorb-meet {a},{b}");
            }
        }
    }

    // -- Enumerate the finite fact space -----------------------------------

    fn all_fact_combos() -> Vec<EvidenceFacts> {
        let mut out = Vec::with_capacity(64);
        for bits in 0u8..64 {
            out.push(EvidenceFacts {
                artifact_git_tracked: bits & 1 != 0,
                verification_passed: bits & 2 != 0,
                receipt_exit_zero: bits & 4 != 0,
                repro_lock_present: bits & 8 != 0,
                fresh: bits & 16 != 0,
                adversarially_verified: bits & 32 != 0,
                freshness_days: None,
                notes: Vec::new(),
            });
        }
        out
    }

    #[test]
    fn tier_is_monotone_over_the_whole_fact_lattice() {
        let combos = all_fact_combos();
        for a in &combos {
            for b in &combos {
                if b.dominates(a) {
                    assert!(
                        tier(b) >= tier(a),
                        "monotonicity violated: tier({:?})={} < tier({:?})={}",
                        b,
                        tier(b),
                        a,
                        tier(a),
                    );
                }
            }
        }
    }

    #[test]
    fn ceiling_is_total_and_monotone() {
        let tiers = EvidenceTier::all();
        for &t1 in &tiers {
            for &t2 in &tiers {
                if t1 <= t2 {
                    assert!(ceiling(t1) <= ceiling(t2), "ceiling not monotone {t1},{t2}");
                }
            }
        }
        // Totality: ceiling is defined (does not panic) for every tier.
        assert_eq!(
            ceiling(EvidenceTier::Unbacked),
            ClaimAssertionState::Hypothesis
        );
        assert_eq!(
            ceiling(EvidenceTier::AdversariallyVerified),
            ClaimAssertionState::Observed
        );
    }

    // -- The headline acceptance test --------------------------------------

    #[test]
    fn observed_with_unbacked_evidence_scores_below_one_and_is_rejected() {
        // A row claiming `observed` with zero committed evidence is exactly the
        // drift the gate must catch.
        let unbacked = ClaimRow {
            claim_id: "FE-CLAIM-SYNTH-DRIFT".into(),
            asserted_state: ClaimAssertionState::Observed,
            facts: EvidenceFacts::default(), // all false → tier = Unbacked
        };
        let verdict = ClaimVerdict::score(&unbacked);
        assert_eq!(verdict.evidence_tier, EvidenceTier::Unbacked);
        assert_eq!(verdict.ceiling, ClaimAssertionState::Hypothesis);
        assert!(!verdict.sound, "observed-with-unbacked must be unsound");

        // A genuinely sound row: hypothesis wording with no evidence is fine.
        let honest = ClaimRow {
            claim_id: "FE-CLAIM-SYNTH-HONEST".into(),
            asserted_state: ClaimAssertionState::Hypothesis,
            facts: EvidenceFacts::default(),
        };

        let report = IntegrityReport::score(&[unbacked, honest]);
        assert_eq!(report.total_rows, 2);
        assert_eq!(report.sound_rows, 1);
        assert!(
            report.coverage_millionths < COVERAGE_SCALE,
            "coverage must be < 1.0"
        );
        assert_eq!(report.coverage_millionths, 500_000);
        assert!(
            !report.is_sound(),
            "report with a drifted row must be rejected"
        );
        assert_eq!(report.unsound().len(), 1);
        assert_eq!(report.unsound()[0].claim_id, "FE-CLAIM-SYNTH-DRIFT");
    }

    #[test]
    fn fully_backed_observed_row_is_sound() {
        let row = ClaimRow {
            claim_id: "FE-CLAIM-SYNTH-GOOD".into(),
            asserted_state: ClaimAssertionState::Observed,
            facts: EvidenceFacts {
                artifact_git_tracked: true,
                verification_passed: true,
                receipt_exit_zero: true,
                repro_lock_present: true,
                fresh: true,
                adversarially_verified: false,
                freshness_days: Some(2),
                notes: Vec::new(),
            },
        };
        let verdict = ClaimVerdict::score(&row);
        assert_eq!(verdict.evidence_tier, EvidenceTier::Reproduced);
        assert_eq!(verdict.ceiling, ClaimAssertionState::Observed);
        assert!(verdict.sound);

        let report = IntegrityReport::score(&[row]);
        assert!(report.is_sound());
        assert_eq!(report.coverage_millionths, COVERAGE_SCALE);
    }

    #[test]
    fn exercised_but_not_reproduced_caps_at_target() {
        // Passing gate, committed artifact, but no repro.lock → Exercised → Target.
        let facts = EvidenceFacts {
            artifact_git_tracked: true,
            verification_passed: true,
            receipt_exit_zero: true,
            repro_lock_present: false,
            fresh: false,
            adversarially_verified: false,
            freshness_days: None,
            notes: Vec::new(),
        };
        assert_eq!(tier(&facts), EvidenceTier::Exercised);
        assert_eq!(ceiling(tier(&facts)), ClaimAssertionState::Target);
        // An `observed` assertion on Exercised-only evidence is unsound.
        let row = ClaimRow {
            claim_id: "X".into(),
            asserted_state: ClaimAssertionState::Observed,
            facts: facts.clone(),
        };
        assert!(!ClaimVerdict::score(&row).sound);
        // A `target` assertion on the same evidence is sound.
        let row_t = ClaimRow {
            claim_id: "X".into(),
            asserted_state: ClaimAssertionState::Target,
            facts,
        };
        assert!(ClaimVerdict::score(&row_t).sound);
    }

    // -- Determinism / content-addressing ----------------------------------

    #[test]
    fn coverage_digest_is_deterministic_and_order_invariant() {
        let mk = |id: &str, s: ClaimAssertionState| ClaimRow {
            claim_id: id.into(),
            asserted_state: s,
            facts: EvidenceFacts::default(),
        };
        let a = IntegrityReport::score(&[
            mk("FE-CLAIM-001", ClaimAssertionState::Hypothesis),
            mk("FE-CLAIM-002", ClaimAssertionState::Observed),
        ]);
        // Same rows in the opposite input order → identical digest (BTree-sorted).
        let b = IntegrityReport::score(&[
            mk("FE-CLAIM-002", ClaimAssertionState::Observed),
            mk("FE-CLAIM-001", ClaimAssertionState::Hypothesis),
        ]);
        assert_eq!(a.coverage_digest, b.coverage_digest);
        assert_eq!(a.coverage_digest.len(), 64);

        // A changed assertion state must change the digest (injectivity).
        let c = IntegrityReport::score(&[
            mk("FE-CLAIM-001", ClaimAssertionState::Target),
            mk("FE-CLAIM-002", ClaimAssertionState::Observed),
        ]);
        assert_ne!(a.coverage_digest, c.coverage_digest);
    }

    #[test]
    fn empty_matrix_is_vacuously_sound() {
        let report = IntegrityReport::score(&[]);
        assert!(report.is_sound());
        assert_eq!(report.coverage_millionths, COVERAGE_SCALE);
        assert_eq!(report.total_rows, 0);
    }

    #[test]
    fn claim_state_parse_roundtrips_matrix_strings() {
        for s in ["hypothesis", "target", "observed"] {
            let parsed = ClaimAssertionState::parse(s).unwrap();
            assert_eq!(parsed.to_string(), s);
        }
        assert_eq!(
            ClaimAssertionState::parse("  OBSERVED ").unwrap(),
            ClaimAssertionState::Observed
        );
        assert!(ClaimAssertionState::parse("guaranteed").is_err());
    }

    #[test]
    fn backfilled_pending_bundle_never_reaches_observed_ceiling() {
        // Mirrors the real FE-CLAIM-004 bundle: committed but verification pending.
        let facts = EvidenceFacts {
            artifact_git_tracked: true,
            verification_passed: false, // pending / backfill
            receipt_exit_zero: true,
            repro_lock_present: true,
            fresh: false, // ~25d old
            adversarially_verified: false,
            freshness_days: Some(25),
            notes: vec!["verification_result=pending".into()],
        };
        assert_eq!(tier(&facts), EvidenceTier::Asserted);
        assert_eq!(ceiling(tier(&facts)), ClaimAssertionState::Target);
    }
}
