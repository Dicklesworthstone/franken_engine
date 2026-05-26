//! Sibling-repo verification operator surface (M.4, `bd-cixqu.13.4`).
//!
//! Deterministic, testable core for the cross-repo integration-verification
//! posture defined in [`docs/CROSS_REPO_DEPENDENCY_ISOLATION_V1.md`]. It models
//! the four operator-facing concerns Track M needs to make a cross-repo
//! regression triageable:
//!
//! 1. **Per-sibling pass/skip/fail semantics** ([`SiblingVerdict`]) — the M.1
//!    pass criteria, surfaced per repository.
//! 2. **SHA-pin governance** ([`SiblingPin`]) — the M.2 pinned commit for each
//!    sibling, with last-passed timestamp and last-failed reason.
//! 3. **The pin-update round-trip** ([`PinAuditLedger::apply_update`]) — record
//!    the prior pin in an append-only audit ledger, then commit the new pin
//!    *only* when the integration smoke passes. When smoke fails the pin holds
//!    at the last-passed SHA; that hold is the safety property that prevents a
//!    silent upstream regression from flowing into our build.
//! 4. **The frankentui "sibling-repo health" dashboard**
//!    ([`SiblingRepoHealthDashboard`]) — a self-contained view model + plain
//!    renderer the panel layer can adopt.
//!
//! The operator shell scripts (`runbooks/scripts/sibling_status.sh`,
//! `runbooks/scripts/sibling_pin_update.sh`) and the
//! `docs/operator-gates/RGC_GATES_REFERENCE.md` section describe the human
//! procedure; this module is the canonical core they mirror so the JSON shapes,
//! validation rules, and the commit-only-on-pass invariant live in exactly one
//! place.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{self, CanonicalValue};
use crate::hash_tiers::ContentHash;

/// Component name used in structured log events (per `bd-cixqu.45`).
pub const COMPONENT: &str = "sibling_repo_verification";
/// Schema version pinning the health-report JSON shape.
pub const SCHEMA_VERSION: &str = "franken-engine.sibling-repo-health.v1";

fn hash_bytes(data: &[u8]) -> [u8; 32] {
    *ContentHash::compute(data).as_bytes()
}

/// A git commit SHA is valid for pinning iff it is 7-40 lowercase hex digits.
///
/// Mirrors the `^[a-f0-9]{7,40}$` validation already used by
/// `scripts/perf/freeze_baseline.sh` and the verification commands in
/// `CROSS_REPO_DEPENDENCY_ISOLATION_V1.md`.
#[must_use]
pub fn is_valid_sha(sha: &str) -> bool {
    let len = sha.len();
    (7..=40).contains(&len) && sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Short-form (7 hex) rendering of a SHA for compact dashboard columns.
#[must_use]
pub fn short_sha(sha: &str) -> String {
    sha.chars().take(7).collect()
}

// --------------------------------------------------------------------------- //
// Sibling identity
// --------------------------------------------------------------------------- //

/// The six sibling repositories pinned in `CROSS_REPO_DEPENDENCY_ISOLATION_V1.md`.
///
/// This is a superset of [`crate::sibling_integration_benchmark_gate::SiblingIntegration`]
/// (which covers only the four benchmarked control-plane siblings): the
/// SHA-pin governance table also pins `asupersync` and `frankenpandas`, so the
/// verification surface must enumerate all six.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SiblingRepo {
    Asupersync,
    Frankentui,
    Frankensqlite,
    SqlmodelRust,
    FastapiRust,
    Frankenpandas,
}

impl SiblingRepo {
    /// Canonical lowercase slug (matches the on-disk `/dp/<slug>` directory).
    #[must_use]
    pub fn slug(self) -> &'static str {
        match self {
            Self::Asupersync => "asupersync",
            Self::Frankentui => "frankentui",
            Self::Frankensqlite => "frankensqlite",
            Self::SqlmodelRust => "sqlmodel_rust",
            Self::FastapiRust => "fastapi_rust",
            Self::Frankenpandas => "frankenpandas",
        }
    }

    /// All siblings in canonical (declaration) order.
    #[must_use]
    pub fn all() -> Vec<Self> {
        vec![
            Self::Asupersync,
            Self::Frankentui,
            Self::Frankensqlite,
            Self::SqlmodelRust,
            Self::FastapiRust,
            Self::Frankenpandas,
        ]
    }

    /// Parse a slug back into a [`SiblingRepo`].
    #[must_use]
    pub fn from_slug(slug: &str) -> Option<Self> {
        Self::all().into_iter().find(|repo| repo.slug() == slug)
    }
}

impl fmt::Display for SiblingRepo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

// --------------------------------------------------------------------------- //
// Per-sibling verdict (M.1 pass/skip/fail)
// --------------------------------------------------------------------------- //

/// Outcome of the per-sibling integration check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SiblingVerdict {
    /// Integration smoke passed against the pinned SHA.
    Passed,
    /// Integration intentionally not run for this sibling (e.g. optional,
    /// feature-gated off). Skips never block.
    Skipped,
    /// Integration smoke failed against the pinned SHA. Blocking.
    Failed,
}

impl SiblingVerdict {
    /// Compact lowercase token used in JSON and the status script.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "pass",
            Self::Skipped => "skip",
            Self::Failed => "fail",
        }
    }

    /// Only [`SiblingVerdict::Failed`] is a release-blocking failure.
    #[must_use]
    pub fn is_blocking_failure(self) -> bool {
        matches!(self, Self::Failed)
    }
}

impl fmt::Display for SiblingVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// --------------------------------------------------------------------------- //
// Errors
// --------------------------------------------------------------------------- //

/// Errors raised when constructing or mutating pins.
///
/// Not `Serialize`/`Deserialize`: errors flow through `Result` returns, never
/// into serialized artifacts, and the `&'static str` field cannot be
/// deserialized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinError {
    /// SHA failed the `^[a-f0-9]{7,40}$` validation.
    InvalidSha {
        repo: SiblingRepo,
        field: &'static str,
        value: String,
    },
    /// The update date was empty (audit trails require a timestamp).
    EmptyUpdatedDate { repo: SiblingRepo },
}

impl fmt::Display for PinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSha { repo, field, value } => write!(
                f,
                "invalid SHA for {repo} ({field}): {value:?} (expected 7-40 lowercase hex digits)"
            ),
            Self::EmptyUpdatedDate { repo } => {
                write!(f, "empty updated date for {repo}")
            }
        }
    }
}

impl std::error::Error for PinError {}

// --------------------------------------------------------------------------- //
// Sibling pin
// --------------------------------------------------------------------------- //

/// The pinned state of one sibling repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiblingPin {
    pub repo: SiblingRepo,
    pub pinned_sha: String,
    pub updated_utc: String,
    pub last_passed_utc: Option<String>,
    pub last_failed_reason: Option<String>,
    pub verdict: SiblingVerdict,
}

impl SiblingPin {
    /// Construct a validated pin. Returns [`PinError`] when the SHA is malformed
    /// or the update date is empty.
    pub fn new(
        repo: SiblingRepo,
        pinned_sha: impl Into<String>,
        updated_utc: impl Into<String>,
        verdict: SiblingVerdict,
        last_passed_utc: Option<String>,
        last_failed_reason: Option<String>,
    ) -> Result<Self, PinError> {
        let pinned_sha = pinned_sha.into();
        let updated_utc = updated_utc.into();
        if !is_valid_sha(&pinned_sha) {
            return Err(PinError::InvalidSha {
                repo,
                field: "pinned_sha",
                value: pinned_sha,
            });
        }
        if updated_utc.trim().is_empty() {
            return Err(PinError::EmptyUpdatedDate { repo });
        }
        Ok(Self {
            repo,
            pinned_sha,
            updated_utc,
            last_passed_utc,
            last_failed_reason,
            verdict,
        })
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("repo".to_string(), CanonicalValue::str(self.repo.slug()));
        map.insert(
            "pinned_sha".to_string(),
            CanonicalValue::str(self.pinned_sha.clone()),
        );
        map.insert(
            "updated_utc".to_string(),
            CanonicalValue::str(self.updated_utc.clone()),
        );
        map.insert(
            "verdict".to_string(),
            CanonicalValue::str(self.verdict.as_str()),
        );
        map.insert(
            "last_passed_utc".to_string(),
            match &self.last_passed_utc {
                Some(ts) => CanonicalValue::str(ts.clone()),
                None => CanonicalValue::Null,
            },
        );
        map.insert(
            "last_failed_reason".to_string(),
            match &self.last_failed_reason {
                Some(reason) => CanonicalValue::str(reason.clone()),
                None => CanonicalValue::Null,
            },
        );
        CanonicalValue::Map(map)
    }

    /// Deterministic content hash over the canonical encoding.
    #[must_use]
    pub fn content_hash(&self) -> [u8; 32] {
        hash_bytes(&deterministic_serde::encode_value(&self.canonical_value()))
    }
}

// --------------------------------------------------------------------------- //
// Health report
// --------------------------------------------------------------------------- //

/// Aggregated health view across all reported siblings — the JSON the
/// `sibling_status.sh` script and the dashboard consume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiblingHealthReport {
    pub schema_version: String,
    pub generated_utc: String,
    pub pins: Vec<SiblingPin>,
    pub total: usize,
    pub passed: usize,
    pub skipped: usize,
    pub failed: usize,
}

impl SiblingHealthReport {
    /// Build a report from a set of pins. Pins are sorted by repository so the
    /// output (and its content hash) is independent of insertion order.
    #[must_use]
    pub fn from_pins(generated_utc: impl Into<String>, mut pins: Vec<SiblingPin>) -> Self {
        pins.sort_by(|a, b| a.repo.cmp(&b.repo));
        let mut passed = 0;
        let mut skipped = 0;
        let mut failed = 0;
        for pin in &pins {
            match pin.verdict {
                SiblingVerdict::Passed => passed += 1,
                SiblingVerdict::Skipped => skipped += 1,
                SiblingVerdict::Failed => failed += 1,
            }
        }
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            generated_utc: generated_utc.into(),
            total: pins.len(),
            passed,
            skipped,
            failed,
            pins,
        }
    }

    /// True when no sibling is in a blocking-failure state.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.failed == 0
    }

    /// Find the pin for a given sibling, if present.
    #[must_use]
    pub fn pin_for(&self, repo: SiblingRepo) -> Option<&SiblingPin> {
        self.pins.iter().find(|pin| pin.repo == repo)
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "schema_version".to_string(),
            CanonicalValue::str(self.schema_version.clone()),
        );
        map.insert(
            "generated_utc".to_string(),
            CanonicalValue::str(self.generated_utc.clone()),
        );
        map.insert("total".to_string(), CanonicalValue::U64(self.total as u64));
        map.insert(
            "passed".to_string(),
            CanonicalValue::U64(self.passed as u64),
        );
        map.insert(
            "skipped".to_string(),
            CanonicalValue::U64(self.skipped as u64),
        );
        map.insert(
            "failed".to_string(),
            CanonicalValue::U64(self.failed as u64),
        );
        map.insert(
            "pins".to_string(),
            CanonicalValue::Array(self.pins.iter().map(SiblingPin::canonical_value).collect()),
        );
        CanonicalValue::Map(map)
    }

    /// Deterministic content hash over the canonical encoding.
    #[must_use]
    pub fn content_hash(&self) -> [u8; 32] {
        hash_bytes(&deterministic_serde::encode_value(&self.canonical_value()))
    }

    /// Serialize to pretty JSON (the `sibling_status.sh --json` payload).
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("SiblingHealthReport serialization is infallible")
    }
}

// --------------------------------------------------------------------------- //
// Pin-update round-trip + audit ledger
// --------------------------------------------------------------------------- //

/// A requested pin advance for one sibling, carrying the integration-smoke
/// outcome that gates whether the advance is committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinUpdateRequest {
    pub repo: SiblingRepo,
    pub prior_sha: String,
    pub new_sha: String,
    pub smoke_passed: bool,
    pub timestamp_utc: String,
    pub smoke_failure_reason: Option<String>,
}

/// One append-only entry in the pin audit ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinAuditEntry {
    pub repo: SiblingRepo,
    pub prior_sha: String,
    pub new_sha: String,
    pub smoke_passed: bool,
    pub committed: bool,
    pub timestamp_utc: String,
    pub note: String,
}

impl PinAuditEntry {
    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("repo".to_string(), CanonicalValue::str(self.repo.slug()));
        map.insert(
            "prior_sha".to_string(),
            CanonicalValue::str(self.prior_sha.clone()),
        );
        map.insert(
            "new_sha".to_string(),
            CanonicalValue::str(self.new_sha.clone()),
        );
        map.insert(
            "smoke_passed".to_string(),
            CanonicalValue::Bool(self.smoke_passed),
        );
        map.insert(
            "committed".to_string(),
            CanonicalValue::Bool(self.committed),
        );
        map.insert(
            "timestamp_utc".to_string(),
            CanonicalValue::str(self.timestamp_utc.clone()),
        );
        map.insert("note".to_string(), CanonicalValue::str(self.note.clone()));
        CanonicalValue::Map(map)
    }
}

/// Result of applying a [`PinUpdateRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinUpdateOutcome {
    pub repo: SiblingRepo,
    /// `true` iff the new SHA was committed (smoke passed).
    pub committed: bool,
    /// The SHA that is now in effect: the new SHA when committed, else the
    /// prior SHA (the pin *holds* — the safety property).
    pub effective_sha: String,
    /// Index of the recorded entry in the ledger.
    pub audit_index: usize,
}

/// Append-only ledger of every attempted pin update, the source of the
/// pin-history shown in the dashboard.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinAuditLedger {
    pub entries: Vec<PinAuditEntry>,
}

impl PinAuditLedger {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Apply a pin update.
    ///
    /// Invariant (the M.4 contract): the prior pin is *always* recorded in the
    /// ledger, and the new SHA is committed **only** when `smoke_passed` is
    /// true. On failure the effective SHA stays at `prior_sha` so the pin holds
    /// at the last-passed state.
    pub fn apply_update(&mut self, req: &PinUpdateRequest) -> Result<PinUpdateOutcome, PinError> {
        if !is_valid_sha(&req.prior_sha) {
            return Err(PinError::InvalidSha {
                repo: req.repo,
                field: "prior_sha",
                value: req.prior_sha.clone(),
            });
        }
        if !is_valid_sha(&req.new_sha) {
            return Err(PinError::InvalidSha {
                repo: req.repo,
                field: "new_sha",
                value: req.new_sha.clone(),
            });
        }
        if req.timestamp_utc.trim().is_empty() {
            return Err(PinError::EmptyUpdatedDate { repo: req.repo });
        }

        let committed = req.smoke_passed;
        let note = if committed {
            format!(
                "smoke passed; pin advanced {} -> {}",
                short_sha(&req.prior_sha),
                short_sha(&req.new_sha)
            )
        } else {
            let reason = req
                .smoke_failure_reason
                .clone()
                .unwrap_or_else(|| "unspecified smoke failure".to_string());
            format!(
                "smoke FAILED ({reason}); pin held at {} (safety property)",
                short_sha(&req.prior_sha)
            )
        };

        let entry = PinAuditEntry {
            repo: req.repo,
            prior_sha: req.prior_sha.clone(),
            new_sha: req.new_sha.clone(),
            smoke_passed: req.smoke_passed,
            committed,
            timestamp_utc: req.timestamp_utc.clone(),
            note,
        };
        let audit_index = self.entries.len();
        let effective_sha = if committed {
            req.new_sha.clone()
        } else {
            req.prior_sha.clone()
        };
        self.entries.push(entry);

        Ok(PinUpdateOutcome {
            repo: req.repo,
            committed,
            effective_sha,
            audit_index,
        })
    }

    /// All entries for a given sibling, in ledger order.
    #[must_use]
    pub fn entries_for(&self, repo: SiblingRepo) -> Vec<&PinAuditEntry> {
        self.entries.iter().filter(|e| e.repo == repo).collect()
    }

    /// Number of committed (successful) pin advances for a sibling.
    #[must_use]
    pub fn commit_count(&self, repo: SiblingRepo) -> usize {
        self.entries
            .iter()
            .filter(|e| e.repo == repo && e.committed)
            .count()
    }

    /// Deterministic content hash over the full ledger.
    #[must_use]
    pub fn content_hash(&self) -> [u8; 32] {
        let value = CanonicalValue::Array(
            self.entries
                .iter()
                .map(PinAuditEntry::canonical_value)
                .collect(),
        );
        hash_bytes(&deterministic_serde::encode_value(&value))
    }
}

// --------------------------------------------------------------------------- //
// Structured logging (bd-cixqu.45 discipline)
// --------------------------------------------------------------------------- //

/// Structured log event mirroring the shape used by the benchmark gate so the
/// status/update scripts and Rust core emit the same evidence narrative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiblingLogEvent {
    pub component: String,
    pub event: String,
    pub repo: String,
    pub outcome: String,
    pub detail: Option<String>,
}

impl SiblingLogEvent {
    /// Build the log event describing a completed pin-update outcome.
    #[must_use]
    pub fn for_pin_update(outcome: &PinUpdateOutcome, note: &str) -> Self {
        Self {
            component: COMPONENT.to_string(),
            event: "pin_update".to_string(),
            repo: outcome.repo.slug().to_string(),
            outcome: if outcome.committed {
                "committed".to_string()
            } else {
                "held".to_string()
            },
            detail: Some(note.to_string()),
        }
    }
}

// --------------------------------------------------------------------------- //
// frankentui dashboard view model
// --------------------------------------------------------------------------- //

/// One row of the "sibling-repo health" dashboard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiblingHealthPanelRow {
    pub repo: String,
    pub short_sha: String,
    pub verdict: String,
    pub last_passed: String,
    pub last_failed_reason: String,
    pub pin_advances: usize,
}

/// Self-contained view model for the frankentui "sibling-repo health" panel.
///
/// Kept out of `frankentui_adapter.rs` deliberately: the adapter owns the
/// `FrankentuiViewPayload` enum and is independently in-flight. Wiring a
/// `FrankentuiViewPayload::SiblingRepoHealth(SiblingRepoHealthDashboard)`
/// variant is a one-line follow-up once that file settles; the data + render
/// model below is complete and tested here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiblingRepoHealthDashboard {
    pub title: String,
    pub generated_utc: String,
    pub rows: Vec<SiblingHealthPanelRow>,
    pub healthy: bool,
}

impl SiblingRepoHealthDashboard {
    /// Build the dashboard from a health report and the pin-update ledger
    /// (for the per-sibling pin-history count).
    #[must_use]
    pub fn from_report(report: &SiblingHealthReport, ledger: &PinAuditLedger) -> Self {
        let rows = report
            .pins
            .iter()
            .map(|pin| SiblingHealthPanelRow {
                repo: pin.repo.slug().to_string(),
                short_sha: short_sha(&pin.pinned_sha),
                verdict: pin.verdict.as_str().to_string(),
                last_passed: pin
                    .last_passed_utc
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
                last_failed_reason: pin
                    .last_failed_reason
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
                pin_advances: ledger.commit_count(pin.repo),
            })
            .collect();
        Self {
            title: "Sibling-repo health".to_string(),
            generated_utc: report.generated_utc.clone(),
            rows,
            healthy: report.is_healthy(),
        }
    }

    /// Render the panel as a deterministic aligned text table.
    #[must_use]
    pub fn render_plain(&self) -> String {
        let headers = [
            "REPO",
            "SHA",
            "VERDICT",
            "LAST PASSED",
            "ADVANCES",
            "FAILURE",
        ];
        let mut widths = headers.map(str::len);
        for row in &self.rows {
            let cells = [
                row.repo.len(),
                row.short_sha.len(),
                row.verdict.len(),
                row.last_passed.len(),
                row.pin_advances.to_string().len(),
                row.last_failed_reason.len(),
            ];
            for (w, c) in widths.iter_mut().zip(cells) {
                *w = (*w).max(c);
            }
        }

        let mut out = String::new();
        out.push_str(&self.title);
        out.push_str(&format!(
            " ({}) — {}\n",
            self.generated_utc,
            if self.healthy { "HEALTHY" } else { "DEGRADED" }
        ));
        let fmt_row = |cells: [&str; 6]| -> String {
            let mut line = String::new();
            for (i, cell) in cells.iter().enumerate() {
                if i > 0 {
                    line.push_str("  ");
                }
                line.push_str(&format!("{cell:<width$}", width = widths[i]));
            }
            // Trim trailing padding for a stable golden.
            line.trim_end().to_string()
        };
        out.push_str(&fmt_row(headers));
        out.push('\n');
        for row in &self.rows {
            let advances = row.pin_advances.to_string();
            out.push_str(&fmt_row([
                row.repo.as_str(),
                row.short_sha.as_str(),
                row.verdict.as_str(),
                row.last_passed.as_str(),
                advances.as_str(),
                row.last_failed_reason.as_str(),
            ]));
            out.push('\n');
        }
        out
    }

    /// Deterministic content hash over the dashboard view model.
    #[must_use]
    pub fn content_hash(&self) -> [u8; 32] {
        hash_bytes(self.render_plain().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA_A: &str = "094b59c859611f7f804fac79d185538d6e7aa171";
    const SHA_B: &str = "33ad1c57d545292242e41a477c8278c70ed7e0d6";

    fn passing_pin(repo: SiblingRepo) -> SiblingPin {
        SiblingPin::new(
            repo,
            SHA_A,
            "2026-05-21",
            SiblingVerdict::Passed,
            Some("2026-05-21T00:00:00Z".to_string()),
            None,
        )
        .expect("valid pin")
    }

    #[test]
    fn sibling_repo_slug_roundtrips_for_all() {
        for repo in SiblingRepo::all() {
            assert_eq!(SiblingRepo::from_slug(repo.slug()), Some(repo));
        }
    }

    #[test]
    fn sibling_repo_all_has_six_pinned_siblings() {
        assert_eq!(SiblingRepo::all().len(), 6);
    }

    #[test]
    fn sibling_repo_from_slug_rejects_unknown() {
        assert_eq!(SiblingRepo::from_slug("not_a_sibling"), None);
        assert_eq!(SiblingRepo::from_slug(""), None);
    }

    #[test]
    fn sibling_repo_display_matches_slug() {
        assert_eq!(SiblingRepo::SqlmodelRust.to_string(), "sqlmodel_rust");
    }

    #[test]
    fn sibling_verdict_tokens_and_blocking() {
        assert_eq!(SiblingVerdict::Passed.as_str(), "pass");
        assert_eq!(SiblingVerdict::Skipped.as_str(), "skip");
        assert_eq!(SiblingVerdict::Failed.as_str(), "fail");
        assert!(SiblingVerdict::Failed.is_blocking_failure());
        assert!(!SiblingVerdict::Passed.is_blocking_failure());
        assert!(!SiblingVerdict::Skipped.is_blocking_failure());
    }

    #[test]
    fn is_valid_sha_accepts_boundary_lengths() {
        assert!(is_valid_sha("a1b2c3d")); // 7 (min)
        assert!(is_valid_sha(SHA_A)); // 40 (max)
        assert!(is_valid_sha("0123456789abcdef0123")); // 20 mid
    }

    #[test]
    fn is_valid_sha_rejects_off_boundaries_and_nonhex() {
        assert!(!is_valid_sha("a1b2c3")); // 6 (too short)
        assert!(!is_valid_sha(&"a".repeat(41))); // 41 (too long)
        assert!(!is_valid_sha("g1b2c3d")); // non-hex
        assert!(!is_valid_sha("A1B2C3D")); // uppercase rejected
        assert!(!is_valid_sha("")); // empty
    }

    #[test]
    fn short_sha_takes_seven() {
        assert_eq!(short_sha(SHA_A), "094b59c");
        assert_eq!(short_sha("abc"), "abc");
    }

    #[test]
    fn sibling_pin_new_validates_sha() {
        let err = SiblingPin::new(
            SiblingRepo::Frankentui,
            "xyz",
            "2026-05-21",
            SiblingVerdict::Passed,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PinError::InvalidSha {
                field: "pinned_sha",
                ..
            }
        ));
    }

    #[test]
    fn sibling_pin_new_rejects_empty_date() {
        let err = SiblingPin::new(
            SiblingRepo::Frankentui,
            SHA_A,
            "   ",
            SiblingVerdict::Passed,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, PinError::EmptyUpdatedDate { .. }));
    }

    #[test]
    fn sibling_pin_content_hash_is_stable() {
        let a = passing_pin(SiblingRepo::Frankentui);
        let b = passing_pin(SiblingRepo::Frankentui);
        assert_eq!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn sibling_pin_content_hash_changes_with_verdict() {
        let pass = passing_pin(SiblingRepo::Frankentui);
        let mut fail = pass.clone();
        fail.verdict = SiblingVerdict::Failed;
        assert_ne!(pass.content_hash(), fail.content_hash());
    }

    #[test]
    fn sibling_pin_serde_roundtrip() {
        let pin = passing_pin(SiblingRepo::Asupersync);
        let json = serde_json::to_string(&pin).unwrap();
        let back: SiblingPin = serde_json::from_str(&json).unwrap();
        assert_eq!(pin, back);
    }

    #[test]
    fn health_report_counts_verdicts() {
        let pins = vec![
            passing_pin(SiblingRepo::Asupersync),
            SiblingPin::new(
                SiblingRepo::Frankentui,
                SHA_B,
                "2026-05-21",
                SiblingVerdict::Failed,
                None,
                Some("smoke failed".to_string()),
            )
            .unwrap(),
            SiblingPin::new(
                SiblingRepo::Frankenpandas,
                SHA_A,
                "2026-05-21",
                SiblingVerdict::Skipped,
                None,
                None,
            )
            .unwrap(),
        ];
        let report = SiblingHealthReport::from_pins("2026-05-24", pins);
        assert_eq!(report.total, 3);
        assert_eq!(report.passed, 1);
        assert_eq!(report.failed, 1);
        assert_eq!(report.skipped, 1);
        assert!(!report.is_healthy());
    }

    #[test]
    fn health_report_sorts_pins_for_determinism() {
        let unsorted = vec![
            passing_pin(SiblingRepo::Frankenpandas),
            passing_pin(SiblingRepo::Asupersync),
        ];
        let report = SiblingHealthReport::from_pins("2026-05-24", unsorted);
        assert_eq!(report.pins[0].repo, SiblingRepo::Asupersync);
        assert_eq!(report.pins[1].repo, SiblingRepo::Frankenpandas);
    }

    #[test]
    fn health_report_hash_order_independent() {
        let a = SiblingHealthReport::from_pins(
            "2026-05-24",
            vec![
                passing_pin(SiblingRepo::Asupersync),
                passing_pin(SiblingRepo::Frankentui),
            ],
        );
        let b = SiblingHealthReport::from_pins(
            "2026-05-24",
            vec![
                passing_pin(SiblingRepo::Frankentui),
                passing_pin(SiblingRepo::Asupersync),
            ],
        );
        assert_eq!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn health_report_pin_for_lookup() {
        let report = SiblingHealthReport::from_pins(
            "2026-05-24",
            vec![passing_pin(SiblingRepo::FastapiRust)],
        );
        assert!(report.pin_for(SiblingRepo::FastapiRust).is_some());
        assert!(report.pin_for(SiblingRepo::Asupersync).is_none());
    }

    #[test]
    fn health_report_json_has_schema_version() {
        let report = SiblingHealthReport::from_pins(
            "2026-05-24",
            vec![passing_pin(SiblingRepo::Frankentui)],
        );
        let json = report.to_json();
        assert!(json.contains(SCHEMA_VERSION));
        let back: SiblingHealthReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn pin_update_commits_on_smoke_pass() {
        let mut ledger = PinAuditLedger::new();
        let outcome = ledger
            .apply_update(&PinUpdateRequest {
                repo: SiblingRepo::Frankentui,
                prior_sha: SHA_A.to_string(),
                new_sha: SHA_B.to_string(),
                smoke_passed: true,
                timestamp_utc: "2026-05-24T00:00:00Z".to_string(),
                smoke_failure_reason: None,
            })
            .unwrap();
        assert!(outcome.committed);
        assert_eq!(outcome.effective_sha, SHA_B);
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger.commit_count(SiblingRepo::Frankentui), 1);
    }

    #[test]
    fn pin_update_holds_on_smoke_fail() {
        let mut ledger = PinAuditLedger::new();
        let outcome = ledger
            .apply_update(&PinUpdateRequest {
                repo: SiblingRepo::Frankentui,
                prior_sha: SHA_A.to_string(),
                new_sha: SHA_B.to_string(),
                smoke_passed: false,
                timestamp_utc: "2026-05-24T00:00:00Z".to_string(),
                smoke_failure_reason: Some("type error in adapter".to_string()),
            })
            .unwrap();
        assert!(!outcome.committed);
        // The pin HOLDS at the prior SHA — the safety property.
        assert_eq!(outcome.effective_sha, SHA_A);
        // But the attempt is still recorded.
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger.commit_count(SiblingRepo::Frankentui), 0);
        assert!(ledger.entries[0].note.contains("held"));
    }

    #[test]
    fn pin_update_rejects_invalid_prior_and_new() {
        let mut ledger = PinAuditLedger::new();
        let bad_prior = ledger.apply_update(&PinUpdateRequest {
            repo: SiblingRepo::Frankentui,
            prior_sha: "zzz".to_string(),
            new_sha: SHA_B.to_string(),
            smoke_passed: true,
            timestamp_utc: "2026-05-24".to_string(),
            smoke_failure_reason: None,
        });
        assert!(matches!(
            bad_prior,
            Err(PinError::InvalidSha {
                field: "prior_sha",
                ..
            })
        ));
        let bad_new = ledger.apply_update(&PinUpdateRequest {
            repo: SiblingRepo::Frankentui,
            prior_sha: SHA_A.to_string(),
            new_sha: "zzz".to_string(),
            smoke_passed: true,
            timestamp_utc: "2026-05-24".to_string(),
            smoke_failure_reason: None,
        });
        assert!(matches!(
            bad_new,
            Err(PinError::InvalidSha {
                field: "new_sha",
                ..
            })
        ));
        // No entries recorded on validation failure.
        assert!(ledger.is_empty());
    }

    #[test]
    fn pin_update_rejects_empty_timestamp() {
        let mut ledger = PinAuditLedger::new();
        let err = ledger.apply_update(&PinUpdateRequest {
            repo: SiblingRepo::Frankentui,
            prior_sha: SHA_A.to_string(),
            new_sha: SHA_B.to_string(),
            smoke_passed: true,
            timestamp_utc: "".to_string(),
            smoke_failure_reason: None,
        });
        assert!(matches!(err, Err(PinError::EmptyUpdatedDate { .. })));
    }

    #[test]
    fn ledger_accumulates_and_filters_by_repo() {
        let mut ledger = PinAuditLedger::new();
        for (repo, ok) in [
            (SiblingRepo::Frankentui, true),
            (SiblingRepo::Frankentui, false),
            (SiblingRepo::Asupersync, true),
        ] {
            ledger
                .apply_update(&PinUpdateRequest {
                    repo,
                    prior_sha: SHA_A.to_string(),
                    new_sha: SHA_B.to_string(),
                    smoke_passed: ok,
                    timestamp_utc: "2026-05-24".to_string(),
                    smoke_failure_reason: None,
                })
                .unwrap();
        }
        assert_eq!(ledger.len(), 3);
        assert_eq!(ledger.entries_for(SiblingRepo::Frankentui).len(), 2);
        assert_eq!(ledger.commit_count(SiblingRepo::Frankentui), 1);
        assert_eq!(ledger.commit_count(SiblingRepo::Asupersync), 1);
    }

    #[test]
    fn ledger_content_hash_is_deterministic() {
        let mut a = PinAuditLedger::new();
        let mut b = PinAuditLedger::new();
        for ledger in [&mut a, &mut b] {
            ledger
                .apply_update(&PinUpdateRequest {
                    repo: SiblingRepo::Frankentui,
                    prior_sha: SHA_A.to_string(),
                    new_sha: SHA_B.to_string(),
                    smoke_passed: true,
                    timestamp_utc: "2026-05-24".to_string(),
                    smoke_failure_reason: None,
                })
                .unwrap();
        }
        assert_eq!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn log_event_reflects_commit_and_hold() {
        let mut ledger = PinAuditLedger::new();
        let committed = ledger
            .apply_update(&PinUpdateRequest {
                repo: SiblingRepo::Frankentui,
                prior_sha: SHA_A.to_string(),
                new_sha: SHA_B.to_string(),
                smoke_passed: true,
                timestamp_utc: "2026-05-24".to_string(),
                smoke_failure_reason: None,
            })
            .unwrap();
        let ev = SiblingLogEvent::for_pin_update(&committed, "n");
        assert_eq!(ev.outcome, "committed");
        assert_eq!(ev.component, COMPONENT);

        let held = ledger
            .apply_update(&PinUpdateRequest {
                repo: SiblingRepo::Frankentui,
                prior_sha: SHA_A.to_string(),
                new_sha: SHA_B.to_string(),
                smoke_passed: false,
                timestamp_utc: "2026-05-24".to_string(),
                smoke_failure_reason: None,
            })
            .unwrap();
        assert_eq!(SiblingLogEvent::for_pin_update(&held, "n").outcome, "held");
    }

    #[test]
    fn dashboard_row_count_matches_report() {
        let report = SiblingHealthReport::from_pins(
            "2026-05-24",
            SiblingRepo::all().into_iter().map(passing_pin).collect(),
        );
        let dash = SiblingRepoHealthDashboard::from_report(&report, &PinAuditLedger::new());
        assert_eq!(dash.rows.len(), 6);
        assert!(dash.healthy);
    }

    #[test]
    fn dashboard_render_is_deterministic_and_has_header() {
        let report = SiblingHealthReport::from_pins(
            "2026-05-24",
            vec![passing_pin(SiblingRepo::Frankentui)],
        );
        let dash = SiblingRepoHealthDashboard::from_report(&report, &PinAuditLedger::new());
        let r1 = dash.render_plain();
        let r2 = dash.render_plain();
        assert_eq!(r1, r2);
        assert!(r1.contains("Sibling-repo health"));
        assert!(r1.contains("REPO"));
        assert!(r1.contains("frankentui"));
        assert!(r1.contains("HEALTHY"));
    }

    #[test]
    fn dashboard_reflects_pin_advances_from_ledger() {
        let mut ledger = PinAuditLedger::new();
        ledger
            .apply_update(&PinUpdateRequest {
                repo: SiblingRepo::Frankentui,
                prior_sha: SHA_A.to_string(),
                new_sha: SHA_B.to_string(),
                smoke_passed: true,
                timestamp_utc: "2026-05-24".to_string(),
                smoke_failure_reason: None,
            })
            .unwrap();
        let report = SiblingHealthReport::from_pins(
            "2026-05-24",
            vec![passing_pin(SiblingRepo::Frankentui)],
        );
        let dash = SiblingRepoHealthDashboard::from_report(&report, &ledger);
        assert_eq!(dash.rows[0].pin_advances, 1);
    }

    #[test]
    fn dashboard_marks_degraded_on_failure() {
        let report = SiblingHealthReport::from_pins(
            "2026-05-24",
            vec![
                SiblingPin::new(
                    SiblingRepo::Frankentui,
                    SHA_A,
                    "2026-05-21",
                    SiblingVerdict::Failed,
                    None,
                    Some("boom".to_string()),
                )
                .unwrap(),
            ],
        );
        let dash = SiblingRepoHealthDashboard::from_report(&report, &PinAuditLedger::new());
        assert!(!dash.healthy);
        assert!(dash.render_plain().contains("DEGRADED"));
        assert!(dash.render_plain().contains("boom"));
    }
}
