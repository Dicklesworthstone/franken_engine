//! Proof-bundle verification status panel for the frankentui operator console.
//!
//! Track Y, bead `bd-cixqu.25.4` (Y.4 operator surface). This is an
//! **operator-facing only** (not a public downstream-consumer) data contract: a
//! per-release verification history for the third-party-verifiable proof bundles
//! (`scripts/export_proof_bundle.sh` → `proof_bundle.tar.gz`).
//!
//! It mirrors the [`crate::shadow_handoff_contracts`] panel pattern (plain serde
//! data contracts, advisory-only) and is fed from the real output of the
//! operator wrapper [`runbooks/scripts/verify_proof_bundle.sh`] — its
//! `operator_verdict.json` (schema
//! `franken-engine.proof-bundle-operator-verdict.v1`) deserializes directly into
//! a [`ProofBundleVerificationRecord`] via
//! [`ProofBundleVerificationRecord::from_operator_verdict_json`], so the panel
//! reflects genuine verification runs rather than authored status.
//!
//! The two outcome dimensions are kept distinct on purpose (see the Y.4 runbook,
//! `docs/PROOF_BUNDLE_VERIFICATION.md`): a [`VersionStatus`] drift is an operator
//! toolchain concern (the recheck digest is version-independent and still holds),
//! whereas a [`VerificationClassification::ProofRegression`] is a content
//! integrity failure that must be escalated.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::security_epoch::SecurityEpoch;

/// Schema version of the proof-bundle status panel contract.
pub const PROOF_BUNDLE_STATUS_PANEL_VERSION: &str = "1.0.0";

/// Operator verdict schema the wrapper emits and this panel ingests. Pinned to
/// `runbooks/scripts/verify_proof_bundle.sh`'s `OPERATOR_VERDICT_SCHEMA`.
pub const OPERATOR_VERDICT_SCHEMA: &str = "franken-engine.proof-bundle-operator-verdict.v1";

/// Errors surfaced while constructing or ingesting panel records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofBundlePanelError {
    /// A required field was empty.
    EmptyField { field: &'static str },
    /// The operator verdict JSON could not be parsed.
    MalformedVerdict { detail: String },
    /// The verdict carried an unexpected schema version.
    SchemaMismatch { found: String },
}

impl std::fmt::Display for ProofBundlePanelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyField { field } => write!(f, "proof-bundle panel: empty field {field}"),
            Self::MalformedVerdict { detail } => {
                write!(
                    f,
                    "proof-bundle panel: malformed operator verdict: {detail}"
                )
            }
            Self::SchemaMismatch { found } => {
                write!(f, "proof-bundle panel: unexpected verdict schema {found:?}")
            }
        }
    }
}

impl std::error::Error for ProofBundlePanelError {}

/// Operator classification of a single verification run. Mirrors the wrapper's
/// `classification` field (`verify_proof_bundle.sh`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationClassification {
    /// Recheck digest matched the trust anchor; toolchain aligned or absent.
    Verified,
    /// Recheck holds, but the operator toolchain drifts from the bundle pin.
    VersionDrift,
    /// Recheck digest did not reproduce the trust anchor (content integrity).
    ProofRegression,
    /// A wrapper/environment error prevented a determination.
    Error,
}

impl VerificationClassification {
    /// Parse the snake_case string the wrapper writes.
    pub fn parse(value: &str) -> Self {
        match value {
            "verified" => Self::Verified,
            "version_drift" => Self::VersionDrift,
            "proof_regression" => Self::ProofRegression,
            _ => Self::Error,
        }
    }

    /// Only [`Verified`](Self::Verified) licenses relying on the release.
    pub fn is_trusted(self) -> bool {
        matches!(self, Self::Verified)
    }

    /// A proof regression is the only content-integrity failure (escalate).
    pub fn is_regression(self) -> bool {
        matches!(self, Self::ProofRegression)
    }

    /// The operator action this classification recommends.
    pub fn recommended_action(self) -> &'static str {
        match self {
            Self::Verified => "Rely on the release under its stated inputs.",
            Self::VersionDrift => {
                "Update the local proof-assistant toolchain to the bundle pin; \
                 the recheck digest is version-independent and still holds."
            }
            Self::ProofRegression => {
                "Escalate to FrankenEngine maintainers with the verdict JSON; \
                 do not treat the release as verified."
            }
            Self::Error => "Re-run verification; the wrapper hit an environment error.",
        }
    }
}

/// Proof-assistant toolchain alignment, orthogonal to the recheck verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionStatus {
    /// Installed proof-assistant version equals the bundle pin.
    Aligned,
    /// Installed version differs from the bundle pin.
    Drift,
    /// The bundle pin differs from an operator-asserted expected pin.
    ExpectedMismatch,
    /// No matching toolchain installed (informational; recheck is unaffected).
    Absent,
}

impl VersionStatus {
    /// Parse the snake_case string the wrapper writes.
    pub fn parse(value: &str) -> Self {
        match value {
            "aligned" => Self::Aligned,
            "drift" => Self::Drift,
            "expected_mismatch" => Self::ExpectedMismatch,
            _ => Self::Absent,
        }
    }

    /// Drift and expected-mismatch are the advisory toolchain states.
    pub fn is_drifted(self) -> bool {
        matches!(self, Self::Drift | Self::ExpectedMismatch)
    }
}

/// Aggregate health of the panel, derived from the latest record per release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PanelHealth {
    /// No verification records yet.
    Unknown,
    /// Every release's latest verification is `verified`.
    Healthy,
    /// No regressions, but at least one release's latest run drifted on toolchain.
    Drifting,
    /// At least one release's latest verification is a proof regression.
    Compromised,
}

/// One verification of one release's proof bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleVerificationRecord {
    /// Release identifier (tag, commit SHA, or operator-chosen label).
    pub release_id: String,
    /// Bundle file the run verified (basename of `proof_bundle.tar.gz`).
    pub bundle_source: String,
    /// Checker path used: `docker` (clean-room) or `local`.
    pub via: String,
    /// Operator classification of the run.
    pub classification: VerificationClassification,
    /// Proof-assistant toolchain alignment.
    pub version_status: VersionStatus,
    /// Number of proofs covered by the bundle.
    pub claim_count: u32,
    /// Recheck digest the checker recomputed (bare hex, may be empty on error).
    pub recomputed_digest: String,
    /// Trust-anchor digest the bundle declared (bare hex).
    pub expected_digest: String,
    /// Claim ids the checker flagged (tampered / not-proven / off-schema).
    pub failing_claims: Vec<String>,
    /// Security epoch at which the operator recorded this verification.
    pub verified_at: SecurityEpoch,
}

impl ProofBundleVerificationRecord {
    /// Construct a record, validating non-empty identifiers.
    pub fn new(
        release_id: impl Into<String>,
        bundle_source: impl Into<String>,
        via: impl Into<String>,
        classification: VerificationClassification,
        version_status: VersionStatus,
        claim_count: u32,
        verified_at: SecurityEpoch,
    ) -> Result<Self, ProofBundlePanelError> {
        let release_id = release_id.into();
        let bundle_source = bundle_source.into();
        if release_id.is_empty() {
            return Err(ProofBundlePanelError::EmptyField {
                field: "release_id",
            });
        }
        if bundle_source.is_empty() {
            return Err(ProofBundlePanelError::EmptyField {
                field: "bundle_source",
            });
        }
        Ok(Self {
            release_id,
            bundle_source,
            via: via.into(),
            classification,
            version_status,
            claim_count,
            recomputed_digest: String::new(),
            expected_digest: String::new(),
            failing_claims: Vec::new(),
            verified_at,
        })
    }

    /// Attach the recomputed + trust-anchor digests (builder style).
    #[must_use]
    pub fn with_digests(
        mut self,
        recomputed: impl Into<String>,
        expected: impl Into<String>,
    ) -> Self {
        self.recomputed_digest = recomputed.into();
        self.expected_digest = expected.into();
        self
    }

    /// Attach the failing-claim list (builder style).
    #[must_use]
    pub fn with_failing_claims(mut self, claims: Vec<String>) -> Self {
        self.failing_claims = claims;
        self
    }

    /// True iff the recomputed digest equals the trust anchor and both are set.
    pub fn digest_matches(&self) -> bool {
        !self.recomputed_digest.is_empty() && self.recomputed_digest == self.expected_digest
    }

    /// True iff this run licenses relying on the release.
    pub fn is_trusted(&self) -> bool {
        self.classification.is_trusted()
    }

    /// Ingest the operator wrapper's `operator_verdict.json`.
    ///
    /// `release_id` and `verified_at` are supplied by the operator (the verdict
    /// JSON describes a bundle, not a release tag, and carries a wall-clock
    /// timestamp the panel deliberately does not trust for ordering).
    pub fn from_operator_verdict_json(
        json: &str,
        release_id: impl Into<String>,
        verified_at: SecurityEpoch,
    ) -> Result<Self, ProofBundlePanelError> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|e| ProofBundlePanelError::MalformedVerdict {
                detail: e.to_string(),
            })?;

        if let Some(schema) = value.get("schema_version").and_then(|v| v.as_str())
            && schema != OPERATOR_VERDICT_SCHEMA
        {
            return Err(ProofBundlePanelError::SchemaMismatch {
                found: schema.to_string(),
            });
        }

        let classification = value
            .get("classification")
            .and_then(|v| v.as_str())
            .map(VerificationClassification::parse)
            .ok_or_else(|| ProofBundlePanelError::MalformedVerdict {
                detail: "missing classification".to_string(),
            })?;
        let version_status = value
            .get("version_status")
            .and_then(|v| v.as_str())
            .map(VersionStatus::parse)
            .unwrap_or(VersionStatus::Absent);
        let claim_count = value
            .get("claim_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0) as u32;
        let bundle_source = value
            .get("source")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let via = value
            .get("via")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let recomputed = value
            .get("recomputed_recheck_digest")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let expected = value
            .get("expected_recheck_digest")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let failing_claims = value
            .get("failing_claims")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        let mut record = Self::new(
            release_id,
            bundle_source,
            via,
            classification,
            version_status,
            claim_count,
            verified_at,
        )?;
        record.recomputed_digest = recomputed;
        record.expected_digest = expected;
        record.failing_claims = failing_claims;
        Ok(record)
    }
}

/// Operator-facing proof-bundle verification status panel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleStatusPanel {
    /// Panel title for the operator console.
    pub title: String,
    /// Schema version of this panel contract.
    pub panel_version: String,
    /// Verification history, append-only in operator-record order.
    pub history: Vec<ProofBundleVerificationRecord>,
}

impl Default for ProofBundleStatusPanel {
    fn default() -> Self {
        Self {
            title: "Proof Bundle Verification Status".to_string(),
            panel_version: PROOF_BUNDLE_STATUS_PANEL_VERSION.to_string(),
            history: Vec::new(),
        }
    }
}

impl ProofBundleStatusPanel {
    /// New panel with a custom title.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            ..Self::default()
        }
    }

    /// Append a verification record (builder style).
    #[must_use]
    pub fn with_record(mut self, record: ProofBundleVerificationRecord) -> Self {
        self.history.push(record);
        self
    }

    /// Append a verification record in place.
    pub fn record(&mut self, record: ProofBundleVerificationRecord) {
        self.history.push(record);
    }

    /// Most-recently recorded verification across all releases.
    pub fn latest(&self) -> Option<&ProofBundleVerificationRecord> {
        self.history.last()
    }

    /// Most-recently recorded verification for a specific release.
    pub fn latest_for_release(&self, release_id: &str) -> Option<&ProofBundleVerificationRecord> {
        self.history
            .iter()
            .rev()
            .find(|r| r.release_id == release_id)
    }

    /// Latest record per release, keyed by `release_id` (record-order wins).
    pub fn latest_per_release(&self) -> BTreeMap<&str, &ProofBundleVerificationRecord> {
        let mut map: BTreeMap<&str, &ProofBundleVerificationRecord> = BTreeMap::new();
        for record in &self.history {
            map.insert(record.release_id.as_str(), record);
        }
        map
    }

    /// Count of releases whose latest verification is `verified`.
    pub fn trusted_release_count(&self) -> usize {
        self.latest_per_release()
            .values()
            .filter(|r| r.is_trusted())
            .count()
    }

    /// Releases whose latest verification is a proof regression.
    pub fn regressed_releases(&self) -> Vec<&ProofBundleVerificationRecord> {
        self.latest_per_release()
            .into_values()
            .filter(|r| r.classification.is_regression())
            .collect()
    }

    /// Aggregate health derived from each release's latest verification.
    pub fn health(&self) -> PanelHealth {
        let latest = self.latest_per_release();
        if latest.is_empty() {
            return PanelHealth::Unknown;
        }
        let mut drifting = false;
        let mut all_verified = true;
        for record in latest.values() {
            match record.classification {
                VerificationClassification::ProofRegression => return PanelHealth::Compromised,
                VerificationClassification::VersionDrift => {
                    drifting = true;
                    all_verified = false;
                }
                VerificationClassification::Verified => {}
                VerificationClassification::Error => all_verified = false,
            }
        }
        if drifting {
            PanelHealth::Drifting
        } else if all_verified {
            PanelHealth::Healthy
        } else {
            PanelHealth::Unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(n: u64) -> SecurityEpoch {
        SecurityEpoch::from_raw(n)
    }

    fn rec(
        release: &str,
        class: VerificationClassification,
        vstatus: VersionStatus,
        at: u64,
    ) -> ProofBundleVerificationRecord {
        ProofBundleVerificationRecord::new(
            release,
            "proof_bundle.tar.gz",
            "local",
            class,
            vstatus,
            3,
            epoch(at),
        )
        .expect("valid record")
    }

    #[test]
    fn classification_parse_roundtrip() {
        assert_eq!(
            VerificationClassification::parse("verified"),
            VerificationClassification::Verified
        );
        assert_eq!(
            VerificationClassification::parse("version_drift"),
            VerificationClassification::VersionDrift
        );
        assert_eq!(
            VerificationClassification::parse("proof_regression"),
            VerificationClassification::ProofRegression
        );
    }

    #[test]
    fn classification_unknown_maps_to_error() {
        assert_eq!(
            VerificationClassification::parse("nonsense"),
            VerificationClassification::Error
        );
    }

    #[test]
    fn only_verified_is_trusted() {
        assert!(VerificationClassification::Verified.is_trusted());
        assert!(!VerificationClassification::VersionDrift.is_trusted());
        assert!(!VerificationClassification::ProofRegression.is_trusted());
        assert!(!VerificationClassification::Error.is_trusted());
    }

    #[test]
    fn only_regression_is_regression() {
        assert!(VerificationClassification::ProofRegression.is_regression());
        assert!(!VerificationClassification::VersionDrift.is_regression());
        assert!(!VerificationClassification::Verified.is_regression());
    }

    #[test]
    fn recommended_actions_are_distinct() {
        let v = VerificationClassification::Verified.recommended_action();
        let d = VerificationClassification::VersionDrift.recommended_action();
        let r = VerificationClassification::ProofRegression.recommended_action();
        assert_ne!(v, d);
        assert_ne!(d, r);
        assert_ne!(v, r);
        assert!(r.contains("Escalate"));
        assert!(d.contains("Update"));
    }

    #[test]
    fn version_status_parse() {
        assert_eq!(VersionStatus::parse("aligned"), VersionStatus::Aligned);
        assert_eq!(VersionStatus::parse("drift"), VersionStatus::Drift);
        assert_eq!(
            VersionStatus::parse("expected_mismatch"),
            VersionStatus::ExpectedMismatch
        );
        assert_eq!(VersionStatus::parse("absent"), VersionStatus::Absent);
        assert_eq!(VersionStatus::parse("???"), VersionStatus::Absent);
    }

    #[test]
    fn version_status_drifted_predicate() {
        assert!(VersionStatus::Drift.is_drifted());
        assert!(VersionStatus::ExpectedMismatch.is_drifted());
        assert!(!VersionStatus::Aligned.is_drifted());
        assert!(!VersionStatus::Absent.is_drifted());
    }

    #[test]
    fn record_rejects_empty_release_id() {
        let err = ProofBundleVerificationRecord::new(
            "",
            "b.tar.gz",
            "local",
            VerificationClassification::Verified,
            VersionStatus::Aligned,
            1,
            epoch(1),
        )
        .unwrap_err();
        assert_eq!(
            err,
            ProofBundlePanelError::EmptyField {
                field: "release_id"
            }
        );
    }

    #[test]
    fn record_rejects_empty_bundle_source() {
        let err = ProofBundleVerificationRecord::new(
            "v1",
            "",
            "local",
            VerificationClassification::Verified,
            VersionStatus::Aligned,
            1,
            epoch(1),
        )
        .unwrap_err();
        assert_eq!(
            err,
            ProofBundlePanelError::EmptyField {
                field: "bundle_source"
            }
        );
    }

    #[test]
    fn digest_matches_only_when_equal_and_nonempty() {
        let matching = rec(
            "v1",
            VerificationClassification::Verified,
            VersionStatus::Aligned,
            1,
        )
        .with_digests("abc123", "abc123");
        assert!(matching.digest_matches());
        let mismatch = rec(
            "v1",
            VerificationClassification::ProofRegression,
            VersionStatus::Aligned,
            1,
        )
        .with_digests("abc123", "def456");
        assert!(!mismatch.digest_matches());
        let empty = rec(
            "v1",
            VerificationClassification::Error,
            VersionStatus::Absent,
            1,
        );
        assert!(!empty.digest_matches());
    }

    #[test]
    fn with_failing_claims_attaches() {
        let r = rec(
            "v1",
            VerificationClassification::ProofRegression,
            VersionStatus::Aligned,
            1,
        )
        .with_failing_claims(vec!["FE-CLAIM-019".to_string()]);
        assert_eq!(r.failing_claims, vec!["FE-CLAIM-019".to_string()]);
    }

    #[test]
    fn empty_panel_is_unknown() {
        assert_eq!(
            ProofBundleStatusPanel::default().health(),
            PanelHealth::Unknown
        );
    }

    #[test]
    fn panel_default_title_and_version() {
        let p = ProofBundleStatusPanel::default();
        assert_eq!(p.title, "Proof Bundle Verification Status");
        assert_eq!(p.panel_version, PROOF_BUNDLE_STATUS_PANEL_VERSION);
    }

    #[test]
    fn all_verified_is_healthy() {
        let p = ProofBundleStatusPanel::default()
            .with_record(rec(
                "v1",
                VerificationClassification::Verified,
                VersionStatus::Aligned,
                1,
            ))
            .with_record(rec(
                "v2",
                VerificationClassification::Verified,
                VersionStatus::Absent,
                2,
            ));
        assert_eq!(p.health(), PanelHealth::Healthy);
        assert_eq!(p.trusted_release_count(), 2);
    }

    #[test]
    fn any_drift_no_regression_is_drifting() {
        let p = ProofBundleStatusPanel::default()
            .with_record(rec(
                "v1",
                VerificationClassification::Verified,
                VersionStatus::Aligned,
                1,
            ))
            .with_record(rec(
                "v2",
                VerificationClassification::VersionDrift,
                VersionStatus::Drift,
                2,
            ));
        assert_eq!(p.health(), PanelHealth::Drifting);
    }

    #[test]
    fn any_regression_is_compromised() {
        let p = ProofBundleStatusPanel::default()
            .with_record(rec(
                "v1",
                VerificationClassification::Verified,
                VersionStatus::Aligned,
                1,
            ))
            .with_record(rec(
                "v2",
                VerificationClassification::VersionDrift,
                VersionStatus::Drift,
                2,
            ))
            .with_record(rec(
                "v3",
                VerificationClassification::ProofRegression,
                VersionStatus::Aligned,
                3,
            ));
        assert_eq!(p.health(), PanelHealth::Compromised);
        assert_eq!(p.regressed_releases().len(), 1);
    }

    #[test]
    fn latest_per_release_takes_newest_record() {
        // v1 first regressed, then a later run verified it: latest wins -> healthy.
        let p = ProofBundleStatusPanel::default()
            .with_record(rec(
                "v1",
                VerificationClassification::ProofRegression,
                VersionStatus::Aligned,
                1,
            ))
            .with_record(rec(
                "v1",
                VerificationClassification::Verified,
                VersionStatus::Aligned,
                2,
            ));
        assert_eq!(p.latest_per_release().len(), 1);
        assert_eq!(p.health(), PanelHealth::Healthy);
        assert_eq!(
            p.latest_for_release("v1").unwrap().classification,
            VerificationClassification::Verified
        );
    }

    #[test]
    fn latest_returns_last_recorded() {
        let p = ProofBundleStatusPanel::default()
            .with_record(rec(
                "v1",
                VerificationClassification::Verified,
                VersionStatus::Aligned,
                1,
            ))
            .with_record(rec(
                "v2",
                VerificationClassification::VersionDrift,
                VersionStatus::Drift,
                2,
            ));
        assert_eq!(p.latest().unwrap().release_id, "v2");
    }

    #[test]
    fn latest_for_unknown_release_is_none() {
        let p = ProofBundleStatusPanel::default().with_record(rec(
            "v1",
            VerificationClassification::Verified,
            VersionStatus::Aligned,
            1,
        ));
        assert!(p.latest_for_release("does-not-exist").is_none());
    }

    #[test]
    fn record_in_place_appends() {
        let mut p = ProofBundleStatusPanel::new("custom");
        assert_eq!(p.title, "custom");
        p.record(rec(
            "v1",
            VerificationClassification::Verified,
            VersionStatus::Aligned,
            1,
        ));
        assert_eq!(p.history.len(), 1);
    }

    #[test]
    fn ingest_verified_verdict_json() {
        let json = r#"{
          "schema_version": "franken-engine.proof-bundle-operator-verdict.v1",
          "classification": "verified",
          "version_status": "aligned",
          "claim_count": 3,
          "source": "proof_bundle.tar.gz",
          "via": "docker",
          "recomputed_recheck_digest": "aa11",
          "expected_recheck_digest": "aa11",
          "failing_claims": []
        }"#;
        let r = ProofBundleVerificationRecord::from_operator_verdict_json(json, "v1.0.0", epoch(7))
            .expect("parse");
        assert_eq!(r.classification, VerificationClassification::Verified);
        assert_eq!(r.version_status, VersionStatus::Aligned);
        assert_eq!(r.claim_count, 3);
        assert_eq!(r.via, "docker");
        assert!(r.digest_matches());
        assert!(r.is_trusted());
        assert_eq!(r.release_id, "v1.0.0");
        assert_eq!(r.verified_at, epoch(7));
    }

    #[test]
    fn ingest_regression_verdict_json_surfaces_failing_claims() {
        let json = r#"{
          "schema_version": "franken-engine.proof-bundle-operator-verdict.v1",
          "classification": "proof_regression",
          "version_status": "absent",
          "claim_count": 3,
          "source": "proof_bundle_tampered.tar.gz",
          "via": "local",
          "recomputed_recheck_digest": "bbbb",
          "expected_recheck_digest": "cccc",
          "failing_claims": ["FE-CLAIM-019"]
        }"#;
        let r = ProofBundleVerificationRecord::from_operator_verdict_json(json, "v1.0.0", epoch(8))
            .expect("parse");
        assert!(r.classification.is_regression());
        assert!(!r.digest_matches());
        assert_eq!(r.failing_claims, vec!["FE-CLAIM-019".to_string()]);
    }

    #[test]
    fn ingest_drift_verdict_json() {
        let json = r#"{
          "schema_version": "franken-engine.proof-bundle-operator-verdict.v1",
          "classification": "version_drift",
          "version_status": "drift",
          "claim_count": 2,
          "source": "proof_bundle.tar.gz",
          "via": "local",
          "recomputed_recheck_digest": "ee",
          "expected_recheck_digest": "ee",
          "failing_claims": []
        }"#;
        let r = ProofBundleVerificationRecord::from_operator_verdict_json(json, "v2.0.0", epoch(9))
            .expect("parse");
        assert_eq!(r.classification, VerificationClassification::VersionDrift);
        assert!(r.version_status.is_drifted());
        // Drift still reproduces the digest — content is intact.
        assert!(r.digest_matches());
    }

    #[test]
    fn ingest_rejects_malformed_json() {
        let err =
            ProofBundleVerificationRecord::from_operator_verdict_json("{not json", "v1", epoch(1))
                .unwrap_err();
        assert!(matches!(
            err,
            ProofBundlePanelError::MalformedVerdict { .. }
        ));
    }

    #[test]
    fn ingest_rejects_wrong_schema() {
        let json = r#"{"schema_version":"some.other.schema.v9","classification":"verified"}"#;
        let err = ProofBundleVerificationRecord::from_operator_verdict_json(json, "v1", epoch(1))
            .unwrap_err();
        assert!(matches!(err, ProofBundlePanelError::SchemaMismatch { .. }));
    }

    #[test]
    fn ingest_requires_classification() {
        let json = r#"{"schema_version":"franken-engine.proof-bundle-operator-verdict.v1"}"#;
        let err = ProofBundleVerificationRecord::from_operator_verdict_json(json, "v1", epoch(1))
            .unwrap_err();
        assert!(matches!(
            err,
            ProofBundlePanelError::MalformedVerdict { .. }
        ));
    }

    #[test]
    fn panel_serde_roundtrip() {
        let p = ProofBundleStatusPanel::default()
            .with_record(
                rec(
                    "v1",
                    VerificationClassification::Verified,
                    VersionStatus::Aligned,
                    1,
                )
                .with_digests("aa", "aa"),
            )
            .with_record(rec(
                "v2",
                VerificationClassification::ProofRegression,
                VersionStatus::Absent,
                2,
            ));
        let json = serde_json::to_string(&p).expect("serialize");
        let back: ProofBundleStatusPanel = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(p, back);
        assert_eq!(back.health(), PanelHealth::Compromised);
    }

    #[test]
    fn ingested_record_feeds_panel_health() {
        let verified = r#"{
          "schema_version": "franken-engine.proof-bundle-operator-verdict.v1",
          "classification": "verified", "version_status": "absent", "claim_count": 2,
          "source": "b.tar.gz", "via": "docker",
          "recomputed_recheck_digest": "dd", "expected_recheck_digest": "dd", "failing_claims": []
        }"#;
        let mut panel = ProofBundleStatusPanel::new("ops");
        panel.record(
            ProofBundleVerificationRecord::from_operator_verdict_json(verified, "v1.0.0", epoch(3))
                .unwrap(),
        );
        assert_eq!(panel.health(), PanelHealth::Healthy);
        assert_eq!(panel.trusted_release_count(), 1);
    }

    #[test]
    fn error_classification_is_unknown_health() {
        let p = ProofBundleStatusPanel::default().with_record(rec(
            "v1",
            VerificationClassification::Error,
            VersionStatus::Absent,
            1,
        ));
        assert_eq!(p.health(), PanelHealth::Unknown);
    }
}
