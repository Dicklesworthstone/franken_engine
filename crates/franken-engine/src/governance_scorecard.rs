//! Deterministic governance scorecard publication for Section 10.15 (`bd-12n5`).
//!
//! Publishes a unified governance view across:
//! - attested-receipt coverage
//! - privacy-budget health
//! - moonshot-governor decision behavior
//! - cross-repo conformance stability
//!
//! The publication artifact is deterministic, signed, and append-only recorded
//! in the governance audit ledger.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::dp_budget_accountant::BudgetAccountant;
use crate::portfolio_governor::governance_audit_ledger::{
    GovernanceActor, GovernanceAuditLedger, GovernanceDecisionType, GovernanceLedgerError,
    GovernanceLedgerInput, GovernanceRationale, GovernanceReport, ScorecardSnapshot,
};
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    Signature, SignatureError, SigningKey, VerificationKey, sign_preimage, verify_signature,
};
use crate::version_matrix_lane::MatrixHealthSummary;

pub const GOVERNANCE_SCORECARD_COMPONENT: &str = "governance_scorecard";
pub const GOVERNANCE_SCORECARD_SCHEMA_VERSION: &str = "franken-engine.governance-scorecard.v1";

const ERROR_INVALID_INPUT: &str = "FE-GOV-SCORE-3001";
const ERROR_SERIALIZATION: &str = "FE-GOV-SCORE-3002";
const ERROR_SIGNATURE: &str = "FE-GOV-SCORE-3003";
const ERROR_LEDGER: &str = "FE-GOV-SCORE-3004";
const ERROR_THRESHOLD: &str = "FE-GOV-SCORE-3005";
const ERROR_TREND_REGRESSION: &str = "FE-GOV-SCORE-3006";

const MILLION: u128 = 1_000_000;
const NS_PER_HOUR: u128 = 3_600_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceScorecardOutcome {
    Healthy,
    Warning,
    Critical,
}

impl GovernanceScorecardOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceScorecardThresholds {
    /// Target from plan: >= 95% high-impact receipts must have valid
    /// non-expired attestation bindings.
    pub min_attested_receipt_coverage_millionths: u64,
    /// Target from plan: zero budget overruns.
    pub max_privacy_overrun_incidents: u64,
    /// Operational threshold for epoch budget pressure.
    pub max_privacy_epoch_consumption_millionths: u64,
    /// Warn when projected exhaustion is within this lead time.
    pub warn_privacy_exhaustion_within_ns: Option<u64>,
    /// Operational governance threshold.
    pub max_moonshot_override_frequency_millionths: u64,
    /// Operational governance threshold.
    pub max_moonshot_kill_rate_millionths: u64,
    /// Optional operator threshold.
    pub max_moonshot_mean_time_to_decision_ns: Option<u64>,
    /// Cross-repo conformance release floor.
    pub min_conformance_pass_rate_millionths: u64,
    /// Universal version-matrix failures should normally be zero.
    pub max_universal_failures: u64,
    /// Version-specific failures can be non-zero but bounded.
    pub max_version_specific_failures: u64,
    /// Outstanding exemptions should be bounded.
    pub max_outstanding_exemptions: u64,
    /// If true, trend regression blocks publication.
    pub fail_on_trend_regression: bool,
}

impl Default for GovernanceScorecardThresholds {
    fn default() -> Self {
        Self {
            min_attested_receipt_coverage_millionths: 950_000,
            max_privacy_overrun_incidents: 0,
            max_privacy_epoch_consumption_millionths: 900_000,
            warn_privacy_exhaustion_within_ns: Some(24 * 3_600_000_000_000),
            max_moonshot_override_frequency_millionths: 200_000,
            max_moonshot_kill_rate_millionths: 250_000,
            max_moonshot_mean_time_to_decision_ns: Some(7 * 24 * 3_600_000_000_000),
            min_conformance_pass_rate_millionths: 950_000,
            max_universal_failures: 0,
            max_version_specific_failures: 5,
            max_outstanding_exemptions: 0,
            fail_on_trend_regression: false,
        }
    }
}

impl GovernanceScorecardThresholds {
    fn validate(&self) -> Result<(), GovernanceScorecardError> {
        if self.min_attested_receipt_coverage_millionths > 1_000_000 {
            return Err(GovernanceScorecardError::InvalidInput {
                field: "thresholds.min_attested_receipt_coverage_millionths".to_string(),
                detail: "must be <= 1_000_000".to_string(),
            });
        }
        if self.max_privacy_epoch_consumption_millionths > 1_000_000 {
            return Err(GovernanceScorecardError::InvalidInput {
                field: "thresholds.max_privacy_epoch_consumption_millionths".to_string(),
                detail: "must be <= 1_000_000".to_string(),
            });
        }
        if self.max_moonshot_override_frequency_millionths > 1_000_000 {
            return Err(GovernanceScorecardError::InvalidInput {
                field: "thresholds.max_moonshot_override_frequency_millionths".to_string(),
                detail: "must be <= 1_000_000".to_string(),
            });
        }
        if self.max_moonshot_kill_rate_millionths > 1_000_000 {
            return Err(GovernanceScorecardError::InvalidInput {
                field: "thresholds.max_moonshot_kill_rate_millionths".to_string(),
                detail: "must be <= 1_000_000".to_string(),
            });
        }
        if self.min_conformance_pass_rate_millionths > 1_000_000 {
            return Err(GovernanceScorecardError::InvalidInput {
                field: "thresholds.min_conformance_pass_rate_millionths".to_string(),
                detail: "must be <= 1_000_000".to_string(),
            });
        }
        if let Some(lead) = self.warn_privacy_exhaustion_within_ns
            && lead == 0
        {
            return Err(GovernanceScorecardError::InvalidInput {
                field: "thresholds.warn_privacy_exhaustion_within_ns".to_string(),
                detail: "must be > 0 when provided".to_string(),
            });
        }
        if let Some(max_decision_ns) = self.max_moonshot_mean_time_to_decision_ns
            && max_decision_ns == 0
        {
            return Err(GovernanceScorecardError::InvalidInput {
                field: "thresholds.max_moonshot_mean_time_to_decision_ns".to_string(),
                detail: "must be > 0 when provided".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedReceiptObservation {
    pub receipt_id: String,
    pub high_impact: bool,
    pub attestation_binding_valid: bool,
    pub timestamp_ns: u64,
}

impl AttestedReceiptObservation {
    fn validate(&self) -> Result<(), GovernanceScorecardError> {
        if self.receipt_id.trim().is_empty() {
            return Err(GovernanceScorecardError::InvalidInput {
                field: "attested_receipts[].receipt_id".to_string(),
                detail: "must not be empty".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetHealthInput {
    pub accountant: BudgetAccountant,
    pub overrun_incidents: u64,
    pub measurement_window_ns: u64,
    pub measurement_end_ns: u64,
}

impl PrivacyBudgetHealthInput {
    fn validate(&self) -> Result<(), GovernanceScorecardError> {
        if self.measurement_window_ns == 0 {
            return Err(GovernanceScorecardError::InvalidInput {
                field: "privacy_budget.measurement_window_ns".to_string(),
                detail: "must be > 0".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoonshotGovernorHealthInput {
    pub governance_report: GovernanceReport,
    pub active_moonshots: u64,
    pub paused_moonshots: u64,
    pub killed_moonshots: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossRepoConformanceInput {
    pub release_id: String,
    pub matrix_health: MatrixHealthSummary,
    pub failure_class_distribution: BTreeMap<String, u64>,
    pub outstanding_exemptions: u64,
}

impl CrossRepoConformanceInput {
    fn validate(&self) -> Result<(), GovernanceScorecardError> {
        if self.release_id.trim().is_empty() {
            return Err(GovernanceScorecardError::InvalidInput {
                field: "conformance.release_id".to_string(),
                detail: "must not be empty".to_string(),
            });
        }
        if self.matrix_health.passed_cells + self.matrix_health.failed_cells
            != self.matrix_health.total_cells
        {
            return Err(GovernanceScorecardError::InvalidInput {
                field: "conformance.matrix_health".to_string(),
                detail: "passed_cells + failed_cells must equal total_cells".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceScorecardTrendPoint {
    pub scorecard_id: String,
    pub generated_at_ns: u64,
    pub attested_receipt_coverage_millionths: u64,
    pub privacy_epoch_consumption_millionths: u64,
    pub moonshot_override_frequency_millionths: u64,
    pub conformance_pass_rate_millionths: u64,
    pub outcome: GovernanceScorecardOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceScorecardRequest {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub scorecard_run_id: String,
    pub generated_at_ns: u64,
    pub attested_receipts: Vec<AttestedReceiptObservation>,
    pub privacy_budget: PrivacyBudgetHealthInput,
    pub moonshot_governor: MoonshotGovernorHealthInput,
    pub conformance: CrossRepoConformanceInput,
    pub historical: Vec<GovernanceScorecardTrendPoint>,
    pub thresholds: Option<GovernanceScorecardThresholds>,
}

impl GovernanceScorecardRequest {
    fn validate(&self) -> Result<(), GovernanceScorecardError> {
        validate_non_empty(&self.trace_id, "trace_id")?;
        validate_non_empty(&self.decision_id, "decision_id")?;
        validate_non_empty(&self.policy_id, "policy_id")?;

        if self.generated_at_ns == 0 {
            return Err(GovernanceScorecardError::InvalidInput {
                field: "generated_at_ns".to_string(),
                detail: "must be > 0".to_string(),
            });
        }
        if self.attested_receipts.is_empty() {
            return Err(GovernanceScorecardError::InvalidInput {
                field: "attested_receipts".to_string(),
                detail: "must not be empty".to_string(),
            });
        }

        let mut seen = BTreeSet::new();
        for receipt in &self.attested_receipts {
            receipt.validate()?;
            if !seen.insert(receipt.receipt_id.clone()) {
                return Err(GovernanceScorecardError::InvalidInput {
                    field: "attested_receipts[].receipt_id".to_string(),
                    detail: format!("duplicate receipt_id `{}`", receipt.receipt_id),
                });
            }
        }

        let high_impact_count = self
            .attested_receipts
            .iter()
            .filter(|receipt| receipt.high_impact)
            .count();
        if high_impact_count == 0 {
            return Err(GovernanceScorecardError::InvalidInput {
                field: "attested_receipts".to_string(),
                detail: "must include at least one high-impact receipt".to_string(),
            });
        }

        self.privacy_budget.validate()?;
        self.conformance.validate()?;
        if let Some(thresholds) = &self.thresholds {
            thresholds.validate()?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedReceiptCoverageSummary {
    pub high_impact_total: u64,
    pub high_impact_with_valid_attestation: u64,
    pub high_impact_missing_or_invalid_attestation: u64,
    pub coverage_millionths: u64,
    pub threshold_pass: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetHealthSummary {
    pub epoch: SecurityEpoch,
    pub epoch_epsilon_budget_millionths: u64,
    pub epoch_epsilon_spent_millionths: u64,
    pub epoch_delta_budget_millionths: u64,
    pub epoch_delta_spent_millionths: u64,
    pub epoch_consumption_millionths: u64,
    pub lifetime_epsilon_remaining_millionths: u64,
    pub lifetime_delta_remaining_millionths: u64,
    pub estimated_remaining_operations: u64,
    pub epsilon_burn_rate_per_hour_millionths: u64,
    pub delta_burn_rate_per_hour_millionths: u64,
    pub projected_epsilon_exhaustion_ns: Option<u64>,
    pub projected_delta_exhaustion_ns: Option<u64>,
    pub overrun_incidents: u64,
    pub threshold_pass: bool,
    pub near_term_exhaustion_warning: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoonshotGovernorDecisionSummary {
    pub total_decisions: u64,
    pub override_count: u64,
    pub kill_count: u64,
    pub override_frequency_millionths: u64,
    pub kill_rate_millionths: u64,
    pub mean_time_to_decision_ns: Option<u64>,
    pub active_moonshots: u64,
    pub paused_moonshots: u64,
    pub killed_moonshots: u64,
    pub threshold_pass: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossRepoConformanceStabilitySummary {
    pub release_id: String,
    pub total_cells: u64,
    pub passed_cells: u64,
    pub failed_cells: u64,
    pub pass_rate_millionths: u64,
    pub universal_failures: u64,
    pub version_specific_failures: u64,
    pub outstanding_exemptions: u64,
    pub failure_class_distribution: BTreeMap<String, u64>,
    pub threshold_pass: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceScorecardEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub dimension: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceScorecardPublication {
    pub schema_version: String,
    pub scorecard_id: String,
    pub generated_at_ns: u64,
    pub outcome: GovernanceScorecardOutcome,
    pub thresholds: GovernanceScorecardThresholds,
    pub attested_receipt_coverage: AttestedReceiptCoverageSummary,
    pub privacy_budget_health: PrivacyBudgetHealthSummary,
    pub moonshot_governor: MoonshotGovernorDecisionSummary,
    pub cross_repo_conformance: CrossRepoConformanceStabilitySummary,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
    pub trend: Vec<GovernanceScorecardTrendPoint>,
    pub trend_regression_detected: bool,
    pub artifact_hash_hex: String,
    pub signature: Signature,
    pub signer_key: VerificationKey,
    pub ledger_sequence: u64,
    pub events: Vec<GovernanceScorecardEvent>,
}

impl GovernanceScorecardPublication {
    pub fn to_json_pretty(&self) -> Result<String, GovernanceScorecardError> {
        serde_json::to_string_pretty(self)
            .map_err(|err| GovernanceScorecardError::SerializationFailure(err.to_string()))
    }

    pub fn to_markdown_report(&self) -> String {
        let mut out = String::new();
        out.push_str("# Governance Scorecard\n\n");
        out.push_str(&format!("- Scorecard ID: `{}`\n", self.scorecard_id));
        out.push_str(&format!(
            "- Generated At (ns): `{}`\n",
            self.generated_at_ns
        ));
        out.push_str(&format!(
            "- Outcome: **{}**\n",
            self.outcome.as_str().to_uppercase()
        ));
        out.push_str(&format!("- Ledger Sequence: `{}`\n", self.ledger_sequence));
        out.push_str(&format!("- Artifact Hash: `{}`\n", self.artifact_hash_hex));
        out.push_str(&format!("- Signer Key: `{}`\n\n", self.signer_key.to_hex()));

        if !self.blockers.is_empty() {
            out.push_str("## Blockers\n\n");
            for blocker in &self.blockers {
                out.push_str(&format!("- {blocker}\n"));
            }
            out.push('\n');
        }

        if !self.warnings.is_empty() {
            out.push_str("## Warnings\n\n");
            for warning in &self.warnings {
                out.push_str(&format!("- {warning}\n"));
            }
            out.push('\n');
        }

        out.push_str("## Dimensions\n\n");
        out.push_str("| Dimension | Value | Threshold | Pass |\n");
        out.push_str("|---|---|---|---|\n");
        out.push_str(&format!(
            "| Attested receipt coverage | {} | >= {} | {} |\n",
            format_pct(self.attested_receipt_coverage.coverage_millionths),
            format_pct(self.thresholds.min_attested_receipt_coverage_millionths),
            pass_mark(self.attested_receipt_coverage.threshold_pass),
        ));
        out.push_str(&format!(
            "| Privacy epoch consumption | {} | <= {} | {} |\n",
            format_pct(self.privacy_budget_health.epoch_consumption_millionths),
            format_pct(self.thresholds.max_privacy_epoch_consumption_millionths),
            pass_mark(self.privacy_budget_health.threshold_pass),
        ));
        out.push_str(&format!(
            "| Moonshot override frequency | {} | <= {} | {} |\n",
            format_pct(self.moonshot_governor.override_frequency_millionths),
            format_pct(self.thresholds.max_moonshot_override_frequency_millionths),
            pass_mark(self.moonshot_governor.threshold_pass),
        ));
        out.push_str(&format!(
            "| Cross-repo conformance pass rate | {} | >= {} | {} |\n\n",
            format_pct(self.cross_repo_conformance.pass_rate_millionths),
            format_pct(self.thresholds.min_conformance_pass_rate_millionths),
            pass_mark(self.cross_repo_conformance.threshold_pass),
        ));

        out.push_str("## Trend\n\n");
        out.push_str("| Scorecard | Generated At (ns) | Attested Coverage | Privacy Consumption | Override Frequency | Conformance Pass Rate | Outcome |\n");
        out.push_str("|---|---:|---:|---:|---:|---:|---|\n");
        for point in &self.trend {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                point.scorecard_id,
                point.generated_at_ns,
                format_pct(point.attested_receipt_coverage_millionths),
                format_pct(point.privacy_epoch_consumption_millionths),
                format_pct(point.moonshot_override_frequency_millionths),
                format_pct(point.conformance_pass_rate_millionths),
                point.outcome.as_str(),
            ));
        }
        out.push('\n');

        out
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GovernanceScorecardError {
    #[error("invalid input field `{field}`: {detail}")]
    InvalidInput { field: String, detail: String },
    #[error("serialization failure: {0}")]
    SerializationFailure(String),
    #[error("signature failure: {0}")]
    SignatureFailure(String),
    #[error("ledger write failure: {0}")]
    LedgerWriteFailure(String),
}

impl GovernanceScorecardError {
    pub fn stable_code(&self) -> &'static str {
        match self {
            Self::InvalidInput { .. } => ERROR_INVALID_INPUT,
            Self::SerializationFailure(_) => ERROR_SERIALIZATION,
            Self::SignatureFailure(_) => ERROR_SIGNATURE,
            Self::LedgerWriteFailure(_) => ERROR_LEDGER,
        }
    }
}

pub fn publish_governance_scorecard(
    request: &GovernanceScorecardRequest,
    signing_key: &SigningKey,
    ledger: &mut GovernanceAuditLedger,
    actor: GovernanceActor,
) -> Result<GovernanceScorecardPublication, GovernanceScorecardError> {
    request.validate()?;

    let thresholds = request.thresholds.clone().unwrap_or_default();
    thresholds.validate()?;

    let mut events = vec![make_event(
        request,
        "governance_scorecard_started",
        "pass",
        None,
        None,
        None,
    )];

    let attested_receipt_coverage =
        summarize_attested_receipts(&request.attested_receipts, &thresholds);
    events.push(make_event(
        request,
        "attested_receipt_coverage_evaluated",
        if attested_receipt_coverage.threshold_pass {
            "pass"
        } else {
            "fail"
        },
        if attested_receipt_coverage.threshold_pass {
            None
        } else {
            Some(ERROR_THRESHOLD.to_string())
        },
        Some("attested_receipt_coverage".to_string()),
        None,
    ));

    let privacy_budget_health = summarize_privacy_budget(&request.privacy_budget, &thresholds);
    events.push(make_event(
        request,
        "privacy_budget_health_evaluated",
        if privacy_budget_health.threshold_pass {
            "pass"
        } else {
            "fail"
        },
        if privacy_budget_health.threshold_pass {
            None
        } else {
            Some(ERROR_THRESHOLD.to_string())
        },
        Some("privacy_budget_health".to_string()),
        None,
    ));

    let moonshot_governor = summarize_moonshot_governor(&request.moonshot_governor, &thresholds);
    events.push(make_event(
        request,
        "moonshot_governor_evaluated",
        if moonshot_governor.threshold_pass {
            "pass"
        } else {
            "fail"
        },
        if moonshot_governor.threshold_pass {
            None
        } else {
            Some(ERROR_THRESHOLD.to_string())
        },
        Some("moonshot_governor".to_string()),
        None,
    ));

    let cross_repo_conformance = summarize_conformance(&request.conformance, &thresholds);
    events.push(make_event(
        request,
        "cross_repo_conformance_evaluated",
        if cross_repo_conformance.threshold_pass {
            "pass"
        } else {
            "fail"
        },
        if cross_repo_conformance.threshold_pass {
            None
        } else {
            Some(ERROR_THRESHOLD.to_string())
        },
        Some("cross_repo_conformance".to_string()),
        None,
    ));

    let mut blockers = Vec::new();
    let mut warnings = Vec::new();

    if !attested_receipt_coverage.threshold_pass {
        blockers.push(format!(
            "attested-receipt coverage {} below threshold {}",
            format_pct(attested_receipt_coverage.coverage_millionths),
            format_pct(thresholds.min_attested_receipt_coverage_millionths)
        ));
    }

    if !privacy_budget_health.threshold_pass {
        blockers.push(format!(
            "privacy budget health failed: overruns={} epoch_consumption={}",
            privacy_budget_health.overrun_incidents,
            format_pct(privacy_budget_health.epoch_consumption_millionths)
        ));
    }

    if privacy_budget_health.near_term_exhaustion_warning {
        warnings.push("privacy budget projected to exhaust within warning lead time".to_string());
    }

    if !moonshot_governor.threshold_pass {
        blockers.push(format!(
            "moonshot-governor decision health degraded: overrides={} ({}) kill_rate={}",
            moonshot_governor.override_count,
            format_pct(moonshot_governor.override_frequency_millionths),
            format_pct(moonshot_governor.kill_rate_millionths)
        ));
    }

    if !cross_repo_conformance.threshold_pass {
        blockers.push(format!(
            "cross-repo conformance stability degraded: pass_rate={} universal_failures={} exemptions={}",
            format_pct(cross_repo_conformance.pass_rate_millionths),
            cross_repo_conformance.universal_failures,
            cross_repo_conformance.outstanding_exemptions
        ));
    }

    let scorecard_id = derive_scorecard_id(
        request,
        &attested_receipt_coverage,
        &privacy_budget_health,
        &moonshot_governor,
        &cross_repo_conformance,
    )?;

    let mut trend = request.historical.clone();
    trend.sort_by(|left, right| {
        left.generated_at_ns
            .cmp(&right.generated_at_ns)
            .then(left.scorecard_id.cmp(&right.scorecard_id))
    });

    let provisional_outcome = if !blockers.is_empty() {
        GovernanceScorecardOutcome::Critical
    } else if !warnings.is_empty() {
        GovernanceScorecardOutcome::Warning
    } else {
        GovernanceScorecardOutcome::Healthy
    };

    let current_point = GovernanceScorecardTrendPoint {
        scorecard_id: scorecard_id.clone(),
        generated_at_ns: request.generated_at_ns,
        attested_receipt_coverage_millionths: attested_receipt_coverage.coverage_millionths,
        privacy_epoch_consumption_millionths: privacy_budget_health.epoch_consumption_millionths,
        moonshot_override_frequency_millionths: moonshot_governor.override_frequency_millionths,
        conformance_pass_rate_millionths: cross_repo_conformance.pass_rate_millionths,
        outcome: provisional_outcome,
    };

    let trend_regression_detected = trend
        .last()
        .map(|previous| is_trend_regression(previous, &current_point))
        .unwrap_or(false);

    if trend_regression_detected {
        events.push(make_event(
            request,
            "trend_regression_check",
            if thresholds.fail_on_trend_regression {
                "fail"
            } else {
                "warn"
            },
            Some(ERROR_TREND_REGRESSION.to_string()),
            None,
            None,
        ));
        if thresholds.fail_on_trend_regression {
            blockers.push(
                "trend regression detected against previous scorecard (fail_on_trend_regression=true)"
                    .to_string(),
            );
        } else {
            warnings.push("trend regression detected against previous scorecard".to_string());
        }
    } else {
        events.push(make_event(
            request,
            "trend_regression_check",
            "pass",
            None,
            None,
            None,
        ));
    }

    trend.push(current_point);

    let outcome = if !blockers.is_empty() {
        GovernanceScorecardOutcome::Critical
    } else if !warnings.is_empty() {
        GovernanceScorecardOutcome::Warning
    } else {
        GovernanceScorecardOutcome::Healthy
    };

    let mut unsigned_publication = UnsignedGovernanceScorecardPublication {
        schema_version: GOVERNANCE_SCORECARD_SCHEMA_VERSION.to_string(),
        scorecard_id: scorecard_id.clone(),
        generated_at_ns: request.generated_at_ns,
        outcome,
        thresholds,
        attested_receipt_coverage: attested_receipt_coverage.clone(),
        privacy_budget_health: privacy_budget_health.clone(),
        moonshot_governor: moonshot_governor.clone(),
        cross_repo_conformance: cross_repo_conformance.clone(),
        blockers: blockers.clone(),
        warnings: warnings.clone(),
        trend: trend.clone(),
        trend_regression_detected,
    };

    let payload_bytes = serde_json::to_vec(&unsigned_publication)
        .map_err(|err| GovernanceScorecardError::SerializationFailure(err.to_string()))?;
    let artifact_hash_hex = sha256_hex(&payload_bytes);

    let signature = sign_preimage(signing_key, &payload_bytes)
        .map_err(|err| GovernanceScorecardError::SignatureFailure(err.to_string()))?;
    let signer_key = signing_key.verification_key();
    verify_signature(&signer_key, &payload_bytes, &signature)
        .map_err(|err| GovernanceScorecardError::SignatureFailure(err.to_string()))?;

    let decision_type = match outcome {
        GovernanceScorecardOutcome::Healthy => GovernanceDecisionType::Promote,
        GovernanceScorecardOutcome::Warning => GovernanceDecisionType::Hold,
        GovernanceScorecardOutcome::Critical => GovernanceDecisionType::Kill,
    };

    let passed_criteria = build_passed_criteria(
        &attested_receipt_coverage,
        &privacy_budget_health,
        &moonshot_governor,
        &cross_repo_conformance,
    );

    let confidence_millionths = attested_receipt_coverage.coverage_millionths;
    let risk_of_harm_millionths = compute_risk_of_harm(
        &attested_receipt_coverage,
        &privacy_budget_health,
        &moonshot_governor,
        &cross_repo_conformance,
    );

    let snapshot = ScorecardSnapshot {
        ev_millionths: cross_repo_conformance.pass_rate_millionths as i64
            - privacy_budget_health.epoch_consumption_millionths as i64,
        confidence_millionths,
        risk_of_harm_millionths,
        implementation_friction_millionths: ratio_millionths_floor(
            cross_repo_conformance.version_specific_failures,
            cross_repo_conformance.total_cells.max(1),
        ),
        cross_initiative_interference_millionths: moonshot_governor.override_frequency_millionths,
        operational_burden_millionths: max_u64(
            privacy_budget_health.epoch_consumption_millionths,
            ratio_millionths_floor(
                cross_repo_conformance.outstanding_exemptions,
                cross_repo_conformance.total_cells.max(1),
            ),
        ),
    };

    let ledger_entry = ledger
        .append(GovernanceLedgerInput {
            decision_id: request.decision_id.clone(),
            moonshot_id: format!("governance-scorecard:{}", scorecard_id),
            decision_type,
            actor,
            rationale: GovernanceRationale::for_automatic_decision(
                format!(
                    "governance scorecard {} published with outcome {}",
                    scorecard_id,
                    outcome.as_str()
                ),
                confidence_millionths,
                risk_of_harm_millionths,
                passed_criteria,
                blockers.clone(),
            ),
            scorecard_snapshot: snapshot,
            artifact_references: vec![
                format!("artifact://governance-scorecard/{scorecard_id}"),
                format!("hash://{artifact_hash_hex}"),
            ],
            timestamp_ns: request.generated_at_ns,
            moonshot_started_at_ns: None,
        })
        .map_err(|err| map_ledger_error(&err))?;

    events.push(make_event(
        request,
        "governance_scorecard_ledger_append",
        "pass",
        None,
        None,
        Some(format!("sequence={}", ledger_entry.sequence)),
    ));

    events.push(make_event(
        request,
        "governance_scorecard_decision",
        match outcome {
            GovernanceScorecardOutcome::Healthy => "allow",
            GovernanceScorecardOutcome::Warning => "warn",
            GovernanceScorecardOutcome::Critical => "deny",
        },
        if blockers.is_empty() {
            None
        } else {
            Some(ERROR_THRESHOLD.to_string())
        },
        None,
        None,
    ));

    unsigned_publication.blockers = blockers;
    unsigned_publication.warnings = warnings;

    Ok(GovernanceScorecardPublication {
        schema_version: unsigned_publication.schema_version,
        scorecard_id: unsigned_publication.scorecard_id,
        generated_at_ns: unsigned_publication.generated_at_ns,
        outcome: unsigned_publication.outcome,
        thresholds: unsigned_publication.thresholds,
        attested_receipt_coverage: unsigned_publication.attested_receipt_coverage,
        privacy_budget_health: unsigned_publication.privacy_budget_health,
        moonshot_governor: unsigned_publication.moonshot_governor,
        cross_repo_conformance: unsigned_publication.cross_repo_conformance,
        blockers: unsigned_publication.blockers,
        warnings: unsigned_publication.warnings,
        trend: unsigned_publication.trend,
        trend_regression_detected: unsigned_publication.trend_regression_detected,
        artifact_hash_hex,
        signature,
        signer_key,
        ledger_sequence: ledger_entry.sequence,
        events,
    })
}

pub fn verify_governance_scorecard_signature(
    publication: &GovernanceScorecardPublication,
) -> Result<(), GovernanceScorecardError> {
    let unsigned = publication.to_unsigned();
    let payload = serde_json::to_vec(&unsigned)
        .map_err(|err| GovernanceScorecardError::SerializationFailure(err.to_string()))?;
    verify_signature(&publication.signer_key, &payload, &publication.signature)
        .map_err(|err| GovernanceScorecardError::SignatureFailure(err.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UnsignedGovernanceScorecardPublication {
    schema_version: String,
    scorecard_id: String,
    generated_at_ns: u64,
    outcome: GovernanceScorecardOutcome,
    thresholds: GovernanceScorecardThresholds,
    attested_receipt_coverage: AttestedReceiptCoverageSummary,
    privacy_budget_health: PrivacyBudgetHealthSummary,
    moonshot_governor: MoonshotGovernorDecisionSummary,
    cross_repo_conformance: CrossRepoConformanceStabilitySummary,
    blockers: Vec<String>,
    warnings: Vec<String>,
    trend: Vec<GovernanceScorecardTrendPoint>,
    trend_regression_detected: bool,
}

impl GovernanceScorecardPublication {
    fn to_unsigned(&self) -> UnsignedGovernanceScorecardPublication {
        UnsignedGovernanceScorecardPublication {
            schema_version: self.schema_version.clone(),
            scorecard_id: self.scorecard_id.clone(),
            generated_at_ns: self.generated_at_ns,
            outcome: self.outcome,
            thresholds: self.thresholds.clone(),
            attested_receipt_coverage: self.attested_receipt_coverage.clone(),
            privacy_budget_health: self.privacy_budget_health.clone(),
            moonshot_governor: self.moonshot_governor.clone(),
            cross_repo_conformance: self.cross_repo_conformance.clone(),
            blockers: self.blockers.clone(),
            warnings: self.warnings.clone(),
            trend: self.trend.clone(),
            trend_regression_detected: self.trend_regression_detected,
        }
    }
}

fn summarize_attested_receipts(
    receipts: &[AttestedReceiptObservation],
    thresholds: &GovernanceScorecardThresholds,
) -> AttestedReceiptCoverageSummary {
    let high_impact_total = receipts
        .iter()
        .filter(|receipt| receipt.high_impact)
        .count() as u64;
    let valid_count = receipts
        .iter()
        .filter(|receipt| receipt.high_impact && receipt.attestation_binding_valid)
        .count() as u64;

    let coverage = ratio_millionths_floor(valid_count, high_impact_total);
    let threshold_pass = coverage >= thresholds.min_attested_receipt_coverage_millionths;

    AttestedReceiptCoverageSummary {
        high_impact_total,
        high_impact_with_valid_attestation: valid_count,
        high_impact_missing_or_invalid_attestation: high_impact_total.saturating_sub(valid_count),
        coverage_millionths: coverage,
        threshold_pass,
    }
}

fn summarize_privacy_budget(
    input: &PrivacyBudgetHealthInput,
    thresholds: &GovernanceScorecardThresholds,
) -> PrivacyBudgetHealthSummary {
    let epoch = input.accountant.current_epoch;
    let epoch_budget = input.accountant.epoch_budget();

    let epoch_epsilon_budget = non_negative_i64_to_u64(epoch_budget.epsilon_budget_millionths);
    let epoch_epsilon_spent = non_negative_i64_to_u64(epoch_budget.epsilon_spent_millionths);
    let epoch_delta_budget = non_negative_i64_to_u64(epoch_budget.delta_budget_millionths);
    let epoch_delta_spent = non_negative_i64_to_u64(epoch_budget.delta_spent_millionths);

    let epsilon_consumption =
        ratio_millionths_floor(epoch_epsilon_spent, epoch_epsilon_budget.max(1));
    let delta_consumption = ratio_millionths_floor(epoch_delta_spent, epoch_delta_budget.max(1));
    let epoch_consumption = max_u64(epsilon_consumption, delta_consumption);

    let epsilon_burn_rate_per_hour =
        rate_per_hour(epoch_epsilon_spent, input.measurement_window_ns);
    let delta_burn_rate_per_hour = rate_per_hour(epoch_delta_spent, input.measurement_window_ns);

    let projected_epsilon_exhaustion_ns = projected_exhaustion_ns(
        input.measurement_end_ns,
        epoch_budget.epsilon_remaining(),
        epsilon_burn_rate_per_hour,
    );
    let projected_delta_exhaustion_ns = projected_exhaustion_ns(
        input.measurement_end_ns,
        epoch_budget.delta_remaining(),
        delta_burn_rate_per_hour,
    );

    let threshold_pass = input.overrun_incidents <= thresholds.max_privacy_overrun_incidents
        && epoch_consumption <= thresholds.max_privacy_epoch_consumption_millionths
        && !input.accountant.is_exhausted();

    let near_term_exhaustion_warning = thresholds
        .warn_privacy_exhaustion_within_ns
        .map(|lead_time| {
            let horizon = input.measurement_end_ns.saturating_add(lead_time);
            projected_epsilon_exhaustion_ns.is_some_and(|ts| ts <= horizon)
                || projected_delta_exhaustion_ns.is_some_and(|ts| ts <= horizon)
        })
        .unwrap_or(false);

    let forecast = input.accountant.forecast();

    PrivacyBudgetHealthSummary {
        epoch,
        epoch_epsilon_budget_millionths: epoch_epsilon_budget,
        epoch_epsilon_spent_millionths: epoch_epsilon_spent,
        epoch_delta_budget_millionths: epoch_delta_budget,
        epoch_delta_spent_millionths: epoch_delta_spent,
        epoch_consumption_millionths: epoch_consumption,
        lifetime_epsilon_remaining_millionths: non_negative_i64_to_u64(
            forecast.lifetime_epsilon_remaining_millionths,
        ),
        lifetime_delta_remaining_millionths: non_negative_i64_to_u64(
            forecast.lifetime_delta_remaining_millionths,
        ),
        estimated_remaining_operations: forecast.estimated_remaining_operations,
        epsilon_burn_rate_per_hour_millionths: epsilon_burn_rate_per_hour,
        delta_burn_rate_per_hour_millionths: delta_burn_rate_per_hour,
        projected_epsilon_exhaustion_ns,
        projected_delta_exhaustion_ns,
        overrun_incidents: input.overrun_incidents,
        threshold_pass,
        near_term_exhaustion_warning,
    }
}

fn summarize_moonshot_governor(
    input: &MoonshotGovernorHealthInput,
    thresholds: &GovernanceScorecardThresholds,
) -> MoonshotGovernorDecisionSummary {
    let report = &input.governance_report;

    let threshold_pass = report.override_frequency_millionths
        <= thresholds.max_moonshot_override_frequency_millionths
        && report.kill_rate_millionths <= thresholds.max_moonshot_kill_rate_millionths
        && thresholds
            .max_moonshot_mean_time_to_decision_ns
            .is_none_or(|max_ns| {
                report
                    .mean_time_to_decision_ns
                    .is_none_or(|actual| actual <= max_ns)
            });

    MoonshotGovernorDecisionSummary {
        total_decisions: report.total_decisions as u64,
        override_count: report.override_count as u64,
        kill_count: report.kill_count as u64,
        override_frequency_millionths: report.override_frequency_millionths,
        kill_rate_millionths: report.kill_rate_millionths,
        mean_time_to_decision_ns: report.mean_time_to_decision_ns,
        active_moonshots: input.active_moonshots,
        paused_moonshots: input.paused_moonshots,
        killed_moonshots: input.killed_moonshots,
        threshold_pass,
    }
}

fn summarize_conformance(
    input: &CrossRepoConformanceInput,
    thresholds: &GovernanceScorecardThresholds,
) -> CrossRepoConformanceStabilitySummary {
    let total_cells = input.matrix_health.total_cells as u64;
    let passed_cells = input.matrix_health.passed_cells as u64;
    let failed_cells = input.matrix_health.failed_cells as u64;
    let pass_rate = ratio_millionths_floor(passed_cells, total_cells.max(1));

    let threshold_pass = pass_rate >= thresholds.min_conformance_pass_rate_millionths
        && (input.matrix_health.universal_failures as u64) <= thresholds.max_universal_failures
        && (input.matrix_health.version_specific_failures as u64)
            <= thresholds.max_version_specific_failures
        && input.outstanding_exemptions <= thresholds.max_outstanding_exemptions;

    CrossRepoConformanceStabilitySummary {
        release_id: input.release_id.clone(),
        total_cells,
        passed_cells,
        failed_cells,
        pass_rate_millionths: pass_rate,
        universal_failures: input.matrix_health.universal_failures as u64,
        version_specific_failures: input.matrix_health.version_specific_failures as u64,
        outstanding_exemptions: input.outstanding_exemptions,
        failure_class_distribution: input.failure_class_distribution.clone(),
        threshold_pass,
    }
}

fn build_passed_criteria(
    attested: &AttestedReceiptCoverageSummary,
    privacy: &PrivacyBudgetHealthSummary,
    moonshot: &MoonshotGovernorDecisionSummary,
    conformance: &CrossRepoConformanceStabilitySummary,
) -> Vec<String> {
    let mut criteria = Vec::new();
    if attested.threshold_pass {
        criteria.push("attested_receipt_coverage".to_string());
    }
    if privacy.threshold_pass {
        criteria.push("privacy_budget_health".to_string());
    }
    if moonshot.threshold_pass {
        criteria.push("moonshot_governor".to_string());
    }
    if conformance.threshold_pass {
        criteria.push("cross_repo_conformance".to_string());
    }
    criteria
}

fn compute_risk_of_harm(
    attested: &AttestedReceiptCoverageSummary,
    privacy: &PrivacyBudgetHealthSummary,
    moonshot: &MoonshotGovernorDecisionSummary,
    conformance: &CrossRepoConformanceStabilitySummary,
) -> u64 {
    let attested_risk = 1_000_000u64.saturating_sub(attested.coverage_millionths);
    let conformance_risk = 1_000_000u64.saturating_sub(conformance.pass_rate_millionths);
    max_u64(
        max_u64(attested_risk, privacy.epoch_consumption_millionths),
        max_u64(
            conformance_risk,
            max_u64(
                moonshot.override_frequency_millionths,
                moonshot.kill_rate_millionths,
            ),
        ),
    )
}

fn derive_scorecard_id(
    request: &GovernanceScorecardRequest,
    attested: &AttestedReceiptCoverageSummary,
    privacy: &PrivacyBudgetHealthSummary,
    moonshot: &MoonshotGovernorDecisionSummary,
    conformance: &CrossRepoConformanceStabilitySummary,
) -> Result<String, GovernanceScorecardError> {
    if !request.scorecard_run_id.trim().is_empty() {
        return Ok(request.scorecard_run_id.clone());
    }

    let mut hasher = Sha256::new();
    hasher.update(request.trace_id.as_bytes());
    hasher.update(request.decision_id.as_bytes());
    hasher.update(request.policy_id.as_bytes());
    hasher.update(request.generated_at_ns.to_le_bytes());
    hasher.update(attested.coverage_millionths.to_le_bytes());
    hasher.update(privacy.epoch_consumption_millionths.to_le_bytes());
    hasher.update(moonshot.override_frequency_millionths.to_le_bytes());
    hasher.update(conformance.pass_rate_millionths.to_le_bytes());

    let digest = hasher.finalize();
    let mut short = String::with_capacity(24);
    for byte in &digest[..12] {
        short.push_str(&format!("{byte:02x}"));
    }
    Ok(format!("gov-scorecard-{short}"))
}

fn is_trend_regression(
    previous: &GovernanceScorecardTrendPoint,
    current: &GovernanceScorecardTrendPoint,
) -> bool {
    current.attested_receipt_coverage_millionths < previous.attested_receipt_coverage_millionths
        || current.conformance_pass_rate_millionths < previous.conformance_pass_rate_millionths
        || current.moonshot_override_frequency_millionths
            > previous.moonshot_override_frequency_millionths
        || current.privacy_epoch_consumption_millionths
            > previous.privacy_epoch_consumption_millionths
}

fn map_ledger_error(err: &GovernanceLedgerError) -> GovernanceScorecardError {
    GovernanceScorecardError::LedgerWriteFailure(format!("{} ({})", err, err.code()))
}

fn make_event(
    request: &GovernanceScorecardRequest,
    event: &str,
    outcome: &str,
    error_code: Option<String>,
    dimension: Option<String>,
    detail: Option<String>,
) -> GovernanceScorecardEvent {
    GovernanceScorecardEvent {
        trace_id: request.trace_id.clone(),
        decision_id: request.decision_id.clone(),
        policy_id: request.policy_id.clone(),
        component: GOVERNANCE_SCORECARD_COMPONENT.to_string(),
        event: event.to_string(),
        outcome: outcome.to_string(),
        error_code,
        dimension,
        detail,
    }
}

fn validate_non_empty(value: &str, field: &str) -> Result<(), GovernanceScorecardError> {
    if value.trim().is_empty() {
        return Err(GovernanceScorecardError::InvalidInput {
            field: field.to_string(),
            detail: "must not be empty".to_string(),
        });
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn non_negative_i64_to_u64(value: i64) -> u64 {
    if value <= 0 { 0 } else { value as u64 }
}

fn projected_exhaustion_ns(
    now_ns: u64,
    remaining_millionths: i64,
    burn_rate_per_hour: u64,
) -> Option<u64> {
    if remaining_millionths <= 0 {
        return Some(now_ns);
    }
    if burn_rate_per_hour == 0 {
        return None;
    }

    let remaining = remaining_millionths as u128;
    let burn = burn_rate_per_hour as u128;
    let delta_ns = remaining
        .saturating_mul(NS_PER_HOUR)
        .saturating_add(burn.saturating_sub(1))
        / burn;

    let bounded = delta_ns.min(u64::MAX as u128) as u64;
    Some(now_ns.saturating_add(bounded))
}

fn ratio_millionths_floor(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    ((numerator as u128).saturating_mul(MILLION) / denominator as u128).min(1_000_000) as u64
}

fn rate_per_hour(value_millionths: u64, window_ns: u64) -> u64 {
    if window_ns == 0 {
        return 0;
    }
    ((value_millionths as u128).saturating_mul(NS_PER_HOUR) / window_ns as u128)
        .min(u64::MAX as u128) as u64
}

fn max_u64(left: u64, right: u64) -> u64 {
    if left >= right { left } else { right }
}

fn pass_mark(pass: bool) -> &'static str {
    if pass { "yes" } else { "no" }
}

fn format_pct(millionths: u64) -> String {
    let whole = millionths / 10_000;
    let frac = millionths % 10_000;
    format!("{whole}.{frac:04}%")
}

impl From<SignatureError> for GovernanceScorecardError {
    fn from(value: SignatureError) -> Self {
        GovernanceScorecardError::SignatureFailure(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dp_budget_accountant::{AccountantConfig, BudgetAccountant};
    use crate::portfolio_governor::governance_audit_ledger::{
        GovernanceAuditLedger, GovernanceLedgerConfig, GovernanceReport,
    };
    use crate::privacy_learning_contract::CompositionMethod;

    // ── helpers ──────────────────────────────────────────────────────

    fn test_accountant() -> BudgetAccountant {
        BudgetAccountant::new(AccountantConfig {
            zone: "test-zone".to_string(),
            epsilon_per_epoch_millionths: 1_000_000,
            delta_per_epoch_millionths: 1_000_000,
            lifetime_epsilon_budget_millionths: 10_000_000,
            lifetime_delta_budget_millionths: 10_000_000,
            composition_method: CompositionMethod::Basic,
            epoch: SecurityEpoch::from_raw(1),
            now_ns: 1_000_000_000,
        })
        .unwrap()
    }

    fn test_privacy_budget() -> PrivacyBudgetHealthInput {
        PrivacyBudgetHealthInput {
            accountant: test_accountant(),
            overrun_incidents: 0,
            measurement_window_ns: 3_600_000_000_000, // 1 hour
            measurement_end_ns: 1_000_000_000,
        }
    }

    fn test_governance_report() -> GovernanceReport {
        GovernanceReport {
            total_decisions: 100,
            override_count: 5,
            kill_count: 10,
            override_frequency_millionths: 50_000,
            kill_rate_millionths: 100_000,
            mean_time_to_decision_ns: Some(86_400_000_000_000), // 1 day
            portfolio_health_trend: Vec::new(),
        }
    }

    fn test_moonshot_governor() -> MoonshotGovernorHealthInput {
        MoonshotGovernorHealthInput {
            governance_report: test_governance_report(),
            active_moonshots: 3,
            paused_moonshots: 1,
            killed_moonshots: 2,
        }
    }

    fn test_matrix_health() -> MatrixHealthSummary {
        MatrixHealthSummary {
            total_cells: 100,
            passed_cells: 98,
            failed_cells: 2,
            universal_failures: 0,
            version_specific_failures: 2,
        }
    }

    fn test_conformance() -> CrossRepoConformanceInput {
        CrossRepoConformanceInput {
            release_id: "rel-001".to_string(),
            matrix_health: test_matrix_health(),
            failure_class_distribution: BTreeMap::new(),
            outstanding_exemptions: 0,
        }
    }

    fn test_receipts() -> Vec<AttestedReceiptObservation> {
        vec![
            AttestedReceiptObservation {
                receipt_id: "r-1".to_string(),
                high_impact: true,
                attestation_binding_valid: true,
                timestamp_ns: 1_000,
            },
            AttestedReceiptObservation {
                receipt_id: "r-2".to_string(),
                high_impact: true,
                attestation_binding_valid: true,
                timestamp_ns: 2_000,
            },
            AttestedReceiptObservation {
                receipt_id: "r-3".to_string(),
                high_impact: false,
                attestation_binding_valid: false,
                timestamp_ns: 3_000,
            },
        ]
    }

    fn test_request() -> GovernanceScorecardRequest {
        GovernanceScorecardRequest {
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            scorecard_run_id: "run-001".to_string(),
            generated_at_ns: 1_000_000_000,
            attested_receipts: test_receipts(),
            privacy_budget: test_privacy_budget(),
            moonshot_governor: test_moonshot_governor(),
            conformance: test_conformance(),
            historical: Vec::new(),
            thresholds: None,
        }
    }

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes([42u8; 32])
    }

    fn test_ledger() -> GovernanceAuditLedger {
        GovernanceAuditLedger::new(GovernanceLedgerConfig::default()).unwrap()
    }

    fn test_actor() -> GovernanceActor {
        GovernanceActor::System("governance-scorecard-test".to_string())
    }

    // ── GovernanceScorecardOutcome ──────────────────────────────────

    #[test]
    fn outcome_as_str() {
        assert_eq!(GovernanceScorecardOutcome::Healthy.as_str(), "healthy");
        assert_eq!(GovernanceScorecardOutcome::Warning.as_str(), "warning");
        assert_eq!(GovernanceScorecardOutcome::Critical.as_str(), "critical");
    }

    #[test]
    fn outcome_ordering() {
        assert!(GovernanceScorecardOutcome::Healthy < GovernanceScorecardOutcome::Warning);
        assert!(GovernanceScorecardOutcome::Warning < GovernanceScorecardOutcome::Critical);
    }

    #[test]
    fn outcome_serde_roundtrip() {
        for outcome in [
            GovernanceScorecardOutcome::Healthy,
            GovernanceScorecardOutcome::Warning,
            GovernanceScorecardOutcome::Critical,
        ] {
            let json = serde_json::to_string(&outcome).unwrap();
            let back: GovernanceScorecardOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(back, outcome);
        }
    }

    // ── GovernanceScorecardThresholds ───────────────────────────────

    #[test]
    fn thresholds_default_values() {
        let t = GovernanceScorecardThresholds::default();
        assert_eq!(t.min_attested_receipt_coverage_millionths, 950_000);
        assert_eq!(t.max_privacy_overrun_incidents, 0);
        assert_eq!(t.max_privacy_epoch_consumption_millionths, 900_000);
        assert_eq!(t.min_conformance_pass_rate_millionths, 950_000);
        assert_eq!(t.max_universal_failures, 0);
        assert!(!t.fail_on_trend_regression);
    }

    #[test]
    fn thresholds_default_validates() {
        let t = GovernanceScorecardThresholds::default();
        assert!(t.validate().is_ok());
    }

    #[test]
    fn thresholds_attested_receipt_too_high() {
        let t = GovernanceScorecardThresholds {
            min_attested_receipt_coverage_millionths: 1_000_001,
            ..GovernanceScorecardThresholds::default()
        };
        let err = t.validate().unwrap_err();
        assert!(matches!(err, GovernanceScorecardError::InvalidInput { .. }));
    }

    #[test]
    fn thresholds_privacy_consumption_too_high() {
        let t = GovernanceScorecardThresholds {
            max_privacy_epoch_consumption_millionths: 1_000_001,
            ..GovernanceScorecardThresholds::default()
        };
        assert!(t.validate().is_err());
    }

    #[test]
    fn thresholds_moonshot_override_too_high() {
        let t = GovernanceScorecardThresholds {
            max_moonshot_override_frequency_millionths: 1_000_001,
            ..GovernanceScorecardThresholds::default()
        };
        assert!(t.validate().is_err());
    }

    #[test]
    fn thresholds_moonshot_kill_rate_too_high() {
        let t = GovernanceScorecardThresholds {
            max_moonshot_kill_rate_millionths: 1_000_001,
            ..GovernanceScorecardThresholds::default()
        };
        assert!(t.validate().is_err());
    }

    #[test]
    fn thresholds_conformance_pass_rate_too_high() {
        let t = GovernanceScorecardThresholds {
            min_conformance_pass_rate_millionths: 1_000_001,
            ..GovernanceScorecardThresholds::default()
        };
        assert!(t.validate().is_err());
    }

    #[test]
    fn thresholds_exhaustion_lead_zero() {
        let t = GovernanceScorecardThresholds {
            warn_privacy_exhaustion_within_ns: Some(0),
            ..GovernanceScorecardThresholds::default()
        };
        assert!(t.validate().is_err());
    }

    #[test]
    fn thresholds_decision_ns_zero() {
        let t = GovernanceScorecardThresholds {
            max_moonshot_mean_time_to_decision_ns: Some(0),
            ..GovernanceScorecardThresholds::default()
        };
        assert!(t.validate().is_err());
    }

    #[test]
    fn thresholds_serde_roundtrip() {
        let t = GovernanceScorecardThresholds::default();
        let json = serde_json::to_string(&t).unwrap();
        let back: GovernanceScorecardThresholds = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }

    // ── GovernanceScorecardError ────────────────────────────────────

    #[test]
    fn error_stable_codes() {
        let cases: [(GovernanceScorecardError, &str); 4] = [
            (
                GovernanceScorecardError::InvalidInput {
                    field: "f".to_string(),
                    detail: "d".to_string(),
                },
                "FE-GOV-SCORE-3001",
            ),
            (
                GovernanceScorecardError::SerializationFailure("s".to_string()),
                "FE-GOV-SCORE-3002",
            ),
            (
                GovernanceScorecardError::SignatureFailure("s".to_string()),
                "FE-GOV-SCORE-3003",
            ),
            (
                GovernanceScorecardError::LedgerWriteFailure("l".to_string()),
                "FE-GOV-SCORE-3004",
            ),
        ];
        for (err, code) in cases {
            assert_eq!(err.stable_code(), code);
        }
    }

    #[test]
    fn error_display() {
        let err = GovernanceScorecardError::InvalidInput {
            field: "f".to_string(),
            detail: "d".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("f"));
        assert!(msg.contains("d"));
    }

    // ── input validation ────────────────────────────────────────────

    #[test]
    fn receipt_validate_empty_id() {
        let receipt = AttestedReceiptObservation {
            receipt_id: "  ".to_string(),
            high_impact: true,
            attestation_binding_valid: true,
            timestamp_ns: 1,
        };
        assert!(receipt.validate().is_err());
    }

    #[test]
    fn receipt_validate_ok() {
        let receipt = AttestedReceiptObservation {
            receipt_id: "r-1".to_string(),
            high_impact: false,
            attestation_binding_valid: false,
            timestamp_ns: 0,
        };
        assert!(receipt.validate().is_ok());
    }

    #[test]
    fn privacy_validate_zero_window() {
        let mut pb = test_privacy_budget();
        pb.measurement_window_ns = 0;
        assert!(pb.validate().is_err());
    }

    #[test]
    fn conformance_validate_empty_release_id() {
        let mut c = test_conformance();
        c.release_id = "".to_string();
        assert!(c.validate().is_err());
    }

    #[test]
    fn conformance_validate_cells_mismatch() {
        let mut c = test_conformance();
        c.matrix_health.total_cells = 50; // passed + failed != 50
        assert!(c.validate().is_err());
    }

    #[test]
    fn request_validate_empty_trace_id() {
        let mut req = test_request();
        req.trace_id = "".to_string();
        assert!(req.validate().is_err());
    }

    #[test]
    fn request_validate_empty_decision_id() {
        let mut req = test_request();
        req.decision_id = "  ".to_string();
        assert!(req.validate().is_err());
    }

    #[test]
    fn request_validate_zero_generated_at() {
        let mut req = test_request();
        req.generated_at_ns = 0;
        assert!(req.validate().is_err());
    }

    #[test]
    fn request_validate_empty_receipts() {
        let mut req = test_request();
        req.attested_receipts = Vec::new();
        assert!(req.validate().is_err());
    }

    #[test]
    fn request_validate_no_high_impact_receipts() {
        let mut req = test_request();
        for receipt in &mut req.attested_receipts {
            receipt.high_impact = false;
        }
        assert!(req.validate().is_err());
    }

    #[test]
    fn request_validate_duplicate_receipt_id() {
        let mut req = test_request();
        req.attested_receipts.push(AttestedReceiptObservation {
            receipt_id: "r-1".to_string(), // duplicate
            high_impact: true,
            attestation_binding_valid: true,
            timestamp_ns: 4_000,
        });
        let err = req.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("duplicate"));
    }

    #[test]
    fn request_validate_ok() {
        let req = test_request();
        assert!(req.validate().is_ok());
    }

    // ── publish_governance_scorecard ─────────────────────────────────

    #[test]
    fn publish_healthy_scorecard() {
        let req = test_request();
        let key = test_signing_key();
        let mut ledger = test_ledger();
        let actor = test_actor();
        let pub_result = publish_governance_scorecard(&req, &key, &mut ledger, actor);
        assert!(pub_result.is_ok());
        let publication = pub_result.unwrap();
        assert_eq!(publication.outcome, GovernanceScorecardOutcome::Healthy);
        assert!(publication.blockers.is_empty());
        assert!(publication.warnings.is_empty());
        assert_eq!(publication.scorecard_id, "run-001");
        assert_eq!(
            publication.schema_version,
            GOVERNANCE_SCORECARD_SCHEMA_VERSION
        );
        assert!(!publication.artifact_hash_hex.is_empty());
        assert!(!publication.trend.is_empty());
    }

    #[test]
    fn publish_scorecard_deterministic() {
        let req = test_request();
        let key = test_signing_key();
        let mut ledger1 = test_ledger();
        let mut ledger2 = test_ledger();
        let p1 = publish_governance_scorecard(
            &req,
            &key,
            &mut ledger1,
            GovernanceActor::System("test".to_string()),
        )
        .unwrap();
        let p2 = publish_governance_scorecard(
            &req,
            &key,
            &mut ledger2,
            GovernanceActor::System("test".to_string()),
        )
        .unwrap();
        assert_eq!(p1.artifact_hash_hex, p2.artifact_hash_hex);
    }

    #[test]
    fn publish_scorecard_signature_verifies() {
        let req = test_request();
        let key = test_signing_key();
        let mut ledger = test_ledger();
        let publication =
            publish_governance_scorecard(&req, &key, &mut ledger, test_actor()).unwrap();
        assert!(verify_governance_scorecard_signature(&publication).is_ok());
    }

    #[test]
    fn publish_scorecard_low_coverage_critical() {
        let mut req = test_request();
        // Make only 1 of 2 high-impact receipts valid
        req.attested_receipts[1].attestation_binding_valid = false;
        // coverage = 50% < 95% threshold → Critical
        let key = test_signing_key();
        let mut ledger = test_ledger();
        let publication =
            publish_governance_scorecard(&req, &key, &mut ledger, test_actor()).unwrap();
        assert_eq!(publication.outcome, GovernanceScorecardOutcome::Critical);
        assert!(!publication.blockers.is_empty());
        assert!(
            publication
                .blockers
                .iter()
                .any(|b| b.contains("attested-receipt coverage"))
        );
    }

    #[test]
    fn publish_scorecard_privacy_overrun_critical() {
        let mut req = test_request();
        req.privacy_budget.overrun_incidents = 1; // > 0 threshold
        let key = test_signing_key();
        let mut ledger = test_ledger();
        let publication =
            publish_governance_scorecard(&req, &key, &mut ledger, test_actor()).unwrap();
        assert_eq!(publication.outcome, GovernanceScorecardOutcome::Critical);
        assert!(
            publication
                .blockers
                .iter()
                .any(|b| b.contains("privacy budget"))
        );
    }

    #[test]
    fn publish_scorecard_moonshot_override_high_critical() {
        let mut req = test_request();
        req.moonshot_governor
            .governance_report
            .override_frequency_millionths = 500_000; // > 200k
        let key = test_signing_key();
        let mut ledger = test_ledger();
        let publication =
            publish_governance_scorecard(&req, &key, &mut ledger, test_actor()).unwrap();
        assert_eq!(publication.outcome, GovernanceScorecardOutcome::Critical);
        assert!(publication.blockers.iter().any(|b| b.contains("moonshot")));
    }

    #[test]
    fn publish_scorecard_conformance_low_pass_rate() {
        let mut req = test_request();
        req.conformance.matrix_health = MatrixHealthSummary {
            total_cells: 100,
            passed_cells: 50,
            failed_cells: 50,
            universal_failures: 0,
            version_specific_failures: 2,
        };
        let key = test_signing_key();
        let mut ledger = test_ledger();
        let publication =
            publish_governance_scorecard(&req, &key, &mut ledger, test_actor()).unwrap();
        assert_eq!(publication.outcome, GovernanceScorecardOutcome::Critical);
        assert!(
            publication
                .blockers
                .iter()
                .any(|b| b.contains("conformance"))
        );
    }

    #[test]
    fn publish_scorecard_events_populated() {
        let req = test_request();
        let key = test_signing_key();
        let mut ledger = test_ledger();
        let publication =
            publish_governance_scorecard(&req, &key, &mut ledger, test_actor()).unwrap();
        assert!(!publication.events.is_empty());
        assert_eq!(
            publication.events[0].component,
            GOVERNANCE_SCORECARD_COMPONENT
        );
        // Should have: started, 4 dimension evals, trend check, ledger append, decision
        assert!(publication.events.len() >= 7);
    }

    #[test]
    fn publish_scorecard_ledger_sequence() {
        let req = test_request();
        let key = test_signing_key();
        let mut ledger = test_ledger();
        let p1 = publish_governance_scorecard(
            &req,
            &key,
            &mut ledger,
            GovernanceActor::System("test".to_string()),
        )
        .unwrap();
        assert!(p1.ledger_sequence > 0);
    }

    #[test]
    fn publish_scorecard_auto_derived_id() {
        let mut req = test_request();
        req.scorecard_run_id = "".to_string(); // empty → auto-derive
        let key = test_signing_key();
        let mut ledger = test_ledger();
        let publication =
            publish_governance_scorecard(&req, &key, &mut ledger, test_actor()).unwrap();
        assert!(publication.scorecard_id.starts_with("gov-scorecard-"));
    }

    #[test]
    fn publish_scorecard_invalid_request_fails() {
        let mut req = test_request();
        req.trace_id = "".to_string();
        let key = test_signing_key();
        let mut ledger = test_ledger();
        let result = publish_governance_scorecard(&req, &key, &mut ledger, test_actor());
        assert!(result.is_err());
    }

    // ── trend regression ────────────────────────────────────────────

    #[test]
    fn trend_regression_detected_warning() {
        let mut req = test_request();
        req.historical = vec![GovernanceScorecardTrendPoint {
            scorecard_id: "prev".to_string(),
            generated_at_ns: 500_000_000,
            attested_receipt_coverage_millionths: 1_000_000, // was 100%
            privacy_epoch_consumption_millionths: 0,
            moonshot_override_frequency_millionths: 0,
            conformance_pass_rate_millionths: 1_000_000,
            outcome: GovernanceScorecardOutcome::Healthy,
        }];
        // coverage = 2/2 = 1_000_000 → no regression on coverage
        // conformance = 98/100 = 980_000 < 1_000_000 → regression!
        let key = test_signing_key();
        let mut ledger = test_ledger();
        let publication =
            publish_governance_scorecard(&req, &key, &mut ledger, test_actor()).unwrap();
        assert!(publication.trend_regression_detected);
        assert_eq!(publication.outcome, GovernanceScorecardOutcome::Warning);
        assert!(
            publication
                .warnings
                .iter()
                .any(|w| w.contains("trend regression"))
        );
    }

    #[test]
    fn trend_regression_blocks_when_configured() {
        let mut req = test_request();
        req.historical = vec![GovernanceScorecardTrendPoint {
            scorecard_id: "prev".to_string(),
            generated_at_ns: 500_000_000,
            attested_receipt_coverage_millionths: 1_000_000,
            privacy_epoch_consumption_millionths: 0,
            moonshot_override_frequency_millionths: 0,
            conformance_pass_rate_millionths: 1_000_000,
            outcome: GovernanceScorecardOutcome::Healthy,
        }];
        req.thresholds = Some(GovernanceScorecardThresholds {
            fail_on_trend_regression: true,
            ..GovernanceScorecardThresholds::default()
        });
        let key = test_signing_key();
        let mut ledger = test_ledger();
        let publication =
            publish_governance_scorecard(&req, &key, &mut ledger, test_actor()).unwrap();
        assert!(publication.trend_regression_detected);
        assert_eq!(publication.outcome, GovernanceScorecardOutcome::Critical);
        assert!(
            publication
                .blockers
                .iter()
                .any(|b| b.contains("trend regression"))
        );
    }

    #[test]
    fn no_trend_regression_when_no_history() {
        let req = test_request();
        let key = test_signing_key();
        let mut ledger = test_ledger();
        let publication =
            publish_governance_scorecard(&req, &key, &mut ledger, test_actor()).unwrap();
        assert!(!publication.trend_regression_detected);
    }

    #[test]
    fn trend_includes_current_point() {
        let req = test_request();
        let key = test_signing_key();
        let mut ledger = test_ledger();
        let publication =
            publish_governance_scorecard(&req, &key, &mut ledger, test_actor()).unwrap();
        assert_eq!(publication.trend.len(), 1);
        assert_eq!(publication.trend[0].scorecard_id, "run-001");
    }

    // ── markdown report ─────────────────────────────────────────────

    #[test]
    fn markdown_report_sections() {
        let req = test_request();
        let key = test_signing_key();
        let mut ledger = test_ledger();
        let publication =
            publish_governance_scorecard(&req, &key, &mut ledger, test_actor()).unwrap();
        let md = publication.to_markdown_report();
        assert!(md.contains("# Governance Scorecard"));
        assert!(md.contains("## Dimensions"));
        assert!(md.contains("## Trend"));
        assert!(md.contains("Scorecard ID"));
        assert!(md.contains("HEALTHY"));
    }

    #[test]
    fn markdown_report_blockers_section() {
        let mut req = test_request();
        req.attested_receipts[1].attestation_binding_valid = false; // cause blocker
        let key = test_signing_key();
        let mut ledger = test_ledger();
        let publication =
            publish_governance_scorecard(&req, &key, &mut ledger, test_actor()).unwrap();
        let md = publication.to_markdown_report();
        assert!(md.contains("## Blockers"));
    }

    // ── json output ─────────────────────────────────────────────────

    #[test]
    fn json_pretty_roundtrip() {
        let req = test_request();
        let key = test_signing_key();
        let mut ledger = test_ledger();
        let publication =
            publish_governance_scorecard(&req, &key, &mut ledger, test_actor()).unwrap();
        let json = publication.to_json_pretty().unwrap();
        let back: GovernanceScorecardPublication = serde_json::from_str(&json).unwrap();
        assert_eq!(back.scorecard_id, publication.scorecard_id);
        assert_eq!(back.outcome, publication.outcome);
    }

    // ── helper functions via publish ─────────────────────────────────

    #[test]
    fn attested_receipt_coverage_summary() {
        let req = test_request();
        let key = test_signing_key();
        let mut ledger = test_ledger();
        let publication =
            publish_governance_scorecard(&req, &key, &mut ledger, test_actor()).unwrap();
        let arc = &publication.attested_receipt_coverage;
        assert_eq!(arc.high_impact_total, 2);
        assert_eq!(arc.high_impact_with_valid_attestation, 2);
        assert_eq!(arc.high_impact_missing_or_invalid_attestation, 0);
        assert_eq!(arc.coverage_millionths, 1_000_000);
        assert!(arc.threshold_pass);
    }

    #[test]
    fn privacy_budget_health_summary() {
        let req = test_request();
        let key = test_signing_key();
        let mut ledger = test_ledger();
        let publication =
            publish_governance_scorecard(&req, &key, &mut ledger, test_actor()).unwrap();
        let pbh = &publication.privacy_budget_health;
        assert_eq!(pbh.overrun_incidents, 0);
        assert!(pbh.threshold_pass);
        assert!(!pbh.near_term_exhaustion_warning);
    }

    #[test]
    fn moonshot_governor_summary() {
        let req = test_request();
        let key = test_signing_key();
        let mut ledger = test_ledger();
        let publication =
            publish_governance_scorecard(&req, &key, &mut ledger, test_actor()).unwrap();
        let mg = &publication.moonshot_governor;
        assert_eq!(mg.total_decisions, 100);
        assert_eq!(mg.override_count, 5);
        assert_eq!(mg.kill_count, 10);
        assert!(mg.threshold_pass);
    }

    #[test]
    fn cross_repo_conformance_summary() {
        let req = test_request();
        let key = test_signing_key();
        let mut ledger = test_ledger();
        let publication =
            publish_governance_scorecard(&req, &key, &mut ledger, test_actor()).unwrap();
        let crc = &publication.cross_repo_conformance;
        assert_eq!(crc.total_cells, 100);
        assert_eq!(crc.passed_cells, 98);
        assert_eq!(crc.pass_rate_millionths, 980_000);
        assert!(crc.threshold_pass);
    }

    // ── serde roundtrips ────────────────────────────────────────────

    #[test]
    fn receipt_observation_serde() {
        let r = test_receipts()[0].clone();
        let json = serde_json::to_string(&r).unwrap();
        let back: AttestedReceiptObservation = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn trend_point_serde() {
        let tp = GovernanceScorecardTrendPoint {
            scorecard_id: "tp-1".to_string(),
            generated_at_ns: 999,
            attested_receipt_coverage_millionths: 950_000,
            privacy_epoch_consumption_millionths: 100_000,
            moonshot_override_frequency_millionths: 50_000,
            conformance_pass_rate_millionths: 980_000,
            outcome: GovernanceScorecardOutcome::Healthy,
        };
        let json = serde_json::to_string(&tp).unwrap();
        let back: GovernanceScorecardTrendPoint = serde_json::from_str(&json).unwrap();
        assert_eq!(back, tp);
    }

    #[test]
    fn scorecard_event_serde() {
        let ev = GovernanceScorecardEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            dimension: Some("dim".to_string()),
            detail: None,
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: GovernanceScorecardEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ev);
    }

    // ── format_pct ──────────────────────────────────────────────────

    #[test]
    fn format_pct_values() {
        assert_eq!(format_pct(1_000_000), "100.0000%");
        assert_eq!(format_pct(0), "0.0000%");
        assert_eq!(format_pct(500_000), "50.0000%");
        assert_eq!(format_pct(950_000), "95.0000%");
    }

    // ── ratio_millionths_floor ──────────────────────────────────────

    #[test]
    fn ratio_millionths_floor_values() {
        assert_eq!(ratio_millionths_floor(1, 2), 500_000);
        assert_eq!(ratio_millionths_floor(0, 100), 0);
        assert_eq!(ratio_millionths_floor(100, 100), 1_000_000);
        assert_eq!(ratio_millionths_floor(5, 0), 0); // division by zero → 0
    }

    // ── is_trend_regression ─────────────────────────────────────────

    #[test]
    fn is_trend_regression_no_regression() {
        let prev = GovernanceScorecardTrendPoint {
            scorecard_id: "p".to_string(),
            generated_at_ns: 1,
            attested_receipt_coverage_millionths: 950_000,
            privacy_epoch_consumption_millionths: 100_000,
            moonshot_override_frequency_millionths: 50_000,
            conformance_pass_rate_millionths: 980_000,
            outcome: GovernanceScorecardOutcome::Healthy,
        };
        let current = GovernanceScorecardTrendPoint {
            scorecard_id: "c".to_string(),
            generated_at_ns: 2,
            attested_receipt_coverage_millionths: 960_000, // improved
            privacy_epoch_consumption_millionths: 90_000,  // improved
            moonshot_override_frequency_millionths: 40_000, // improved
            conformance_pass_rate_millionths: 990_000,     // improved
            outcome: GovernanceScorecardOutcome::Healthy,
        };
        assert!(!is_trend_regression(&prev, &current));
    }

    #[test]
    fn is_trend_regression_coverage_drop() {
        let prev = GovernanceScorecardTrendPoint {
            scorecard_id: "p".to_string(),
            generated_at_ns: 1,
            attested_receipt_coverage_millionths: 960_000,
            privacy_epoch_consumption_millionths: 0,
            moonshot_override_frequency_millionths: 0,
            conformance_pass_rate_millionths: 1_000_000,
            outcome: GovernanceScorecardOutcome::Healthy,
        };
        let current = GovernanceScorecardTrendPoint {
            scorecard_id: "c".to_string(),
            generated_at_ns: 2,
            attested_receipt_coverage_millionths: 950_000, // dropped
            privacy_epoch_consumption_millionths: 0,
            moonshot_override_frequency_millionths: 0,
            conformance_pass_rate_millionths: 1_000_000,
            outcome: GovernanceScorecardOutcome::Healthy,
        };
        assert!(is_trend_regression(&prev, &current));
    }

    #[test]
    fn is_trend_regression_privacy_consumption_increase() {
        let prev = GovernanceScorecardTrendPoint {
            scorecard_id: "p".to_string(),
            generated_at_ns: 1,
            attested_receipt_coverage_millionths: 1_000_000,
            privacy_epoch_consumption_millionths: 100_000,
            moonshot_override_frequency_millionths: 0,
            conformance_pass_rate_millionths: 1_000_000,
            outcome: GovernanceScorecardOutcome::Healthy,
        };
        let current = GovernanceScorecardTrendPoint {
            scorecard_id: "c".to_string(),
            generated_at_ns: 2,
            attested_receipt_coverage_millionths: 1_000_000,
            privacy_epoch_consumption_millionths: 200_000, // increased
            moonshot_override_frequency_millionths: 0,
            conformance_pass_rate_millionths: 1_000_000,
            outcome: GovernanceScorecardOutcome::Healthy,
        };
        assert!(is_trend_regression(&prev, &current));
    }

    // -- Enrichment: missing serde roundtrips, std::error --

    #[test]
    fn privacy_budget_health_input_serde_roundtrip() {
        let input = test_privacy_budget();
        let json = serde_json::to_string(&input).unwrap();
        let restored: PrivacyBudgetHealthInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input, restored);
    }

    #[test]
    fn moonshot_governor_health_input_serde_roundtrip() {
        let input = test_moonshot_governor();
        let json = serde_json::to_string(&input).unwrap();
        let restored: MoonshotGovernorHealthInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input, restored);
    }

    #[test]
    fn cross_repo_conformance_input_serde_roundtrip() {
        let input = test_conformance();
        let json = serde_json::to_string(&input).unwrap();
        let restored: CrossRepoConformanceInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input, restored);
    }

    #[test]
    fn attested_receipt_coverage_summary_serde_roundtrip() {
        let summary = AttestedReceiptCoverageSummary {
            high_impact_total: 10,
            high_impact_with_valid_attestation: 8,
            high_impact_missing_or_invalid_attestation: 2,
            coverage_millionths: 800_000,
            threshold_pass: true,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let restored: AttestedReceiptCoverageSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, restored);
    }

    #[test]
    fn privacy_budget_health_summary_serde_roundtrip() {
        let summary = PrivacyBudgetHealthSummary {
            epoch: crate::security_epoch::SecurityEpoch::from_raw(1),
            epoch_epsilon_budget_millionths: 1_000_000,
            epoch_epsilon_spent_millionths: 500_000,
            epoch_delta_budget_millionths: 100_000,
            epoch_delta_spent_millionths: 10_000,
            epoch_consumption_millionths: 500_000,
            lifetime_epsilon_remaining_millionths: 5_000_000,
            lifetime_delta_remaining_millionths: 900_000,
            estimated_remaining_operations: 100,
            epsilon_burn_rate_per_hour_millionths: 50_000,
            delta_burn_rate_per_hour_millionths: 1_000,
            projected_epsilon_exhaustion_ns: Some(999_999_999),
            projected_delta_exhaustion_ns: None,
            overrun_incidents: 0,
            threshold_pass: true,
            near_term_exhaustion_warning: false,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let restored: PrivacyBudgetHealthSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, restored);
    }

    #[test]
    fn moonshot_governor_decision_summary_serde_roundtrip() {
        let summary = MoonshotGovernorDecisionSummary {
            total_decisions: 50,
            override_count: 3,
            kill_count: 1,
            override_frequency_millionths: 60_000,
            kill_rate_millionths: 20_000,
            mean_time_to_decision_ns: Some(5_000_000),
            active_moonshots: 4,
            paused_moonshots: 1,
            killed_moonshots: 1,
            threshold_pass: true,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let restored: MoonshotGovernorDecisionSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, restored);
    }

    #[test]
    fn cross_repo_conformance_stability_summary_serde_roundtrip() {
        let summary = CrossRepoConformanceStabilitySummary {
            release_id: "v1.0.0".to_string(),
            total_cells: 100,
            passed_cells: 95,
            failed_cells: 5,
            pass_rate_millionths: 950_000,
            universal_failures: 1,
            version_specific_failures: 4,
            outstanding_exemptions: 2,
            failure_class_distribution: BTreeMap::from([
                ("timeout".to_string(), 3),
                ("assertion".to_string(), 2),
            ]),
            threshold_pass: true,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let restored: CrossRepoConformanceStabilitySummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, restored);
    }

    #[test]
    fn governance_scorecard_error_std_error_trait() {
        let errs: [Box<dyn std::error::Error>; 4] = [
            Box::new(GovernanceScorecardError::InvalidInput {
                field: "f".to_string(),
                detail: "d".to_string(),
            }),
            Box::new(GovernanceScorecardError::SerializationFailure(
                "s".to_string(),
            )),
            Box::new(GovernanceScorecardError::SignatureFailure(
                "sig".to_string(),
            )),
            Box::new(GovernanceScorecardError::LedgerWriteFailure(
                "lw".to_string(),
            )),
        ];
        for e in &errs {
            assert!(!e.to_string().is_empty());
        }
        assert_eq!(errs.len(), 4);
    }

    #[test]
    fn outcome_ordering_full_chain() {
        assert!(GovernanceScorecardOutcome::Healthy < GovernanceScorecardOutcome::Warning);
        assert!(GovernanceScorecardOutcome::Warning < GovernanceScorecardOutcome::Critical);
        assert!(GovernanceScorecardOutcome::Healthy < GovernanceScorecardOutcome::Critical);
    }

    // -- Enrichment: PearlTower 2026-02-26 session 7 --

    #[test]
    fn verify_signature_standalone() {
        let req = test_request();
        let key = test_signing_key();
        let mut ledger = test_ledger();
        let publication =
            publish_governance_scorecard(&req, &key, &mut ledger, test_actor()).unwrap();
        // Standalone signature verification (not via publish pipeline).
        verify_governance_scorecard_signature(&publication).unwrap();
    }

    #[test]
    fn stable_codes_all_distinct() {
        let codes = [
            GovernanceScorecardError::InvalidInput {
                field: "x".into(),
                detail: "y".into(),
            }
            .stable_code(),
            GovernanceScorecardError::SerializationFailure("s".into()).stable_code(),
            GovernanceScorecardError::SignatureFailure("sig".into()).stable_code(),
            GovernanceScorecardError::LedgerWriteFailure("lw".into()).stable_code(),
        ];
        let unique: BTreeSet<&str> = codes.iter().copied().collect();
        assert_eq!(unique.len(), 4, "all error stable codes must be distinct");
    }

    #[test]
    fn markdown_report_warnings_section() {
        let mut req = test_request();
        // Create trend regression to add a warning (but not a blocker).
        req.historical = vec![GovernanceScorecardTrendPoint {
            scorecard_id: "prev".to_string(),
            generated_at_ns: 500_000_000,
            attested_receipt_coverage_millionths: 1_000_000,
            privacy_epoch_consumption_millionths: 0,
            moonshot_override_frequency_millionths: 0,
            conformance_pass_rate_millionths: 1_000_000,
            outcome: GovernanceScorecardOutcome::Healthy,
        }];
        let key = test_signing_key();
        let mut ledger = test_ledger();
        let publication =
            publish_governance_scorecard(&req, &key, &mut ledger, test_actor()).unwrap();
        assert_eq!(publication.outcome, GovernanceScorecardOutcome::Warning);
        let md = publication.to_markdown_report();
        assert!(
            md.contains("## Warnings"),
            "markdown report should include Warnings section"
        );
        assert!(md.contains("WARNING"));
    }

    #[test]
    fn empty_scorecard_run_id_derives_id() {
        let mut req = test_request();
        req.scorecard_run_id = "".to_string();
        let key = test_signing_key();
        let mut ledger = test_ledger();
        let publication =
            publish_governance_scorecard(&req, &key, &mut ledger, test_actor()).unwrap();
        assert!(
            publication.scorecard_id.starts_with("gov-scorecard-"),
            "derived ID should start with gov-scorecard-"
        );
        assert!(publication.scorecard_id.len() > "gov-scorecard-".len());
    }

    #[test]
    fn conformance_outstanding_exemptions_causes_critical() {
        let mut req = test_request();
        req.conformance.outstanding_exemptions = 10; // default max is 0
        let key = test_signing_key();
        let mut ledger = test_ledger();
        let publication =
            publish_governance_scorecard(&req, &key, &mut ledger, test_actor()).unwrap();
        assert_eq!(publication.outcome, GovernanceScorecardOutcome::Critical);
        assert!(
            publication
                .blockers
                .iter()
                .any(|b| b.contains("exemptions")),
            "blocker should mention exemptions"
        );
    }

    #[test]
    fn request_validate_empty_policy_id_fails() {
        let mut req = test_request();
        req.policy_id = "  ".to_string();
        let err = req.validate().unwrap_err();
        assert!(
            matches!(err, GovernanceScorecardError::InvalidInput { ref field, .. } if field == "policy_id")
        );
    }

    #[test]
    fn thresholds_serde_roundtrip_custom_values() {
        let t = GovernanceScorecardThresholds {
            min_attested_receipt_coverage_millionths: 800_000,
            max_privacy_overrun_incidents: 2,
            max_privacy_epoch_consumption_millionths: 500_000,
            warn_privacy_exhaustion_within_ns: Some(3_600_000_000_000),
            max_moonshot_override_frequency_millionths: 100_000,
            max_moonshot_kill_rate_millionths: 150_000,
            max_moonshot_mean_time_to_decision_ns: Some(86_400_000_000_000),
            min_conformance_pass_rate_millionths: 900_000,
            max_universal_failures: 1,
            max_version_specific_failures: 3,
            max_outstanding_exemptions: 2,
            fail_on_trend_regression: true,
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: GovernanceScorecardThresholds = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn is_trend_regression_by_privacy_consumption_increase() {
        let prev = GovernanceScorecardTrendPoint {
            scorecard_id: "old".to_string(),
            generated_at_ns: 100,
            attested_receipt_coverage_millionths: 950_000,
            privacy_epoch_consumption_millionths: 200_000,
            moonshot_override_frequency_millionths: 50_000,
            conformance_pass_rate_millionths: 980_000,
            outcome: GovernanceScorecardOutcome::Healthy,
        };
        let current = GovernanceScorecardTrendPoint {
            scorecard_id: "new".to_string(),
            generated_at_ns: 200,
            attested_receipt_coverage_millionths: 950_000,
            privacy_epoch_consumption_millionths: 300_000, // increased
            moonshot_override_frequency_millionths: 50_000,
            conformance_pass_rate_millionths: 980_000,
            outcome: GovernanceScorecardOutcome::Healthy,
        };
        assert!(is_trend_regression(&prev, &current));
    }
}
