//! Release gate for proof-carrying optimization pipeline readiness.
//!
//! This module does not implement optimization passes. It validates that a
//! delivered optimization pipeline satisfies release-gate requirements:
//! - every optimization pass emits a proof artifact
//! - artifacts are replayable by an independent verifier
//! - failed proofs force unoptimized fallback with receipt
//! - replay time stays within a bounded multiplier
//! - artifacts are content-addressed for evidence/replay integration
//!
//! Plan reference: Section 10.9 item 4 (`bd-2rx`), implementation ownership
//! for pipeline itself in 10.12.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{self, CanonicalValue};
use crate::hash_tiers::ContentHash;

const PROOF_RELEASE_GATE_DOMAIN: &[u8] = b"FrankenEngine.ProofReleaseGate.v1";

fn hash_bytes(data: &[u8]) -> [u8; 32] {
    *ContentHash::compute(data).as_bytes()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizationProofArtifact {
    pub optimization_pass: String,
    pub optimization_applied: bool,
    pub pre_ir_hash: [u8; 32],
    pub post_ir_hash: [u8; 32],
    pub ir_diff_size_bytes: u64,
    pub proof_hash: [u8; 32],
    pub verifier_version: String,
    pub proof_generation_time_ns: u64,
    pub verification_time_ns: u64,
    pub independent_replay_verified: bool,
    pub replay_command: String,
    pub proof_verified: bool,
    pub fallback_triggered: bool,
    pub fallback_receipt_id: Option<String>,
}

impl OptimizationProofArtifact {
    fn has_required_bundle_fields(&self) -> bool {
        !self.optimization_pass.trim().is_empty()
            && !self.verifier_version.trim().is_empty()
            && !self.replay_command.trim().is_empty()
            && self.ir_diff_size_bytes > 0
            && self.proof_generation_time_ns > 0
            && self.verification_time_ns > 0
            && self.proof_hash != [0u8; 32]
            && self.pre_ir_hash != [0u8; 32]
            && self.post_ir_hash != [0u8; 32]
    }

    fn fallback_is_valid(&self) -> bool {
        if self.proof_verified {
            return true;
        }
        !self.optimization_applied
            && self.fallback_triggered
            && self
                .fallback_receipt_id
                .as_ref()
                .is_some_and(|s| !s.trim().is_empty())
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = std::collections::BTreeMap::new();
        map.insert(
            "fallback_receipt_id".to_string(),
            match &self.fallback_receipt_id {
                Some(v) => CanonicalValue::String(v.clone()),
                None => CanonicalValue::Null,
            },
        );
        map.insert(
            "fallback_triggered".to_string(),
            CanonicalValue::Bool(self.fallback_triggered),
        );
        map.insert(
            "independent_replay_verified".to_string(),
            CanonicalValue::Bool(self.independent_replay_verified),
        );
        map.insert(
            "ir_diff_size_bytes".to_string(),
            CanonicalValue::U64(self.ir_diff_size_bytes),
        );
        map.insert(
            "optimization_applied".to_string(),
            CanonicalValue::Bool(self.optimization_applied),
        );
        map.insert(
            "optimization_pass".to_string(),
            CanonicalValue::String(self.optimization_pass.clone()),
        );
        map.insert(
            "post_ir_hash".to_string(),
            CanonicalValue::Bytes(self.post_ir_hash.to_vec()),
        );
        map.insert(
            "pre_ir_hash".to_string(),
            CanonicalValue::Bytes(self.pre_ir_hash.to_vec()),
        );
        map.insert(
            "proof_generation_time_ns".to_string(),
            CanonicalValue::U64(self.proof_generation_time_ns),
        );
        map.insert(
            "proof_hash".to_string(),
            CanonicalValue::Bytes(self.proof_hash.to_vec()),
        );
        map.insert(
            "proof_verified".to_string(),
            CanonicalValue::Bool(self.proof_verified),
        );
        map.insert(
            "replay_command".to_string(),
            CanonicalValue::String(self.replay_command.clone()),
        );
        map.insert(
            "verification_time_ns".to_string(),
            CanonicalValue::U64(self.verification_time_ns),
        );
        map.insert(
            "verifier_version".to_string(),
            CanonicalValue::String(self.verifier_version.clone()),
        );
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofChainBundle {
    pub candidate_version: String,
    pub compilation_id: String,
    pub original_compile_time_ns: u64,
    pub replay_time_ns: u64,
    pub archive_root: [u8; 32],
    pub archive_uri: String,
    pub artifacts: Vec<OptimizationProofArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestEvidenceBundle {
    pub unit_coverage_millionths: u32,
    pub mutation_score_millionths: u32,
    pub required_failure_mode_tests: u32,
    pub executed_failure_mode_tests: u32,
    pub required_e2e_scenarios: u32,
    pub executed_e2e_scenarios: u32,
    pub logging_artifact_count: u32,
    pub logging_artifact_max_age_ns: u64,
    pub trace_correlated_logging: bool,
}

impl TestEvidenceBundle {
    fn has_required_fields(&self) -> bool {
        self.required_failure_mode_tests > 0
            && self.required_e2e_scenarios > 0
            && self.logging_artifact_count > 0
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = std::collections::BTreeMap::new();
        map.insert(
            "executed_e2e_scenarios".to_string(),
            CanonicalValue::U64(u64::from(self.executed_e2e_scenarios)),
        );
        map.insert(
            "executed_failure_mode_tests".to_string(),
            CanonicalValue::U64(u64::from(self.executed_failure_mode_tests)),
        );
        map.insert(
            "logging_artifact_count".to_string(),
            CanonicalValue::U64(u64::from(self.logging_artifact_count)),
        );
        map.insert(
            "logging_artifact_max_age_ns".to_string(),
            CanonicalValue::U64(self.logging_artifact_max_age_ns),
        );
        map.insert(
            "mutation_score_millionths".to_string(),
            CanonicalValue::U64(u64::from(self.mutation_score_millionths)),
        );
        map.insert(
            "required_e2e_scenarios".to_string(),
            CanonicalValue::U64(u64::from(self.required_e2e_scenarios)),
        );
        map.insert(
            "required_failure_mode_tests".to_string(),
            CanonicalValue::U64(u64::from(self.required_failure_mode_tests)),
        );
        map.insert(
            "trace_correlated_logging".to_string(),
            CanonicalValue::Bool(self.trace_correlated_logging),
        );
        map.insert(
            "unit_coverage_millionths".to_string(),
            CanonicalValue::U64(u64::from(self.unit_coverage_millionths)),
        );
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseGateInput {
    pub trace_id: String,
    pub policy_id: String,
    pub expected_optimization_passes: BTreeSet<String>,
    pub bundle: ProofChainBundle,
    pub test_evidence: Option<TestEvidenceBundle>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseGateThresholds {
    pub max_replay_multiplier_millionths: u64,
    pub min_unit_coverage_millionths: u32,
    pub min_mutation_score_millionths: u32,
    pub max_logging_artifact_age_ns: u64,
    pub require_trace_correlated_logging: bool,
}

impl Default for ReleaseGateThresholds {
    fn default() -> Self {
        Self {
            // 5x replay bound from bead definition.
            max_replay_multiplier_millionths: 5_000_000,
            min_unit_coverage_millionths: 900_000,
            min_mutation_score_millionths: 850_000,
            max_logging_artifact_age_ns: 3_600_000_000_000,
            require_trace_correlated_logging: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GateFailureCode {
    MissingProofArtifact,
    MissingBundleField,
    ProofVerificationFailed,
    FallbackPathInvalid,
    IndependentReplayFailed,
    ReplayMultiplierExceeded,
    ArchiveNotContentAddressed,
    MissingTestEvidence,
    TestEvidenceBelowThreshold,
    LoggingArtifactsMissing,
    LoggingArtifactsStale,
    LoggingArtifactsUncorrelated,
}

impl fmt::Display for GateFailureCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingProofArtifact => f.write_str("missing_proof_artifact"),
            Self::MissingBundleField => f.write_str("missing_bundle_field"),
            Self::ProofVerificationFailed => f.write_str("proof_verification_failed"),
            Self::FallbackPathInvalid => f.write_str("fallback_path_invalid"),
            Self::IndependentReplayFailed => f.write_str("independent_replay_failed"),
            Self::ReplayMultiplierExceeded => f.write_str("replay_multiplier_exceeded"),
            Self::ArchiveNotContentAddressed => f.write_str("archive_not_content_addressed"),
            Self::MissingTestEvidence => f.write_str("missing_test_evidence"),
            Self::TestEvidenceBelowThreshold => f.write_str("test_evidence_below_threshold"),
            Self::LoggingArtifactsMissing => f.write_str("logging_artifacts_missing"),
            Self::LoggingArtifactsStale => f.write_str("logging_artifacts_stale"),
            Self::LoggingArtifactsUncorrelated => f.write_str("logging_artifacts_uncorrelated"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateFinding {
    pub code: GateFailureCode,
    pub optimization_pass: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofGateLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub optimization_pass: Option<String>,
    pub proof_status: Option<String>,
    pub proof_hash: Option<String>,
    pub fallback_triggered: Option<bool>,
    pub verification_time_ns: Option<u64>,
    pub ir_diff_size_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionDecisionArtifact {
    pub decision_id: String,
    pub candidate_version: String,
    pub pass: bool,
    pub replay_multiplier_millionths: u64,
    pub rollback_token: String,
    pub findings: Vec<GateFinding>,
    pub logs: Vec<ProofGateLogEvent>,
}

fn is_content_addressed_archive(uri: &str, root: &[u8; 32]) -> bool {
    uri.starts_with("cas://") && *root != [0u8; 32]
}

fn compute_replay_multiplier_millionths(replay_ns: u64, compile_ns: u64) -> u64 {
    if compile_ns == 0 {
        return u64::MAX;
    }
    let m = (replay_ns as u128 * 1_000_000) / (compile_ns as u128);
    if m > u64::MAX as u128 {
        u64::MAX
    } else {
        m as u64
    }
}

fn canonical_decision_value(
    input: &ReleaseGateInput,
    thresholds: &ReleaseGateThresholds,
    findings: &[GateFinding],
    pass: bool,
    replay_multiplier_millionths: u64,
) -> CanonicalValue {
    let mut map = std::collections::BTreeMap::new();
    let mut expected_passes: Vec<String> =
        input.expected_optimization_passes.iter().cloned().collect();
    expected_passes.sort();
    let expected_array = expected_passes
        .into_iter()
        .map(CanonicalValue::String)
        .collect::<Vec<_>>();
    let artifact_values = input
        .bundle
        .artifacts
        .iter()
        .map(OptimizationProofArtifact::canonical_value)
        .collect::<Vec<_>>();
    let finding_values = findings
        .iter()
        .map(|finding| {
            let mut inner = std::collections::BTreeMap::new();
            inner.insert(
                "code".to_string(),
                CanonicalValue::String(finding.code.to_string()),
            );
            inner.insert(
                "detail".to_string(),
                CanonicalValue::String(finding.detail.clone()),
            );
            inner.insert(
                "optimization_pass".to_string(),
                match &finding.optimization_pass {
                    Some(pass_name) => CanonicalValue::String(pass_name.clone()),
                    None => CanonicalValue::Null,
                },
            );
            CanonicalValue::Map(inner)
        })
        .collect::<Vec<_>>();

    map.insert(
        "archive_root".to_string(),
        CanonicalValue::Bytes(input.bundle.archive_root.to_vec()),
    );
    map.insert(
        "archive_uri".to_string(),
        CanonicalValue::String(input.bundle.archive_uri.clone()),
    );
    map.insert(
        "artifacts".to_string(),
        CanonicalValue::Array(artifact_values),
    );
    map.insert(
        "candidate_version".to_string(),
        CanonicalValue::String(input.bundle.candidate_version.clone()),
    );
    map.insert(
        "compilation_id".to_string(),
        CanonicalValue::String(input.bundle.compilation_id.clone()),
    );
    map.insert(
        "expected_optimization_passes".to_string(),
        CanonicalValue::Array(expected_array),
    );
    map.insert(
        "findings".to_string(),
        CanonicalValue::Array(finding_values),
    );
    map.insert("pass".to_string(), CanonicalValue::Bool(pass));
    map.insert(
        "test_evidence".to_string(),
        match &input.test_evidence {
            Some(evidence) => evidence.canonical_value(),
            None => CanonicalValue::Null,
        },
    );
    map.insert(
        "thresholds.max_logging_artifact_age_ns".to_string(),
        CanonicalValue::U64(thresholds.max_logging_artifact_age_ns),
    );
    map.insert(
        "thresholds.max_replay_multiplier_millionths".to_string(),
        CanonicalValue::U64(thresholds.max_replay_multiplier_millionths),
    );
    map.insert(
        "thresholds.min_mutation_score_millionths".to_string(),
        CanonicalValue::U64(u64::from(thresholds.min_mutation_score_millionths)),
    );
    map.insert(
        "thresholds.min_unit_coverage_millionths".to_string(),
        CanonicalValue::U64(u64::from(thresholds.min_unit_coverage_millionths)),
    );
    map.insert(
        "thresholds.require_trace_correlated_logging".to_string(),
        CanonicalValue::Bool(thresholds.require_trace_correlated_logging),
    );
    map.insert(
        "policy_id".to_string(),
        CanonicalValue::String(input.policy_id.clone()),
    );
    map.insert(
        "replay_multiplier_millionths".to_string(),
        CanonicalValue::U64(replay_multiplier_millionths),
    );
    map.insert(
        "trace_id".to_string(),
        CanonicalValue::String(input.trace_id.clone()),
    );
    CanonicalValue::Map(map)
}

fn decision_id_for(
    input: &ReleaseGateInput,
    thresholds: &ReleaseGateThresholds,
    findings: &[GateFinding],
    pass: bool,
    replay_multiplier_millionths: u64,
) -> String {
    let material = canonical_decision_value(
        input,
        thresholds,
        findings,
        pass,
        replay_multiplier_millionths,
    );
    let encoded = deterministic_serde::encode_value(&material);
    let mut preimage = Vec::with_capacity(PROOF_RELEASE_GATE_DOMAIN.len() + encoded.len());
    preimage.extend_from_slice(PROOF_RELEASE_GATE_DOMAIN);
    preimage.extend_from_slice(&encoded);
    to_hex(&hash_bytes(&preimage))
}

pub fn evaluate_release_gate(
    input: &ReleaseGateInput,
    thresholds: &ReleaseGateThresholds,
) -> PromotionDecisionArtifact {
    let mut findings: Vec<GateFinding> = Vec::new();
    let present_passes: BTreeSet<String> = input
        .bundle
        .artifacts
        .iter()
        .map(|artifact| artifact.optimization_pass.clone())
        .collect();

    for expected in &input.expected_optimization_passes {
        if !present_passes.contains(expected) {
            findings.push(GateFinding {
                code: GateFailureCode::MissingProofArtifact,
                optimization_pass: Some(expected.clone()),
                detail: "expected optimization pass has no proof artifact".to_string(),
            });
        }
    }

    for artifact in &input.bundle.artifacts {
        if !artifact.has_required_bundle_fields() {
            findings.push(GateFinding {
                code: GateFailureCode::MissingBundleField,
                optimization_pass: Some(artifact.optimization_pass.clone()),
                detail: "artifact bundle missing required fields".to_string(),
            });
        }

        if !artifact.proof_verified && artifact.optimization_applied {
            findings.push(GateFinding {
                code: GateFailureCode::ProofVerificationFailed,
                optimization_pass: Some(artifact.optimization_pass.clone()),
                detail: "optimization applied despite failed proof verification".to_string(),
            });
        }

        if !artifact.fallback_is_valid() {
            findings.push(GateFinding {
                code: GateFailureCode::FallbackPathInvalid,
                optimization_pass: Some(artifact.optimization_pass.clone()),
                detail: "proof failure did not trigger valid unoptimized fallback".to_string(),
            });
        }

        if artifact.proof_verified && !artifact.independent_replay_verified {
            findings.push(GateFinding {
                code: GateFailureCode::IndependentReplayFailed,
                optimization_pass: Some(artifact.optimization_pass.clone()),
                detail: "proof artifact did not pass independent replay verification".to_string(),
            });
        }
    }

    let replay_multiplier_millionths = compute_replay_multiplier_millionths(
        input.bundle.replay_time_ns,
        input.bundle.original_compile_time_ns,
    );
    if replay_multiplier_millionths > thresholds.max_replay_multiplier_millionths {
        findings.push(GateFinding {
            code: GateFailureCode::ReplayMultiplierExceeded,
            optimization_pass: None,
            detail: format!(
                "replay multiplier {} exceeds threshold {}",
                replay_multiplier_millionths, thresholds.max_replay_multiplier_millionths
            ),
        });
    }

    if !is_content_addressed_archive(&input.bundle.archive_uri, &input.bundle.archive_root) {
        findings.push(GateFinding {
            code: GateFailureCode::ArchiveNotContentAddressed,
            optimization_pass: None,
            detail: "artifact archive must be content-addressed (`cas://`) with non-zero root"
                .to_string(),
        });
    }

    match &input.test_evidence {
        None => findings.push(GateFinding {
            code: GateFailureCode::MissingTestEvidence,
            optimization_pass: None,
            detail: "missing comprehensive unit/e2e/logging test evidence bundle".to_string(),
        }),
        Some(test_evidence) => {
            if !test_evidence.has_required_fields() {
                findings.push(GateFinding {
                    code: GateFailureCode::TestEvidenceBelowThreshold,
                    optimization_pass: None,
                    detail:
                        "test evidence bundle missing required obligations (failure-mode/e2e/logging)"
                            .to_string(),
                });
            }

            if test_evidence.unit_coverage_millionths < thresholds.min_unit_coverage_millionths {
                findings.push(GateFinding {
                    code: GateFailureCode::TestEvidenceBelowThreshold,
                    optimization_pass: None,
                    detail: format!(
                        "unit coverage {} below threshold {}",
                        test_evidence.unit_coverage_millionths,
                        thresholds.min_unit_coverage_millionths
                    ),
                });
            }

            if test_evidence.mutation_score_millionths < thresholds.min_mutation_score_millionths {
                findings.push(GateFinding {
                    code: GateFailureCode::TestEvidenceBelowThreshold,
                    optimization_pass: None,
                    detail: format!(
                        "mutation score {} below threshold {}",
                        test_evidence.mutation_score_millionths,
                        thresholds.min_mutation_score_millionths
                    ),
                });
            }

            if test_evidence.executed_failure_mode_tests < test_evidence.required_failure_mode_tests
            {
                findings.push(GateFinding {
                    code: GateFailureCode::TestEvidenceBelowThreshold,
                    optimization_pass: None,
                    detail: format!(
                        "failure-mode tests executed {} below required {}",
                        test_evidence.executed_failure_mode_tests,
                        test_evidence.required_failure_mode_tests
                    ),
                });
            }

            if test_evidence.executed_e2e_scenarios < test_evidence.required_e2e_scenarios {
                findings.push(GateFinding {
                    code: GateFailureCode::TestEvidenceBelowThreshold,
                    optimization_pass: None,
                    detail: format!(
                        "e2e scenarios executed {} below required {}",
                        test_evidence.executed_e2e_scenarios, test_evidence.required_e2e_scenarios
                    ),
                });
            }

            if test_evidence.logging_artifact_count == 0 {
                findings.push(GateFinding {
                    code: GateFailureCode::LoggingArtifactsMissing,
                    optimization_pass: None,
                    detail: "no structured test/e2e logging artifacts present".to_string(),
                });
            }

            if test_evidence.logging_artifact_max_age_ns > thresholds.max_logging_artifact_age_ns {
                findings.push(GateFinding {
                    code: GateFailureCode::LoggingArtifactsStale,
                    optimization_pass: None,
                    detail: format!(
                        "logging artifacts stale: max_age_ns={} threshold_ns={}",
                        test_evidence.logging_artifact_max_age_ns,
                        thresholds.max_logging_artifact_age_ns
                    ),
                });
            }

            if thresholds.require_trace_correlated_logging
                && !test_evidence.trace_correlated_logging
            {
                findings.push(GateFinding {
                    code: GateFailureCode::LoggingArtifactsUncorrelated,
                    optimization_pass: None,
                    detail:
                        "structured test/e2e logs are not trace-correlated for deterministic replay"
                            .to_string(),
                });
            }
        }
    }

    let pass = findings.is_empty();
    let decision_id = decision_id_for(
        input,
        thresholds,
        &findings,
        pass,
        replay_multiplier_millionths,
    );
    let rollback_token = format!("rollback-{}", &decision_id[..16]);

    let mut logs = Vec::new();
    for artifact in &input.bundle.artifacts {
        logs.push(ProofGateLogEvent {
            trace_id: input.trace_id.clone(),
            decision_id: decision_id.clone(),
            policy_id: input.policy_id.clone(),
            component: "proof_release_gate".to_string(),
            event: "optimization_proof_evaluated".to_string(),
            outcome: if artifact.proof_verified {
                "verified"
            } else {
                "failed"
            }
            .to_string(),
            error_code: if artifact.proof_verified {
                None
            } else {
                Some("proof_verification_failed".to_string())
            },
            optimization_pass: Some(artifact.optimization_pass.clone()),
            proof_status: Some(if artifact.proof_verified {
                "verified".to_string()
            } else {
                "failed".to_string()
            }),
            proof_hash: Some(to_hex(&artifact.proof_hash)),
            fallback_triggered: Some(artifact.fallback_triggered),
            verification_time_ns: Some(artifact.verification_time_ns),
            ir_diff_size_bytes: Some(artifact.ir_diff_size_bytes),
        });
    }

    logs.push(ProofGateLogEvent {
        trace_id: input.trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: input.policy_id.clone(),
        component: "proof_release_gate".to_string(),
        event: "release_gate_decision".to_string(),
        outcome: if pass { "pass" } else { "fail" }.to_string(),
        error_code: findings.first().map(|f| f.code.to_string()),
        optimization_pass: None,
        proof_status: None,
        proof_hash: None,
        fallback_triggered: None,
        verification_time_ns: None,
        ir_diff_size_bytes: None,
    });

    PromotionDecisionArtifact {
        decision_id,
        candidate_version: input.bundle.candidate_version.clone(),
        pass,
        replay_multiplier_millionths,
        rollback_token,
        findings,
        logs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(label: &str) -> [u8; 32] {
        hash_bytes(label.as_bytes())
    }

    fn ok_artifact(pass_name: &str) -> OptimizationProofArtifact {
        OptimizationProofArtifact {
            optimization_pass: pass_name.to_string(),
            optimization_applied: true,
            pre_ir_hash: hash("pre"),
            post_ir_hash: hash("post"),
            ir_diff_size_bytes: 48,
            proof_hash: hash("proof"),
            verifier_version: "verifier-v1".to_string(),
            proof_generation_time_ns: 1_000,
            verification_time_ns: 2_000,
            independent_replay_verified: true,
            replay_command: format!("verify --pass {pass_name}"),
            proof_verified: true,
            fallback_triggered: false,
            fallback_receipt_id: None,
        }
    }

    fn base_input() -> ReleaseGateInput {
        let mut expected = BTreeSet::new();
        expected.insert("inline".to_string());
        expected.insert("dce".to_string());

        ReleaseGateInput {
            trace_id: "trace-gate-1".to_string(),
            policy_id: "policy-opt-gate".to_string(),
            expected_optimization_passes: expected,
            bundle: ProofChainBundle {
                candidate_version: "candidate-2026-02-20".to_string(),
                compilation_id: "compile-0001".to_string(),
                original_compile_time_ns: 50_000_000,
                replay_time_ns: 200_000_000,
                archive_root: hash("archive-root"),
                archive_uri: "cas://proof-chain/compile-0001".to_string(),
                artifacts: vec![ok_artifact("inline"), ok_artifact("dce")],
            },
            test_evidence: Some(TestEvidenceBundle {
                unit_coverage_millionths: 940_000,
                mutation_score_millionths: 900_000,
                required_failure_mode_tests: 12,
                executed_failure_mode_tests: 12,
                required_e2e_scenarios: 9,
                executed_e2e_scenarios: 9,
                logging_artifact_count: 18,
                logging_artifact_max_age_ns: 600_000_000_000,
                trace_correlated_logging: true,
            }),
        }
    }

    #[test]
    fn release_gate_passes_for_complete_replayable_pipeline() {
        let input = base_input();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(decision.pass);
        assert!(decision.findings.is_empty());
        assert_eq!(decision.logs.len(), 3); // 2 artifacts + 1 summary
        assert_eq!(decision.replay_multiplier_millionths, 4_000_000);
    }

    #[test]
    fn release_gate_fails_when_expected_pass_artifact_missing() {
        let mut input = base_input();
        input.bundle.artifacts = vec![ok_artifact("inline")];
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::MissingProofArtifact)
        );
    }

    #[test]
    fn release_gate_fails_when_proof_fails_but_optimization_applied() {
        let mut input = base_input();
        input.bundle.artifacts[0].proof_verified = false;
        input.bundle.artifacts[0].optimization_applied = true;
        input.bundle.artifacts[0].fallback_triggered = false;
        input.bundle.artifacts[0].fallback_receipt_id = None;
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::ProofVerificationFailed)
        );
    }

    #[test]
    fn release_gate_requires_fallback_receipt_on_failed_proof() {
        let mut input = base_input();
        input.bundle.artifacts[0].proof_verified = false;
        input.bundle.artifacts[0].optimization_applied = false;
        input.bundle.artifacts[0].fallback_triggered = false;
        input.bundle.artifacts[0].fallback_receipt_id = None;
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::FallbackPathInvalid)
        );
    }

    #[test]
    fn release_gate_fails_when_replay_multiplier_exceeds_threshold() {
        let mut input = base_input();
        input.bundle.replay_time_ns = 700_000_000;
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::ReplayMultiplierExceeded)
        );
    }

    #[test]
    fn release_gate_decision_is_deterministic() {
        let input = base_input();
        let a = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        let b = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert_eq!(a.decision_id, b.decision_id);
        assert_eq!(a, b);
    }

    // ── GateFailureCode ─────────────────────────────────────────────

    #[test]
    fn gate_failure_code_display() {
        assert_eq!(
            format!("{}", GateFailureCode::MissingProofArtifact),
            "missing_proof_artifact"
        );
        assert_eq!(
            format!("{}", GateFailureCode::MissingBundleField),
            "missing_bundle_field"
        );
        assert_eq!(
            format!("{}", GateFailureCode::ProofVerificationFailed),
            "proof_verification_failed"
        );
        assert_eq!(
            format!("{}", GateFailureCode::FallbackPathInvalid),
            "fallback_path_invalid"
        );
        assert_eq!(
            format!("{}", GateFailureCode::IndependentReplayFailed),
            "independent_replay_failed"
        );
        assert_eq!(
            format!("{}", GateFailureCode::ReplayMultiplierExceeded),
            "replay_multiplier_exceeded"
        );
        assert_eq!(
            format!("{}", GateFailureCode::ArchiveNotContentAddressed),
            "archive_not_content_addressed"
        );
        assert_eq!(
            format!("{}", GateFailureCode::MissingTestEvidence),
            "missing_test_evidence"
        );
        assert_eq!(
            format!("{}", GateFailureCode::TestEvidenceBelowThreshold),
            "test_evidence_below_threshold"
        );
        assert_eq!(
            format!("{}", GateFailureCode::LoggingArtifactsMissing),
            "logging_artifacts_missing"
        );
        assert_eq!(
            format!("{}", GateFailureCode::LoggingArtifactsStale),
            "logging_artifacts_stale"
        );
        assert_eq!(
            format!("{}", GateFailureCode::LoggingArtifactsUncorrelated),
            "logging_artifacts_uncorrelated"
        );
    }

    #[test]
    fn gate_failure_code_ordering() {
        assert!(GateFailureCode::MissingProofArtifact < GateFailureCode::MissingBundleField);
        assert!(
            GateFailureCode::ReplayMultiplierExceeded < GateFailureCode::ArchiveNotContentAddressed
        );
        assert!(GateFailureCode::ArchiveNotContentAddressed < GateFailureCode::MissingTestEvidence);
    }

    #[test]
    fn gate_failure_code_serde_roundtrip() {
        for code in [
            GateFailureCode::MissingProofArtifact,
            GateFailureCode::MissingBundleField,
            GateFailureCode::ProofVerificationFailed,
            GateFailureCode::FallbackPathInvalid,
            GateFailureCode::IndependentReplayFailed,
            GateFailureCode::ReplayMultiplierExceeded,
            GateFailureCode::ArchiveNotContentAddressed,
            GateFailureCode::MissingTestEvidence,
            GateFailureCode::TestEvidenceBelowThreshold,
            GateFailureCode::LoggingArtifactsMissing,
            GateFailureCode::LoggingArtifactsStale,
            GateFailureCode::LoggingArtifactsUncorrelated,
        ] {
            let json = serde_json::to_string(&code).unwrap();
            let back: GateFailureCode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, code);
        }
    }

    // ── ReleaseGateThresholds ───────────────────────────────────────

    #[test]
    fn thresholds_default() {
        let t = ReleaseGateThresholds::default();
        assert_eq!(t.max_replay_multiplier_millionths, 5_000_000);
        assert_eq!(t.min_unit_coverage_millionths, 900_000);
        assert_eq!(t.min_mutation_score_millionths, 850_000);
        assert_eq!(t.max_logging_artifact_age_ns, 3_600_000_000_000);
        assert!(t.require_trace_correlated_logging);
    }

    #[test]
    fn thresholds_serde_roundtrip() {
        let t = ReleaseGateThresholds {
            max_replay_multiplier_millionths: 3_000_000,
            min_unit_coverage_millionths: 910_000,
            min_mutation_score_millionths: 870_000,
            max_logging_artifact_age_ns: 1_200_000_000_000,
            require_trace_correlated_logging: false,
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: ReleaseGateThresholds = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }

    // ── compute_replay_multiplier ───────────────────────────────────

    #[test]
    fn replay_multiplier_normal() {
        assert_eq!(
            compute_replay_multiplier_millionths(200_000_000, 50_000_000),
            4_000_000
        );
    }

    #[test]
    fn replay_multiplier_zero_compile_time() {
        assert_eq!(compute_replay_multiplier_millionths(100, 0), u64::MAX);
    }

    #[test]
    fn replay_multiplier_one_to_one() {
        assert_eq!(compute_replay_multiplier_millionths(100, 100), 1_000_000);
    }

    // ── is_content_addressed_archive ────────────────────────────────

    #[test]
    fn content_addressed_archive_valid() {
        assert!(is_content_addressed_archive("cas://foo", &hash("x")));
    }

    #[test]
    fn content_addressed_archive_wrong_scheme() {
        assert!(!is_content_addressed_archive("https://foo", &hash("x")));
    }

    #[test]
    fn content_addressed_archive_zero_root() {
        assert!(!is_content_addressed_archive("cas://foo", &[0u8; 32]));
    }

    // ── artifact validation ─────────────────────────────────────────

    #[test]
    fn artifact_missing_bundle_fields_detected() {
        let mut input = base_input();
        input.bundle.artifacts[0].optimization_pass = "  ".to_string();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::MissingBundleField)
        );
    }

    #[test]
    fn artifact_zero_proof_hash_is_missing_field() {
        let mut input = base_input();
        input.bundle.artifacts[0].proof_hash = [0u8; 32];
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::MissingBundleField)
        );
    }

    #[test]
    fn independent_replay_not_verified_fails() {
        let mut input = base_input();
        input.bundle.artifacts[0].proof_verified = true;
        input.bundle.artifacts[0].independent_replay_verified = false;
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::IndependentReplayFailed)
        );
    }

    #[test]
    fn archive_not_content_addressed_fails() {
        let mut input = base_input();
        input.bundle.archive_uri = "https://not-cas".to_string();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::ArchiveNotContentAddressed)
        );
    }

    // ── valid fallback path ─────────────────────────────────────────

    #[test]
    fn valid_fallback_with_receipt_passes() {
        let mut input = base_input();
        // Proof failed but correct fallback
        input.bundle.artifacts[0].proof_verified = false;
        input.bundle.artifacts[0].optimization_applied = false;
        input.bundle.artifacts[0].fallback_triggered = true;
        input.bundle.artifacts[0].fallback_receipt_id = Some("receipt-001".to_string());
        // This still has independent_replay_verified=true but proof_verified=false
        // → IndependentReplayFailed won't fire because the check is `proof_verified && !independent_replay_verified`
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        // Should not have FallbackPathInvalid or ProofVerificationFailed
        assert!(
            !decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::FallbackPathInvalid)
        );
        assert!(
            !decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::ProofVerificationFailed)
        );
    }

    // ── decision artifact structure ─────────────────────────────────

    #[test]
    fn decision_has_rollback_token() {
        let input = base_input();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(decision.rollback_token.starts_with("rollback-"));
        assert_eq!(decision.rollback_token.len(), "rollback-".len() + 16);
    }

    #[test]
    fn decision_candidate_version() {
        let input = base_input();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert_eq!(decision.candidate_version, "candidate-2026-02-20");
    }

    #[test]
    fn decision_logs_include_per_artifact_and_summary() {
        let input = base_input();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        // 2 artifacts + 1 summary
        assert_eq!(decision.logs.len(), 3);
        let summary = &decision.logs[2];
        assert_eq!(summary.event, "release_gate_decision");
        assert_eq!(summary.outcome, "pass");
    }

    #[test]
    fn decision_log_failed_proof_has_error_code() {
        let mut input = base_input();
        input.bundle.artifacts[0].proof_verified = false;
        input.bundle.artifacts[0].optimization_applied = false;
        input.bundle.artifacts[0].fallback_triggered = true;
        input.bundle.artifacts[0].fallback_receipt_id = Some("r".to_string());
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        let log = &decision.logs[0];
        assert_eq!(log.outcome, "failed");
        assert_eq!(log.error_code.as_deref(), Some("proof_verification_failed"));
    }

    // ── serde roundtrips ────────────────────────────────────────────

    #[test]
    fn optimization_proof_artifact_serde() {
        let artifact = ok_artifact("inline");
        let json = serde_json::to_string(&artifact).unwrap();
        let back: OptimizationProofArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(back, artifact);
    }

    #[test]
    fn proof_chain_bundle_serde() {
        let input = base_input();
        let json = serde_json::to_string(&input.bundle).unwrap();
        let back: ProofChainBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back, input.bundle);
    }

    #[test]
    fn promotion_decision_artifact_serde() {
        let input = base_input();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        let json = serde_json::to_string(&decision).unwrap();
        let back: PromotionDecisionArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(back, decision);
    }

    #[test]
    fn gate_finding_serde() {
        let finding = GateFinding {
            code: GateFailureCode::MissingProofArtifact,
            optimization_pass: Some("inline".to_string()),
            detail: "missing artifact".to_string(),
        };
        let json = serde_json::to_string(&finding).unwrap();
        let back: GateFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, finding);
    }

    // ── custom thresholds ───────────────────────────────────────────

    #[test]
    fn custom_replay_threshold_allows_higher_multiplier() {
        let mut input = base_input();
        input.bundle.replay_time_ns = 700_000_000; // 14x > 5x default
        let thresholds = ReleaseGateThresholds {
            max_replay_multiplier_millionths: 15_000_000, // 15x
            ..ReleaseGateThresholds::default()
        };
        let decision = evaluate_release_gate(&input, &thresholds);
        assert!(
            !decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::ReplayMultiplierExceeded)
        );
    }

    // ── has_required_bundle_fields edge cases ─────────────────────

    #[test]
    fn artifact_empty_verifier_version_is_missing_field() {
        let mut input = base_input();
        input.bundle.artifacts[0].verifier_version = "  ".to_string();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::MissingBundleField)
        );
    }

    #[test]
    fn artifact_empty_replay_command_is_missing_field() {
        let mut input = base_input();
        input.bundle.artifacts[0].replay_command = String::new();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::MissingBundleField)
        );
    }

    #[test]
    fn artifact_zero_ir_diff_size_is_missing_field() {
        let mut input = base_input();
        input.bundle.artifacts[0].ir_diff_size_bytes = 0;
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::MissingBundleField)
        );
    }

    #[test]
    fn artifact_zero_proof_gen_time_is_missing_field() {
        let mut input = base_input();
        input.bundle.artifacts[0].proof_generation_time_ns = 0;
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::MissingBundleField)
        );
    }

    #[test]
    fn artifact_zero_verification_time_is_missing_field() {
        let mut input = base_input();
        input.bundle.artifacts[0].verification_time_ns = 0;
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::MissingBundleField)
        );
    }

    #[test]
    fn artifact_zero_pre_ir_hash_is_missing_field() {
        let mut input = base_input();
        input.bundle.artifacts[0].pre_ir_hash = [0u8; 32];
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::MissingBundleField)
        );
    }

    #[test]
    fn artifact_zero_post_ir_hash_is_missing_field() {
        let mut input = base_input();
        input.bundle.artifacts[0].post_ir_hash = [0u8; 32];
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::MissingBundleField)
        );
    }

    // ── fallback edge cases ───────────────────────────────────────

    #[test]
    fn fallback_with_whitespace_only_receipt_is_invalid() {
        let mut input = base_input();
        input.bundle.artifacts[0].proof_verified = false;
        input.bundle.artifacts[0].optimization_applied = false;
        input.bundle.artifacts[0].fallback_triggered = true;
        input.bundle.artifacts[0].fallback_receipt_id = Some("   ".to_string());
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::FallbackPathInvalid)
        );
    }

    #[test]
    fn fallback_without_trigger_is_invalid() {
        let mut input = base_input();
        input.bundle.artifacts[0].proof_verified = false;
        input.bundle.artifacts[0].optimization_applied = false;
        input.bundle.artifacts[0].fallback_triggered = false;
        input.bundle.artifacts[0].fallback_receipt_id = Some("receipt-001".to_string());
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::FallbackPathInvalid)
        );
    }

    // ── test evidence fail-closed policy ───────────────────────────

    #[test]
    fn missing_test_evidence_fails_closed() {
        let mut input = base_input();
        input.test_evidence = None;
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::MissingTestEvidence)
        );
    }

    #[test]
    fn low_unit_coverage_fails_threshold() {
        let mut input = base_input();
        let evidence = input.test_evidence.as_mut().expect("test evidence");
        evidence.unit_coverage_millionths = 100_000;
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::TestEvidenceBelowThreshold)
        );
    }

    #[test]
    fn stale_logging_artifacts_fail_closed() {
        let mut input = base_input();
        let evidence = input.test_evidence.as_mut().expect("test evidence");
        evidence.logging_artifact_max_age_ns = 9_000_000_000_000;
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::LoggingArtifactsStale)
        );
    }

    #[test]
    fn uncorrelated_logging_fails_when_required() {
        let mut input = base_input();
        let evidence = input.test_evidence.as_mut().expect("test evidence");
        evidence.trace_correlated_logging = false;
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::LoggingArtifactsUncorrelated)
        );
    }

    // ── compute_replay_multiplier edge cases ──────────────────────

    #[test]
    fn replay_multiplier_sub_one_x() {
        // replay < compile → sub-1x multiplier
        assert!(compute_replay_multiplier_millionths(50, 100) < 1_000_000);
        assert_eq!(compute_replay_multiplier_millionths(50, 100), 500_000);
    }

    #[test]
    fn replay_multiplier_zero_replay_is_zero() {
        assert_eq!(compute_replay_multiplier_millionths(0, 100), 0);
    }

    // ── empty / extra artifacts ───────────────────────────────────

    #[test]
    fn empty_artifacts_with_expected_passes_fails() {
        let mut input = base_input();
        input.bundle.artifacts.clear();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(!decision.pass);
        // Should report missing for each expected pass
        let missing_count = decision
            .findings
            .iter()
            .filter(|f| f.code == GateFailureCode::MissingProofArtifact)
            .count();
        assert_eq!(missing_count, 2);
    }

    #[test]
    fn extra_artifact_beyond_expected_is_allowed() {
        let mut input = base_input();
        input.bundle.artifacts.push(ok_artifact("cse")); // extra, not in expected set
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(decision.pass);
    }

    #[test]
    fn no_expected_passes_with_empty_artifacts_passes() {
        let mut input = base_input();
        input.expected_optimization_passes.clear();
        input.bundle.artifacts.clear();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        // Should pass: no expected, no artifacts, archive is CAS, replay under threshold
        assert!(
            !decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::MissingProofArtifact)
        );
    }

    // ── multiple failures accumulate ──────────────────────────────

    #[test]
    fn multiple_failure_codes_accumulate() {
        let mut input = base_input();
        input.bundle.artifacts[0].proof_verified = false;
        input.bundle.artifacts[0].optimization_applied = true; // ProofVerificationFailed + FallbackPathInvalid
        input.bundle.archive_uri = "https://nope".to_string(); // ArchiveNotContentAddressed
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(!decision.pass);
        let codes: BTreeSet<GateFailureCode> = decision.findings.iter().map(|f| f.code).collect();
        assert!(codes.contains(&GateFailureCode::ProofVerificationFailed));
        assert!(codes.contains(&GateFailureCode::FallbackPathInvalid));
        assert!(codes.contains(&GateFailureCode::ArchiveNotContentAddressed));
    }

    // ── decision_id uniqueness ────────────────────────────────────

    #[test]
    fn decision_id_differs_for_different_inputs() {
        let input_a = base_input();
        let mut input_b = base_input();
        input_b.trace_id = "trace-gate-2".to_string();
        let a = evaluate_release_gate(&input_a, &ReleaseGateThresholds::default());
        let b = evaluate_release_gate(&input_b, &ReleaseGateThresholds::default());
        assert_ne!(a.decision_id, b.decision_id);
    }

    #[test]
    fn decision_id_is_valid_hex() {
        let input = base_input();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(decision.decision_id.len() == 64);
        assert!(decision.decision_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ── log event detail checks ───────────────────────────────────

    #[test]
    fn per_artifact_log_carries_proof_hash() {
        let input = base_input();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        for log in &decision.logs[..2] {
            assert!(log.proof_hash.is_some());
            assert_eq!(log.proof_hash.as_ref().unwrap().len(), 64);
        }
    }

    #[test]
    fn per_artifact_log_carries_timing_and_diff() {
        let input = base_input();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        let log = &decision.logs[0];
        assert_eq!(log.verification_time_ns, Some(2_000));
        assert_eq!(log.ir_diff_size_bytes, Some(48));
    }

    #[test]
    fn summary_log_on_failure_includes_first_finding_code() {
        let mut input = base_input();
        input.bundle.archive_uri = "https://bad".to_string();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        let summary = decision.logs.last().unwrap();
        assert_eq!(summary.outcome, "fail");
        assert!(summary.error_code.is_some());
    }

    #[test]
    fn summary_log_on_pass_has_no_error_code() {
        let input = base_input();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        let summary = decision.logs.last().unwrap();
        assert_eq!(summary.outcome, "pass");
        assert!(summary.error_code.is_none());
    }

    // ── serde roundtrips for remaining types ──────────────────────

    #[test]
    fn release_gate_input_serde() {
        let input = base_input();
        let json = serde_json::to_string(&input).unwrap();
        let back: ReleaseGateInput = serde_json::from_str(&json).unwrap();
        assert_eq!(back, input);
    }

    #[test]
    fn proof_gate_log_event_serde() {
        let input = base_input();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        for log in &decision.logs {
            let json = serde_json::to_string(log).unwrap();
            let back: ProofGateLogEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, log);
        }
    }

    // ── to_hex helper ─────────────────────────────────────────────

    #[test]
    fn to_hex_empty() {
        assert_eq!(to_hex(&[]), "");
    }

    #[test]
    fn to_hex_known_bytes() {
        assert_eq!(to_hex(&[0x00, 0xff, 0xab]), "00ffab");
    }

    // ── content_addressed_archive empty uri ───────────────────────

    #[test]
    fn content_addressed_archive_empty_uri() {
        assert!(!is_content_addressed_archive("", &hash("x")));
    }

    // ── replay at exact threshold boundary ────────────────────────

    #[test]
    fn replay_at_exact_threshold_passes() {
        let mut input = base_input();
        // 5x exactly: replay = 250M, compile = 50M → 5_000_000 millionths
        input.bundle.replay_time_ns = 250_000_000;
        input.bundle.original_compile_time_ns = 50_000_000;
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(
            !decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::ReplayMultiplierExceeded)
        );
    }

    #[test]
    fn replay_just_above_threshold_fails() {
        let mut input = base_input();
        // Just above 5x: replay = 251M, compile = 50M → 5_020_000 > 5_000_000
        input.bundle.replay_time_ns = 251_000_000;
        input.bundle.original_compile_time_ns = 50_000_000;
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::ReplayMultiplierExceeded)
        );
    }

    // -- Enrichment: serde roundtrips for untested types (PearlTower 2026-02-26) --

    #[test]
    fn test_evidence_bundle_serde_roundtrip() {
        let bundle = TestEvidenceBundle {
            unit_coverage_millionths: 800_000,
            mutation_score_millionths: 700_000,
            required_failure_mode_tests: 10,
            executed_failure_mode_tests: 9,
            required_e2e_scenarios: 5,
            executed_e2e_scenarios: 5,
            logging_artifact_count: 3,
            logging_artifact_max_age_ns: 1_000_000_000,
            trace_correlated_logging: true,
        };
        let json = serde_json::to_string(&bundle).unwrap();
        let back: TestEvidenceBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, back);
    }

    #[test]
    fn gate_failure_code_display_all_unique() {
        let codes = [
            GateFailureCode::MissingProofArtifact,
            GateFailureCode::MissingBundleField,
            GateFailureCode::ProofVerificationFailed,
            GateFailureCode::FallbackPathInvalid,
            GateFailureCode::IndependentReplayFailed,
            GateFailureCode::ReplayMultiplierExceeded,
            GateFailureCode::ArchiveNotContentAddressed,
            GateFailureCode::MissingTestEvidence,
            GateFailureCode::TestEvidenceBelowThreshold,
            GateFailureCode::LoggingArtifactsMissing,
            GateFailureCode::LoggingArtifactsStale,
            GateFailureCode::LoggingArtifactsUncorrelated,
        ];
        let displays: std::collections::BTreeSet<String> =
            codes.iter().map(|c| c.to_string()).collect();
        assert_eq!(displays.len(), 12);
    }

    // ── enrichment tests (PearlTower 2026-03-02) ─────────────────

    #[test]
    fn enrichment_gate_failure_code_copy_semantics() {
        let a = GateFailureCode::MissingProofArtifact;
        let b = a; // Copy
        assert_eq!(a, b);
        // Original still usable after copy
        assert_eq!(format!("{a}"), "missing_proof_artifact");
    }

    #[test]
    fn enrichment_gate_failure_code_btreeset_dedup() {
        let mut set = BTreeSet::new();
        set.insert(GateFailureCode::MissingProofArtifact);
        set.insert(GateFailureCode::MissingProofArtifact);
        set.insert(GateFailureCode::FallbackPathInvalid);
        assert_eq!(set.len(), 2);
        assert!(set.contains(&GateFailureCode::MissingProofArtifact));
        assert!(set.contains(&GateFailureCode::FallbackPathInvalid));
    }

    #[test]
    fn enrichment_gate_failure_code_ord_total_ordering() {
        let mut codes = [
            GateFailureCode::LoggingArtifactsUncorrelated,
            GateFailureCode::MissingProofArtifact,
            GateFailureCode::ArchiveNotContentAddressed,
            GateFailureCode::FallbackPathInvalid,
        ];
        codes.sort();
        // Verify sorted order matches derive(Ord) variant declaration order
        assert!(codes[0] <= codes[1]);
        assert!(codes[1] <= codes[2]);
        assert!(codes[2] <= codes[3]);
        assert_eq!(codes[0], GateFailureCode::MissingProofArtifact);
    }

    #[test]
    fn enrichment_optimization_proof_artifact_clone_independence() {
        let original = ok_artifact("inline");
        let mut cloned = original.clone();
        cloned.optimization_pass = "dce".to_string();
        cloned.proof_verified = false;
        // Original unchanged
        assert_eq!(original.optimization_pass, "inline");
        assert!(original.proof_verified);
    }

    #[test]
    fn enrichment_proof_chain_bundle_clone_independence() {
        let input = base_input();
        let mut cloned = input.bundle.clone();
        cloned.candidate_version = "candidate-modified".to_string();
        cloned.artifacts.clear();
        // Original unchanged
        assert_eq!(input.bundle.candidate_version, "candidate-2026-02-20");
        assert_eq!(input.bundle.artifacts.len(), 2);
    }

    #[test]
    fn enrichment_promotion_decision_artifact_clone_independence() {
        let input = base_input();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        let mut cloned = decision.clone();
        cloned.pass = !decision.pass;
        cloned.findings.push(GateFinding {
            code: GateFailureCode::MissingTestEvidence,
            optimization_pass: None,
            detail: "injected".to_string(),
        });
        // Original unchanged
        assert!(decision.pass);
        assert!(decision.findings.is_empty());
    }

    #[test]
    fn enrichment_gate_finding_json_field_names() {
        let finding = GateFinding {
            code: GateFailureCode::ReplayMultiplierExceeded,
            optimization_pass: None,
            detail: "exceeded".to_string(),
        };
        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("\"code\""));
        assert!(json.contains("\"optimization_pass\""));
        assert!(json.contains("\"detail\""));
    }

    #[test]
    fn enrichment_proof_gate_log_event_json_field_names() {
        let input = base_input();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        let json = serde_json::to_string(&decision.logs[0]).unwrap();
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"decision_id\""));
        assert!(json.contains("\"policy_id\""));
        assert!(json.contains("\"component\""));
        assert!(json.contains("\"event\""));
        assert!(json.contains("\"outcome\""));
        assert!(json.contains("\"optimization_pass\""));
        assert!(json.contains("\"proof_status\""));
        assert!(json.contains("\"proof_hash\""));
        assert!(json.contains("\"fallback_triggered\""));
        assert!(json.contains("\"verification_time_ns\""));
        assert!(json.contains("\"ir_diff_size_bytes\""));
    }

    #[test]
    fn enrichment_release_gate_thresholds_json_field_names() {
        let t = ReleaseGateThresholds::default();
        let json = serde_json::to_string(&t).unwrap();
        assert!(json.contains("\"max_replay_multiplier_millionths\""));
        assert!(json.contains("\"min_unit_coverage_millionths\""));
        assert!(json.contains("\"min_mutation_score_millionths\""));
        assert!(json.contains("\"max_logging_artifact_age_ns\""));
        assert!(json.contains("\"require_trace_correlated_logging\""));
    }

    #[test]
    fn enrichment_test_evidence_has_required_fields_zero_failure_tests() {
        let mut input = base_input();
        let evidence = input.test_evidence.as_mut().unwrap();
        evidence.required_failure_mode_tests = 0;
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::TestEvidenceBelowThreshold
                    && f.detail.contains("missing required obligations"))
        );
    }

    #[test]
    fn enrichment_test_evidence_has_required_fields_zero_e2e() {
        let mut input = base_input();
        let evidence = input.test_evidence.as_mut().unwrap();
        evidence.required_e2e_scenarios = 0;
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::TestEvidenceBelowThreshold
                    && f.detail.contains("missing required obligations"))
        );
    }

    #[test]
    fn enrichment_test_evidence_has_required_fields_zero_logging() {
        let mut input = base_input();
        let evidence = input.test_evidence.as_mut().unwrap();
        evidence.logging_artifact_count = 0;
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        // Should trigger both TestEvidenceBelowThreshold (required fields)
        // and LoggingArtifactsMissing
        let codes: BTreeSet<GateFailureCode> = decision.findings.iter().map(|f| f.code).collect();
        assert!(codes.contains(&GateFailureCode::TestEvidenceBelowThreshold));
        assert!(codes.contains(&GateFailureCode::LoggingArtifactsMissing));
    }

    #[test]
    fn enrichment_mutation_score_below_threshold_fails() {
        let mut input = base_input();
        let evidence = input.test_evidence.as_mut().unwrap();
        evidence.mutation_score_millionths = 100_000; // well below 850_000
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::TestEvidenceBelowThreshold
                    && f.detail.contains("mutation score"))
        );
    }

    #[test]
    fn enrichment_failure_mode_tests_below_required_fails() {
        let mut input = base_input();
        let evidence = input.test_evidence.as_mut().unwrap();
        evidence.executed_failure_mode_tests = 5; // below required 12
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::TestEvidenceBelowThreshold
                    && f.detail.contains("failure-mode tests"))
        );
    }

    #[test]
    fn enrichment_e2e_scenarios_below_required_fails() {
        let mut input = base_input();
        let evidence = input.test_evidence.as_mut().unwrap();
        evidence.executed_e2e_scenarios = 3; // below required 9
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::TestEvidenceBelowThreshold
                    && f.detail.contains("e2e scenarios"))
        );
    }

    #[test]
    fn enrichment_decision_id_changes_with_policy_id() {
        let input_a = base_input();
        let mut input_b = base_input();
        input_b.policy_id = "policy-different".to_string();
        let a = evaluate_release_gate(&input_a, &ReleaseGateThresholds::default());
        let b = evaluate_release_gate(&input_b, &ReleaseGateThresholds::default());
        assert_ne!(a.decision_id, b.decision_id);
    }

    #[test]
    fn enrichment_decision_id_changes_with_thresholds() {
        let input = base_input();
        let t_default = ReleaseGateThresholds::default();
        let t_custom = ReleaseGateThresholds {
            max_replay_multiplier_millionths: 99_000_000,
            ..ReleaseGateThresholds::default()
        };
        let a = evaluate_release_gate(&input, &t_default);
        let b = evaluate_release_gate(&input, &t_custom);
        assert_ne!(a.decision_id, b.decision_id);
    }

    #[test]
    fn enrichment_replay_multiplier_overflow_large_values() {
        // Very large replay relative to compile should not panic
        let result = compute_replay_multiplier_millionths(u64::MAX, 1);
        assert_eq!(result, u64::MAX);
    }

    #[test]
    fn enrichment_duplicate_artifact_pass_names_only_counted_once() {
        let mut input = base_input();
        // Two artifacts with same pass name "inline"
        input.bundle.artifacts = vec![
            ok_artifact("inline"),
            ok_artifact("inline"),
            ok_artifact("dce"),
        ];
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        // Both expected passes are covered, so no MissingProofArtifact
        assert!(
            !decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::MissingProofArtifact)
        );
        // Should have 4 logs: 3 artifacts + 1 summary
        assert_eq!(decision.logs.len(), 4);
    }

    #[test]
    fn enrichment_release_gate_input_without_evidence_serde() {
        let mut input = base_input();
        input.test_evidence = None;
        let json = serde_json::to_string(&input).unwrap();
        let back: ReleaseGateInput = serde_json::from_str(&json).unwrap();
        assert_eq!(back, input);
        assert!(back.test_evidence.is_none());
        assert!(json.contains("\"test_evidence\":null"));
    }

    #[test]
    fn enrichment_fallback_is_valid_when_proof_verified() {
        // When proof_verified is true, fallback_is_valid always returns true
        // regardless of other fallback fields
        let mut artifact = ok_artifact("inline");
        artifact.proof_verified = true;
        artifact.fallback_triggered = false;
        artifact.fallback_receipt_id = None;
        artifact.optimization_applied = true;
        assert!(artifact.fallback_is_valid());
    }

    #[test]
    fn enrichment_uncorrelated_logging_passes_when_not_required() {
        let mut input = base_input();
        let evidence = input.test_evidence.as_mut().unwrap();
        evidence.trace_correlated_logging = false;
        let thresholds = ReleaseGateThresholds {
            require_trace_correlated_logging: false,
            ..ReleaseGateThresholds::default()
        };
        let decision = evaluate_release_gate(&input, &thresholds);
        assert!(
            !decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::LoggingArtifactsUncorrelated)
        );
    }
}
