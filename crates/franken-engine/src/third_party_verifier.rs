//! Third-party verifier toolkit primitives for externally auditable claims.
//!
//! This module keeps verification deterministic and artifact-driven so
//! independent operators can validate benchmark, replay, and containment
//! claims without a running FrankenEngine control plane.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::benchmark_denominator::{
    PublicationContext, PublicationGateInput, evaluate_publication_gate,
};
use crate::causal_replay::CounterfactualConfig;
use crate::engine_object_id::EngineObjectId;
use crate::hash_tiers::ContentHash;
use crate::incident_replay_bundle::{BundleVerifier, CheckOutcome, IncidentReplayBundle};
use crate::quarantine_mesh_gate::GateValidationResult;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    SIGNATURE_LEN, SIGNING_KEY_LEN, Signature, SigningKey, VERIFICATION_KEY_LEN, VerificationKey,
    sign_preimage, verify_signature,
};

pub const THIRD_PARTY_VERIFIER_COMPONENT: &str = "third_party_verifier";
pub const DEFAULT_CONTAINMENT_LATENCY_SLA_NS: u64 = 500_000_000;

pub const EXIT_CODE_VERIFIED: i32 = 0;
pub const EXIT_CODE_PARTIALLY_VERIFIED: i32 = 24;
pub const EXIT_CODE_FAILED: i32 = 25;
pub const EXIT_CODE_INCONCLUSIVE: i32 = 26;

const EPSILON: f64 = 1e-12;
const CODE_BENCHMARK_EVAL: &str = "FE-TPV-BENCH-0001";
const CODE_BENCHMARK_SCORE: &str = "FE-TPV-BENCH-0002";
const CODE_BENCHMARK_PUBLISH: &str = "FE-TPV-BENCH-0003";
const CODE_BENCHMARK_BLOCKERS: &str = "FE-TPV-BENCH-0004";
const CODE_BENCHMARK_FAIRNESS: &str = "FE-TPV-BENCH-0005";
const CODE_REPLAY_PARSE: &str = "FE-TPV-REPLAY-0001";
const CODE_REPLAY_VERIFY: &str = "FE-TPV-REPLAY-0002";
const CODE_CONTAINMENT_COUNTS: &str = "FE-TPV-CONT-0001";
const CODE_CONTAINMENT_CRITERIA: &str = "FE-TPV-CONT-0002";
const CODE_CONTAINMENT_SLA: &str = "FE-TPV-CONT-0003";
const CODE_CONTAINMENT_INVARIANT: &str = "FE-TPV-CONT-0004";
const CODE_ATTESTATION_ENVELOPE: &str = "FE-TPV-ATTEST-0001";
const CODE_ATTESTATION_DIGEST: &str = "FE-TPV-ATTEST-0002";
const CODE_ATTESTATION_PARSE: &str = "FE-TPV-ATTEST-0003";
const CODE_ATTESTATION_SIGNATURE: &str = "FE-TPV-ATTEST-0004";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationVerdict {
    Verified,
    PartiallyVerified,
    Failed,
    Inconclusive,
}

impl VerificationVerdict {
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Verified => EXIT_CODE_VERIFIED,
            Self::PartiallyVerified => EXIT_CODE_PARTIALLY_VERIFIED,
            Self::Failed => EXIT_CODE_FAILED,
            Self::Inconclusive => EXIT_CODE_INCONCLUSIVE,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::PartiallyVerified => "partially_verified",
            Self::Failed => "failed",
            Self::Inconclusive => "inconclusive",
        }
    }
}

impl fmt::Display for VerificationVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationCheckResult {
    pub name: String,
    pub passed: bool,
    pub error_code: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThirdPartyVerificationReport {
    pub claim_type: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub verdict: VerificationVerdict,
    #[serde(default)]
    pub confidence_statement: String,
    #[serde(default)]
    pub scope_limitations: Vec<String>,
    pub checks: Vec<VerificationCheckResult>,
    pub events: Vec<VerifierEvent>,
}

impl ThirdPartyVerificationReport {
    pub fn exit_code(&self) -> i32 {
        self.verdict.exit_code()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimedBenchmarkOutcome {
    pub score_vs_node: f64,
    pub score_vs_bun: f64,
    pub publish_allowed: bool,
    #[serde(default)]
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkClaimBundle {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub input: PublicationGateInput,
    pub claimed: ClaimedBenchmarkOutcome,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayClaimBundle {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub verification_timestamp_ns: u64,
    pub current_epoch: u64,
    pub bundle: IncidentReplayBundle,
    #[serde(default)]
    pub signature_verification_key_hex: Option<String>,
    #[serde(default)]
    pub receipt_verification_keys_hex: BTreeMap<String, String>,
    #[serde(default)]
    pub counterfactual_configs: Vec<CounterfactualConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentClaimBundle {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub result: GateValidationResult,
    #[serde(default = "default_containment_latency_sla_ns")]
    pub detection_latency_sla_ns: u64,
}

fn default_containment_latency_sla_ns() -> u64 {
    DEFAULT_CONTAINMENT_LATENCY_SLA_NS
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationAttestationInput {
    pub report: ThirdPartyVerificationReport,
    pub issued_at_utc: String,
    pub verifier_name: String,
    pub verifier_version: String,
    pub verifier_environment: String,
    pub methodology: String,
    #[serde(default)]
    pub scope_limitations: Vec<String>,
    #[serde(default)]
    pub signing_key_hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationAttestation {
    pub claim_type: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub verdict: VerificationVerdict,
    pub issued_at_utc: String,
    pub verifier_name: String,
    pub verifier_version: String,
    pub verifier_environment: String,
    pub methodology: String,
    #[serde(default)]
    pub scope_limitations: Vec<String>,
    pub report_digest_hex: String,
    pub statement: String,
    #[serde(default)]
    pub signer_verification_key_hex: Option<String>,
    #[serde(default)]
    pub signature_hex: Option<String>,
    pub report: ThirdPartyVerificationReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VerificationAttestationPayload {
    claim_type: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    verdict: VerificationVerdict,
    issued_at_utc: String,
    verifier_name: String,
    verifier_version: String,
    verifier_environment: String,
    methodology: String,
    scope_limitations: Vec<String>,
    report_digest_hex: String,
    statement: String,
    report: ThirdPartyVerificationReport,
}

pub fn verify_benchmark_claim(bundle: &BenchmarkClaimBundle) -> ThirdPartyVerificationReport {
    let mut checks = Vec::new();
    let mut events = vec![event(
        bundle,
        "benchmark_verification_started",
        "pass",
        None,
    )];

    let ctx = PublicationContext::new(
        bundle.trace_id.clone(),
        bundle.decision_id.clone(),
        bundle.policy_id.clone(),
    );

    match evaluate_publication_gate(&bundle.input, &ctx) {
        Ok(recomputed) => {
            compare_float_check(
                &mut checks,
                "score_vs_node_matches",
                bundle.claimed.score_vs_node,
                recomputed.score_vs_node,
                CODE_BENCHMARK_SCORE,
            );
            compare_float_check(
                &mut checks,
                "score_vs_bun_matches",
                bundle.claimed.score_vs_bun,
                recomputed.score_vs_bun,
                CODE_BENCHMARK_SCORE,
            );

            if bundle.claimed.publish_allowed == recomputed.publish_allowed {
                pass_check(
                    &mut checks,
                    "publish_allowed_matches",
                    "claimed publish decision matches recomputed decision".to_string(),
                );
            } else {
                fail_check(
                    &mut checks,
                    "publish_allowed_matches",
                    CODE_BENCHMARK_PUBLISH,
                    format!(
                        "claimed publish_allowed={} but recomputed={}",
                        bundle.claimed.publish_allowed, recomputed.publish_allowed
                    ),
                );
            }

            let claimed_blockers = normalize_strings(&bundle.claimed.blockers);
            let actual_blockers = normalize_strings(&recomputed.blockers);
            if claimed_blockers == actual_blockers {
                pass_check(
                    &mut checks,
                    "blocker_set_matches",
                    "claimed blockers match recomputed blockers".to_string(),
                );
            } else {
                fail_check(
                    &mut checks,
                    "blocker_set_matches",
                    CODE_BENCHMARK_BLOCKERS,
                    format!(
                        "claimed blockers {:?} differ from recomputed {:?}",
                        claimed_blockers, actual_blockers
                    ),
                );
            }

            let node_ids = workload_id_set(&bundle.input.node_cases);
            let bun_ids = workload_id_set(&bundle.input.bun_cases);
            if node_ids == bun_ids {
                pass_check(
                    &mut checks,
                    "cross_runtime_workload_set_matches",
                    "node and bun workload sets are identical".to_string(),
                );
            } else {
                fail_check(
                    &mut checks,
                    "cross_runtime_workload_set_matches",
                    CODE_BENCHMARK_FAIRNESS,
                    format!(
                        "node workload ids {:?} differ from bun workload ids {:?}",
                        node_ids, bun_ids
                    ),
                );
            }
        }
        Err(error) => fail_check(
            &mut checks,
            "benchmark_gate_recompute",
            CODE_BENCHMARK_EVAL,
            format!("failed to recompute benchmark publication gate: {error}"),
        ),
    }

    let verdict = verdict_from_checks(&checks, false);
    events.push(event_with_verdict(
        bundle,
        "benchmark_verification_completed",
        verdict,
    ));
    append_failure_events(bundle, &checks, &mut events);

    build_report(bundle, "benchmark", verdict, checks, events)
}

pub fn verify_replay_claim(bundle: &ReplayClaimBundle) -> ThirdPartyVerificationReport {
    let mut checks = Vec::new();
    let mut events = vec![event(bundle, "replay_verification_started", "pass", None)];
    let mut saw_skipped = false;
    let verifier = BundleVerifier::new();

    append_report_checks(
        "integrity",
        &verifier.verify_integrity(&bundle.bundle, bundle.verification_timestamp_ns),
        &mut checks,
        &mut saw_skipped,
    );
    append_report_checks(
        "fidelity",
        &verifier.verify_replay(&bundle.bundle, bundle.verification_timestamp_ns),
        &mut checks,
        &mut saw_skipped,
    );

    if let Some(key_hex) = &bundle.signature_verification_key_hex {
        match parse_verification_key_hex(key_hex) {
            Ok(key) => append_report_checks(
                "signature",
                &verifier.verify_signature(&bundle.bundle, &key, bundle.verification_timestamp_ns),
                &mut checks,
                &mut saw_skipped,
            ),
            Err(error) => fail_check(&mut checks, "signature_key_parse", CODE_REPLAY_PARSE, error),
        }
    }

    if !bundle.receipt_verification_keys_hex.is_empty() {
        match parse_receipt_verification_keys(&bundle.receipt_verification_keys_hex) {
            Ok(keys) => append_report_checks(
                "receipts",
                &verifier.verify_receipts(
                    &bundle.bundle,
                    &keys,
                    SecurityEpoch::from_raw(bundle.current_epoch),
                    bundle.verification_timestamp_ns,
                ),
                &mut checks,
                &mut saw_skipped,
            ),
            Err(error) => fail_check(&mut checks, "receipt_key_parse", CODE_REPLAY_PARSE, error),
        }
    }

    if !bundle.counterfactual_configs.is_empty() {
        append_report_checks(
            "counterfactual",
            &verifier.verify_counterfactual(
                &bundle.bundle,
                &bundle.counterfactual_configs,
                bundle.verification_timestamp_ns,
            ),
            &mut checks,
            &mut saw_skipped,
        );
    }

    let verdict = verdict_from_checks(&checks, saw_skipped);
    events.push(event_with_verdict(
        bundle,
        "replay_verification_completed",
        verdict,
    ));
    append_failure_events(bundle, &checks, &mut events);

    build_report(bundle, "replay", verdict, checks, events)
}

pub fn verify_containment_claim(bundle: &ContainmentClaimBundle) -> ThirdPartyVerificationReport {
    let mut checks = Vec::new();
    let mut events = vec![event(
        bundle,
        "containment_verification_started",
        "pass",
        None,
    )];

    let total = bundle.result.scenarios.len();
    if total == 0 {
        fail_check(
            &mut checks,
            "scenario_set_non_empty",
            CODE_CONTAINMENT_COUNTS,
            "containment verification requires at least one scenario result".to_string(),
        );
    } else {
        pass_check(
            &mut checks,
            "scenario_set_non_empty",
            format!("scenario count={total}"),
        );
    }

    if total == bundle.result.total_scenarios {
        pass_check(
            &mut checks,
            "scenario_count_matches",
            format!(
                "scenarios={} and total_scenarios={}",
                total, bundle.result.total_scenarios
            ),
        );
    } else {
        fail_check(
            &mut checks,
            "scenario_count_matches",
            CODE_CONTAINMENT_COUNTS,
            format!(
                "scenarios={} but total_scenarios={}",
                total, bundle.result.total_scenarios
            ),
        );
    }

    let passed_count = bundle.result.scenarios.iter().filter(|s| s.passed).count();
    if passed_count == bundle.result.passed_scenarios {
        pass_check(
            &mut checks,
            "passed_count_matches",
            format!(
                "passed_scenarios={} and computed={}",
                bundle.result.passed_scenarios, passed_count
            ),
        );
    } else {
        fail_check(
            &mut checks,
            "passed_count_matches",
            CODE_CONTAINMENT_COUNTS,
            format!(
                "passed_scenarios={} but computed={}",
                bundle.result.passed_scenarios, passed_count
            ),
        );
    }

    let computed_overall = passed_count == total;
    if computed_overall == bundle.result.passed {
        pass_check(
            &mut checks,
            "overall_pass_flag_matches",
            format!(
                "result.passed={} and computed={}",
                bundle.result.passed, computed_overall
            ),
        );
    } else {
        fail_check(
            &mut checks,
            "overall_pass_flag_matches",
            CODE_CONTAINMENT_COUNTS,
            format!(
                "result.passed={} but computed={}",
                bundle.result.passed, computed_overall
            ),
        );
    }

    for scenario in &bundle.result.scenarios {
        let criteria_all_pass = scenario.criteria.iter().all(|c| c.passed);
        if scenario.criteria.is_empty() {
            fail_check(
                &mut checks,
                format!("criteria_consistency:{}", scenario.scenario_id),
                CODE_CONTAINMENT_CRITERIA,
                "scenario criteria list is empty".to_string(),
            );
        } else if criteria_all_pass == scenario.passed {
            pass_check(
                &mut checks,
                format!("criteria_consistency:{}", scenario.scenario_id),
                "scenario pass flag matches criterion outcomes".to_string(),
            );
        } else {
            fail_check(
                &mut checks,
                format!("criteria_consistency:{}", scenario.scenario_id),
                CODE_CONTAINMENT_CRITERIA,
                "scenario pass flag does not match criterion outcomes".to_string(),
            );
        }

        if scenario.detection_latency_ns > bundle.detection_latency_sla_ns {
            fail_check(
                &mut checks,
                format!("latency_sla:{}", scenario.scenario_id),
                CODE_CONTAINMENT_SLA,
                format!(
                    "detection latency {}ns exceeds SLA {}ns",
                    scenario.detection_latency_ns, bundle.detection_latency_sla_ns
                ),
            );
        } else {
            pass_check(
                &mut checks,
                format!("latency_sla:{}", scenario.scenario_id),
                format!(
                    "detection latency {}ns within SLA {}ns",
                    scenario.detection_latency_ns, bundle.detection_latency_sla_ns
                ),
            );
        }

        if !scenario.isolation_verified {
            fail_check(
                &mut checks,
                format!("isolation_verified:{}", scenario.scenario_id),
                CODE_CONTAINMENT_INVARIANT,
                "isolation invariant not satisfied".to_string(),
            );
        } else {
            pass_check(
                &mut checks,
                format!("isolation_verified:{}", scenario.scenario_id),
                format!("isolation_verified={}", scenario.isolation_verified),
            );
        }

        if !scenario.recovery_verified {
            fail_check(
                &mut checks,
                format!("recovery_verified:{}", scenario.scenario_id),
                CODE_CONTAINMENT_INVARIANT,
                "recovery invariant not satisfied".to_string(),
            );
        } else {
            pass_check(
                &mut checks,
                format!("recovery_verified:{}", scenario.scenario_id),
                format!("recovery_verified={}", scenario.recovery_verified),
            );
        }
    }

    let verdict = verdict_from_checks(&checks, false);
    events.push(event_with_verdict(
        bundle,
        "containment_verification_completed",
        verdict,
    ));
    append_failure_events(bundle, &checks, &mut events);

    build_report(bundle, "containment", verdict, checks, events)
}

pub fn generate_attestation(
    input: &VerificationAttestationInput,
) -> Result<VerificationAttestation, String> {
    let issued_at_utc = required_field(input.issued_at_utc.trim(), "issued_at_utc")?;
    let verifier_name = required_field(input.verifier_name.trim(), "verifier_name")?;
    let verifier_version = required_field(input.verifier_version.trim(), "verifier_version")?;
    let verifier_environment =
        required_field(input.verifier_environment.trim(), "verifier_environment")?;
    let methodology = required_field(input.methodology.trim(), "methodology")?;
    let scope_limitations = normalize_strings(&input.scope_limitations);
    let report_digest_hex = digest_report_hex(&input.report)?;
    let statement = format_attestation_statement(&AttestationStatementInput {
        verifier_name,
        verifier_version,
        trace_id: &input.report.trace_id,
        claim_type: &input.report.claim_type,
        verdict: input.report.verdict,
        issued_at_utc,
        methodology,
        verifier_environment,
        scope_limitations: &scope_limitations,
    });

    let mut attestation = VerificationAttestation {
        claim_type: input.report.claim_type.clone(),
        trace_id: input.report.trace_id.clone(),
        decision_id: input.report.decision_id.clone(),
        policy_id: input.report.policy_id.clone(),
        verdict: input.report.verdict,
        issued_at_utc: issued_at_utc.to_string(),
        verifier_name: verifier_name.to_string(),
        verifier_version: verifier_version.to_string(),
        verifier_environment: verifier_environment.to_string(),
        methodology: methodology.to_string(),
        scope_limitations,
        report_digest_hex,
        statement,
        signer_verification_key_hex: None,
        signature_hex: None,
        report: input.report.clone(),
    };

    if let Some(signing_key_hex) = &input.signing_key_hex {
        let signing_key = parse_signing_key_hex(signing_key_hex)?;
        let payload = attestation_payload(&attestation);
        let payload_bytes = encode_attestation_payload(&payload)?;
        let signature = sign_preimage(&signing_key, &payload_bytes)
            .map_err(|error| format!("failed to sign attestation payload: {error}"))?;
        attestation.signer_verification_key_hex = Some(signing_key.verification_key().to_hex());
        attestation.signature_hex = Some(encode_signature_hex(&signature));
    }

    Ok(attestation)
}

pub fn verify_attestation(attestation: &VerificationAttestation) -> ThirdPartyVerificationReport {
    let mut checks = Vec::new();
    let mut events = vec![event(
        attestation,
        "attestation_verification_started",
        "pass",
        None,
    )];
    let mut saw_skipped = false;

    if attestation.claim_type.trim().is_empty()
        || attestation.trace_id.trim().is_empty()
        || attestation.decision_id.trim().is_empty()
        || attestation.policy_id.trim().is_empty()
        || attestation.issued_at_utc.trim().is_empty()
        || attestation.verifier_name.trim().is_empty()
        || attestation.verifier_version.trim().is_empty()
        || attestation.verifier_environment.trim().is_empty()
        || attestation.methodology.trim().is_empty()
    {
        fail_check(
            &mut checks,
            "attestation_required_fields",
            CODE_ATTESTATION_ENVELOPE,
            "one or more required attestation fields are empty".to_string(),
        );
    } else {
        pass_check(
            &mut checks,
            "attestation_required_fields",
            "all required attestation fields are present".to_string(),
        );
    }

    if attestation.claim_type == attestation.report.claim_type {
        pass_check(
            &mut checks,
            "claim_type_matches_report",
            format!("claim_type={}", attestation.claim_type),
        );
    } else {
        fail_check(
            &mut checks,
            "claim_type_matches_report",
            CODE_ATTESTATION_ENVELOPE,
            format!(
                "attestation claim_type={} differs from embedded report claim_type={}",
                attestation.claim_type, attestation.report.claim_type
            ),
        );
    }

    if attestation.trace_id == attestation.report.trace_id
        && attestation.decision_id == attestation.report.decision_id
        && attestation.policy_id == attestation.report.policy_id
    {
        pass_check(
            &mut checks,
            "context_matches_report",
            "trace_id/decision_id/policy_id match embedded report".to_string(),
        );
    } else {
        fail_check(
            &mut checks,
            "context_matches_report",
            CODE_ATTESTATION_ENVELOPE,
            "trace_id/decision_id/policy_id differ from embedded report".to_string(),
        );
    }

    if attestation.verdict == attestation.report.verdict {
        pass_check(
            &mut checks,
            "verdict_matches_report",
            format!("verdict={}", verdict_label(attestation.verdict)),
        );
    } else {
        fail_check(
            &mut checks,
            "verdict_matches_report",
            CODE_ATTESTATION_ENVELOPE,
            format!(
                "attestation verdict={} differs from report verdict={}",
                verdict_label(attestation.verdict),
                verdict_label(attestation.report.verdict)
            ),
        );
    }

    match digest_report_hex(&attestation.report) {
        Ok(recomputed_digest) => {
            if recomputed_digest == attestation.report_digest_hex {
                pass_check(
                    &mut checks,
                    "report_digest_matches",
                    format!("report_digest_hex={}", attestation.report_digest_hex),
                );
            } else {
                fail_check(
                    &mut checks,
                    "report_digest_matches",
                    CODE_ATTESTATION_DIGEST,
                    format!(
                        "attestation report_digest_hex={} differs from recomputed={}",
                        attestation.report_digest_hex, recomputed_digest
                    ),
                );
            }
        }
        Err(error) => fail_check(
            &mut checks,
            "report_digest_matches",
            CODE_ATTESTATION_DIGEST,
            error,
        ),
    }

    let expected_statement = format_attestation_statement(&AttestationStatementInput {
        verifier_name: attestation.verifier_name.trim(),
        verifier_version: attestation.verifier_version.trim(),
        trace_id: attestation.trace_id.trim(),
        claim_type: &attestation.claim_type,
        verdict: attestation.verdict,
        issued_at_utc: attestation.issued_at_utc.trim(),
        methodology: attestation.methodology.trim(),
        verifier_environment: attestation.verifier_environment.trim(),
        scope_limitations: &attestation.scope_limitations,
    });
    if attestation.statement == expected_statement {
        pass_check(
            &mut checks,
            "statement_matches_canonical_template",
            "statement matches canonical attestation template".to_string(),
        );
    } else {
        fail_check(
            &mut checks,
            "statement_matches_canonical_template",
            CODE_ATTESTATION_ENVELOPE,
            "statement does not match canonical attestation template".to_string(),
        );
    }

    match (
        &attestation.signer_verification_key_hex,
        &attestation.signature_hex,
    ) {
        (Some(verification_key_hex), Some(signature_hex)) => {
            let payload = attestation_payload(attestation);
            match (
                encode_attestation_payload(&payload),
                parse_verification_key_hex(verification_key_hex),
                parse_signature_hex(signature_hex),
            ) {
                (Ok(payload_bytes), Ok(verification_key), Ok(signature)) => {
                    match verify_signature(&verification_key, &payload_bytes, &signature) {
                        Ok(()) => pass_check(
                            &mut checks,
                            "signature_valid",
                            "attestation payload signature verified".to_string(),
                        ),
                        Err(error) => fail_check(
                            &mut checks,
                            "signature_valid",
                            CODE_ATTESTATION_SIGNATURE,
                            format!("signature verification failed: {error}"),
                        ),
                    }
                }
                (payload_result, key_result, signature_result) => {
                    if let Err(error) = payload_result {
                        fail_check(
                            &mut checks,
                            "signature_payload_encode",
                            CODE_ATTESTATION_PARSE,
                            error,
                        );
                    }
                    if let Err(error) = key_result {
                        fail_check(
                            &mut checks,
                            "signature_key_parse",
                            CODE_ATTESTATION_PARSE,
                            error,
                        );
                    }
                    if let Err(error) = signature_result {
                        fail_check(
                            &mut checks,
                            "signature_parse",
                            CODE_ATTESTATION_PARSE,
                            error,
                        );
                    }
                }
            }
        }
        (None, None) => {
            saw_skipped = true;
            checks.push(VerificationCheckResult {
                name: "signature_valid".to_string(),
                passed: true,
                error_code: None,
                detail: "skipped: unsigned attestation".to_string(),
            });
        }
        _ => fail_check(
            &mut checks,
            "signature_presence_consistent",
            CODE_ATTESTATION_ENVELOPE,
            "signer_verification_key_hex and signature_hex must both be set or both be empty"
                .to_string(),
        ),
    }

    let verdict = verdict_from_checks(&checks, saw_skipped);
    events.push(event_with_verdict(
        attestation,
        "attestation_verification_completed",
        verdict,
    ));
    append_failure_events(attestation, &checks, &mut events);

    build_report(attestation, "attestation", verdict, checks, events)
}

pub fn render_attestation_summary(attestation: &VerificationAttestation) -> String {
    format!(
        "claim_type={} verdict={} signed={} verifier={} issued_at={}",
        attestation.claim_type,
        verdict_label(attestation.verdict),
        attestation.signature_hex.is_some(),
        format_args!(
            "{}@{}",
            attestation.verifier_name, attestation.verifier_version
        ),
        attestation.issued_at_utc,
    )
}

pub fn render_report_summary(report: &ThirdPartyVerificationReport) -> String {
    let failed = report.checks.iter().filter(|check| !check.passed).count();
    format!(
        "claim_type={} verdict={} checks={} failed={} limitations={} exit_code={} confidence=\"{}\"",
        report.claim_type,
        report.verdict,
        report.checks.len(),
        failed,
        report.scope_limitations.len(),
        report.exit_code(),
        report.confidence_statement,
    )
}

fn append_report_checks(
    phase: &str,
    report: &crate::incident_replay_bundle::VerificationReport,
    checks: &mut Vec<VerificationCheckResult>,
    saw_skipped: &mut bool,
) {
    for check in &report.checks {
        let name = format!("{phase}:{}", check.name);
        match &check.outcome {
            CheckOutcome::Pass => pass_check(checks, name, "pass".to_string()),
            CheckOutcome::Fail { reason } => {
                fail_check(checks, name, CODE_REPLAY_VERIFY, reason.clone())
            }
            CheckOutcome::Skipped { reason } => {
                *saw_skipped = true;
                checks.push(VerificationCheckResult {
                    name,
                    passed: true,
                    error_code: None,
                    detail: format!("skipped: {reason}"),
                });
            }
        }
    }
}

fn compare_float_check(
    checks: &mut Vec<VerificationCheckResult>,
    name: &str,
    claimed: f64,
    recomputed: f64,
    code: &str,
) {
    if (claimed - recomputed).abs() <= EPSILON {
        pass_check(
            checks,
            name.to_string(),
            format!("claimed={claimed:.12} recomputed={recomputed:.12}"),
        );
    } else {
        fail_check(
            checks,
            name.to_string(),
            code,
            format!("claimed={claimed:.12} recomputed={recomputed:.12}"),
        );
    }
}

fn verdict_from_checks(
    checks: &[VerificationCheckResult],
    saw_skipped: bool,
) -> VerificationVerdict {
    if checks.is_empty() {
        return VerificationVerdict::Inconclusive;
    }
    if checks.iter().any(|check| !check.passed) {
        return VerificationVerdict::Failed;
    }
    if saw_skipped {
        return VerificationVerdict::PartiallyVerified;
    }
    VerificationVerdict::Verified
}

fn pass_check(checks: &mut Vec<VerificationCheckResult>, name: impl Into<String>, detail: String) {
    checks.push(VerificationCheckResult {
        name: name.into(),
        passed: true,
        error_code: None,
        detail,
    });
}

fn fail_check(
    checks: &mut Vec<VerificationCheckResult>,
    name: impl Into<String>,
    error_code: &str,
    detail: String,
) {
    checks.push(VerificationCheckResult {
        name: name.into(),
        passed: false,
        error_code: Some(error_code.to_string()),
        detail,
    });
}

fn normalize_strings(values: &[String]) -> Vec<String> {
    let mut normalized: Vec<String> = values
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();
    normalized.sort();
    normalized.dedup();
    normalized
}

fn collect_scope_limitations(checks: &[VerificationCheckResult]) -> Vec<String> {
    let mut limits = BTreeSet::new();
    for check in checks {
        if let Some(detail) = check.detail.strip_prefix("skipped:") {
            let normalized = detail.trim();
            if !normalized.is_empty() {
                limits.insert(normalized.to_string());
            }
        }
    }
    limits.into_iter().collect()
}

fn confidence_statement(
    verdict: VerificationVerdict,
    total_checks: usize,
    failed_checks: usize,
    scope_limitations: &[String],
) -> String {
    match verdict {
        VerificationVerdict::Verified => {
            format!("all {total_checks} checks passed with no skipped verification scope")
        }
        VerificationVerdict::PartiallyVerified => {
            if scope_limitations.is_empty() {
                format!(
                    "all {total_checks} checks passed, but verification scope is partially constrained"
                )
            } else {
                format!(
                    "all {total_checks} checks passed with {} scope limitation(s): {}",
                    scope_limitations.len(),
                    scope_limitations.join("; "),
                )
            }
        }
        VerificationVerdict::Failed => {
            format!("{failed_checks} of {total_checks} checks failed; claim verification failed")
        }
        VerificationVerdict::Inconclusive => {
            "no verification checks were executed; claim remains inconclusive".to_string()
        }
    }
}

fn workload_id_set(cases: &[crate::benchmark_denominator::BenchmarkCase]) -> BTreeSet<String> {
    cases
        .iter()
        .map(|case| case.workload_id.trim().to_string())
        .filter(|id| !id.is_empty())
        .collect()
}

fn required_field<'a>(value: &'a str, field_name: &str) -> Result<&'a str, String> {
    if value.is_empty() {
        return Err(format!("{field_name} must not be empty"));
    }
    Ok(value)
}

fn digest_report_hex(report: &ThirdPartyVerificationReport) -> Result<String, String> {
    let bytes = serde_json::to_vec(report)
        .map_err(|error| format!("failed to encode verification report for digest: {error}"))?;
    Ok(ContentHash::compute(&bytes).to_hex())
}

struct AttestationStatementInput<'a> {
    verifier_name: &'a str,
    verifier_version: &'a str,
    trace_id: &'a str,
    claim_type: &'a str,
    verdict: VerificationVerdict,
    issued_at_utc: &'a str,
    methodology: &'a str,
    verifier_environment: &'a str,
    scope_limitations: &'a [String],
}

fn format_attestation_statement(input: &AttestationStatementInput<'_>) -> String {
    let AttestationStatementInput {
        verifier_name,
        verifier_version,
        trace_id,
        claim_type,
        verdict,
        issued_at_utc,
        methodology,
        verifier_environment,
        scope_limitations,
    } = input;
    let scope_text = if scope_limitations.is_empty() {
        "none".to_string()
    } else {
        scope_limitations.join("; ")
    };
    format!(
        "{verifier_name} {verifier_version} attests that {claim_type} claims for trace {trace_id} are {verdict} as of {issued_at_utc} using {methodology}. Environment: {verifier_environment}. Scope limitations: {scope_text}.",
        verdict = verdict_label(*verdict),
    )
}

fn attestation_payload(attestation: &VerificationAttestation) -> VerificationAttestationPayload {
    VerificationAttestationPayload {
        claim_type: attestation.claim_type.clone(),
        trace_id: attestation.trace_id.clone(),
        decision_id: attestation.decision_id.clone(),
        policy_id: attestation.policy_id.clone(),
        verdict: attestation.verdict,
        issued_at_utc: attestation.issued_at_utc.clone(),
        verifier_name: attestation.verifier_name.clone(),
        verifier_version: attestation.verifier_version.clone(),
        verifier_environment: attestation.verifier_environment.clone(),
        methodology: attestation.methodology.clone(),
        scope_limitations: attestation.scope_limitations.clone(),
        report_digest_hex: attestation.report_digest_hex.clone(),
        statement: attestation.statement.clone(),
        report: attestation.report.clone(),
    }
}

fn encode_attestation_payload(payload: &VerificationAttestationPayload) -> Result<Vec<u8>, String> {
    serde_json::to_vec(payload)
        .map_err(|error| format!("failed to encode attestation payload for signing: {error}"))
}

fn parse_signing_key_hex(raw_hex: &str) -> Result<SigningKey, String> {
    let trimmed = raw_hex.trim();
    let bytes = hex::decode(trimmed)
        .map_err(|error| format!("failed to decode signing key hex '{trimmed}': {error}"))?;
    if bytes.len() != SIGNING_KEY_LEN {
        return Err(format!(
            "signing key hex must decode to {SIGNING_KEY_LEN} bytes, got {}",
            bytes.len()
        ));
    }
    let mut key = [0u8; SIGNING_KEY_LEN];
    key.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(key))
}

fn parse_verification_key_hex(raw_hex: &str) -> Result<VerificationKey, String> {
    let trimmed = raw_hex.trim();
    let bytes = hex::decode(trimmed)
        .map_err(|error| format!("failed to decode verification key hex '{trimmed}': {error}"))?;
    if bytes.len() != VERIFICATION_KEY_LEN {
        return Err(format!(
            "verification key hex must decode to {VERIFICATION_KEY_LEN} bytes, got {}",
            bytes.len()
        ));
    }
    let mut key = [0u8; VERIFICATION_KEY_LEN];
    key.copy_from_slice(&bytes);
    Ok(VerificationKey::from_bytes(key))
}

fn parse_receipt_verification_keys(
    raw: &BTreeMap<String, String>,
) -> Result<BTreeMap<EngineObjectId, VerificationKey>, String> {
    let mut parsed = BTreeMap::new();
    for (signer_id_hex, key_hex) in raw {
        let signer_id = EngineObjectId::from_hex(signer_id_hex.trim())
            .map_err(|error| format!("invalid signer id '{signer_id_hex}': {error}"))?;
        let key = parse_verification_key_hex(key_hex)?;
        parsed.insert(signer_id, key);
    }
    Ok(parsed)
}

fn parse_signature_hex(raw_hex: &str) -> Result<Signature, String> {
    let trimmed = raw_hex.trim();
    let bytes = hex::decode(trimmed)
        .map_err(|error| format!("failed to decode signature hex '{trimmed}': {error}"))?;
    if bytes.len() != SIGNATURE_LEN {
        return Err(format!(
            "signature hex must decode to {SIGNATURE_LEN} bytes, got {}",
            bytes.len()
        ));
    }
    let mut signature = [0u8; SIGNATURE_LEN];
    signature.copy_from_slice(&bytes);
    Ok(Signature::from_bytes(signature))
}

fn encode_signature_hex(signature: &Signature) -> String {
    hex::encode(signature.to_bytes())
}

fn verdict_label(verdict: VerificationVerdict) -> &'static str {
    match verdict {
        VerificationVerdict::Verified => "verified",
        VerificationVerdict::PartiallyVerified => "partially_verified",
        VerificationVerdict::Failed => "failed",
        VerificationVerdict::Inconclusive => "inconclusive",
    }
}

fn event<T: ClaimContext>(
    ctx: &T,
    event: &str,
    outcome: &str,
    error_code: Option<&str>,
) -> VerifierEvent {
    VerifierEvent {
        trace_id: ctx.trace_id().to_string(),
        decision_id: ctx.decision_id().to_string(),
        policy_id: ctx.policy_id().to_string(),
        component: THIRD_PARTY_VERIFIER_COMPONENT.to_string(),
        event: event.to_string(),
        outcome: outcome.to_string(),
        error_code: error_code.map(str::to_string),
    }
}

fn event_with_verdict<T: ClaimContext>(
    ctx: &T,
    event_name: &str,
    verdict: VerificationVerdict,
) -> VerifierEvent {
    let outcome = match verdict {
        VerificationVerdict::Verified => "pass",
        VerificationVerdict::PartiallyVerified => "partial",
        VerificationVerdict::Failed => "fail",
        VerificationVerdict::Inconclusive => "inconclusive",
    };
    event(ctx, event_name, outcome, None)
}

fn append_failure_events<T: ClaimContext>(
    ctx: &T,
    checks: &[VerificationCheckResult],
    events: &mut Vec<VerifierEvent>,
) {
    for check in checks.iter().filter(|check| !check.passed) {
        events.push(event(
            ctx,
            &format!("check_failed:{}", check.name),
            "fail",
            check.error_code.as_deref(),
        ));
    }
}

fn build_report<T: ClaimContext>(
    ctx: &T,
    claim_type: &str,
    verdict: VerificationVerdict,
    checks: Vec<VerificationCheckResult>,
    events: Vec<VerifierEvent>,
) -> ThirdPartyVerificationReport {
    let scope_limitations = collect_scope_limitations(&checks);
    let failed_checks = checks.iter().filter(|check| !check.passed).count();
    let confidence_statement =
        confidence_statement(verdict, checks.len(), failed_checks, &scope_limitations);
    ThirdPartyVerificationReport {
        claim_type: claim_type.to_string(),
        trace_id: ctx.trace_id().to_string(),
        decision_id: ctx.decision_id().to_string(),
        policy_id: ctx.policy_id().to_string(),
        component: THIRD_PARTY_VERIFIER_COMPONENT.to_string(),
        verdict,
        confidence_statement,
        scope_limitations,
        checks,
        events,
    }
}

trait ClaimContext {
    fn trace_id(&self) -> &str;
    fn decision_id(&self) -> &str;
    fn policy_id(&self) -> &str;
}

impl ClaimContext for BenchmarkClaimBundle {
    fn trace_id(&self) -> &str {
        &self.trace_id
    }

    fn decision_id(&self) -> &str {
        &self.decision_id
    }

    fn policy_id(&self) -> &str {
        &self.policy_id
    }
}

impl ClaimContext for ReplayClaimBundle {
    fn trace_id(&self) -> &str {
        &self.trace_id
    }

    fn decision_id(&self) -> &str {
        &self.decision_id
    }

    fn policy_id(&self) -> &str {
        &self.policy_id
    }
}

impl ClaimContext for ContainmentClaimBundle {
    fn trace_id(&self) -> &str {
        &self.trace_id
    }

    fn decision_id(&self) -> &str {
        &self.decision_id
    }

    fn policy_id(&self) -> &str {
        &self.policy_id
    }
}

impl ClaimContext for VerificationAttestation {
    fn trace_id(&self) -> &str {
        &self.trace_id
    }

    fn decision_id(&self) -> &str {
        &self.decision_id
    }

    fn policy_id(&self) -> &str {
        &self.policy_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quarantine_mesh_gate::{CriterionResult, FaultScenarioResult, GateValidationResult};

    // ── helpers ──────────────────────────────────────────────────────

    fn make_scenario(id: &str, passed: bool, latency_ns: u64) -> FaultScenarioResult {
        let criteria = vec![CriterionResult {
            name: "crit_a".to_string(),
            passed,
            detail: "detail".to_string(),
        }];
        FaultScenarioResult {
            scenario_id: id.to_string(),
            fault_type: crate::quarantine_mesh_gate::FaultType::NetworkPartition,
            passed,
            criteria,
            receipts_emitted: 1,
            final_state: None,
            detection_latency_ns: latency_ns,
            isolation_verified: passed,
            recovery_verified: passed,
        }
    }

    fn make_gate_result(scenarios: Vec<FaultScenarioResult>) -> GateValidationResult {
        let total = scenarios.len();
        let passed_count = scenarios.iter().filter(|s| s.passed).count();
        let all_pass = passed_count == total;
        GateValidationResult {
            seed: 42,
            scenarios,
            passed: all_pass,
            total_scenarios: total,
            passed_scenarios: passed_count,
            events: Vec::new(),
            result_digest: "digest-test".to_string(),
        }
    }

    fn make_containment_bundle(result: GateValidationResult) -> ContainmentClaimBundle {
        ContainmentClaimBundle {
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            result,
            detection_latency_sla_ns: DEFAULT_CONTAINMENT_LATENCY_SLA_NS,
        }
    }

    fn make_report(verdict: VerificationVerdict) -> ThirdPartyVerificationReport {
        ThirdPartyVerificationReport {
            claim_type: "containment".to_string(),
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            component: THIRD_PARTY_VERIFIER_COMPONENT.to_string(),
            verdict,
            confidence_statement: "all checks passed".to_string(),
            scope_limitations: Vec::new(),
            checks: vec![VerificationCheckResult {
                name: "check1".to_string(),
                passed: true,
                error_code: None,
                detail: "ok".to_string(),
            }],
            events: Vec::new(),
        }
    }

    fn make_attestation_input(
        report: ThirdPartyVerificationReport,
        signing_key_hex: Option<String>,
    ) -> VerificationAttestationInput {
        VerificationAttestationInput {
            report,
            issued_at_utc: "2026-02-24T00:00:00Z".to_string(),
            verifier_name: "acme-verifier".to_string(),
            verifier_version: "1.0.0".to_string(),
            verifier_environment: "production".to_string(),
            methodology: "deterministic-replay".to_string(),
            scope_limitations: Vec::new(),
            signing_key_hex,
        }
    }

    // ── VerificationVerdict ─────────────────────────────────────────

    #[test]
    fn verdict_exit_code_verified() {
        assert_eq!(
            VerificationVerdict::Verified.exit_code(),
            EXIT_CODE_VERIFIED
        );
    }

    #[test]
    fn verdict_exit_code_partially_verified() {
        assert_eq!(
            VerificationVerdict::PartiallyVerified.exit_code(),
            EXIT_CODE_PARTIALLY_VERIFIED
        );
    }

    #[test]
    fn verdict_exit_code_failed() {
        assert_eq!(VerificationVerdict::Failed.exit_code(), EXIT_CODE_FAILED);
    }

    #[test]
    fn verdict_exit_code_inconclusive() {
        assert_eq!(
            VerificationVerdict::Inconclusive.exit_code(),
            EXIT_CODE_INCONCLUSIVE
        );
    }

    #[test]
    fn verdict_serde_roundtrip() {
        for verdict in [
            VerificationVerdict::Verified,
            VerificationVerdict::PartiallyVerified,
            VerificationVerdict::Failed,
            VerificationVerdict::Inconclusive,
        ] {
            let json = serde_json::to_string(&verdict).unwrap();
            let back: VerificationVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(back, verdict);
        }
    }

    // ── constants ───────────────────────────────────────────────────

    #[test]
    fn exit_code_constants() {
        assert_eq!(EXIT_CODE_VERIFIED, 0);
        assert_eq!(EXIT_CODE_PARTIALLY_VERIFIED, 24);
        assert_eq!(EXIT_CODE_FAILED, 25);
        assert_eq!(EXIT_CODE_INCONCLUSIVE, 26);
    }

    #[test]
    fn default_containment_sla() {
        assert_eq!(DEFAULT_CONTAINMENT_LATENCY_SLA_NS, 500_000_000);
    }

    // ── verify_containment_claim ────────────────────────────────────

    #[test]
    fn containment_all_pass_verified() {
        let scenarios = vec![
            make_scenario("s1", true, 100_000),
            make_scenario("s2", true, 200_000),
        ];
        let result = make_gate_result(scenarios);
        let bundle = make_containment_bundle(result);
        let report = verify_containment_claim(&bundle);
        assert_eq!(report.verdict, VerificationVerdict::Verified);
        assert_eq!(report.claim_type, "containment");
        assert!(report.checks.iter().all(|c| c.passed));
    }

    #[test]
    fn containment_scenario_count_mismatch() {
        let scenarios = vec![make_scenario("s1", true, 100_000)];
        let mut result = make_gate_result(scenarios);
        result.total_scenarios = 5; // mismatch: 1 scenario but total says 5
        let bundle = make_containment_bundle(result);
        let report = verify_containment_claim(&bundle);
        assert_eq!(report.verdict, VerificationVerdict::Failed);
        let failed = report
            .checks
            .iter()
            .find(|c| c.name == "scenario_count_matches")
            .unwrap();
        assert!(!failed.passed);
        assert_eq!(failed.error_code.as_deref(), Some(CODE_CONTAINMENT_COUNTS));
    }

    #[test]
    fn containment_passed_count_mismatch() {
        let scenarios = vec![make_scenario("s1", true, 100_000)];
        let mut result = make_gate_result(scenarios);
        result.passed_scenarios = 0; // says 0 passed but actually 1
        let bundle = make_containment_bundle(result);
        let report = verify_containment_claim(&bundle);
        assert_eq!(report.verdict, VerificationVerdict::Failed);
        let failed = report
            .checks
            .iter()
            .find(|c| c.name == "passed_count_matches")
            .unwrap();
        assert!(!failed.passed);
    }

    #[test]
    fn containment_overall_pass_flag_mismatch() {
        let scenarios = vec![make_scenario("s1", true, 100_000)];
        let mut result = make_gate_result(scenarios);
        result.passed = false; // 1/1 passed but overall says false
        let bundle = make_containment_bundle(result);
        let report = verify_containment_claim(&bundle);
        assert_eq!(report.verdict, VerificationVerdict::Failed);
        let failed = report
            .checks
            .iter()
            .find(|c| c.name == "overall_pass_flag_matches")
            .unwrap();
        assert!(!failed.passed);
    }

    #[test]
    fn containment_criteria_consistency_mismatch() {
        // Scenario says passed=true but its criterion says passed=false
        let mut scenario = make_scenario("s1", true, 100_000);
        scenario.criteria = vec![CriterionResult {
            name: "bad_crit".to_string(),
            passed: false,
            detail: "fail".to_string(),
        }];
        // Keep scenario.passed = true, creating an inconsistency
        let result = make_gate_result(vec![scenario]);
        let bundle = make_containment_bundle(result);
        let report = verify_containment_claim(&bundle);
        assert_eq!(report.verdict, VerificationVerdict::Failed);
        let failed = report
            .checks
            .iter()
            .find(|c| c.name == "criteria_consistency:s1")
            .unwrap();
        assert!(!failed.passed);
        assert_eq!(
            failed.error_code.as_deref(),
            Some(CODE_CONTAINMENT_CRITERIA)
        );
    }

    #[test]
    fn containment_latency_sla_exceeded() {
        let scenarios = vec![make_scenario("s1", true, 999_999_999)]; // way over 500ms SLA
        let result = make_gate_result(scenarios);
        let bundle = make_containment_bundle(result);
        let report = verify_containment_claim(&bundle);
        assert_eq!(report.verdict, VerificationVerdict::Failed);
        let failed = report
            .checks
            .iter()
            .find(|c| c.name == "latency_sla:s1")
            .unwrap();
        assert!(!failed.passed);
        assert_eq!(failed.error_code.as_deref(), Some(CODE_CONTAINMENT_SLA));
    }

    #[test]
    fn containment_latency_sla_within_limit() {
        let scenarios = vec![make_scenario("s1", true, 100_000_000)]; // 100ms < 500ms
        let result = make_gate_result(scenarios);
        let bundle = make_containment_bundle(result);
        let report = verify_containment_claim(&bundle);
        let check = report
            .checks
            .iter()
            .find(|c| c.name == "latency_sla:s1")
            .unwrap();
        assert!(check.passed);
    }

    #[test]
    fn containment_isolation_not_verified() {
        let mut scenario = make_scenario("s1", true, 100_000);
        scenario.isolation_verified = false;
        let result = make_gate_result(vec![scenario]);
        let bundle = make_containment_bundle(result);
        let report = verify_containment_claim(&bundle);
        assert_eq!(report.verdict, VerificationVerdict::Failed);
        let failed = report
            .checks
            .iter()
            .find(|c| c.name == "isolation_verified:s1")
            .unwrap();
        assert!(!failed.passed);
        assert_eq!(
            failed.error_code.as_deref(),
            Some(CODE_CONTAINMENT_INVARIANT)
        );
    }

    #[test]
    fn containment_recovery_not_verified() {
        let mut scenario = make_scenario("s1", true, 100_000);
        scenario.recovery_verified = false;
        let result = make_gate_result(vec![scenario]);
        let bundle = make_containment_bundle(result);
        let report = verify_containment_claim(&bundle);
        assert_eq!(report.verdict, VerificationVerdict::Failed);
        let failed = report
            .checks
            .iter()
            .find(|c| c.name == "recovery_verified:s1")
            .unwrap();
        assert!(!failed.passed);
    }

    #[test]
    fn containment_empty_scenarios_fail_closed() {
        let result = make_gate_result(Vec::new());
        let bundle = make_containment_bundle(result);
        let report = verify_containment_claim(&bundle);
        assert_eq!(report.verdict, VerificationVerdict::Failed);
        let failed = report
            .checks
            .iter()
            .find(|c| c.name == "scenario_set_non_empty")
            .unwrap();
        assert!(!failed.passed);
    }

    #[test]
    fn containment_failed_scenario_still_audits_sla_and_invariants() {
        let mut scenario = make_scenario("s1", false, 999_999_999);
        scenario.isolation_verified = false;
        scenario.recovery_verified = false;
        let result = make_gate_result(vec![scenario]);
        let bundle = make_containment_bundle(result);
        let report = verify_containment_claim(&bundle);
        let latency_check = report
            .checks
            .iter()
            .find(|c| c.name == "latency_sla:s1")
            .unwrap();
        assert!(!latency_check.passed);
        let isolation_check = report
            .checks
            .iter()
            .find(|c| c.name == "isolation_verified:s1")
            .unwrap();
        assert!(!isolation_check.passed);
        let recovery_check = report
            .checks
            .iter()
            .find(|c| c.name == "recovery_verified:s1")
            .unwrap();
        assert!(!recovery_check.passed);
    }

    #[test]
    fn containment_passed_scenario_requires_criteria() {
        let mut scenario = make_scenario("s1", true, 100_000);
        scenario.criteria.clear();
        let result = make_gate_result(vec![scenario]);
        let bundle = make_containment_bundle(result);
        let report = verify_containment_claim(&bundle);
        assert_eq!(report.verdict, VerificationVerdict::Failed);
        let failed = report
            .checks
            .iter()
            .find(|c| c.name == "criteria_consistency:s1")
            .unwrap();
        assert!(!failed.passed);
    }

    #[test]
    fn containment_multiple_scenarios_mixed() {
        let scenarios = vec![
            make_scenario("s1", true, 100_000),
            make_scenario("s2", false, 200_000),
        ];
        let result = make_gate_result(scenarios);
        let bundle = make_containment_bundle(result);
        let report = verify_containment_claim(&bundle);
        assert_eq!(report.verdict, VerificationVerdict::Failed);
    }

    #[test]
    fn containment_report_has_events() {
        let result = make_gate_result(vec![make_scenario("s1", true, 100_000)]);
        let bundle = make_containment_bundle(result);
        let report = verify_containment_claim(&bundle);
        assert!(report.events.len() >= 2); // started + completed
        assert_eq!(report.events[0].trace_id, "t-1");
        assert_eq!(report.events[0].component, THIRD_PARTY_VERIFIER_COMPONENT);
    }

    #[test]
    fn containment_report_exit_code_matches_verdict() {
        let result = make_gate_result(vec![make_scenario("s1", true, 100_000)]);
        let bundle = make_containment_bundle(result);
        let report = verify_containment_claim(&bundle);
        assert_eq!(report.exit_code(), report.verdict.exit_code());
    }

    #[test]
    fn containment_custom_sla_ns() {
        let mut bundle =
            make_containment_bundle(make_gate_result(vec![make_scenario("s1", true, 50)]));
        bundle.detection_latency_sla_ns = 10; // very tight SLA
        let report = verify_containment_claim(&bundle);
        assert_eq!(report.verdict, VerificationVerdict::Failed);
        let sla_check = report
            .checks
            .iter()
            .find(|c| c.name == "latency_sla:s1")
            .unwrap();
        assert!(!sla_check.passed);
    }

    // ── generate_attestation ────────────────────────────────────────

    #[test]
    fn generate_attestation_unsigned() {
        let report = make_report(VerificationVerdict::Verified);
        let input = make_attestation_input(report.clone(), None);
        let attestation = generate_attestation(&input).unwrap();
        assert_eq!(attestation.claim_type, "containment");
        assert_eq!(attestation.verdict, VerificationVerdict::Verified);
        assert_eq!(attestation.verifier_name, "acme-verifier");
        assert!(!attestation.report_digest_hex.is_empty());
        assert!(attestation.signature_hex.is_none());
        assert!(attestation.signer_verification_key_hex.is_none());
    }

    #[test]
    fn generate_attestation_signed() {
        let report = make_report(VerificationVerdict::Verified);
        let key = SigningKey::from_bytes([42u8; SIGNING_KEY_LEN]);
        let key_hex = hex::encode(key.as_bytes());
        let input = make_attestation_input(report.clone(), Some(key_hex));
        let attestation = generate_attestation(&input).unwrap();
        assert!(attestation.signature_hex.is_some());
        assert!(attestation.signer_verification_key_hex.is_some());
    }

    #[test]
    fn generate_attestation_empty_verifier_name_error() {
        let report = make_report(VerificationVerdict::Verified);
        let mut input = make_attestation_input(report, None);
        input.verifier_name = "".to_string();
        let result = generate_attestation(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("verifier_name"));
    }

    #[test]
    fn generate_attestation_empty_issued_at_error() {
        let report = make_report(VerificationVerdict::Verified);
        let mut input = make_attestation_input(report, None);
        input.issued_at_utc = "  ".to_string();
        let result = generate_attestation(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("issued_at_utc"));
    }

    #[test]
    fn generate_attestation_empty_methodology_error() {
        let report = make_report(VerificationVerdict::Verified);
        let mut input = make_attestation_input(report, None);
        input.methodology = "".to_string();
        let result = generate_attestation(&input);
        assert!(result.is_err());
    }

    #[test]
    fn generate_attestation_invalid_signing_key_error() {
        let report = make_report(VerificationVerdict::Verified);
        let input = make_attestation_input(report, Some("not-hex".to_string()));
        let result = generate_attestation(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("signing key"));
    }

    #[test]
    fn generate_attestation_wrong_length_signing_key_error() {
        let report = make_report(VerificationVerdict::Verified);
        let input = make_attestation_input(report, Some(hex::encode([0u8; 16])));
        let result = generate_attestation(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("bytes"));
    }

    #[test]
    fn generate_attestation_scope_limitations_included() {
        let report = make_report(VerificationVerdict::Verified);
        let mut input = make_attestation_input(report, None);
        input.scope_limitations = vec!["no-crypto-audit".to_string(), "sandbox-only".to_string()];
        let attestation = generate_attestation(&input).unwrap();
        assert!(attestation.statement.contains("no-crypto-audit"));
        assert!(attestation.statement.contains("sandbox-only"));
    }

    #[test]
    fn generate_attestation_statement_format() {
        let report = make_report(VerificationVerdict::Verified);
        let input = make_attestation_input(report, None);
        let attestation = generate_attestation(&input).unwrap();
        assert!(attestation.statement.contains("acme-verifier"));
        assert!(attestation.statement.contains("1.0.0"));
        assert!(attestation.statement.contains("verified"));
        assert!(attestation.statement.contains("deterministic-replay"));
        assert!(attestation.statement.contains("Scope limitations: none"));
    }

    // ── verify_attestation ──────────────────────────────────────────

    #[test]
    fn verify_attestation_unsigned_partially_verified() {
        let report = make_report(VerificationVerdict::Verified);
        let input = make_attestation_input(report, None);
        let attestation = generate_attestation(&input).unwrap();
        let verification = verify_attestation(&attestation);
        // Unsigned → skipped signature check → PartiallyVerified
        assert_eq!(verification.verdict, VerificationVerdict::PartiallyVerified);
        assert!(verification.checks.iter().all(|c| c.passed));
    }

    #[test]
    fn verify_attestation_signed_verified() {
        let report = make_report(VerificationVerdict::Verified);
        let key = SigningKey::from_bytes([42u8; SIGNING_KEY_LEN]);
        let key_hex = hex::encode(key.as_bytes());
        let input = make_attestation_input(report, Some(key_hex));
        let attestation = generate_attestation(&input).unwrap();
        let verification = verify_attestation(&attestation);
        assert_eq!(verification.verdict, VerificationVerdict::Verified);
        assert!(verification.checks.iter().all(|c| c.passed));
    }

    #[test]
    fn verify_attestation_mismatched_claim_type() {
        let report = make_report(VerificationVerdict::Verified);
        let input = make_attestation_input(report, None);
        let mut attestation = generate_attestation(&input).unwrap();
        attestation.claim_type = "wrong_type".to_string();
        let verification = verify_attestation(&attestation);
        assert_eq!(verification.verdict, VerificationVerdict::Failed);
        let failed = verification
            .checks
            .iter()
            .find(|c| c.name == "claim_type_matches_report")
            .unwrap();
        assert!(!failed.passed);
    }

    #[test]
    fn verify_attestation_mismatched_verdict() {
        let report = make_report(VerificationVerdict::Verified);
        let input = make_attestation_input(report, None);
        let mut attestation = generate_attestation(&input).unwrap();
        attestation.verdict = VerificationVerdict::Failed;
        let verification = verify_attestation(&attestation);
        assert_eq!(verification.verdict, VerificationVerdict::Failed);
    }

    #[test]
    fn verify_attestation_mismatched_context() {
        let report = make_report(VerificationVerdict::Verified);
        let input = make_attestation_input(report, None);
        let mut attestation = generate_attestation(&input).unwrap();
        attestation.trace_id = "wrong-trace".to_string();
        let verification = verify_attestation(&attestation);
        assert_eq!(verification.verdict, VerificationVerdict::Failed);
        let failed = verification
            .checks
            .iter()
            .find(|c| c.name == "context_matches_report")
            .unwrap();
        assert!(!failed.passed);
    }

    #[test]
    fn verify_attestation_tampered_digest() {
        let report = make_report(VerificationVerdict::Verified);
        let input = make_attestation_input(report, None);
        let mut attestation = generate_attestation(&input).unwrap();
        attestation.report_digest_hex = "0000000000000000".to_string();
        let verification = verify_attestation(&attestation);
        assert_eq!(verification.verdict, VerificationVerdict::Failed);
        let failed = verification
            .checks
            .iter()
            .find(|c| c.name == "report_digest_matches")
            .unwrap();
        assert!(!failed.passed);
    }

    #[test]
    fn verify_attestation_tampered_statement() {
        let report = make_report(VerificationVerdict::Verified);
        let input = make_attestation_input(report, None);
        let mut attestation = generate_attestation(&input).unwrap();
        attestation.statement = "tampered statement".to_string();
        let verification = verify_attestation(&attestation);
        assert_eq!(verification.verdict, VerificationVerdict::Failed);
        let failed = verification
            .checks
            .iter()
            .find(|c| c.name == "statement_matches_canonical_template")
            .unwrap();
        assert!(!failed.passed);
    }

    #[test]
    fn verify_attestation_empty_required_fields() {
        let report = make_report(VerificationVerdict::Verified);
        let input = make_attestation_input(report, None);
        let mut attestation = generate_attestation(&input).unwrap();
        attestation.verifier_name = "".to_string();
        let verification = verify_attestation(&attestation);
        assert_eq!(verification.verdict, VerificationVerdict::Failed);
        let failed = verification
            .checks
            .iter()
            .find(|c| c.name == "attestation_required_fields")
            .unwrap();
        assert!(!failed.passed);
    }

    #[test]
    fn verify_attestation_only_sig_key_no_sig() {
        let report = make_report(VerificationVerdict::Verified);
        let input = make_attestation_input(report, None);
        let mut attestation = generate_attestation(&input).unwrap();
        attestation.signer_verification_key_hex = Some("abcd".to_string());
        // signature_hex is still None → inconsistent
        let verification = verify_attestation(&attestation);
        assert_eq!(verification.verdict, VerificationVerdict::Failed);
        let failed = verification
            .checks
            .iter()
            .find(|c| c.name == "signature_presence_consistent")
            .unwrap();
        assert!(!failed.passed);
    }

    #[test]
    fn verify_attestation_tampered_signature_fails() {
        let report = make_report(VerificationVerdict::Verified);
        let key = SigningKey::from_bytes([42u8; SIGNING_KEY_LEN]);
        let key_hex = hex::encode(key.as_bytes());
        let input = make_attestation_input(report, Some(key_hex));
        let mut attestation = generate_attestation(&input).unwrap();
        // Tamper with signature
        attestation.signature_hex = Some(hex::encode([0u8; SIGNATURE_LEN]));
        let verification = verify_attestation(&attestation);
        assert_eq!(verification.verdict, VerificationVerdict::Failed);
        let failed = verification
            .checks
            .iter()
            .find(|c| c.name == "signature_valid")
            .unwrap();
        assert!(!failed.passed);
    }

    // ── render functions ────────────────────────────────────────────

    #[test]
    fn render_report_summary_format() {
        let mut report = make_report(VerificationVerdict::Verified);
        report.checks.push(VerificationCheckResult {
            name: "bad_check".to_string(),
            passed: false,
            error_code: Some("ERR".to_string()),
            detail: "something failed".to_string(),
        });
        let summary = render_report_summary(&report);
        assert!(summary.contains("claim_type=containment"));
        assert!(summary.contains("checks=2"));
        assert!(summary.contains("failed=1"));
        assert!(summary.contains("exit_code="));
    }

    #[test]
    fn render_attestation_summary_format() {
        let report = make_report(VerificationVerdict::Verified);
        let input = make_attestation_input(report, None);
        let attestation = generate_attestation(&input).unwrap();
        let summary = render_attestation_summary(&attestation);
        assert!(summary.contains("claim_type=containment"));
        assert!(summary.contains("signed=false"));
        assert!(summary.contains("verifier=acme-verifier@1.0.0"));
    }

    #[test]
    fn render_attestation_summary_signed() {
        let report = make_report(VerificationVerdict::Verified);
        let key = SigningKey::from_bytes([42u8; SIGNING_KEY_LEN]);
        let key_hex = hex::encode(key.as_bytes());
        let input = make_attestation_input(report, Some(key_hex));
        let attestation = generate_attestation(&input).unwrap();
        let summary = render_attestation_summary(&attestation);
        assert!(summary.contains("signed=true"));
    }

    // ── serde roundtrips ────────────────────────────────────────────

    #[test]
    fn verification_check_result_serde() {
        let check = VerificationCheckResult {
            name: "test_check".to_string(),
            passed: false,
            error_code: Some("ERR-001".to_string()),
            detail: "detail text".to_string(),
        };
        let json = serde_json::to_string(&check).unwrap();
        let back: VerificationCheckResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back, check);
    }

    #[test]
    fn verifier_event_serde() {
        let ev = VerifierEvent {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: "comp".to_string(),
            event: "ev".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: VerifierEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn third_party_verification_report_serde() {
        let report = make_report(VerificationVerdict::Failed);
        let json = serde_json::to_string(&report).unwrap();
        let back: ThirdPartyVerificationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, report);
    }

    #[test]
    fn containment_claim_bundle_serde() {
        let result = make_gate_result(vec![make_scenario("s1", true, 100)]);
        let bundle = make_containment_bundle(result);
        let json = serde_json::to_string(&bundle).unwrap();
        let back: ContainmentClaimBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back, bundle);
    }

    #[test]
    fn attestation_input_serde() {
        let report = make_report(VerificationVerdict::Verified);
        let input = make_attestation_input(report, None);
        let json = serde_json::to_string(&input).unwrap();
        let back: VerificationAttestationInput = serde_json::from_str(&json).unwrap();
        assert_eq!(back, input);
    }

    #[test]
    fn attestation_unsigned_serde() {
        let report = make_report(VerificationVerdict::Verified);
        let input = make_attestation_input(report, None);
        let attestation = generate_attestation(&input).unwrap();
        let json = serde_json::to_string(&attestation).unwrap();
        let back: VerificationAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(back, attestation);
    }

    #[test]
    fn attestation_signed_serde() {
        let report = make_report(VerificationVerdict::Verified);
        let key = SigningKey::from_bytes([42u8; SIGNING_KEY_LEN]);
        let input = make_attestation_input(report, Some(hex::encode(key.as_bytes())));
        let attestation = generate_attestation(&input).unwrap();
        let json = serde_json::to_string(&attestation).unwrap();
        let back: VerificationAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(back, attestation);
    }

    // ── attestation digest determinism ──────────────────────────────

    #[test]
    fn attestation_digest_deterministic() {
        let report = make_report(VerificationVerdict::Verified);
        let input = make_attestation_input(report, None);
        let a1 = generate_attestation(&input).unwrap();
        let a2 = generate_attestation(&input).unwrap();
        assert_eq!(a1.report_digest_hex, a2.report_digest_hex);
    }

    #[test]
    fn attestation_digest_changes_with_report() {
        let report1 = make_report(VerificationVerdict::Verified);
        let report2 = make_report(VerificationVerdict::Failed);
        let a1 = generate_attestation(&make_attestation_input(report1, None)).unwrap();
        let a2 = generate_attestation(&make_attestation_input(report2, None)).unwrap();
        assert_ne!(a1.report_digest_hex, a2.report_digest_hex);
    }

    // ── end-to-end containment → attestation → verify ───────────────

    #[test]
    fn end_to_end_containment_attestation_unsigned() {
        let result = make_gate_result(vec![make_scenario("s1", true, 100_000)]);
        let bundle = make_containment_bundle(result);
        let report = verify_containment_claim(&bundle);
        assert_eq!(report.verdict, VerificationVerdict::Verified);

        let input = make_attestation_input(report, None);
        let attestation = generate_attestation(&input).unwrap();
        assert_eq!(attestation.verdict, VerificationVerdict::Verified);

        let verification = verify_attestation(&attestation);
        assert_eq!(verification.verdict, VerificationVerdict::PartiallyVerified);
        assert!(verification.checks.iter().all(|c| c.passed));
    }

    #[test]
    fn end_to_end_containment_attestation_signed() {
        let result = make_gate_result(vec![make_scenario("s1", true, 100_000)]);
        let bundle = make_containment_bundle(result);
        let report = verify_containment_claim(&bundle);

        let key = SigningKey::from_bytes([99u8; SIGNING_KEY_LEN]);
        let input = make_attestation_input(report, Some(hex::encode(key.as_bytes())));
        let attestation = generate_attestation(&input).unwrap();

        let verification = verify_attestation(&attestation);
        assert_eq!(verification.verdict, VerificationVerdict::Verified);
        assert!(verification.checks.iter().all(|c| c.passed));
    }

    // ── report.exit_code() delegation ───────────────────────────────

    #[test]
    fn report_exit_code_delegates_to_verdict() {
        let report = make_report(VerificationVerdict::Failed);
        assert_eq!(report.exit_code(), EXIT_CODE_FAILED);
    }

    // ── default containment sla deserialization ─────────────────────

    #[test]
    fn containment_bundle_default_sla_from_json() {
        let json = r#"{
            "trace_id": "t",
            "decision_id": "d",
            "policy_id": "p",
            "result": {
                "seed": 0,
                "scenarios": [],
                "passed": true,
                "total_scenarios": 0,
                "passed_scenarios": 0,
                "events": [],
                "result_digest": ""
            }
        }"#;
        let bundle: ContainmentClaimBundle = serde_json::from_str(json).unwrap();
        assert_eq!(
            bundle.detection_latency_sla_ns,
            DEFAULT_CONTAINMENT_LATENCY_SLA_NS
        );
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn claimed_benchmark_outcome_serde_defaults() {
        // blockers defaults to empty vec via #[serde(default)]
        let json = r#"{"score_vs_node": 0.95, "score_vs_bun": 0.92, "publish_allowed": true}"#;
        let outcome: ClaimedBenchmarkOutcome = serde_json::from_str(json).unwrap();
        assert!(outcome.blockers.is_empty());
        assert!(outcome.publish_allowed);
        assert!((outcome.score_vs_node - 0.95).abs() < 1e-12);
    }

    #[test]
    fn claimed_benchmark_outcome_with_blockers_serde() {
        let outcome = ClaimedBenchmarkOutcome {
            score_vs_node: 0.88,
            score_vs_bun: 0.85,
            publish_allowed: false,
            blockers: vec![
                "perf-regression".to_string(),
                "behavior-mismatch".to_string(),
            ],
        };
        let json = serde_json::to_string(&outcome).unwrap();
        let back: ClaimedBenchmarkOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome.blockers, back.blockers);
        assert_eq!(outcome.publish_allowed, back.publish_allowed);
    }

    #[test]
    fn verification_check_result_failed_with_error_code() {
        let check = VerificationCheckResult {
            name: "latency_sla_met".to_string(),
            passed: false,
            error_code: Some("LATENCY_SLA_EXCEEDED".to_string()),
            detail: "400ms > 100ms sla".to_string(),
        };
        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("LATENCY_SLA_EXCEEDED"));
        let back: VerificationCheckResult = serde_json::from_str(&json).unwrap();
        assert!(!back.passed);
        assert_eq!(back.error_code, Some("LATENCY_SLA_EXCEEDED".to_string()));
    }

    #[test]
    fn verification_check_result_passed_no_error_code() {
        let check = VerificationCheckResult {
            name: "integrity_check".to_string(),
            passed: true,
            error_code: None,
            detail: "all hashes match".to_string(),
        };
        let json = serde_json::to_string(&check).unwrap();
        let back: VerificationCheckResult = serde_json::from_str(&json).unwrap();
        assert!(back.passed);
        assert!(back.error_code.is_none());
    }

    #[test]
    fn verifier_event_with_error_code_serde() {
        let event = VerifierEvent {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: THIRD_PARTY_VERIFIER_COMPONENT.to_string(),
            event: "check_failed:latency_sla_met".to_string(),
            outcome: "fail".to_string(),
            error_code: Some("CONTAINMENT_SLA".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: VerifierEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn report_with_mixed_checks_has_correct_exit_code() {
        let report = ThirdPartyVerificationReport {
            claim_type: "containment".to_string(),
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: THIRD_PARTY_VERIFIER_COMPONENT.to_string(),
            verdict: VerificationVerdict::PartiallyVerified,
            confidence_statement: "partial coverage".to_string(),
            scope_limitations: vec!["unsigned attestation".to_string()],
            checks: vec![
                VerificationCheckResult {
                    name: "a".to_string(),
                    passed: true,
                    error_code: None,
                    detail: "ok".to_string(),
                },
                VerificationCheckResult {
                    name: "b".to_string(),
                    passed: false,
                    error_code: Some("ERR".to_string()),
                    detail: "not ok".to_string(),
                },
            ],
            events: Vec::new(),
        };
        assert_eq!(report.exit_code(), EXIT_CODE_PARTIALLY_VERIFIED);
    }

    #[test]
    fn render_report_summary_includes_failed_count() {
        let report = ThirdPartyVerificationReport {
            claim_type: "test".to_string(),
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: THIRD_PARTY_VERIFIER_COMPONENT.to_string(),
            verdict: VerificationVerdict::Failed,
            confidence_statement: "1 check failed".to_string(),
            scope_limitations: Vec::new(),
            checks: vec![
                VerificationCheckResult {
                    name: "a".to_string(),
                    passed: true,
                    error_code: None,
                    detail: "ok".to_string(),
                },
                VerificationCheckResult {
                    name: "b".to_string(),
                    passed: false,
                    error_code: Some("ERR".to_string()),
                    detail: "not ok".to_string(),
                },
                VerificationCheckResult {
                    name: "c".to_string(),
                    passed: false,
                    error_code: Some("ERR2".to_string()),
                    detail: "also not ok".to_string(),
                },
            ],
            events: Vec::new(),
        };
        let summary = render_report_summary(&report);
        assert!(summary.contains("failed=2"), "summary: {summary}");
        assert!(summary.contains("checks=3"), "summary: {summary}");
        assert!(summary.contains("limitations=0"), "summary: {summary}");
    }

    #[test]
    fn report_confidence_statement_includes_scope_limitations_for_partial_verdict() {
        let input = make_attestation_input(make_report(VerificationVerdict::Verified), None);
        let attestation = generate_attestation(&input).expect("attestation should generate");
        let report = verify_attestation(&attestation);
        assert_eq!(report.verdict, VerificationVerdict::PartiallyVerified);
        assert!(report.confidence_statement.contains("scope limitation"));
        assert!(
            report
                .scope_limitations
                .iter()
                .any(|entry| entry.contains("unsigned attestation"))
        );
    }

    #[test]
    fn generate_attestation_empty_verifier_version_error() {
        let report = make_report(VerificationVerdict::Verified);
        let mut input = make_attestation_input(report, None);
        input.verifier_version = String::new();
        let err = generate_attestation(&input).unwrap_err();
        assert!(err.contains("verifier_version"), "err: {err}");
    }

    #[test]
    fn generate_attestation_empty_environment_error() {
        let report = make_report(VerificationVerdict::Verified);
        let mut input = make_attestation_input(report, None);
        input.verifier_environment = String::new();
        let err = generate_attestation(&input).unwrap_err();
        assert!(err.contains("verifier_environment"), "err: {err}");
    }

    #[test]
    fn attestation_scope_limitations_in_statement() {
        let report = make_report(VerificationVerdict::Verified);
        let mut input = make_attestation_input(report, None);
        input.scope_limitations = vec!["no-network".to_string(), "synthetic-data".to_string()];
        let attestation = generate_attestation(&input).unwrap();
        assert_eq!(attestation.scope_limitations.len(), 2);
        assert!(
            attestation.statement.contains("no-network")
                || attestation.statement.contains("synthetic-data")
        );
    }

    #[test]
    fn exit_code_constants_are_distinct() {
        let codes = [
            EXIT_CODE_VERIFIED,
            EXIT_CODE_PARTIALLY_VERIFIED,
            EXIT_CODE_FAILED,
            EXIT_CODE_INCONCLUSIVE,
        ];
        let mut sorted = codes.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len());
    }

    #[test]
    fn verdict_serde_all_variants_distinct() {
        let variants = [
            VerificationVerdict::Verified,
            VerificationVerdict::PartiallyVerified,
            VerificationVerdict::Failed,
            VerificationVerdict::Inconclusive,
        ];
        let jsons: Vec<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        let mut deduped = jsons.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(jsons.len(), deduped.len());
    }

    #[test]
    fn containment_claim_bundle_custom_sla_serde() {
        let result = make_gate_result(vec![make_scenario("s1", true, 100_000)]);
        let mut bundle = make_containment_bundle(result);
        bundle.detection_latency_sla_ns = 250_000_000;
        let json = serde_json::to_string(&bundle).unwrap();
        let back: ContainmentClaimBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back.detection_latency_sla_ns, 250_000_000);
    }

    #[test]
    fn verification_attestation_serde_with_scope_limitations() {
        let report = make_report(VerificationVerdict::Verified);
        let mut input = make_attestation_input(report, None);
        input.scope_limitations = vec!["limited-to-unit-tests".to_string()];
        let attestation = generate_attestation(&input).unwrap();
        let json = serde_json::to_string(&attestation).unwrap();
        let back: VerificationAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.scope_limitations,
            vec!["limited-to-unit-tests".to_string()]
        );
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn verdict_serde_exact_snake_case_all_4() {
        assert_eq!(
            serde_json::to_string(&VerificationVerdict::Verified).unwrap(),
            "\"verified\""
        );
        assert_eq!(
            serde_json::to_string(&VerificationVerdict::PartiallyVerified).unwrap(),
            "\"partially_verified\""
        );
        assert_eq!(
            serde_json::to_string(&VerificationVerdict::Failed).unwrap(),
            "\"failed\""
        );
        assert_eq!(
            serde_json::to_string(&VerificationVerdict::Inconclusive).unwrap(),
            "\"inconclusive\""
        );
    }

    #[test]
    fn render_attestation_summary_with_failed_verdict() {
        let report = make_report(VerificationVerdict::Failed);
        let input = make_attestation_input(report, None);
        let attestation = generate_attestation(&input).unwrap();
        let summary = render_attestation_summary(&attestation);
        assert!(summary.contains("verdict=failed"), "summary: {summary}");
        assert!(summary.contains("signed=false"), "summary: {summary}");
    }

    #[test]
    fn scope_limitations_deduplicated_and_trimmed_in_attestation() {
        let report = make_report(VerificationVerdict::Verified);
        let mut input = make_attestation_input(report, None);
        input.scope_limitations = vec![
            "  alpha  ".to_string(),
            "beta".to_string(),
            "alpha".to_string(), // duplicate after trim
            "  ".to_string(),    // empty after trim → filtered
        ];
        let attestation = generate_attestation(&input).unwrap();
        assert_eq!(attestation.scope_limitations, vec!["alpha", "beta"]);
    }

    #[test]
    fn attestation_input_serde_with_signing_key_hex_some() {
        let report = make_report(VerificationVerdict::Verified);
        let key = SigningKey::from_bytes([7u8; SIGNING_KEY_LEN]);
        let input = make_attestation_input(report, Some(hex::encode(key.as_bytes())));
        let json = serde_json::to_string(&input).unwrap();
        let back: VerificationAttestationInput = serde_json::from_str(&json).unwrap();
        assert_eq!(back.signing_key_hex, input.signing_key_hex);
    }

    #[test]
    fn verify_attestation_decision_id_mismatch_fails() {
        let report = make_report(VerificationVerdict::Verified);
        let input = make_attestation_input(report, None);
        let mut attestation = generate_attestation(&input).unwrap();
        attestation.decision_id = "wrong-decision".to_string();
        let verification = verify_attestation(&attestation);
        assert_eq!(verification.verdict, VerificationVerdict::Failed);
        let failed = verification
            .checks
            .iter()
            .find(|c| c.name == "context_matches_report")
            .unwrap();
        assert!(!failed.passed);
    }

    #[test]
    fn verify_attestation_sig_without_key_fails() {
        let report = make_report(VerificationVerdict::Verified);
        let input = make_attestation_input(report, None);
        let mut attestation = generate_attestation(&input).unwrap();
        // Set signature_hex but leave signer_verification_key_hex as None
        attestation.signature_hex = Some(hex::encode([1u8; SIGNATURE_LEN]));
        let verification = verify_attestation(&attestation);
        assert_eq!(verification.verdict, VerificationVerdict::Failed);
        let failed = verification
            .checks
            .iter()
            .find(|c| c.name == "signature_presence_consistent")
            .unwrap();
        assert!(!failed.passed);
    }

    #[test]
    fn containment_verified_confidence_exact_format() {
        let result = make_gate_result(vec![
            make_scenario("s1", true, 100_000),
            make_scenario("s2", true, 200_000),
        ]);
        let bundle = make_containment_bundle(result);
        let report = verify_containment_claim(&bundle);
        assert_eq!(report.verdict, VerificationVerdict::Verified);
        let total = report.checks.len();
        assert_eq!(
            report.confidence_statement,
            format!("all {total} checks passed with no skipped verification scope")
        );
    }

    #[test]
    fn containment_failed_confidence_exact_format() {
        let scenarios = vec![make_scenario("s1", true, 100_000)];
        let mut result = make_gate_result(scenarios);
        result.total_scenarios = 99; // mismatch forces failure
        let bundle = make_containment_bundle(result);
        let report = verify_containment_claim(&bundle);
        assert_eq!(report.verdict, VerificationVerdict::Failed);
        let total = report.checks.len();
        let failed = report.checks.iter().filter(|c| !c.passed).count();
        assert_eq!(
            report.confidence_statement,
            format!("{failed} of {total} checks failed; claim verification failed")
        );
    }

    #[test]
    fn attestation_report_digest_is_valid_hex() {
        let report = make_report(VerificationVerdict::Verified);
        let input = make_attestation_input(report, None);
        let attestation = generate_attestation(&input).unwrap();
        let decoded = hex::decode(&attestation.report_digest_hex);
        assert!(decoded.is_ok(), "digest should be valid hex");
        assert!(!decoded.unwrap().is_empty());
    }

    #[test]
    fn render_report_summary_confidence_is_quoted() {
        let report = make_report(VerificationVerdict::Verified);
        let summary = render_report_summary(&report);
        // confidence= value is wrapped in double quotes in the format string
        assert!(
            summary.contains("confidence=\""),
            "summary should contain quoted confidence: {summary}"
        );
    }

    #[test]
    fn containment_per_scenario_produces_four_check_types() {
        let result = make_gate_result(vec![make_scenario("s1", true, 100_000)]);
        let bundle = make_containment_bundle(result);
        let report = verify_containment_claim(&bundle);
        // 3 global checks + 4 per-scenario checks = 7 total for 1 scenario
        let per_scenario: Vec<_> = report
            .checks
            .iter()
            .filter(|c| c.name.contains(":s1"))
            .collect();
        assert_eq!(per_scenario.len(), 4);
        let names: Vec<&str> = per_scenario.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"criteria_consistency:s1"));
        assert!(names.contains(&"latency_sla:s1"));
        assert!(names.contains(&"isolation_verified:s1"));
        assert!(names.contains(&"recovery_verified:s1"));
    }
}
