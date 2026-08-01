//! Integration test for the replay-vaccine lane (bd-fqlfw.10.1, E10.T1).
//!
//! Drives the full local-only lifecycle end-to-end on real recorded traces:
//! incident recording → motif derivation → intervention proposal →
//! counterfactual proof through the real `CounterfactualReplayEngine` →
//! clean-trace collateral estimate → signed package → transparency-log
//! commit → shadow application → motif matching → operator-approved
//! enforcement → kill switch and tamper drills.

use std::collections::BTreeMap;

use frankenengine_engine::causal_replay::{
    DecisionSnapshot, RecorderConfig, RecordingMode, TraceRecord, TraceRecorder,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::replay_vaccine::{
    CandidateRejection, DistributionScope, EnforcementRefusal, OperatorApproval, RegistryConfig,
    VaccineFactory, VaccineFactoryConfig, VaccineIntervention, VaccineRegistry, VaccineState,
    commit_vaccine_to_transparency_log,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;
use frankenengine_engine::transparency_log::TransparencyLog;

fn signing_key(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    bytes[31] = seed.wrapping_add(1);
    SigningKey::from_bytes(bytes).expect("non-zero key")
}

fn loss_matrix() -> BTreeMap<String, i64> {
    let mut m = BTreeMap::new();
    m.insert("allow".to_string(), 900_000);
    m.insert("sandbox".to_string(), 50_000);
    m.insert("quarantine".to_string(), 100_000);
    m
}

fn snapshot(
    index: u64,
    trace_id: &str,
    extension: &str,
    action: &str,
    outcome: i64,
) -> DecisionSnapshot {
    DecisionSnapshot {
        decision_index: index,
        trace_id: trace_id.to_string(),
        decision_id: format!("decision-{index}"),
        policy_id: "baseline".to_string(),
        policy_version: 1,
        epoch: SecurityEpoch::from_raw(3),
        tick: 100 + index * 10,
        threshold_millionths: 500_000,
        loss_matrix: loss_matrix(),
        evidence_hashes: vec![ContentHash::compute(format!("ev-{index}").as_bytes())],
        chosen_action: action.to_string(),
        outcome_millionths: outcome,
        extension_id: extension.to_string(),
        nondeterminism_range: (0, 0),
    }
}

fn record_trace(
    trace_id: &str,
    incident_id: Option<&str>,
    decisions: &[DecisionSnapshot],
) -> TraceRecord {
    let mut recorder = TraceRecorder::new_lab(RecorderConfig {
        trace_id: trace_id.to_string(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(3),
        start_tick: 100,
    });
    if let Some(id) = incident_id {
        recorder.set_incident_id(id.to_string());
    }
    for decision in decisions {
        recorder.record_decision(decision.clone());
    }
    recorder.finalize().expect("lab trace should finalize")
}

/// An exfiltration-shaped incident: the extension probes twice then leaks.
fn incident_trace() -> TraceRecord {
    record_trace(
        "incident-trace-1",
        Some("incident-exfil-9"),
        &[
            snapshot(0, "incident-trace-1", "ext-benign", "allow", 350_000),
            snapshot(1, "incident-trace-1", "ext-exfil", "allow", 150_000),
            snapshot(2, "incident-trace-1", "ext-exfil", "allow", -500_000),
            snapshot(3, "incident-trace-1", "ext-exfil", "allow", -900_000),
        ],
    )
}

fn clean_traces() -> Vec<TraceRecord> {
    vec![
        record_trace(
            "clean-1",
            None,
            &[
                snapshot(0, "clean-1", "ext-a", "allow", 300_000),
                snapshot(1, "clean-1", "ext-a", "allow", 320_000),
                snapshot(2, "clean-1", "ext-a", "sandbox", 250_000),
                snapshot(3, "clean-1", "ext-b", "allow", 400_000),
            ],
        ),
        record_trace(
            "clean-2",
            None,
            &[
                snapshot(0, "clean-2", "ext-c", "allow", 280_000),
                snapshot(1, "clean-2", "ext-c", "allow", 290_000),
                snapshot(2, "clean-2", "ext-c", "allow", 310_000),
            ],
        ),
    ]
}

#[test]
fn full_vaccine_lifecycle_end_to_end() {
    let producer = signing_key(41);
    let operator = signing_key(51);
    let incident = incident_trace();
    let clean = clean_traces();

    // 1. Derive + propose + prove + estimate + package, via the factory's
    //    candidate loop. The threshold-only candidate must be rejected as
    //    not stopping the incident; force-sandbox must win first.
    let mut factory = VaccineFactory::new_lab(VaccineFactoryConfig::default());
    let motif = factory.derive_motif(&incident).expect("motif derives");
    assert_eq!(motif.incident_id, "incident-exfil-9");
    assert_eq!(motif.harmful_source_indices(), vec![2, 3]);

    let mut candidates = vec![VaccineIntervention::ChangeLossThreshold {
        threshold_millionths: 100_000,
    }];
    candidates.extend(factory.propose_interventions(&motif));

    let outcome = factory
        .build_best(&incident, &clean, &candidates, &producer, 1_720_000_000)
        .expect("build succeeds");
    assert!(outcome.is_success());
    assert_eq!(outcome.rejected.len(), 1);
    assert!(matches!(
        outcome.rejected[0].rejection,
        CandidateRejection::DidNotStopIncident { .. }
    ));

    let vaccine = outcome.vaccine.expect("vaccine present");
    assert_eq!(vaccine.intervention, VaccineIntervention::ForceSandbox);
    assert_eq!(vaccine.distribution_scope, DistributionScope::LocalOnly);
    assert!(vaccine.proof.stopped_incident);
    assert_eq!(vaccine.proof.harmful_steps_total, 2);
    assert_eq!(vaccine.proof.harmful_steps_neutralized, 2);
    assert!(vaccine.proof.net_improvement_millionths > 0);
    assert_eq!(vaccine.collateral.motif_firings, 0);
    assert_eq!(vaccine.collateral.collateral_rate_millionths, 0);
    assert!(vaccine.collateral.unscoped_divergence_rate_millionths > 0);

    // 2. The package verifies: signature, content-derived id.
    vaccine
        .verify(&producer.verification_key())
        .expect("producer signature verifies");
    assert!(vaccine.verify_id().expect("id check runs"));

    // 3. Commit to a transparency log for later fleet distribution.
    let mut log = TransparencyLog::new("vaccine-log".to_string());
    let leaf =
        commit_vaccine_to_transparency_log(&vaccine, &mut log, 1_720_000_001).expect("log append");
    assert_eq!(leaf, 0);
    assert_eq!(log.entries()[0].receipt_hash, vaccine.content_hash());

    // 4. Shadow-apply on a registry trusting the producer + operator keys.
    let mut registry = VaccineRegistry::new(
        RegistryConfig::default(),
        producer.verification_key(),
        operator.verification_key(),
    );
    registry
        .register_shadow(vaccine.clone())
        .expect("shadow registration");
    assert_eq!(
        registry.state(&vaccine.vaccine_id_hex),
        Some(VaccineState::Shadow)
    );

    // 5. Replay the incident behavior against the live registry: the motif
    //    completes and produces exactly one shadow match event.
    let mut events = Vec::new();
    for entry in &incident.entries {
        events.extend(registry.observe_decision(&entry.decision));
    }
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].vaccine_id_hex, vaccine.vaccine_id_hex);
    assert_eq!(events[0].would_apply_action.as_deref(), Some("sandbox"));

    // Clean traffic does not fire.
    for trace in &clean {
        for entry in &trace.entries {
            assert!(registry.observe_decision(&entry.decision).is_empty());
        }
    }

    // 6. Enforcement requires a valid operator approval.
    let approval = OperatorApproval::create(
        vaccine.vaccine_id_hex.clone(),
        SecurityEpoch::from_raw(4),
        &operator,
    )
    .expect("approval signs");
    let receipt = registry
        .approve_enforcement(&vaccine.vaccine_id_hex, &approval)
        .expect("enforcement approved");
    assert_eq!(receipt.vaccine_id_hex, vaccine.vaccine_id_hex);
    assert_eq!(
        registry.state(&vaccine.vaccine_id_hex),
        Some(VaccineState::Enforced)
    );

    // 7. Kill switch: safe mode suppresses matching after enforcement too.
    registry.set_safe_mode(true);
    for entry in &incident.entries {
        assert!(registry.observe_decision(&entry.decision).is_empty());
    }
}

#[test]
fn tamper_and_impostor_drills_fail_closed() {
    let producer = signing_key(41);
    let operator = signing_key(51);
    let incident = incident_trace();
    let clean = clean_traces();

    let mut factory = VaccineFactory::new_lab(VaccineFactoryConfig::default());
    let outcome = factory
        .build_best(
            &incident,
            &clean,
            &[VaccineIntervention::Quarantine],
            &producer,
            1_720_000_000,
        )
        .expect("build succeeds");
    let vaccine = outcome.vaccine.expect("vaccine present");

    // Tampering with the packaged collateral breaks the signature.
    let mut tampered = vaccine.clone();
    assert_ne!(tampered.collateral.collateral_rate_millionths, 999_999);
    tampered.collateral.collateral_rate_millionths = 999_999;
    assert!(tampered.verify(&producer.verification_key()).is_err());

    let mut registry = VaccineRegistry::new(
        RegistryConfig::default(),
        producer.verification_key(),
        operator.verification_key(),
    );
    assert!(registry.register_shadow(tampered).is_err());

    // A valid registration cannot be enforced by an impostor operator.
    registry
        .register_shadow(vaccine.clone())
        .expect("shadow registration");
    let impostor = signing_key(99);
    let forged = OperatorApproval::create(
        vaccine.vaccine_id_hex.clone(),
        SecurityEpoch::from_raw(4),
        &impostor,
    )
    .expect("impostor can sign, registry must refuse");
    assert_eq!(
        registry
            .approve_enforcement(&vaccine.vaccine_id_hex, &forged)
            .unwrap_err(),
        EnforcementRefusal::ApprovalSignatureInvalid
    );
    assert_eq!(
        registry.state(&vaccine.vaccine_id_hex),
        Some(VaccineState::Shadow)
    );
}

#[test]
fn vaccine_id_is_stable_across_equivalent_builds() {
    let producer = signing_key(41);
    let incident = incident_trace();
    let clean = clean_traces();

    let build = |factory: &mut VaccineFactory| {
        factory
            .build_best(
                &incident,
                &clean,
                &[VaccineIntervention::Quarantine],
                &producer,
                1_720_000_000,
            )
            .expect("build succeeds")
            .vaccine
            .expect("vaccine present")
    };
    let mut f1 = VaccineFactory::new_lab(VaccineFactoryConfig::default());
    let mut f2 = VaccineFactory::new_lab(VaccineFactoryConfig::default());
    let v1 = build(&mut f1);
    let v2 = build(&mut f2);
    assert_eq!(v1.vaccine_id_hex, v2.vaccine_id_hex);
    assert_eq!(v1, v2);
}
