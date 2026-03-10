#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process,
};

#[path = "../src/claim_entitlement.rs"]
mod claim_entitlement;

use claim_entitlement::{
    CLAIM_ENTITLEMENT_COMPONENT, CLAIM_ENTITLEMENT_CONTRACT_JSON,
    CLAIM_ENTITLEMENT_COUNTEREXAMPLE_LEDGER_SCHEMA_VERSION,
    CLAIM_ENTITLEMENT_CUTSET_SCHEMA_VERSION, CLAIM_ENTITLEMENT_IMPOSSIBILITY_SCHEMA_VERSION,
    CLAIM_ENTITLEMENT_POLICY_ID, CLAIM_ENTITLEMENT_REPORT_SCHEMA_VERSION,
    CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION, CLAIM_ENTITLEMENT_SCHEMA_VERSION, ClaimDomain,
    ClaimEntitlementContract, ClaimEvaluationOutputs, ClaimEvaluationScenarioSet, ClaimTier,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn repo_relative_env_path(var: &str, default_relative: &str) -> PathBuf {
    std::env::var_os(var)
        .map(PathBuf::from)
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                repo_root().join(path)
            }
        })
        .unwrap_or_else(|| repo_root().join(default_relative))
}

fn load_contract() -> ClaimEntitlementContract {
    ClaimEntitlementContract::from_embedded_json()
}

fn load_scenarios() -> ClaimEvaluationScenarioSet {
    let path = repo_relative_env_path(
        "RGC_CLAIM_ENTITLEMENT_SCENARIO_FIXTURE",
        "crates/franken-engine/tests/fixtures/claim_entitlement_scenarios_v1.json",
    );
    let contents = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&contents)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

fn scenario_report<'a>(
    outputs: &'a ClaimEvaluationOutputs,
    scenario_id: &str,
) -> &'a claim_entitlement::ScenarioVerdictReport {
    outputs
        .claim_entitlement_report
        .evaluated_scenarios
        .iter()
        .find(|scenario| scenario.scenario_id == scenario_id)
        .unwrap_or_else(|| panic!("missing verdict report for scenario {scenario_id}"))
}

fn scenario_cutsets<'a>(
    outputs: &'a ClaimEvaluationOutputs,
    scenario_id: &str,
) -> &'a claim_entitlement::ScenarioMissingEvidenceCutsets {
    outputs
        .missing_evidence_cutsets
        .evaluated_scenarios
        .iter()
        .find(|scenario| scenario.scenario_id == scenario_id)
        .unwrap_or_else(|| panic!("missing cutset report for scenario {scenario_id}"))
}

fn scenario_certificates<'a>(
    outputs: &'a ClaimEvaluationOutputs,
    scenario_id: &str,
) -> &'a claim_entitlement::ScenarioImpossibilityCertificates {
    outputs
        .impossibility_certificates
        .evaluated_scenarios
        .iter()
        .find(|scenario| scenario.scenario_id == scenario_id)
        .unwrap_or_else(|| panic!("missing impossibility report for scenario {scenario_id}"))
}

fn scenario_counterexamples<'a>(
    outputs: &'a ClaimEvaluationOutputs,
    scenario_id: &str,
) -> &'a claim_entitlement::ScenarioCounterexampleLedger {
    outputs
        .claim_counterexample_ledger
        .evaluated_scenarios
        .iter()
        .find(|scenario| scenario.scenario_id == scenario_id)
        .unwrap_or_else(|| panic!("missing counterexample ledger for scenario {scenario_id}"))
}

fn write_outputs(output_dir: &Path, outputs: &ClaimEvaluationOutputs) {
    fs::create_dir_all(output_dir)
        .unwrap_or_else(|err| panic!("failed to create {}: {err}", output_dir.display()));

    let artifacts = [
        (
            "claim_entitlement_report.json",
            serde_json::to_vec_pretty(&outputs.claim_entitlement_report)
                .expect("claim entitlement report should serialize"),
        ),
        (
            "missing_evidence_cutsets.json",
            serde_json::to_vec_pretty(&outputs.missing_evidence_cutsets)
                .expect("missing evidence cutsets should serialize"),
        ),
        (
            "impossibility_certificates.json",
            serde_json::to_vec_pretty(&outputs.impossibility_certificates)
                .expect("impossibility certificates should serialize"),
        ),
        (
            "claim_counterexample_ledger.json",
            serde_json::to_vec_pretty(&outputs.claim_counterexample_ledger)
                .expect("counterexample ledger should serialize"),
        ),
    ];

    for (filename, bytes) in artifacts {
        let path = output_dir.join(filename);
        fs::write(&path, bytes)
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
    }
}

#[test]
fn rgc_017_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_CLAIM_ENTITLEMENT_ALGEBRA_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    for section in [
        "# RGC Claim Entitlement Algebra V1",
        "## Purpose",
        "## Contract Version",
        "## Claim Atoms",
        "## Evidence Morphisms",
        "## Side-Constraint Lattice",
        "## Disqualifier Rules",
        "## Operator Verification",
    ] {
        assert!(
            doc.contains(section),
            "missing required section in {}: {section}",
            path.display()
        );
    }
}

#[test]
fn rgc_017_contract_parses_and_validates() {
    let contract = load_contract();
    assert_eq!(contract.schema_version, CLAIM_ENTITLEMENT_SCHEMA_VERSION);
    assert_eq!(contract.track.id, "RGC-017");
    assert_eq!(contract.track.name, "Claim Entitlement Algebra");
    assert_eq!(contract.bead_id, "bd-1lsy.1.7");
    assert_eq!(contract.generated_by, "bd-1lsy.1.7");
    assert!(contract.generated_at_utc.ends_with('Z'));

    contract
        .validate()
        .unwrap_or_else(|errors| panic!("contract validation failed: {errors:#?}"));
}

#[test]
fn rgc_017_claim_atoms_cover_shipped_frontier_and_unsupported_tiers() {
    let contract = load_contract();
    let atom_ids = contract
        .claim_atom_catalog
        .atoms
        .iter()
        .map(|atom| atom.atom_id.as_str())
        .collect::<BTreeSet<_>>();

    for atom_id in [
        "claim.frankenctl.compile.shipped",
        "claim.frankenctl.run.shipped",
        "claim.frankenctl.doctor.shipped",
        "claim.react.compile.target",
        "claim.react.ssr.unsupported",
        "claim.v8.universal_dominance.frontier",
        "claim.v8.scoped_observed.publishable",
        "claim.support.unsupported_surface.visible",
        "claim.rollout.doctor_guidance.shipped",
        "claim.ga.exit_evidence.gated",
    ] {
        assert!(
            atom_ids.contains(atom_id),
            "missing required atom {atom_id}"
        );
    }

    let domains = contract
        .claim_atom_catalog
        .atoms
        .iter()
        .map(|atom| atom.domain)
        .collect::<BTreeSet<_>>();
    for domain in [
        ClaimDomain::ShippedSurface,
        ClaimDomain::React,
        ClaimDomain::Supremacy,
        ClaimDomain::Rollout,
        ClaimDomain::Ga,
        ClaimDomain::SupportSurface,
    ] {
        assert!(domains.contains(&domain), "missing domain {domain:?}");
    }

    let tiers = contract
        .claim_atom_catalog
        .atoms
        .iter()
        .map(|atom| atom.tier)
        .collect::<BTreeSet<_>>();
    for tier in [
        ClaimTier::ShippedFact,
        ClaimTier::ScopedObserved,
        ClaimTier::FrontierAmbition,
        ClaimTier::UnsupportedSurface,
    ] {
        assert!(tiers.contains(&tier), "missing tier {tier:?}");
    }
}

#[test]
fn rgc_017_morphisms_bind_known_evidence_sources_to_known_atoms() {
    let contract = load_contract();
    let evidence_kinds = contract
        .evidence_morphism_catalog
        .morphisms
        .iter()
        .map(|morphism| morphism.evidence_kind.as_str())
        .collect::<BTreeSet<_>>();

    for evidence_kind in [
        "docs_help_surface_audit",
        "frankenctl_cli_tests",
        "react_capability_contract",
        "v8_supremacy_contract",
        "runtime_diagnostics_doctor",
        "support_surface_contract",
        "ga_evidence_package",
        "counterexample_ledger",
    ] {
        assert!(
            evidence_kinds.contains(evidence_kind),
            "missing evidence morphism for {evidence_kind}"
        );
    }
}

#[test]
fn rgc_017_required_artifacts_and_log_fields_are_stable() {
    let contract = load_contract();

    let artifacts = contract
        .required_artifacts
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for artifact in [
        "claim_atom_catalog.json",
        "evidence_morphism_catalog.json",
        "side_constraint_lattice.json",
        "disqualifier_rules.json",
        "claim_entitlement_report.json",
        "missing_evidence_cutsets.json",
        "impossibility_certificates.json",
        "claim_counterexample_ledger.json",
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
    ] {
        assert!(artifacts.contains(artifact), "missing artifact {artifact}");
    }

    let log_fields = contract
        .required_structured_log_fields
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for field in [
        "schema_version",
        "scenario_id",
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(log_fields.contains(field), "missing log field {field}");
    }
}

#[test]
fn rgc_017_operator_verification_references_gate_and_replay() {
    let contract = load_contract();
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|command| command == "./scripts/run_rgc_claim_entitlement_algebra.sh ci")
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|command| command == "./scripts/e2e/rgc_claim_entitlement_algebra_replay.sh ci")
    );
}

#[test]
fn rgc_017_scenarios_evaluate_expected_states_and_minimal_cutsets() {
    let contract = load_contract();
    let scenarios = load_scenarios();
    assert_eq!(
        scenarios.schema_version,
        CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION
    );

    let outputs = contract
        .evaluate_scenarios(&scenarios)
        .unwrap_or_else(|errors| panic!("scenario evaluation failed: {errors:#?}"));

    assert_eq!(
        outputs.claim_entitlement_report.schema_version,
        CLAIM_ENTITLEMENT_REPORT_SCHEMA_VERSION
    );
    assert_eq!(
        outputs.missing_evidence_cutsets.schema_version,
        CLAIM_ENTITLEMENT_CUTSET_SCHEMA_VERSION
    );
    assert_eq!(
        outputs.impossibility_certificates.schema_version,
        CLAIM_ENTITLEMENT_IMPOSSIBILITY_SCHEMA_VERSION
    );
    assert_eq!(
        outputs.claim_counterexample_ledger.schema_version,
        CLAIM_ENTITLEMENT_COUNTEREXAMPLE_LEDGER_SCHEMA_VERSION
    );

    for scenario in &scenarios.scenarios {
        let report = scenario_report(&outputs, &scenario.scenario_id);
        let cutsets = scenario_cutsets(&outputs, &scenario.scenario_id);
        let certificates = scenario_certificates(&outputs, &scenario.scenario_id);
        let counterexamples = scenario_counterexamples(&outputs, &scenario.scenario_id);

        for expected in &scenario.expected_outcomes {
            let verdict = report
                .verdicts
                .iter()
                .find(|verdict| verdict.atom_id == expected.atom_id)
                .unwrap_or_else(|| {
                    panic!(
                        "missing verdict for scenario {} atom {}",
                        scenario.scenario_id, expected.atom_id
                    )
                });
            assert_eq!(
                verdict.state, expected.state,
                "unexpected verdict state for scenario {} atom {}",
                scenario.scenario_id, expected.atom_id
            );

            if let Some(morphism_id) = expected.minimal_morphism_id.as_deref() {
                let actual_morphisms = verdict
                    .minimal_cutset_ids
                    .iter()
                    .map(|cutset_id| {
                        cutsets
                            .cutsets
                            .iter()
                            .find(|cutset| cutset.cutset_id == *cutset_id)
                            .unwrap_or_else(|| {
                                panic!(
                                    "missing cutset {} for scenario {}",
                                    cutset_id, scenario.scenario_id
                                )
                            })
                            .supporting_morphism_id
                            .as_str()
                    })
                    .collect::<BTreeSet<_>>();
                assert!(
                    actual_morphisms.contains(morphism_id),
                    "scenario {} atom {} missing minimal morphism {}",
                    scenario.scenario_id,
                    expected.atom_id,
                    morphism_id
                );
            }

            if let Some(rule_id) = expected.impossible_rule_id.as_deref() {
                let actual_rules = verdict
                    .impossibility_certificate_ids
                    .iter()
                    .map(|certificate_id| {
                        certificates
                            .certificates
                            .iter()
                            .find(|certificate| certificate.certificate_id == *certificate_id)
                            .unwrap_or_else(|| {
                                panic!(
                                    "missing certificate {} for scenario {}",
                                    certificate_id, scenario.scenario_id
                                )
                            })
                            .blocking_rule_id
                            .as_str()
                    })
                    .collect::<BTreeSet<_>>();
                assert!(
                    actual_rules.contains(rule_id),
                    "scenario {} atom {} missing impossibility rule {}",
                    scenario.scenario_id,
                    expected.atom_id,
                    rule_id
                );
            }
        }

        if scenario.scenario_id == "not_yet_proven_prefers_smallest_cutset" {
            let atom_cutsets: Vec<_> = cutsets
                .cutsets
                .iter()
                .filter(|c| c.atom_id == "claim.frankenctl.compile.shipped")
                .collect();
            assert_eq!(atom_cutsets.len(), 1);
            assert_eq!(
                atom_cutsets[0].supporting_morphism_id,
                "morphism.docs_help_surface_audit_to_frankenctl_surface"
            );
            assert_eq!(atom_cutsets[0].cost, 1);
        }

        if scenario.scenario_id == "stale_docs_surface_blocks_claim" {
            assert!(
                cutsets.cutsets.iter().any(|cutset| {
                    cutset
                        .blocking_rule_ids
                        .contains(&"rule.stale_evidence".to_string())
                }),
                "stale scenario should preserve the stale-evidence blocker"
            );
        }

        if scenario.scenario_id == "active_counterexample_forbids_shipped_run" {
            let atom_certs: Vec<_> = certificates
                .certificates
                .iter()
                .filter(|c| c.atom_id == "claim.frankenctl.run.shipped")
                .collect();
            assert_eq!(atom_certs.len(), 1);
            let atom_ledger: Vec<_> = counterexamples
                .entries
                .iter()
                .filter(|e| e.atom_id == "claim.frankenctl.run.shipped")
                .collect();
            assert_eq!(atom_ledger.len(), 1);
            assert_eq!(
                atom_ledger[0].blocking_rule_id,
                "rule.active_counterexample"
            );
        }
    }
}

#[test]
fn rgc_017_scenario_artifacts_emit_stable_reports() {
    let contract = load_contract();
    let scenarios = load_scenarios();
    let outputs = contract
        .evaluate_scenarios(&scenarios)
        .unwrap_or_else(|errors| panic!("scenario evaluation failed: {errors:#?}"));

    let output_dir = std::env::var_os("RGC_CLAIM_ENTITLEMENT_ARTIFACT_DIR")
        .map(|_| repo_relative_env_path("RGC_CLAIM_ENTITLEMENT_ARTIFACT_DIR", "artifacts"))
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("rgc-claim-entitlement-{}", process::id()))
        });
    write_outputs(&output_dir, &outputs);

    for artifact in [
        "claim_entitlement_report.json",
        "missing_evidence_cutsets.json",
        "impossibility_certificates.json",
        "claim_counterexample_ledger.json",
    ] {
        let path = output_dir.join(artifact);
        assert!(path.is_file(), "missing artifact {}", path.display());
        let contents = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        assert!(
            contents.contains("schema_version"),
            "artifact {} should contain schema metadata",
            path.display()
        );
    }
}

#[test]
fn rgc_017_gate_script_is_rch_backed_and_materializes_expected_artifacts() {
    let path = repo_root().join("scripts/run_rgc_claim_entitlement_algebra.sh");
    let script = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    for required_fragment in [
        "rch exec -- env",
        "cargo check -p frankenengine-engine --test claim_entitlement",
        "cargo test -p frankenengine-engine --test claim_entitlement",
        "cargo clippy -p frankenengine-engine --test claim_entitlement -- -D warnings",
        "RGC_CLAIM_ENTITLEMENT_ARTIFACT_DIR",
        "RGC_CLAIM_ENTITLEMENT_SCENARIO_FIXTURE",
        "claim_entitlement_report.json",
        "missing_evidence_cutsets.json",
        "impossibility_certificates.json",
        "claim_counterexample_ledger.json",
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
    ] {
        assert!(
            script.contains(required_fragment),
            "script missing fragment `{required_fragment}`"
        );
    }
}

#[test]
fn rgc_017_component_and_policy_ids_are_stable() {
    let contract = load_contract();
    assert_eq!(CLAIM_ENTITLEMENT_COMPONENT, "rgc_claim_entitlement_algebra");
    assert_eq!(
        CLAIM_ENTITLEMENT_POLICY_ID,
        "policy-rgc-claim-entitlement-algebra-v1"
    );
    assert!(CLAIM_ENTITLEMENT_CONTRACT_JSON.contains(CLAIM_ENTITLEMENT_SCHEMA_VERSION));
    assert_eq!(contract.track.id, "RGC-017");
}

// ---------------------------------------------------------------------------
// Serde round-trip tests for enums
// ---------------------------------------------------------------------------

#[test]
fn serde_round_trip_claim_domain_all_variants() {
    use claim_entitlement::ClaimDomain;
    let variants = [
        ClaimDomain::Compatibility,
        ClaimDomain::ShippedSurface,
        ClaimDomain::React,
        ClaimDomain::Supremacy,
        ClaimDomain::Rollout,
        ClaimDomain::Ga,
        ClaimDomain::SupportSurface,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialize ClaimDomain");
        let back: ClaimDomain = serde_json::from_str(&json).expect("deserialize ClaimDomain");
        assert_eq!(*variant, back);
    }
}

#[test]
fn serde_claim_domain_snake_case_values() {
    use claim_entitlement::ClaimDomain;
    assert_eq!(
        serde_json::to_string(&ClaimDomain::ShippedSurface).unwrap(),
        "\"shipped_surface\""
    );
    assert_eq!(
        serde_json::to_string(&ClaimDomain::SupportSurface).unwrap(),
        "\"support_surface\""
    );
    assert_eq!(
        serde_json::to_string(&ClaimDomain::Compatibility).unwrap(),
        "\"compatibility\""
    );
}

#[test]
fn serde_round_trip_claim_tier_all_variants() {
    use claim_entitlement::ClaimTier;
    let variants = [
        ClaimTier::ShippedFact,
        ClaimTier::ScopedObserved,
        ClaimTier::FrontierAmbition,
        ClaimTier::UnsupportedSurface,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialize ClaimTier");
        let back: ClaimTier = serde_json::from_str(&json).expect("deserialize ClaimTier");
        assert_eq!(*variant, back);
    }
}

#[test]
fn serde_claim_tier_snake_case_values() {
    use claim_entitlement::ClaimTier;
    assert_eq!(
        serde_json::to_string(&ClaimTier::ShippedFact).unwrap(),
        "\"shipped_fact\""
    );
    assert_eq!(
        serde_json::to_string(&ClaimTier::FrontierAmbition).unwrap(),
        "\"frontier_ambition\""
    );
}

#[test]
fn serde_round_trip_morphism_effect_all_variants() {
    use claim_entitlement::MorphismEffect;
    let variants = [
        MorphismEffect::Supports,
        MorphismEffect::Constrains,
        MorphismEffect::Disqualifies,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialize MorphismEffect");
        let back: MorphismEffect = serde_json::from_str(&json).expect("deserialize MorphismEffect");
        assert_eq!(*variant, back);
    }
}

#[test]
fn serde_round_trip_disqualifier_verdict_all_variants() {
    use claim_entitlement::DisqualifierVerdict;
    let variants = [
        DisqualifierVerdict::Forbid,
        DisqualifierVerdict::DowngradeToScoped,
        DisqualifierVerdict::DowngradeToTarget,
        DisqualifierVerdict::RequireOperatorGuidance,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialize DisqualifierVerdict");
        let back: DisqualifierVerdict =
            serde_json::from_str(&json).expect("deserialize DisqualifierVerdict");
        assert_eq!(*variant, back);
    }
}

#[test]
fn serde_round_trip_evidence_state_all_variants() {
    use claim_entitlement::EvidenceState;
    let variants = [EvidenceState::Fresh, EvidenceState::Stale];
    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialize EvidenceState");
        let back: EvidenceState = serde_json::from_str(&json).expect("deserialize EvidenceState");
        assert_eq!(*variant, back);
    }
}

#[test]
fn serde_round_trip_claim_verdict_state_all_variants() {
    use claim_entitlement::ClaimVerdictState;
    let variants = [
        ClaimVerdictState::Entitled,
        ClaimVerdictState::NotYetProven,
        ClaimVerdictState::BlockedByMissingEvidence,
        ClaimVerdictState::CurrentlyFalseUnderActiveCounterexample,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialize ClaimVerdictState");
        let back: ClaimVerdictState =
            serde_json::from_str(&json).expect("deserialize ClaimVerdictState");
        assert_eq!(*variant, back);
    }
}

// ---------------------------------------------------------------------------
// Serde round-trip tests for struct types
// ---------------------------------------------------------------------------

#[test]
fn serde_round_trip_contract_track() {
    use claim_entitlement::ContractTrack;
    let track = ContractTrack {
        id: "RGC-017".to_string(),
        name: "Claim Entitlement Algebra".to_string(),
    };
    let json = serde_json::to_string(&track).unwrap();
    let back: ContractTrack = serde_json::from_str(&json).unwrap();
    assert_eq!(track, back);
}

#[test]
fn serde_round_trip_side_constraint() {
    use claim_entitlement::SideConstraint;
    let constraint = SideConstraint {
        constraint_id: "constraint.test".to_string(),
        constraint_class: "test_class".to_string(),
        description: "A test constraint.".to_string(),
    };
    let json = serde_json::to_string(&constraint).unwrap();
    let back: SideConstraint = serde_json::from_str(&json).unwrap();
    assert_eq!(constraint, back);
}

#[test]
fn serde_round_trip_constraint_relation() {
    use claim_entitlement::ConstraintRelation;
    let relation = ConstraintRelation {
        lower_constraint_id: "constraint.low".to_string(),
        higher_constraint_id: "constraint.high".to_string(),
    };
    let json = serde_json::to_string(&relation).unwrap();
    let back: ConstraintRelation = serde_json::from_str(&json).unwrap();
    assert_eq!(relation, back);
}

#[test]
fn serde_round_trip_observed_evidence() {
    use claim_entitlement::{EvidenceState, ObservedEvidence};
    let evidence = ObservedEvidence {
        evidence_kind: "docs_help_surface_audit".to_string(),
        state: EvidenceState::Fresh,
        triggered_rule_ids: vec!["rule.stale_evidence".to_string()],
    };
    let json = serde_json::to_string(&evidence).unwrap();
    let back: ObservedEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(evidence, back);
}

#[test]
fn serde_round_trip_expected_claim_outcome() {
    use claim_entitlement::{ClaimVerdictState, ExpectedClaimOutcome};
    let outcome = ExpectedClaimOutcome {
        atom_id: "claim.test.atom".to_string(),
        state: ClaimVerdictState::Entitled,
        minimal_morphism_id: Some("morphism.test".to_string()),
        impossible_rule_id: None,
    };
    let json = serde_json::to_string(&outcome).unwrap();
    let back: ExpectedClaimOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(outcome, back);
}

#[test]
fn serde_round_trip_full_contract() {
    let contract = load_contract();
    let json = serde_json::to_string_pretty(&contract).unwrap();
    let back: ClaimEntitlementContract = serde_json::from_str(&json).unwrap();
    assert_eq!(contract, back);
}

#[test]
fn serde_round_trip_full_evaluation_outputs() {
    let contract = load_contract();
    let scenarios = load_scenarios();
    let outputs = contract.evaluate_scenarios(&scenarios).unwrap();
    let json = serde_json::to_string_pretty(&outputs).unwrap();
    let back: ClaimEvaluationOutputs = serde_json::from_str(&json).unwrap();
    assert_eq!(outputs, back);
}

#[test]
fn serde_round_trip_scenario_set() {
    let scenarios = load_scenarios();
    let json = serde_json::to_string_pretty(&scenarios).unwrap();
    let back: ClaimEvaluationScenarioSet = serde_json::from_str(&json).unwrap();
    assert_eq!(scenarios, back);
}

// ---------------------------------------------------------------------------
// Enum ordering tests (Ord is derived)
// ---------------------------------------------------------------------------

#[test]
fn claim_domain_ordering_is_deterministic() {
    use claim_entitlement::ClaimDomain;
    let mut domains = vec![
        ClaimDomain::SupportSurface,
        ClaimDomain::Compatibility,
        ClaimDomain::Ga,
        ClaimDomain::React,
    ];
    domains.sort();
    let expected = vec![
        ClaimDomain::Compatibility,
        ClaimDomain::React,
        ClaimDomain::Ga,
        ClaimDomain::SupportSurface,
    ];
    assert_eq!(domains, expected);
}

#[test]
fn claim_tier_ordering_is_deterministic() {
    use claim_entitlement::ClaimTier;
    let mut tiers = vec![
        ClaimTier::UnsupportedSurface,
        ClaimTier::ShippedFact,
        ClaimTier::FrontierAmbition,
        ClaimTier::ScopedObserved,
    ];
    tiers.sort();
    let expected = vec![
        ClaimTier::ShippedFact,
        ClaimTier::ScopedObserved,
        ClaimTier::FrontierAmbition,
        ClaimTier::UnsupportedSurface,
    ];
    assert_eq!(tiers, expected);
}

// ---------------------------------------------------------------------------
// Validation error path tests
// ---------------------------------------------------------------------------

fn make_minimal_contract() -> ClaimEntitlementContract {
    use claim_entitlement::*;
    ClaimEntitlementContract {
        schema_version: CLAIM_ENTITLEMENT_SCHEMA_VERSION.to_string(),
        contract_version: "0.1.0".to_string(),
        bead_id: "bd-test".to_string(),
        generated_by: "bd-test".to_string(),
        generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
        track: ContractTrack {
            id: "RGC-017".to_string(),
            name: "Test".to_string(),
        },
        required_artifacts: Vec::new(),
        required_structured_log_fields: Vec::new(),
        claim_atom_catalog: ClaimAtomCatalog {
            schema_version: "v1".to_string(),
            atoms: vec![
                ClaimAtom {
                    atom_id: "claim.test.shipped".to_string(),
                    domain: ClaimDomain::ShippedSurface,
                    tier: ClaimTier::ShippedFact,
                    statement_class: "test".to_string(),
                    surface: "test".to_string(),
                    description: "shipped fact".to_string(),
                    source_documents: Vec::new(),
                    owning_beads: Vec::new(),
                },
                ClaimAtom {
                    atom_id: "claim.test.frontier".to_string(),
                    domain: ClaimDomain::Supremacy,
                    tier: ClaimTier::FrontierAmbition,
                    statement_class: "test".to_string(),
                    surface: "test".to_string(),
                    description: "frontier ambition".to_string(),
                    source_documents: Vec::new(),
                    owning_beads: Vec::new(),
                },
                ClaimAtom {
                    atom_id: "claim.test.unsupported".to_string(),
                    domain: ClaimDomain::SupportSurface,
                    tier: ClaimTier::UnsupportedSurface,
                    statement_class: "test".to_string(),
                    surface: "test".to_string(),
                    description: "unsupported surface".to_string(),
                    source_documents: Vec::new(),
                    owning_beads: Vec::new(),
                },
            ],
        },
        evidence_morphism_catalog: EvidenceMorphismCatalog {
            schema_version: "v1".to_string(),
            morphisms: vec![EvidenceMorphism {
                morphism_id: "morphism.test_support".to_string(),
                evidence_kind: "test_evidence".to_string(),
                effect: MorphismEffect::Supports,
                target_atoms: vec!["claim.test.shipped".to_string()],
                requires_side_constraints: vec!["constraint.bottom".to_string()],
                blocked_by_rules: Vec::new(),
                rationale: "test morphism".to_string(),
            }],
        },
        side_constraint_lattice: SideConstraintLattice {
            schema_version: "v1".to_string(),
            top_constraint_id: "constraint.top".to_string(),
            bottom_constraint_id: "constraint.bottom".to_string(),
            constraints: vec![
                SideConstraint {
                    constraint_id: "constraint.top".to_string(),
                    constraint_class: "test".to_string(),
                    description: "top".to_string(),
                },
                SideConstraint {
                    constraint_id: "constraint.bottom".to_string(),
                    constraint_class: "test".to_string(),
                    description: "bottom".to_string(),
                },
            ],
            cover_relations: vec![ConstraintRelation {
                lower_constraint_id: "constraint.bottom".to_string(),
                higher_constraint_id: "constraint.top".to_string(),
            }],
        },
        disqualifier_rules: DisqualifierRuleSet {
            schema_version: "v1".to_string(),
            precedence_order: vec!["rule.test_forbid".to_string()],
            rules: vec![DisqualifierRule {
                rule_id: "rule.test_forbid".to_string(),
                precedence: 0,
                evidence_kind: "counterexample".to_string(),
                condition: "test condition".to_string(),
                target_atoms: vec!["claim.test.shipped".to_string()],
                verdict: DisqualifierVerdict::Forbid,
                remediation: "fix it".to_string(),
            }],
        },
        operator_verification: Vec::new(),
    }
}

#[test]
fn validate_rejects_wrong_schema_version() {
    let mut contract = make_minimal_contract();
    contract.schema_version = "wrong-version".to_string();
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("unexpected schema_version"))
    );
}

#[test]
fn validate_rejects_wrong_track_id() {
    let mut contract = make_minimal_contract();
    contract.track.id = "RGC-999".to_string();
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("unexpected track id"))
    );
}

#[test]
fn validate_detects_duplicate_atom_ids() {
    use claim_entitlement::*;
    let mut contract = make_minimal_contract();
    contract.claim_atom_catalog.atoms.push(ClaimAtom {
        atom_id: "claim.test.shipped".to_string(),
        domain: ClaimDomain::ShippedSurface,
        tier: ClaimTier::ShippedFact,
        statement_class: "test".to_string(),
        surface: "test".to_string(),
        description: "duplicate".to_string(),
        source_documents: Vec::new(),
        owning_beads: Vec::new(),
    });
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("duplicate claim atom id"))
    );
}

#[test]
fn validate_detects_duplicate_morphism_ids() {
    use claim_entitlement::*;
    let mut contract = make_minimal_contract();
    contract
        .evidence_morphism_catalog
        .morphisms
        .push(EvidenceMorphism {
            morphism_id: "morphism.test_support".to_string(),
            evidence_kind: "other_evidence".to_string(),
            effect: MorphismEffect::Supports,
            target_atoms: vec!["claim.test.shipped".to_string()],
            requires_side_constraints: Vec::new(),
            blocked_by_rules: Vec::new(),
            rationale: "dup".to_string(),
        });
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("duplicate evidence morphism id"))
    );
}

#[test]
fn validate_detects_morphism_referencing_unknown_atom() {
    use claim_entitlement::*;
    let mut contract = make_minimal_contract();
    contract
        .evidence_morphism_catalog
        .morphisms
        .push(EvidenceMorphism {
            morphism_id: "morphism.orphan".to_string(),
            evidence_kind: "orphan_evidence".to_string(),
            effect: MorphismEffect::Supports,
            target_atoms: vec!["claim.nonexistent.atom".to_string()],
            requires_side_constraints: Vec::new(),
            blocked_by_rules: Vec::new(),
            rationale: "orphan".to_string(),
        });
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("references unknown atom"))
    );
}

#[test]
fn validate_detects_morphism_referencing_unknown_constraint() {
    use claim_entitlement::*;
    let mut contract = make_minimal_contract();
    contract
        .evidence_morphism_catalog
        .morphisms
        .push(EvidenceMorphism {
            morphism_id: "morphism.bad_constraint".to_string(),
            evidence_kind: "bad_evidence".to_string(),
            effect: MorphismEffect::Constrains,
            target_atoms: vec!["claim.test.shipped".to_string()],
            requires_side_constraints: vec!["constraint.nonexistent".to_string()],
            blocked_by_rules: Vec::new(),
            rationale: "bad".to_string(),
        });
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("references unknown side constraint"))
    );
}

#[test]
fn validate_detects_morphism_referencing_unknown_rule() {
    use claim_entitlement::*;
    let mut contract = make_minimal_contract();
    contract
        .evidence_morphism_catalog
        .morphisms
        .push(EvidenceMorphism {
            morphism_id: "morphism.bad_rule".to_string(),
            evidence_kind: "bad_evidence".to_string(),
            effect: MorphismEffect::Constrains,
            target_atoms: vec!["claim.test.shipped".to_string()],
            requires_side_constraints: Vec::new(),
            blocked_by_rules: vec!["rule.nonexistent".to_string()],
            rationale: "bad".to_string(),
        });
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("references unknown disqualifier rule"))
    );
}

#[test]
fn validate_detects_self_referential_cover_relation() {
    use claim_entitlement::ConstraintRelation;
    let mut contract = make_minimal_contract();
    contract
        .side_constraint_lattice
        .cover_relations
        .push(ConstraintRelation {
            lower_constraint_id: "constraint.bottom".to_string(),
            higher_constraint_id: "constraint.bottom".to_string(),
        });
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("self-referential"))
    );
}

#[test]
fn validate_detects_lattice_cycle() {
    use claim_entitlement::{ConstraintRelation, SideConstraint};
    let mut contract = make_minimal_contract();
    contract
        .side_constraint_lattice
        .constraints
        .push(SideConstraint {
            constraint_id: "constraint.mid".to_string(),
            constraint_class: "test".to_string(),
            description: "mid".to_string(),
        });
    contract.side_constraint_lattice.cover_relations = vec![
        ConstraintRelation {
            lower_constraint_id: "constraint.bottom".to_string(),
            higher_constraint_id: "constraint.mid".to_string(),
        },
        ConstraintRelation {
            lower_constraint_id: "constraint.mid".to_string(),
            higher_constraint_id: "constraint.top".to_string(),
        },
        ConstraintRelation {
            lower_constraint_id: "constraint.top".to_string(),
            higher_constraint_id: "constraint.bottom".to_string(),
        },
    ];
    let errors = contract.validate().unwrap_err();
    assert!(errors.iter().any(|error| error.contains("cycle")));
}

#[test]
fn validate_detects_duplicate_disqualifier_precedence() {
    use claim_entitlement::{DisqualifierRule, DisqualifierVerdict};
    let mut contract = make_minimal_contract();
    contract.disqualifier_rules.rules.push(DisqualifierRule {
        rule_id: "rule.dup_precedence".to_string(),
        precedence: 0,
        evidence_kind: "dup".to_string(),
        condition: "dup".to_string(),
        target_atoms: vec!["claim.test.shipped".to_string()],
        verdict: DisqualifierVerdict::DowngradeToScoped,
        remediation: "dup".to_string(),
    });
    contract.disqualifier_rules.precedence_order = vec![
        "rule.test_forbid".to_string(),
        "rule.dup_precedence".to_string(),
    ];
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("duplicate disqualifier precedence"))
    );
}

#[test]
fn validate_detects_mismatched_precedence_order() {
    use claim_entitlement::{DisqualifierRule, DisqualifierVerdict};
    let mut contract = make_minimal_contract();
    contract.disqualifier_rules.rules.push(DisqualifierRule {
        rule_id: "rule.second".to_string(),
        precedence: 1,
        evidence_kind: "second".to_string(),
        condition: "test".to_string(),
        target_atoms: vec!["claim.test.shipped".to_string()],
        verdict: DisqualifierVerdict::DowngradeToTarget,
        remediation: "fix".to_string(),
    });
    // Wrong order: second should come after test_forbid by precedence
    contract.disqualifier_rules.precedence_order =
        vec!["rule.second".to_string(), "rule.test_forbid".to_string()];
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("precedence_order does not match"))
    );
}

#[test]
fn validate_detects_missing_top_constraint() {
    let mut contract = make_minimal_contract();
    contract.side_constraint_lattice.top_constraint_id = "constraint.missing_top".to_string();
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("top constraint") && error.contains("missing"))
    );
}

#[test]
fn validate_detects_missing_bottom_constraint() {
    let mut contract = make_minimal_contract();
    contract.side_constraint_lattice.bottom_constraint_id = "constraint.missing_bottom".to_string();
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("bottom constraint") && error.contains("missing"))
    );
}

#[test]
fn validate_detects_missing_tier_coverage() {
    let mut contract = make_minimal_contract();
    // Remove all frontier_ambition atoms
    contract
        .claim_atom_catalog
        .atoms
        .retain(|atom| atom.tier != claim_entitlement::ClaimTier::FrontierAmbition);
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("missing frontier_ambition"))
    );
}

// ---------------------------------------------------------------------------
// Scenario evaluation edge case tests
// ---------------------------------------------------------------------------

fn make_minimal_scenarios(
    scenario_id: &str,
    evidence: Vec<claim_entitlement::ObservedEvidence>,
    constraints: Vec<String>,
    expected: Vec<claim_entitlement::ExpectedClaimOutcome>,
) -> ClaimEvaluationScenarioSet {
    ClaimEvaluationScenarioSet {
        schema_version: CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION.to_string(),
        scenario_version: "0.1.0".to_string(),
        scenarios: vec![claim_entitlement::ClaimEvaluationScenario {
            scenario_id: scenario_id.to_string(),
            description: "synthetic test scenario".to_string(),
            evaluated_at_utc: "2026-01-01T00:00:00Z".to_string(),
            observed_evidence: evidence,
            satisfied_constraints: constraints,
            expected_outcomes: expected,
        }],
    }
}

#[test]
fn evaluate_empty_scenarios_produces_empty_outputs() {
    let contract = make_minimal_contract();
    let scenarios = ClaimEvaluationScenarioSet {
        schema_version: CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION.to_string(),
        scenario_version: "0.1.0".to_string(),
        scenarios: Vec::new(),
    };
    let outputs = contract.evaluate_scenarios(&scenarios).unwrap();
    assert!(
        outputs
            .claim_entitlement_report
            .evaluated_scenarios
            .is_empty()
    );
    assert!(
        outputs
            .missing_evidence_cutsets
            .evaluated_scenarios
            .is_empty()
    );
    assert!(
        outputs
            .impossibility_certificates
            .evaluated_scenarios
            .is_empty()
    );
    assert!(
        outputs
            .claim_counterexample_ledger
            .evaluated_scenarios
            .is_empty()
    );
}

#[test]
fn evaluate_scenario_with_no_evidence_yields_not_yet_proven() {
    let contract = make_minimal_contract();
    let scenarios = make_minimal_scenarios(
        "empty_evidence",
        Vec::new(),
        vec!["constraint.bottom".to_string()],
        vec![claim_entitlement::ExpectedClaimOutcome {
            atom_id: "claim.test.shipped".to_string(),
            state: claim_entitlement::ClaimVerdictState::NotYetProven,
            minimal_morphism_id: None,
            impossible_rule_id: None,
        }],
    );
    let outputs = contract.evaluate_scenarios(&scenarios).unwrap();
    let report = &outputs.claim_entitlement_report.evaluated_scenarios[0];
    let verdict = report
        .verdicts
        .iter()
        .find(|v| v.atom_id == "claim.test.shipped")
        .unwrap();
    assert_eq!(
        verdict.state,
        claim_entitlement::ClaimVerdictState::NotYetProven
    );
}

#[test]
fn evaluate_scenario_fresh_evidence_with_constraints_yields_entitled() {
    let contract = make_minimal_contract();
    let scenarios = make_minimal_scenarios(
        "entitled_scenario",
        vec![claim_entitlement::ObservedEvidence {
            evidence_kind: "test_evidence".to_string(),
            state: claim_entitlement::EvidenceState::Fresh,
            triggered_rule_ids: Vec::new(),
        }],
        vec!["constraint.bottom".to_string()],
        vec![claim_entitlement::ExpectedClaimOutcome {
            atom_id: "claim.test.shipped".to_string(),
            state: claim_entitlement::ClaimVerdictState::Entitled,
            minimal_morphism_id: None,
            impossible_rule_id: None,
        }],
    );
    let outputs = contract.evaluate_scenarios(&scenarios).unwrap();
    let report = &outputs.claim_entitlement_report.evaluated_scenarios[0];
    let verdict = report
        .verdicts
        .iter()
        .find(|v| v.atom_id == "claim.test.shipped")
        .unwrap();
    assert_eq!(
        verdict.state,
        claim_entitlement::ClaimVerdictState::Entitled
    );
    assert!(
        verdict
            .supporting_morphism_ids
            .contains(&"morphism.test_support".to_string())
    );
}

#[test]
fn evaluate_scenario_forbid_rule_yields_counterexample() {
    use claim_entitlement::*;
    let contract = make_minimal_contract();
    let scenarios = make_minimal_scenarios(
        "forbid_scenario",
        vec![ObservedEvidence {
            evidence_kind: "counterexample".to_string(),
            state: EvidenceState::Fresh,
            triggered_rule_ids: vec!["rule.test_forbid".to_string()],
        }],
        vec!["constraint.bottom".to_string()],
        vec![ExpectedClaimOutcome {
            atom_id: "claim.test.shipped".to_string(),
            state: ClaimVerdictState::CurrentlyFalseUnderActiveCounterexample,
            minimal_morphism_id: None,
            impossible_rule_id: Some("rule.test_forbid".to_string()),
        }],
    );
    let outputs = contract.evaluate_scenarios(&scenarios).unwrap();
    let report = &outputs.claim_entitlement_report.evaluated_scenarios[0];
    let verdict = report
        .verdicts
        .iter()
        .find(|v| v.atom_id == "claim.test.shipped")
        .unwrap();
    assert_eq!(
        verdict.state,
        ClaimVerdictState::CurrentlyFalseUnderActiveCounterexample
    );
    assert!(!verdict.impossibility_certificate_ids.is_empty());
    // Also check the certificates and counterexample ledger
    let certs = &outputs.impossibility_certificates.evaluated_scenarios[0];
    assert_eq!(certs.certificates.len(), 1);
    assert_eq!(certs.certificates[0].blocking_rule_id, "rule.test_forbid");
    let ledger = &outputs.claim_counterexample_ledger.evaluated_scenarios[0];
    assert_eq!(ledger.entries.len(), 1);
    assert_eq!(ledger.entries[0].blocking_rule_id, "rule.test_forbid");
}

#[test]
fn evaluate_scenario_stale_evidence_yields_blocked_by_missing() {
    use claim_entitlement::*;
    let mut contract = make_minimal_contract();
    // Add a non-forbid blocking rule
    contract.disqualifier_rules.rules.push(DisqualifierRule {
        rule_id: "rule.stale".to_string(),
        precedence: 1,
        evidence_kind: "artifact_ttl".to_string(),
        condition: "stale".to_string(),
        target_atoms: vec!["claim.test.shipped".to_string()],
        verdict: DisqualifierVerdict::DowngradeToScoped,
        remediation: "refresh".to_string(),
    });
    contract.disqualifier_rules.precedence_order =
        vec!["rule.test_forbid".to_string(), "rule.stale".to_string()];
    // Add the stale rule to the morphism's blocked_by_rules
    contract.evidence_morphism_catalog.morphisms[0]
        .blocked_by_rules
        .push("rule.stale".to_string());

    let scenarios = make_minimal_scenarios(
        "stale_scenario",
        vec![ObservedEvidence {
            evidence_kind: "test_evidence".to_string(),
            state: EvidenceState::Stale,
            triggered_rule_ids: vec!["rule.stale".to_string()],
        }],
        vec!["constraint.bottom".to_string()],
        vec![ExpectedClaimOutcome {
            atom_id: "claim.test.shipped".to_string(),
            state: ClaimVerdictState::BlockedByMissingEvidence,
            minimal_morphism_id: None,
            impossible_rule_id: None,
        }],
    );
    let outputs = contract.evaluate_scenarios(&scenarios).unwrap();
    let report = &outputs.claim_entitlement_report.evaluated_scenarios[0];
    let verdict = report
        .verdicts
        .iter()
        .find(|v| v.atom_id == "claim.test.shipped")
        .unwrap();
    assert_eq!(verdict.state, ClaimVerdictState::BlockedByMissingEvidence);
}

#[test]
fn evaluate_rejects_unknown_evidence_kind_in_scenario() {
    let contract = make_minimal_contract();
    let scenarios = make_minimal_scenarios(
        "bad_evidence",
        vec![claim_entitlement::ObservedEvidence {
            evidence_kind: "nonexistent_evidence".to_string(),
            state: claim_entitlement::EvidenceState::Fresh,
            triggered_rule_ids: Vec::new(),
        }],
        Vec::new(),
        Vec::new(),
    );
    let errors = contract.evaluate_scenarios(&scenarios).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("unknown evidence_kind"))
    );
}

#[test]
fn evaluate_rejects_unknown_rule_in_scenario() {
    let contract = make_minimal_contract();
    let scenarios = make_minimal_scenarios(
        "bad_rule",
        vec![claim_entitlement::ObservedEvidence {
            evidence_kind: "test_evidence".to_string(),
            state: claim_entitlement::EvidenceState::Fresh,
            triggered_rule_ids: vec!["rule.nonexistent".to_string()],
        }],
        Vec::new(),
        Vec::new(),
    );
    let errors = contract.evaluate_scenarios(&scenarios).unwrap_err();
    assert!(errors.iter().any(|error| error.contains("unknown rule")));
}

#[test]
fn evaluate_rejects_unknown_constraint_in_scenario() {
    let contract = make_minimal_contract();
    let scenarios = make_minimal_scenarios(
        "bad_constraint",
        Vec::new(),
        vec!["constraint.nonexistent".to_string()],
        Vec::new(),
    );
    let errors = contract.evaluate_scenarios(&scenarios).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("unknown satisfied constraint"))
    );
}

#[test]
fn evaluate_rejects_unknown_atom_in_expected_outcomes() {
    let contract = make_minimal_contract();
    let scenarios = make_minimal_scenarios(
        "bad_atom",
        Vec::new(),
        Vec::new(),
        vec![claim_entitlement::ExpectedClaimOutcome {
            atom_id: "claim.nonexistent.atom".to_string(),
            state: claim_entitlement::ClaimVerdictState::NotYetProven,
            minimal_morphism_id: None,
            impossible_rule_id: None,
        }],
    );
    let errors = contract.evaluate_scenarios(&scenarios).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("unknown expected atom"))
    );
}

#[test]
fn evaluate_rejects_duplicate_scenario_ids() {
    let contract = make_minimal_contract();
    let mut scenarios = ClaimEvaluationScenarioSet {
        schema_version: CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION.to_string(),
        scenario_version: "0.1.0".to_string(),
        scenarios: Vec::new(),
    };
    for _ in 0..2 {
        scenarios
            .scenarios
            .push(claim_entitlement::ClaimEvaluationScenario {
                scenario_id: "dup_scenario".to_string(),
                description: "dup".to_string(),
                evaluated_at_utc: "2026-01-01T00:00:00Z".to_string(),
                observed_evidence: Vec::new(),
                satisfied_constraints: Vec::new(),
                expected_outcomes: Vec::new(),
            });
    }
    let errors = contract.evaluate_scenarios(&scenarios).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("duplicate scenario id"))
    );
}

#[test]
fn evaluate_rejects_wrong_scenario_schema_version() {
    let contract = make_minimal_contract();
    let scenarios = ClaimEvaluationScenarioSet {
        schema_version: "wrong-scenario-version".to_string(),
        scenario_version: "0.1.0".to_string(),
        scenarios: Vec::new(),
    };
    let errors = contract.evaluate_scenarios(&scenarios).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("unexpected scenario schema_version"))
    );
}

// ---------------------------------------------------------------------------
// Determinism tests
// ---------------------------------------------------------------------------

#[test]
fn evaluation_is_deterministic_across_runs() {
    let contract = load_contract();
    let scenarios = load_scenarios();
    let outputs1 = contract.evaluate_scenarios(&scenarios).unwrap();
    let outputs2 = contract.evaluate_scenarios(&scenarios).unwrap();
    assert_eq!(outputs1, outputs2);
}

#[test]
fn evaluation_output_json_is_deterministic() {
    let contract = load_contract();
    let scenarios = load_scenarios();
    let outputs1 = contract.evaluate_scenarios(&scenarios).unwrap();
    let outputs2 = contract.evaluate_scenarios(&scenarios).unwrap();
    let json1 = serde_json::to_string(&outputs1).unwrap();
    let json2 = serde_json::to_string(&outputs2).unwrap();
    assert_eq!(json1, json2);
}

// ---------------------------------------------------------------------------
// Constants stability tests
// ---------------------------------------------------------------------------

#[test]
fn schema_version_constants_are_non_empty_and_prefixed() {
    let versions = [
        CLAIM_ENTITLEMENT_SCHEMA_VERSION,
        CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION,
        CLAIM_ENTITLEMENT_REPORT_SCHEMA_VERSION,
        CLAIM_ENTITLEMENT_CUTSET_SCHEMA_VERSION,
        CLAIM_ENTITLEMENT_IMPOSSIBILITY_SCHEMA_VERSION,
        CLAIM_ENTITLEMENT_COUNTEREXAMPLE_LEDGER_SCHEMA_VERSION,
    ];
    for version in &versions {
        assert!(!version.is_empty());
        assert!(
            version.starts_with("franken-engine."),
            "schema version `{version}` should start with `franken-engine.`"
        );
    }
}

#[test]
fn contract_json_constant_is_valid_json() {
    let value: serde_json::Value = serde_json::from_str(CLAIM_ENTITLEMENT_CONTRACT_JSON)
        .expect("CONTRACT_JSON must be valid JSON");
    assert!(value.is_object());
}

// ---------------------------------------------------------------------------
// Clone and Debug coverage
// ---------------------------------------------------------------------------

#[test]
fn contract_clone_equals_original() {
    let contract = load_contract();
    let cloned = contract.clone();
    assert_eq!(contract, cloned);
}

#[test]
fn claim_verdict_debug_format_contains_field_names() {
    let verdict = claim_entitlement::ClaimVerdict {
        atom_id: "claim.test.atom".to_string(),
        state: claim_entitlement::ClaimVerdictState::Entitled,
        supporting_morphism_ids: vec!["morphism.a".to_string()],
        active_rule_ids: Vec::new(),
        minimal_cutset_ids: Vec::new(),
        impossibility_certificate_ids: Vec::new(),
    };
    let debug = format!("{verdict:?}");
    assert!(debug.contains("atom_id"));
    assert!(debug.contains("Entitled"));
    assert!(debug.contains("morphism.a"));
}

// ---------------------------------------------------------------------------
// Cutset cost computation tests
// ---------------------------------------------------------------------------

#[test]
fn cutset_cost_reflects_missing_evidence_plus_constraints_plus_rules() {
    use claim_entitlement::*;
    let mut contract = make_minimal_contract();
    // Add a second constraint that the morphism requires
    contract
        .side_constraint_lattice
        .constraints
        .push(SideConstraint {
            constraint_id: "constraint.extra".to_string(),
            constraint_class: "test".to_string(),
            description: "extra".to_string(),
        });
    contract.evidence_morphism_catalog.morphisms[0]
        .requires_side_constraints
        .push("constraint.extra".to_string());

    let scenarios = make_minimal_scenarios(
        "cost_check",
        Vec::new(), // no evidence at all
        Vec::new(), // no constraints satisfied
        vec![ExpectedClaimOutcome {
            atom_id: "claim.test.shipped".to_string(),
            state: ClaimVerdictState::NotYetProven,
            minimal_morphism_id: None,
            impossible_rule_id: None,
        }],
    );
    let outputs = contract.evaluate_scenarios(&scenarios).unwrap();
    let cutsets = &outputs.missing_evidence_cutsets.evaluated_scenarios[0];
    assert_eq!(cutsets.cutsets.len(), 1);
    // Cost should be: 1 (missing evidence) + 2 (missing constraints: bottom + extra) = 3
    assert_eq!(cutsets.cutsets[0].cost, 3);
    assert_eq!(cutsets.cutsets[0].missing_evidence_kinds.len(), 1);
    assert_eq!(cutsets.cutsets[0].missing_constraint_ids.len(), 2);
}

#[test]
fn evaluate_rejects_unknown_morphism_in_expected_outcomes() {
    let contract = make_minimal_contract();
    let scenarios = make_minimal_scenarios(
        "bad_morphism",
        Vec::new(),
        Vec::new(),
        vec![claim_entitlement::ExpectedClaimOutcome {
            atom_id: "claim.test.shipped".to_string(),
            state: claim_entitlement::ClaimVerdictState::NotYetProven,
            minimal_morphism_id: Some("morphism.nonexistent".to_string()),
            impossible_rule_id: None,
        }],
    );
    let errors = contract.evaluate_scenarios(&scenarios).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("unknown expected morphism"))
    );
}

#[test]
fn evaluate_rejects_unknown_rule_in_expected_outcomes() {
    let contract = make_minimal_contract();
    let scenarios = make_minimal_scenarios(
        "bad_expected_rule",
        Vec::new(),
        Vec::new(),
        vec![claim_entitlement::ExpectedClaimOutcome {
            atom_id: "claim.test.shipped".to_string(),
            state: claim_entitlement::ClaimVerdictState::NotYetProven,
            minimal_morphism_id: None,
            impossible_rule_id: Some("rule.nonexistent".to_string()),
        }],
    );
    let errors = contract.evaluate_scenarios(&scenarios).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("unknown expected rule"))
    );
}
