#![forbid(unsafe_code)]

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
            assert_eq!(cutsets.cutsets.len(), 1);
            assert_eq!(
                cutsets.cutsets[0].supporting_morphism_id,
                "morphism.docs_help_surface_audit_to_frankenctl_surface"
            );
            assert_eq!(cutsets.cutsets[0].cost, 1);
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
            assert_eq!(certificates.certificates.len(), 1);
            assert_eq!(counterexamples.entries.len(), 1);
            assert_eq!(
                counterexamples.entries[0].blocking_rule_id,
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
