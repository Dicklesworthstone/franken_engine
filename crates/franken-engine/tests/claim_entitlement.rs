#![forbid(unsafe_code)]

use std::{collections::BTreeSet, fs, path::PathBuf};

#[path = "../src/claim_entitlement.rs"]
mod claim_entitlement;

use claim_entitlement::{
    CLAIM_ENTITLEMENT_COMPONENT, CLAIM_ENTITLEMENT_CONTRACT_JSON, CLAIM_ENTITLEMENT_POLICY_ID,
    CLAIM_ENTITLEMENT_SCHEMA_VERSION, ClaimDomain, ClaimEntitlementContract, ClaimTier,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_contract() -> ClaimEntitlementContract {
    ClaimEntitlementContract::from_embedded_json()
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
fn rgc_017_gate_script_is_rch_backed_and_materializes_expected_artifacts() {
    let path = repo_root().join("scripts/run_rgc_claim_entitlement_algebra.sh");
    let script = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    for required_fragment in [
        "rch exec -- env",
        "cargo check -p frankenengine-engine --test claim_entitlement",
        "cargo test -p frankenengine-engine --test claim_entitlement",
        "cargo clippy -p frankenengine-engine --test claim_entitlement -- -D warnings",
        "claim_atom_catalog.json",
        "evidence_morphism_catalog.json",
        "side_constraint_lattice.json",
        "disqualifier_rules.json",
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
