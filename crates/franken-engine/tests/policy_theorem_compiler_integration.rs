#![forbid(unsafe_code)]

//! Integration tests for the `policy_theorem_compiler` module.
//!
//! Covers: Capability, PolicyId, MergeOperator, FormalProperty, AuthorityGrant,
//! Constraint, DecisionPoint, PolicyIrNode, PolicyIr, PropertyWitness,
//! Counterexample, PassResult, CompilationResult, PolicyTheoremCompiler,
//! MachineCheckHooks, HookCheckResult, HookDiagnostic, DiagnosticSeverity,
//! PolicyValidationReceipt, CompilerError — constructors, methods, validation,
//! error paths, Display/Debug, serde round-trips.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::policy_theorem_compiler::{
    AuthorityGrant, Capability, CompilationResult, CompilerError, Constraint, Counterexample,
    DecisionPoint, DiagnosticSeverity, FormalProperty, HookCheckResult, HookDiagnostic,
    MachineCheckHooks, MergeOperator, PassResult, PolicyId, PolicyIr, PolicyIrNode,
    PolicyTheoremCompiler, PolicyValidationReceipt, PropertyWitness,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn cap(name: &str) -> Capability {
    Capability::new(name)
}

fn test_universe() -> BTreeSet<Capability> {
    let mut s = BTreeSet::new();
    s.insert(cap("fs.read"));
    s.insert(cap("fs.write"));
    s.insert(cap("net.egress"));
    s.insert(cap("policy.read"));
    s.insert(cap("policy.write"));
    s
}

fn grant(subject: &str, capability: &str, scope: &str) -> AuthorityGrant {
    AuthorityGrant {
        subject: subject.into(),
        capability: cap(capability),
        conditions: BTreeSet::new(),
        scope: scope.into(),
        lifetime_epochs: 10,
    }
}

fn simple_node(id: &str, merge_op: MergeOperator, grants: Vec<AuthorityGrant>) -> PolicyIrNode {
    PolicyIrNode {
        node_id: id.into(),
        grants,
        merge_op,
        property_claims: BTreeSet::new(),
        constraints: Vec::new(),
        decision_point: None,
        priority: 0,
    }
}

fn valid_policy() -> PolicyIr {
    PolicyIr {
        policy_id: PolicyId::new("test-policy-1"),
        version: 1,
        nodes: vec![
            simple_node(
                "n1",
                MergeOperator::Intersection,
                vec![grant("ext-A", "fs.read", "zone-1")],
            ),
            simple_node(
                "n2",
                MergeOperator::Intersection,
                vec![grant("ext-B", "net.egress", "zone-2")],
            ),
        ],
        capability_universe: test_universe(),
        verified_properties: BTreeSet::new(),
        epoch: SecurityEpoch::from_raw(1),
    }
}

fn signing_pair() -> (
    SigningKey,
    frankenengine_engine::signature_preimage::VerificationKey,
) {
    let sk = SigningKey::from_bytes([42u8; 32]);
    let vk = sk.verification_key();
    (sk, vk)
}

// =========================================================================
// Section 1: Capability — construction, Display, serde
// =========================================================================

#[test]
fn capability_new_and_as_str() {
    let c = Capability::new("fs.read");
    assert_eq!(c.as_str(), "fs.read");
}

#[test]
fn capability_display() {
    let c = Capability::new("net.egress");
    assert_eq!(format!("{c}"), "net.egress");
}

#[test]
fn capability_serde_roundtrip() {
    let c = Capability::new("policy.write");
    let json = serde_json::to_string(&c).unwrap();
    let restored: Capability = serde_json::from_str(&json).unwrap();
    assert_eq!(c, restored);
}

#[test]
fn capability_ord() {
    let a = cap("aaa");
    let b = cap("zzz");
    assert!(a < b);
}

// =========================================================================
// Section 2: PolicyId — construction, Display, serde
// =========================================================================

#[test]
fn policy_id_new_and_as_str() {
    let p = PolicyId::new("my-policy");
    assert_eq!(p.as_str(), "my-policy");
}

#[test]
fn policy_id_display() {
    let p = PolicyId::new("display-test");
    assert_eq!(p.to_string(), "display-test");
}

#[test]
fn policy_id_serde_roundtrip() {
    let p = PolicyId::new("serde-id");
    let json = serde_json::to_string(&p).unwrap();
    let restored: PolicyId = serde_json::from_str(&json).unwrap();
    assert_eq!(p, restored);
}

// =========================================================================
// Section 3: MergeOperator — Display, ordering, serde
// =========================================================================

#[test]
fn merge_operator_display_all_variants() {
    assert_eq!(MergeOperator::Union.to_string(), "union");
    assert_eq!(MergeOperator::Intersection.to_string(), "intersection");
    assert_eq!(MergeOperator::Attenuation.to_string(), "attenuation");
    assert_eq!(MergeOperator::Precedence.to_string(), "precedence");
}

#[test]
fn merge_operator_ordering() {
    assert!(MergeOperator::Union < MergeOperator::Intersection);
    assert!(MergeOperator::Intersection < MergeOperator::Attenuation);
    assert!(MergeOperator::Attenuation < MergeOperator::Precedence);
}

#[test]
fn merge_operator_serde_roundtrip() {
    for op in [
        MergeOperator::Union,
        MergeOperator::Intersection,
        MergeOperator::Attenuation,
        MergeOperator::Precedence,
    ] {
        let json = serde_json::to_string(&op).unwrap();
        let restored: MergeOperator = serde_json::from_str(&json).unwrap();
        assert_eq!(op, restored);
    }
}

// =========================================================================
// Section 4: FormalProperty — Display, ordering, serde
// =========================================================================

#[test]
fn formal_property_display_all_variants() {
    assert_eq!(FormalProperty::Monotonicity.to_string(), "monotonicity");
    assert_eq!(
        FormalProperty::NonInterference.to_string(),
        "non-interference"
    );
    assert_eq!(
        FormalProperty::AttenuationLegality.to_string(),
        "attenuation-legality"
    );
    assert_eq!(
        FormalProperty::MergeDeterminism.to_string(),
        "merge-determinism"
    );
    assert_eq!(
        FormalProperty::PrecedenceStability.to_string(),
        "precedence-stability"
    );
}

#[test]
fn formal_property_ordering() {
    assert!(FormalProperty::Monotonicity < FormalProperty::NonInterference);
    assert!(FormalProperty::NonInterference < FormalProperty::AttenuationLegality);
    assert!(FormalProperty::AttenuationLegality < FormalProperty::MergeDeterminism);
    assert!(FormalProperty::MergeDeterminism < FormalProperty::PrecedenceStability);
}

#[test]
fn formal_property_serde_roundtrip() {
    for fp in [
        FormalProperty::Monotonicity,
        FormalProperty::NonInterference,
        FormalProperty::AttenuationLegality,
        FormalProperty::MergeDeterminism,
        FormalProperty::PrecedenceStability,
    ] {
        let json = serde_json::to_string(&fp).unwrap();
        let restored: FormalProperty = serde_json::from_str(&json).unwrap();
        assert_eq!(fp, restored);
    }
}

// =========================================================================
// Section 5: DiagnosticSeverity — Display, ordering, serde
// =========================================================================

#[test]
fn diagnostic_severity_display() {
    assert_eq!(DiagnosticSeverity::Warning.to_string(), "warning");
    assert_eq!(DiagnosticSeverity::Error.to_string(), "error");
    assert_eq!(DiagnosticSeverity::Fatal.to_string(), "fatal");
}

#[test]
fn diagnostic_severity_ordering() {
    assert!(DiagnosticSeverity::Warning < DiagnosticSeverity::Error);
    assert!(DiagnosticSeverity::Error < DiagnosticSeverity::Fatal);
}

// =========================================================================
// Section 6: Constraint — serde round-trips for all variants
// =========================================================================

#[test]
fn constraint_invariant_serde() {
    let c = Constraint::Invariant("must hold always".into());
    let json = serde_json::to_string(&c).unwrap();
    let restored: Constraint = serde_json::from_str(&json).unwrap();
    assert_eq!(c, restored);
}

#[test]
fn constraint_precondition_serde() {
    let c = Constraint::Precondition("before apply".into());
    let json = serde_json::to_string(&c).unwrap();
    let restored: Constraint = serde_json::from_str(&json).unwrap();
    assert_eq!(c, restored);
}

#[test]
fn constraint_postcondition_serde() {
    let c = Constraint::Postcondition("after apply".into());
    let json = serde_json::to_string(&c).unwrap();
    let restored: Constraint = serde_json::from_str(&json).unwrap();
    assert_eq!(c, restored);
}

#[test]
fn constraint_non_interference_claim_serde() {
    let c = Constraint::NonInterferenceClaim {
        domain_a: "alpha".into(),
        domain_b: "beta".into(),
    };
    let json = serde_json::to_string(&c).unwrap();
    let restored: Constraint = serde_json::from_str(&json).unwrap();
    assert_eq!(c, restored);
}

// =========================================================================
// Section 7: AuthorityGrant — serde, conditions
// =========================================================================

#[test]
fn authority_grant_serde_roundtrip() {
    let mut conds = BTreeSet::new();
    conds.insert("epoch > 5".to_string());
    conds.insert("zone == production".to_string());
    let g = AuthorityGrant {
        subject: "ext-1".into(),
        capability: cap("fs.read"),
        conditions: conds,
        scope: "global".into(),
        lifetime_epochs: 100,
    };
    let json = serde_json::to_string(&g).unwrap();
    let restored: AuthorityGrant = serde_json::from_str(&json).unwrap();
    assert_eq!(g, restored);
}

// =========================================================================
// Section 8: DecisionPoint — serde
// =========================================================================

#[test]
fn decision_point_serde_roundtrip() {
    let dp = DecisionPoint {
        threshold: 3,
        action_map: {
            let mut m = BTreeMap::new();
            m.insert("high-risk".into(), "sandbox".into());
            m.insert("low-risk".into(), "allow".into());
            m
        },
        fallback: "deny".into(),
    };
    let json = serde_json::to_string(&dp).unwrap();
    let restored: DecisionPoint = serde_json::from_str(&json).unwrap();
    assert_eq!(dp, restored);
}

#[test]
fn decision_point_empty_action_map() {
    let dp = DecisionPoint {
        threshold: 0,
        action_map: BTreeMap::new(),
        fallback: "reject".into(),
    };
    let json = serde_json::to_string(&dp).unwrap();
    let restored: DecisionPoint = serde_json::from_str(&json).unwrap();
    assert_eq!(dp, restored);
}

// =========================================================================
// Section 9: PolicyIrNode — serde, with decision point
// =========================================================================

#[test]
fn policy_ir_node_with_decision_point_serde() {
    let mut node = simple_node(
        "decision-node",
        MergeOperator::Precedence,
        vec![grant("ext-A", "fs.read", "zone-1")],
    );
    node.priority = 5;
    node.decision_point = Some(DecisionPoint {
        threshold: 2,
        action_map: {
            let mut m = BTreeMap::new();
            m.insert("cond-a".into(), "action-a".into());
            m
        },
        fallback: "deny".into(),
    });
    node.constraints
        .push(Constraint::Invariant("no escalation".into()));
    node.property_claims.insert(FormalProperty::Monotonicity);

    let json = serde_json::to_string(&node).unwrap();
    let restored: PolicyIrNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, restored);
}

// =========================================================================
// Section 10: PolicyIr — helpers: granted_capabilities, subjects, serde
// =========================================================================

#[test]
fn policy_ir_granted_capabilities() {
    let ir = valid_policy();
    let caps = ir.granted_capabilities();
    assert!(caps.contains(&cap("fs.read")));
    assert!(caps.contains(&cap("net.egress")));
    assert!(!caps.contains(&cap("fs.write")));
}

#[test]
fn policy_ir_subjects() {
    let ir = valid_policy();
    let subs = ir.subjects();
    assert!(subs.contains("ext-A"));
    assert!(subs.contains("ext-B"));
    assert!(!subs.contains("ext-C"));
}

#[test]
fn policy_ir_serde_roundtrip() {
    let ir = valid_policy();
    let json = serde_json::to_string(&ir).unwrap();
    let restored: PolicyIr = serde_json::from_str(&json).unwrap();
    assert_eq!(ir, restored);
}

#[test]
fn policy_ir_empty_nodes_granted_capabilities() {
    let ir = PolicyIr {
        nodes: Vec::new(),
        ..valid_policy()
    };
    assert!(ir.granted_capabilities().is_empty());
    assert!(ir.subjects().is_empty());
}

// =========================================================================
// Section 11: PassResult — is_ok, is_failed, serde
// =========================================================================

#[test]
fn pass_result_ok_variant() {
    let ok = PassResult::Ok(PropertyWitness {
        property: FormalProperty::Monotonicity,
        policy_id: PolicyId::new("p1"),
        explanation: "ok".into(),
        nodes_examined: 1,
        pass_name: "test".into(),
    });
    assert!(ok.is_ok());
    assert!(!ok.is_failed());
}

#[test]
fn pass_result_failed_variant() {
    let failed = PassResult::Failed(Counterexample {
        property: FormalProperty::Monotonicity,
        policy_id: PolicyId::new("p1"),
        violating_nodes: vec!["n1".into()],
        description: "bad".into(),
        merge_path: Vec::new(),
    });
    assert!(!failed.is_ok());
    assert!(failed.is_failed());
}

#[test]
fn pass_result_serde_roundtrip() {
    let ok = PassResult::Ok(PropertyWitness {
        property: FormalProperty::MergeDeterminism,
        policy_id: PolicyId::new("p2"),
        explanation: "checked".into(),
        nodes_examined: 3,
        pass_name: "merge-det".into(),
    });
    let json = serde_json::to_string(&ok).unwrap();
    let restored: PassResult = serde_json::from_str(&json).unwrap();
    assert_eq!(ok, restored);
}

// =========================================================================
// Section 12: PropertyWitness and Counterexample — serde
// =========================================================================

#[test]
fn property_witness_serde_roundtrip() {
    let pw = PropertyWitness {
        property: FormalProperty::NonInterference,
        policy_id: PolicyId::new("witness-p"),
        explanation: "disjoint subjects".into(),
        nodes_examined: 7,
        pass_name: "non-interference".into(),
    };
    let json = serde_json::to_string(&pw).unwrap();
    let restored: PropertyWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(pw, restored);
}

#[test]
fn counterexample_serde_roundtrip() {
    let ce = Counterexample {
        property: FormalProperty::PrecedenceStability,
        policy_id: PolicyId::new("ce-p"),
        violating_nodes: vec!["n1".into(), "n2".into()],
        description: "duplicate priorities".into(),
        merge_path: vec!["path-a".into()],
    };
    let json = serde_json::to_string(&ce).unwrap();
    let restored: Counterexample = serde_json::from_str(&json).unwrap();
    assert_eq!(ce, restored);
}

// =========================================================================
// Section 13: PolicyTheoremCompiler — construction, compile
// =========================================================================

#[test]
fn compiler_default_and_new_equivalent() {
    let c1 = PolicyTheoremCompiler::new();
    let c2 = PolicyTheoremCompiler::default();
    let j1 = serde_json::to_string(&c1).unwrap();
    let j2 = serde_json::to_string(&c2).unwrap();
    assert_eq!(j1, j2);
}

#[test]
fn compiler_with_limits_custom() {
    let c = PolicyTheoremCompiler::with_limits(500, false);
    let json = serde_json::to_string(&c).unwrap();
    assert!(json.contains("500"));
}

#[test]
fn compile_valid_policy_all_passes() {
    let compiler = PolicyTheoremCompiler::new();
    let ir = valid_policy();
    let result = compiler.compile(&ir).unwrap();
    assert!(result.all_passed);
    assert!(result.counterexamples.is_empty());
    // Default compiler has precedence enabled => 6 passes
    assert_eq!(result.pass_results.len(), 6);
    assert_eq!(result.witnesses.len(), 6);
}

#[test]
fn compile_empty_policy_error() {
    let compiler = PolicyTheoremCompiler::new();
    let ir = PolicyIr {
        nodes: Vec::new(),
        ..valid_policy()
    };
    let err = compiler.compile(&ir).unwrap_err();
    match err {
        CompilerError::EmptyPolicy { policy_id } => {
            assert_eq!(policy_id.as_str(), "test-policy-1");
        }
        _ => panic!("expected EmptyPolicy"),
    }
}

#[test]
fn compile_policy_too_large_error() {
    let compiler = PolicyTheoremCompiler::with_limits(1, true);
    let ir = valid_policy(); // has 2 nodes
    let err = compiler.compile(&ir).unwrap_err();
    match err {
        CompilerError::PolicyTooLarge {
            node_count,
            max_nodes,
            ..
        } => {
            assert_eq!(node_count, 2);
            assert_eq!(max_nodes, 1);
        }
        _ => panic!("expected PolicyTooLarge"),
    }
}

#[test]
fn compile_skips_precedence_when_disabled() {
    let compiler_with = PolicyTheoremCompiler::new();
    let compiler_without = PolicyTheoremCompiler::with_limits(10_000, false);
    let ir = valid_policy();
    let r_with = compiler_with.compile(&ir).unwrap();
    let r_without = compiler_without.compile(&ir).unwrap();
    assert!(r_without.pass_results.len() < r_with.pass_results.len());
    assert_eq!(r_without.pass_results.len(), 5);
}

// =========================================================================
// Section 14: Type-check pass — undefined capabilities, zero lifetime
// =========================================================================

#[test]
fn compile_type_check_undefined_capability_detected() {
    let compiler = PolicyTheoremCompiler::new();
    let ir = PolicyIr {
        nodes: vec![simple_node(
            "n1",
            MergeOperator::Intersection,
            vec![grant("ext-A", "does.not.exist", "zone-1")],
        )],
        ..valid_policy()
    };
    let result = compiler.compile(&ir).unwrap();
    assert!(!result.all_passed);
    assert!(
        result
            .counterexamples
            .iter()
            .any(|c| c.description.contains("undefined capabilities"))
    );
}

#[test]
fn compile_type_check_zero_lifetime_detected() {
    let compiler = PolicyTheoremCompiler::new();
    let mut g = grant("ext-A", "fs.read", "zone-1");
    g.lifetime_epochs = 0;
    let ir = PolicyIr {
        nodes: vec![simple_node("n1", MergeOperator::Intersection, vec![g])],
        ..valid_policy()
    };
    let result = compiler.compile(&ir).unwrap();
    assert!(!result.all_passed);
    assert!(
        result
            .counterexamples
            .iter()
            .any(|c| c.description.contains("zero-lifetime"))
    );
}

// =========================================================================
// Section 15: Monotonicity pass
// =========================================================================

#[test]
fn monotonicity_intersection_passes() {
    let compiler = PolicyTheoremCompiler::new();
    let ir = valid_policy();
    let result = compiler.compile(&ir).unwrap();
    assert!(
        !result
            .counterexamples
            .iter()
            .any(|c| c.property == FormalProperty::Monotonicity)
    );
}

#[test]
fn monotonicity_union_without_claim_fails() {
    let compiler = PolicyTheoremCompiler::new();
    let ir = PolicyIr {
        nodes: vec![simple_node(
            "n1",
            MergeOperator::Union,
            vec![grant("ext-A", "fs.read", "zone-1")],
        )],
        ..valid_policy()
    };
    let result = compiler.compile(&ir).unwrap();
    assert!(
        result
            .counterexamples
            .iter()
            .any(|c| c.property == FormalProperty::Monotonicity)
    );
}

#[test]
fn monotonicity_union_with_claim_passes() {
    let compiler = PolicyTheoremCompiler::new();
    let mut node = simple_node(
        "n1",
        MergeOperator::Union,
        vec![grant("ext-A", "fs.read", "zone-1")],
    );
    node.property_claims.insert(FormalProperty::Monotonicity);
    let ir = PolicyIr {
        nodes: vec![node],
        ..valid_policy()
    };
    let result = compiler.compile(&ir).unwrap();
    assert!(
        !result
            .counterexamples
            .iter()
            .any(|c| c.property == FormalProperty::Monotonicity)
    );
}

// =========================================================================
// Section 16: Non-interference pass
// =========================================================================

#[test]
fn non_interference_disjoint_domains_passes() {
    let compiler = PolicyTheoremCompiler::new();
    let mut n1 = simple_node(
        "n1",
        MergeOperator::Intersection,
        vec![grant("ext-A", "fs.read", "domain-alpha")],
    );
    n1.constraints.push(Constraint::NonInterferenceClaim {
        domain_a: "domain-alpha".into(),
        domain_b: "domain-beta".into(),
    });
    let n2 = simple_node(
        "n2",
        MergeOperator::Intersection,
        vec![grant("ext-B", "net.egress", "domain-beta")],
    );
    let ir = PolicyIr {
        nodes: vec![n1, n2],
        ..valid_policy()
    };
    let result = compiler.compile(&ir).unwrap();
    assert!(
        !result
            .counterexamples
            .iter()
            .any(|c| c.property == FormalProperty::NonInterference)
    );
}

#[test]
fn non_interference_overlapping_subjects_fails() {
    let compiler = PolicyTheoremCompiler::new();
    let mut n1 = simple_node(
        "n1",
        MergeOperator::Intersection,
        vec![grant("SHARED", "fs.read", "domain-alpha")],
    );
    n1.constraints.push(Constraint::NonInterferenceClaim {
        domain_a: "domain-alpha".into(),
        domain_b: "domain-beta".into(),
    });
    let n2 = simple_node(
        "n2",
        MergeOperator::Intersection,
        vec![grant("SHARED", "net.egress", "domain-beta")],
    );
    let ir = PolicyIr {
        nodes: vec![n1, n2],
        ..valid_policy()
    };
    let result = compiler.compile(&ir).unwrap();
    assert!(
        result
            .counterexamples
            .iter()
            .any(|c| c.property == FormalProperty::NonInterference)
    );
}

// =========================================================================
// Section 17: Merge determinism pass
// =========================================================================

#[test]
fn merge_determinism_no_precedence_nodes_passes() {
    let compiler = PolicyTheoremCompiler::new();
    let ir = valid_policy();
    let result = compiler.compile(&ir).unwrap();
    assert!(
        !result
            .counterexamples
            .iter()
            .any(|c| c.property == FormalProperty::MergeDeterminism)
    );
}

#[test]
fn merge_determinism_distinct_priorities_passes() {
    let compiler = PolicyTheoremCompiler::new();
    let mut n1 = simple_node(
        "n1",
        MergeOperator::Precedence,
        vec![grant("ext-A", "fs.read", "zone-1")],
    );
    n1.priority = 1;
    let mut n2 = simple_node(
        "n2",
        MergeOperator::Precedence,
        vec![grant("ext-B", "net.egress", "zone-2")],
    );
    n2.priority = 2;
    let ir = PolicyIr {
        nodes: vec![n1, n2],
        ..valid_policy()
    };
    let result = compiler.compile(&ir).unwrap();
    assert!(
        !result
            .counterexamples
            .iter()
            .any(|c| c.property == FormalProperty::MergeDeterminism)
    );
}

#[test]
fn merge_determinism_duplicate_priorities_fails() {
    let compiler = PolicyTheoremCompiler::new();
    let mut n1 = simple_node(
        "n1",
        MergeOperator::Precedence,
        vec![grant("ext-A", "fs.read", "zone-1")],
    );
    n1.priority = 5;
    let mut n2 = simple_node(
        "n2",
        MergeOperator::Precedence,
        vec![grant("ext-B", "net.egress", "zone-2")],
    );
    n2.priority = 5;
    let ir = PolicyIr {
        nodes: vec![n1, n2],
        ..valid_policy()
    };
    let result = compiler.compile(&ir).unwrap();
    assert!(
        result
            .counterexamples
            .iter()
            .any(|c| c.property == FormalProperty::MergeDeterminism)
    );
}

// =========================================================================
// Section 18: Precedence stability pass
// =========================================================================

#[test]
fn precedence_stability_zero_priority_fails() {
    let compiler = PolicyTheoremCompiler::new();
    let n1 = simple_node(
        "n1",
        MergeOperator::Precedence,
        vec![grant("ext-A", "fs.read", "zone-1")],
    );
    // priority is 0 (default)
    let ir = PolicyIr {
        nodes: vec![n1],
        ..valid_policy()
    };
    let result = compiler.compile(&ir).unwrap();
    assert!(
        result
            .counterexamples
            .iter()
            .any(|c| c.property == FormalProperty::PrecedenceStability)
    );
}

#[test]
fn precedence_stability_distinct_nonzero_passes() {
    let compiler = PolicyTheoremCompiler::new();
    let mut n1 = simple_node(
        "n1",
        MergeOperator::Precedence,
        vec![grant("ext-A", "fs.read", "zone-1")],
    );
    n1.priority = 10;
    let mut n2 = simple_node(
        "n2",
        MergeOperator::Precedence,
        vec![grant("ext-B", "net.egress", "zone-2")],
    );
    n2.priority = 20;
    let ir = PolicyIr {
        nodes: vec![n1, n2],
        ..valid_policy()
    };
    let result = compiler.compile(&ir).unwrap();
    assert!(
        !result
            .counterexamples
            .iter()
            .any(|c| c.property == FormalProperty::PrecedenceStability)
    );
}

// =========================================================================
// Section 19: Attenuation legality pass
// =========================================================================

#[test]
fn attenuation_legality_valid_subset() {
    let compiler = PolicyTheoremCompiler::new();
    let base = simple_node(
        "base",
        MergeOperator::Intersection,
        vec![
            grant("ext-A", "fs.read", "zone-1"),
            grant("ext-A", "fs.write", "zone-1"),
        ],
    );
    let attenuated = simple_node(
        "att",
        MergeOperator::Attenuation,
        vec![grant("ext-A", "fs.read", "zone-1")],
    );
    let ir = PolicyIr {
        nodes: vec![base, attenuated],
        ..valid_policy()
    };
    let result = compiler.compile(&ir).unwrap();
    assert!(
        !result
            .counterexamples
            .iter()
            .any(|c| c.property == FormalProperty::AttenuationLegality)
    );
}

#[test]
fn attenuation_escalation_outside_base_fails() {
    let compiler = PolicyTheoremCompiler::new();
    let base = simple_node(
        "base",
        MergeOperator::Intersection,
        vec![grant("ext-A", "fs.read", "zone-1")],
    );
    let escalated = simple_node(
        "att",
        MergeOperator::Attenuation,
        vec![grant("ext-A", "policy.write", "zone-1")],
    );
    let ir = PolicyIr {
        nodes: vec![base, escalated],
        ..valid_policy()
    };
    let result = compiler.compile(&ir).unwrap();
    assert!(
        result
            .counterexamples
            .iter()
            .any(|c| c.property == FormalProperty::AttenuationLegality)
    );
}

// =========================================================================
// Section 20: CompilationResult — serde roundtrip
// =========================================================================

#[test]
fn compilation_result_serde_roundtrip() {
    let compiler = PolicyTheoremCompiler::new();
    let ir = valid_policy();
    let result = compiler.compile(&ir).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let restored: CompilationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

#[test]
fn compilation_deterministic_across_runs() {
    let compiler = PolicyTheoremCompiler::new();
    let ir = valid_policy();
    let r1 = compiler.compile(&ir).unwrap();
    let r2 = compiler.compile(&ir).unwrap();
    assert_eq!(
        serde_json::to_string(&r1).unwrap(),
        serde_json::to_string(&r2).unwrap()
    );
}

// =========================================================================
// Section 21: MachineCheckHooks — pre_merge, pre_deployment, runtime
// =========================================================================

#[test]
fn pre_merge_check_valid_policies_passes() {
    let compiler = PolicyTheoremCompiler::new();
    let mut hooks = MachineCheckHooks::new(compiler);
    let a = valid_policy();
    let b = PolicyIr {
        policy_id: PolicyId::new("test-policy-2"),
        ..valid_policy()
    };
    let result = hooks.pre_merge_check(&a, &b).unwrap();
    assert!(result.passed);
    assert_eq!(result.hook_name, "pre-merge");
    assert!(result.diagnostics.is_empty());
}

#[test]
fn pre_merge_check_detects_monotonicity_violation() {
    let compiler = PolicyTheoremCompiler::new();
    let mut hooks = MachineCheckHooks::new(compiler);
    let a = valid_policy();
    let b = PolicyIr {
        policy_id: PolicyId::new("bad-pol"),
        nodes: vec![simple_node(
            "n1",
            MergeOperator::Union,
            vec![grant("ext-A", "fs.read", "zone-1")],
        )],
        ..valid_policy()
    };
    let result = hooks.pre_merge_check(&a, &b).unwrap();
    assert!(!result.passed);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|d| d.property_violated == FormalProperty::Monotonicity)
    );
}

#[test]
fn pre_deployment_check_valid() {
    let compiler = PolicyTheoremCompiler::new();
    let mut hooks = MachineCheckHooks::new(compiler);
    let ir = valid_policy();
    let result = hooks.pre_deployment_check(&ir).unwrap();
    assert!(result.passed);
    assert_eq!(result.hook_name, "pre-deployment");
}

#[test]
fn pre_deployment_check_detects_violations() {
    let compiler = PolicyTheoremCompiler::new();
    let mut hooks = MachineCheckHooks::new(compiler);
    let ir = PolicyIr {
        nodes: vec![simple_node(
            "n1",
            MergeOperator::Union,
            vec![grant("ext-A", "fs.read", "zone-1")],
        )],
        ..valid_policy()
    };
    let result = hooks.pre_deployment_check(&ir).unwrap();
    assert!(!result.passed);
}

#[test]
fn runtime_check_valid_policy_passes() {
    let compiler = PolicyTheoremCompiler::new();
    let mut hooks = MachineCheckHooks::new(compiler);
    let ir = valid_policy();
    let result = hooks.runtime_check(&ir).unwrap();
    assert!(result.passed);
    assert_eq!(result.hook_name, "runtime");
}

#[test]
fn runtime_check_empty_policy_errors() {
    let compiler = PolicyTheoremCompiler::new();
    let mut hooks = MachineCheckHooks::new(compiler);
    let ir = PolicyIr {
        nodes: Vec::new(),
        ..valid_policy()
    };
    let err = hooks.runtime_check(&ir).unwrap_err();
    assert!(matches!(err, CompilerError::EmptyPolicy { .. }));
}

#[test]
fn runtime_check_attenuation_escalation_fatal() {
    let compiler = PolicyTheoremCompiler::new();
    let mut hooks = MachineCheckHooks::new(compiler);
    let base = simple_node(
        "base",
        MergeOperator::Intersection,
        vec![grant("ext-A", "fs.read", "zone-1")],
    );
    let escalation = simple_node(
        "esc",
        MergeOperator::Attenuation,
        vec![grant("ext-A", "policy.write", "zone-1")],
    );
    let ir = PolicyIr {
        nodes: vec![base, escalation],
        ..valid_policy()
    };
    let result = hooks.runtime_check(&ir).unwrap();
    assert!(!result.passed);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|d| d.severity == DiagnosticSeverity::Fatal)
    );
}

#[test]
fn hook_history_accumulates_across_calls() {
    let compiler = PolicyTheoremCompiler::new();
    let mut hooks = MachineCheckHooks::new(compiler);
    let ir = valid_policy();
    assert_eq!(hooks.hook_history().len(), 0);
    hooks.pre_deployment_check(&ir).unwrap();
    assert_eq!(hooks.hook_history().len(), 1);
    hooks.runtime_check(&ir).unwrap();
    assert_eq!(hooks.hook_history().len(), 2);
    let ir2 = PolicyIr {
        policy_id: PolicyId::new("p2"),
        ..valid_policy()
    };
    hooks.pre_merge_check(&ir, &ir2).unwrap();
    assert_eq!(hooks.hook_history().len(), 3);
}

// =========================================================================
// Section 22: HookCheckResult, HookDiagnostic — serde
// =========================================================================

#[test]
fn hook_check_result_serde_roundtrip() {
    let hcr = HookCheckResult {
        hook_name: "pre-deploy".into(),
        passed: true,
        diagnostics: Vec::new(),
    };
    let json = serde_json::to_string(&hcr).unwrap();
    let restored: HookCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(hcr, restored);
}

#[test]
fn hook_diagnostic_serde_roundtrip() {
    let hd = HookDiagnostic {
        property_violated: FormalProperty::MergeDeterminism,
        counterexample: Some(Counterexample {
            property: FormalProperty::MergeDeterminism,
            policy_id: PolicyId::new("p1"),
            violating_nodes: vec!["n1".into()],
            description: "dup priority".into(),
            merge_path: Vec::new(),
        }),
        policy_ids: vec![PolicyId::new("p1")],
        severity: DiagnosticSeverity::Error,
    };
    let json = serde_json::to_string(&hd).unwrap();
    let restored: HookDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(hd, restored);
}

// =========================================================================
// Section 23: PolicyValidationReceipt — create, sign, verify, tamper
// =========================================================================

#[test]
fn receipt_from_compilation_unsigned() {
    let compiler = PolicyTheoremCompiler::new();
    let ir = valid_policy();
    let result = compiler.compile(&ir).unwrap();
    let (_, vk) = signing_pair();

    let receipt = PolicyValidationReceipt::from_compilation(
        &result,
        [0xAA; 32],
        SecurityEpoch::from_raw(1),
        1_000_000_000,
        &vk,
    );
    assert!(!receipt.properties_verified.is_empty());
    assert_eq!(receipt.policy_id, PolicyId::new("test-policy-1"));
    assert_eq!(receipt.compiler_version, "1.0.0");
    assert!(!receipt.verify()); // unsigned
}

#[test]
fn receipt_sign_and_verify() {
    let compiler = PolicyTheoremCompiler::new();
    let ir = valid_policy();
    let result = compiler.compile(&ir).unwrap();
    let (sk, vk) = signing_pair();

    let mut receipt = PolicyValidationReceipt::from_compilation(
        &result,
        [0xBB; 32],
        SecurityEpoch::from_raw(1),
        2_000_000_000,
        &vk,
    );
    receipt.sign(&sk);
    assert!(receipt.verify());
}

#[test]
fn receipt_tampering_invalidates_signature() {
    let compiler = PolicyTheoremCompiler::new();
    let ir = valid_policy();
    let result = compiler.compile(&ir).unwrap();
    let (sk, vk) = signing_pair();

    let mut receipt = PolicyValidationReceipt::from_compilation(
        &result,
        [0xCC; 32],
        SecurityEpoch::from_raw(1),
        3_000_000_000,
        &vk,
    );
    receipt.sign(&sk);
    assert!(receipt.verify());

    receipt.policy_hash = [0xFF; 32];
    assert!(!receipt.verify());
}

#[test]
fn receipt_serde_roundtrip_preserves_verification() {
    let compiler = PolicyTheoremCompiler::new();
    let ir = valid_policy();
    let result = compiler.compile(&ir).unwrap();
    let (sk, vk) = signing_pair();

    let mut receipt = PolicyValidationReceipt::from_compilation(
        &result,
        [0xDD; 32],
        SecurityEpoch::from_raw(2),
        4_000_000_000,
        &vk,
    );
    receipt.sign(&sk);

    let json = serde_json::to_string(&receipt).unwrap();
    let restored: PolicyValidationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, restored);
    assert!(restored.verify());
}

// =========================================================================
// Section 24: CompilerError — Display, std::error::Error, serde
// =========================================================================

#[test]
fn compiler_error_empty_policy_display() {
    let e = CompilerError::EmptyPolicy {
        policy_id: PolicyId::new("p1"),
    };
    let s = e.to_string();
    assert!(s.contains("empty policy"));
    assert!(s.contains("p1"));
}

#[test]
fn compiler_error_policy_too_large_display() {
    let e = CompilerError::PolicyTooLarge {
        policy_id: PolicyId::new("p2"),
        node_count: 500,
        max_nodes: 100,
    };
    let s = e.to_string();
    assert!(s.contains("too large"));
    assert!(s.contains("500"));
    assert!(s.contains("100"));
}

#[test]
fn compiler_error_hook_failed_display() {
    let e = CompilerError::HookFailed {
        hook_name: "pre-merge".into(),
        diagnostics: vec![],
    };
    let s = e.to_string();
    assert!(s.contains("hook"));
    assert!(s.contains("pre-merge"));
    assert!(s.contains("0 diagnostics"));
}

#[test]
fn compiler_error_is_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(CompilerError::EmptyPolicy {
        policy_id: PolicyId::new("err-test"),
    });
    assert!(!e.to_string().is_empty());
}

#[test]
fn compiler_error_serde_roundtrip() {
    let errors = vec![
        CompilerError::EmptyPolicy {
            policy_id: PolicyId::new("p1"),
        },
        CompilerError::PolicyTooLarge {
            policy_id: PolicyId::new("p2"),
            node_count: 50,
            max_nodes: 10,
        },
        CompilerError::HookFailed {
            hook_name: "test-hook".into(),
            diagnostics: Vec::new(),
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let restored: CompilerError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, &restored);
    }
}

// =========================================================================
// Section 25: Multi-pass interaction — combined violations
// =========================================================================

#[test]
fn compile_multi_violation_policy() {
    // Policy has: Union without monotonicity claim + duplicate priorities
    let compiler = PolicyTheoremCompiler::new();
    let mut n1 = simple_node(
        "n1",
        MergeOperator::Union,
        vec![grant("ext-A", "fs.read", "zone-1")],
    );
    n1.priority = 5;
    // Also make it a Precedence node so we trigger multiple failures
    // Actually we need a separate precedence node for merge-determinism
    let mut n2 = simple_node(
        "n2",
        MergeOperator::Precedence,
        vec![grant("ext-B", "net.egress", "zone-2")],
    );
    n2.priority = 0; // zero priority => precedence stability fail
    let ir = PolicyIr {
        nodes: vec![n1, n2],
        ..valid_policy()
    };
    let result = compiler.compile(&ir).unwrap();
    assert!(!result.all_passed);
    // Should have at least monotonicity and precedence-stability violations
    assert!(result.counterexamples.len() >= 2);
}

#[test]
fn compile_all_merge_operators_mixed() {
    let compiler = PolicyTheoremCompiler::new();
    let n1 = simple_node(
        "n1",
        MergeOperator::Intersection,
        vec![grant("ext-A", "fs.read", "zone-1")],
    );
    let n2 = simple_node(
        "n2",
        MergeOperator::Attenuation,
        vec![grant("ext-A", "fs.read", "zone-1")], // subset of n1
    );
    let ir = PolicyIr {
        nodes: vec![n1, n2],
        ..valid_policy()
    };
    let result = compiler.compile(&ir).unwrap();
    assert!(result.all_passed);
}

// =========================================================================
// Section 26: Edge cases — single node, many nodes at boundary
// =========================================================================

#[test]
fn compile_single_node_policy() {
    let compiler = PolicyTheoremCompiler::new();
    let ir = PolicyIr {
        nodes: vec![simple_node(
            "only",
            MergeOperator::Intersection,
            vec![grant("ext-A", "fs.read", "zone-1")],
        )],
        ..valid_policy()
    };
    let result = compiler.compile(&ir).unwrap();
    assert!(result.all_passed);
}

#[test]
fn compile_exactly_at_max_nodes_limit() {
    let compiler = PolicyTheoremCompiler::with_limits(3, true);
    let ir = PolicyIr {
        nodes: vec![
            simple_node(
                "n1",
                MergeOperator::Intersection,
                vec![grant("a", "fs.read", "z")],
            ),
            simple_node(
                "n2",
                MergeOperator::Intersection,
                vec![grant("b", "fs.read", "z")],
            ),
            simple_node(
                "n3",
                MergeOperator::Intersection,
                vec![grant("c", "fs.read", "z")],
            ),
        ],
        ..valid_policy()
    };
    // 3 nodes with max 3 => should succeed
    let result = compiler.compile(&ir).unwrap();
    assert!(result.all_passed);
}

#[test]
fn compile_one_over_max_nodes_limit() {
    let compiler = PolicyTheoremCompiler::with_limits(2, true);
    let ir = PolicyIr {
        nodes: vec![
            simple_node(
                "n1",
                MergeOperator::Intersection,
                vec![grant("a", "fs.read", "z")],
            ),
            simple_node(
                "n2",
                MergeOperator::Intersection,
                vec![grant("b", "fs.read", "z")],
            ),
            simple_node(
                "n3",
                MergeOperator::Intersection,
                vec![grant("c", "fs.read", "z")],
            ),
        ],
        ..valid_policy()
    };
    let err = compiler.compile(&ir).unwrap_err();
    assert!(matches!(err, CompilerError::PolicyTooLarge { .. }));
}

// =========================================================================
// Section 27: Node with constraints and decision point in full compile
// =========================================================================

#[test]
fn compile_node_with_constraints_and_decision_point() {
    let compiler = PolicyTheoremCompiler::new();
    let mut node = simple_node(
        "complex",
        MergeOperator::Intersection,
        vec![grant("ext-A", "fs.read", "zone-1")],
    );
    node.constraints
        .push(Constraint::Invariant("always safe".into()));
    node.constraints
        .push(Constraint::Precondition("auth present".into()));
    node.decision_point = Some(DecisionPoint {
        threshold: 1,
        action_map: {
            let mut m = BTreeMap::new();
            m.insert("admin".into(), "allow".into());
            m
        },
        fallback: "deny".into(),
    });
    let ir = PolicyIr {
        nodes: vec![node],
        ..valid_policy()
    };
    let result = compiler.compile(&ir).unwrap();
    assert!(result.all_passed);
}

// =========================================================================
// Section 28: Compiler serde roundtrip
// =========================================================================

#[test]
fn compiler_serde_roundtrip() {
    let compiler = PolicyTheoremCompiler::with_limits(777, false);
    let json = serde_json::to_string(&compiler).unwrap();
    let restored: PolicyTheoremCompiler = serde_json::from_str(&json).unwrap();
    let j2 = serde_json::to_string(&restored).unwrap();
    assert_eq!(json, j2);
}

// =========================================================================
// Section 29: Debug output contains useful info
// =========================================================================

#[test]
fn debug_representations_not_empty() {
    let c = cap("fs.read");
    let d = format!("{c:?}");
    assert!(d.contains("fs.read"));

    let p = PolicyId::new("p1");
    let d = format!("{p:?}");
    assert!(d.contains("p1"));

    let compiler = PolicyTheoremCompiler::new();
    let d = format!("{compiler:?}");
    assert!(d.contains("PolicyTheoremCompiler"));

    let e = CompilerError::EmptyPolicy {
        policy_id: PolicyId::new("dbg"),
    };
    let d = format!("{e:?}");
    assert!(d.contains("EmptyPolicy"));
}
