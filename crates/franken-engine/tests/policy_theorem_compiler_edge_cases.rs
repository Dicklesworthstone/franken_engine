//! Integration edge-case tests for the `policy_theorem_compiler` module.
//!
//! Covers type serde/display/ordering, compilation passes via public API,
//! machine-check hooks, PolicyValidationReceipt signing, and CompilerError.

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
    AuthorityGrant, Capability, CompilerError, Constraint, Counterexample, DecisionPoint,
    DiagnosticSeverity, FormalProperty, HookCheckResult, HookDiagnostic, MachineCheckHooks,
    MergeOperator, PassResult, PolicyId, PolicyIr, PolicyIrNode, PolicyTheoremCompiler,
    PolicyValidationReceipt, PropertyWitness,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;

// ===========================================================================
// Helpers
// ===========================================================================

fn cap(name: &str) -> Capability {
    Capability::new(name)
}

fn universe() -> BTreeSet<Capability> {
    [
        "fs.read",
        "fs.write",
        "net.egress",
        "policy.read",
        "policy.write",
    ]
    .iter()
    .map(|s| cap(s))
    .collect()
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
        capability_universe: universe(),
        verified_properties: BTreeSet::new(),
        epoch: SecurityEpoch::from_raw(1),
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes([42u8; 32])
}

// ===========================================================================
// Capability
// ===========================================================================

#[test]
fn capability_new_and_as_str() {
    let c = Capability::new("fs.read");
    assert_eq!(c.as_str(), "fs.read");
}

#[test]
fn capability_display() {
    assert_eq!(cap("net.egress").to_string(), "net.egress");
}

#[test]
fn capability_serde_roundtrip() {
    let c = cap("fs.write");
    let json = serde_json::to_string(&c).unwrap();
    let restored: Capability = serde_json::from_str(&json).unwrap();
    assert_eq!(c, restored);
}

#[test]
fn capability_ordering() {
    let a = cap("aaa");
    let b = cap("bbb");
    assert!(a < b);
}

#[test]
fn capability_hash_stable() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(cap("x"));
    s.insert(cap("x"));
    assert_eq!(s.len(), 1);
}

#[test]
fn capability_empty_string() {
    let c = cap("");
    assert_eq!(c.as_str(), "");
    assert_eq!(c.to_string(), "");
}

// ===========================================================================
// PolicyId
// ===========================================================================

#[test]
fn policy_id_new_and_as_str() {
    let p = PolicyId::new("my-policy");
    assert_eq!(p.as_str(), "my-policy");
}

#[test]
fn policy_id_display() {
    assert_eq!(PolicyId::new("p1").to_string(), "p1");
}

#[test]
fn policy_id_serde_roundtrip() {
    let p = PolicyId::new("policy-42");
    let json = serde_json::to_string(&p).unwrap();
    let restored: PolicyId = serde_json::from_str(&json).unwrap();
    assert_eq!(p, restored);
}

#[test]
fn policy_id_ordering() {
    let a = PolicyId::new("alpha");
    let b = PolicyId::new("beta");
    assert!(a < b);
}

#[test]
fn policy_id_hash_stable() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(PolicyId::new("x"));
    s.insert(PolicyId::new("x"));
    assert_eq!(s.len(), 1);
}

// ===========================================================================
// MergeOperator
// ===========================================================================

#[test]
fn merge_operator_display_all() {
    assert_eq!(MergeOperator::Union.to_string(), "union");
    assert_eq!(MergeOperator::Intersection.to_string(), "intersection");
    assert_eq!(MergeOperator::Attenuation.to_string(), "attenuation");
    assert_eq!(MergeOperator::Precedence.to_string(), "precedence");
}

#[test]
fn merge_operator_serde_all() {
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

#[test]
fn merge_operator_ordering() {
    let mut ops = [
        MergeOperator::Precedence,
        MergeOperator::Union,
        MergeOperator::Attenuation,
        MergeOperator::Intersection,
    ];
    ops.sort();
    // Verify sorting is deterministic (derived Ord).
    let sorted2 = {
        let mut v = ops;
        v.sort();
        v
    };
    assert_eq!(ops, sorted2);
}

#[test]
fn merge_operator_hash() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(MergeOperator::Union);
    s.insert(MergeOperator::Union);
    s.insert(MergeOperator::Intersection);
    assert_eq!(s.len(), 2);
}

// ===========================================================================
// FormalProperty
// ===========================================================================

#[test]
fn formal_property_display_all() {
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
fn formal_property_serde_all() {
    for prop in [
        FormalProperty::Monotonicity,
        FormalProperty::NonInterference,
        FormalProperty::AttenuationLegality,
        FormalProperty::MergeDeterminism,
        FormalProperty::PrecedenceStability,
    ] {
        let json = serde_json::to_string(&prop).unwrap();
        let restored: FormalProperty = serde_json::from_str(&json).unwrap();
        assert_eq!(prop, restored);
    }
}

#[test]
fn formal_property_ordering() {
    let mut props = [
        FormalProperty::PrecedenceStability,
        FormalProperty::Monotonicity,
        FormalProperty::NonInterference,
    ];
    props.sort();
    let sorted2 = {
        let mut v = props;
        v.sort();
        v
    };
    assert_eq!(props, sorted2);
}

#[test]
fn formal_property_hash() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(FormalProperty::Monotonicity);
    s.insert(FormalProperty::Monotonicity);
    assert_eq!(s.len(), 1);
}

// ===========================================================================
// Constraint
// ===========================================================================

#[test]
fn constraint_serde_all_variants() {
    let constraints = [
        Constraint::Invariant("always".into()),
        Constraint::Precondition("before".into()),
        Constraint::Postcondition("after".into()),
        Constraint::NonInterferenceClaim {
            domain_a: "d1".into(),
            domain_b: "d2".into(),
        },
    ];
    for c in &constraints {
        let json = serde_json::to_string(c).unwrap();
        let restored: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(c, &restored);
    }
}

#[test]
fn constraint_ordering() {
    let a = Constraint::Invariant("a".into());
    let b = Constraint::Precondition("b".into());
    // Just confirm they're comparable (derived Ord).
    let mut v = [b.clone(), a.clone()];
    v.sort();
    assert_eq!(v[0], a);
}

// ===========================================================================
// DiagnosticSeverity
// ===========================================================================

#[test]
fn diagnostic_severity_display_all() {
    assert_eq!(DiagnosticSeverity::Warning.to_string(), "warning");
    assert_eq!(DiagnosticSeverity::Error.to_string(), "error");
    assert_eq!(DiagnosticSeverity::Fatal.to_string(), "fatal");
}

#[test]
fn diagnostic_severity_serde_all() {
    for s in [
        DiagnosticSeverity::Warning,
        DiagnosticSeverity::Error,
        DiagnosticSeverity::Fatal,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let restored: DiagnosticSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(s, restored);
    }
}

#[test]
fn diagnostic_severity_ordering() {
    assert!(DiagnosticSeverity::Warning < DiagnosticSeverity::Error);
    assert!(DiagnosticSeverity::Error < DiagnosticSeverity::Fatal);
}

#[test]
fn diagnostic_severity_hash() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(DiagnosticSeverity::Warning);
    s.insert(DiagnosticSeverity::Warning);
    s.insert(DiagnosticSeverity::Fatal);
    assert_eq!(s.len(), 2);
}

// ===========================================================================
// AuthorityGrant
// ===========================================================================

#[test]
fn authority_grant_serde() {
    let g = grant("ext-A", "fs.read", "zone-1");
    let json = serde_json::to_string(&g).unwrap();
    let restored: AuthorityGrant = serde_json::from_str(&json).unwrap();
    assert_eq!(g, restored);
}

#[test]
fn authority_grant_with_conditions() {
    let g = AuthorityGrant {
        conditions: ["cond-a", "cond-b"].iter().map(|s| s.to_string()).collect(),
        ..grant("ext-A", "fs.read", "zone-1")
    };
    let json = serde_json::to_string(&g).unwrap();
    let restored: AuthorityGrant = serde_json::from_str(&json).unwrap();
    assert_eq!(g, restored);
    assert_eq!(g.conditions.len(), 2);
}

#[test]
fn authority_grant_ordering() {
    let a = grant("aaa", "fs.read", "zone-1");
    let b = grant("bbb", "fs.read", "zone-1");
    assert!(a < b);
}

// ===========================================================================
// DecisionPoint
// ===========================================================================

#[test]
fn decision_point_serde() {
    let dp = DecisionPoint {
        threshold: 3,
        action_map: {
            let mut m = BTreeMap::new();
            m.insert("high-risk".into(), "sandbox".into());
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
        fallback: "allow".into(),
    };
    let json = serde_json::to_string(&dp).unwrap();
    let restored: DecisionPoint = serde_json::from_str(&json).unwrap();
    assert_eq!(dp, restored);
}

// ===========================================================================
// PolicyIrNode
// ===========================================================================

#[test]
fn policy_ir_node_serde() {
    let n = simple_node(
        "n1",
        MergeOperator::Intersection,
        vec![grant("ext-A", "fs.read", "zone-1")],
    );
    let json = serde_json::to_string(&n).unwrap();
    let restored: PolicyIrNode = serde_json::from_str(&json).unwrap();
    assert_eq!(n, restored);
}

#[test]
fn policy_ir_node_with_decision_point() {
    let mut n = simple_node(
        "n1",
        MergeOperator::Precedence,
        vec![grant("ext-A", "fs.read", "zone-1")],
    );
    n.decision_point = Some(DecisionPoint {
        threshold: 2,
        action_map: BTreeMap::new(),
        fallback: "deny".into(),
    });
    n.priority = 5;
    let json = serde_json::to_string(&n).unwrap();
    let restored: PolicyIrNode = serde_json::from_str(&json).unwrap();
    assert_eq!(n, restored);
}

#[test]
fn policy_ir_node_with_constraints_and_claims() {
    let mut n = simple_node("n1", MergeOperator::Union, vec![]);
    n.constraints = vec![
        Constraint::Invariant("always-true".into()),
        Constraint::Precondition("pre".into()),
    ];
    n.property_claims.insert(FormalProperty::Monotonicity);
    n.property_claims
        .insert(FormalProperty::AttenuationLegality);
    let json = serde_json::to_string(&n).unwrap();
    let restored: PolicyIrNode = serde_json::from_str(&json).unwrap();
    assert_eq!(n, restored);
    assert_eq!(n.property_claims.len(), 2);
}

// ===========================================================================
// PolicyIr
// ===========================================================================

#[test]
fn policy_ir_serde() {
    let ir = valid_policy();
    let json = serde_json::to_string(&ir).unwrap();
    let restored: PolicyIr = serde_json::from_str(&json).unwrap();
    assert_eq!(ir, restored);
}

#[test]
fn policy_ir_granted_capabilities() {
    let ir = valid_policy();
    let caps = ir.granted_capabilities();
    assert!(caps.contains(&cap("fs.read")));
    assert!(caps.contains(&cap("net.egress")));
    assert!(!caps.contains(&cap("fs.write")));
}

#[test]
fn policy_ir_granted_capabilities_dedup() {
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
        ],
        ..valid_policy()
    };
    let caps = ir.granted_capabilities();
    assert_eq!(caps.len(), 1); // BTreeSet deduplicates
}

#[test]
fn policy_ir_subjects() {
    let ir = valid_policy();
    let subs = ir.subjects();
    assert!(subs.contains("ext-A"));
    assert!(subs.contains("ext-B"));
    assert_eq!(subs.len(), 2);
}

#[test]
fn policy_ir_subjects_dedup() {
    let ir = PolicyIr {
        nodes: vec![
            simple_node(
                "n1",
                MergeOperator::Intersection,
                vec![grant("same", "fs.read", "z")],
            ),
            simple_node(
                "n2",
                MergeOperator::Intersection,
                vec![grant("same", "net.egress", "z")],
            ),
        ],
        ..valid_policy()
    };
    let subs = ir.subjects();
    assert_eq!(subs.len(), 1);
}

// ===========================================================================
// PassResult
// ===========================================================================

#[test]
fn pass_result_ok_is_ok() {
    let ok = PassResult::Ok(PropertyWitness {
        property: FormalProperty::Monotonicity,
        policy_id: PolicyId::new("p"),
        explanation: "fine".into(),
        nodes_examined: 1,
        pass_name: "test".into(),
    });
    assert!(ok.is_ok());
    assert!(!ok.is_failed());
}

#[test]
fn pass_result_failed_is_failed() {
    let failed = PassResult::Failed(Counterexample {
        property: FormalProperty::Monotonicity,
        policy_id: PolicyId::new("p"),
        violating_nodes: vec!["n1".into()],
        description: "bad".into(),
        merge_path: Vec::new(),
    });
    assert!(failed.is_failed());
    assert!(!failed.is_ok());
}

#[test]
fn pass_result_serde() {
    let ok = PassResult::Ok(PropertyWitness {
        property: FormalProperty::MergeDeterminism,
        policy_id: PolicyId::new("p"),
        explanation: "ok".into(),
        nodes_examined: 5,
        pass_name: "merge".into(),
    });
    let json = serde_json::to_string(&ok).unwrap();
    let restored: PassResult = serde_json::from_str(&json).unwrap();
    assert_eq!(ok, restored);
}

// ===========================================================================
// PropertyWitness / Counterexample
// ===========================================================================

#[test]
fn property_witness_serde() {
    let w = PropertyWitness {
        property: FormalProperty::NonInterference,
        policy_id: PolicyId::new("p1"),
        explanation: "domains disjoint".into(),
        nodes_examined: 3,
        pass_name: "non-interference".into(),
    };
    let json = serde_json::to_string(&w).unwrap();
    let restored: PropertyWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(w, restored);
}

#[test]
fn counterexample_serde() {
    let cx = Counterexample {
        property: FormalProperty::MergeDeterminism,
        policy_id: PolicyId::new("p2"),
        violating_nodes: vec!["n1".into(), "n2".into()],
        description: "duplicate priorities".into(),
        merge_path: vec!["step-1".into(), "step-2".into()],
    };
    let json = serde_json::to_string(&cx).unwrap();
    let restored: Counterexample = serde_json::from_str(&json).unwrap();
    assert_eq!(cx, restored);
}

// ===========================================================================
// HookCheckResult / HookDiagnostic
// ===========================================================================

#[test]
fn hook_check_result_serde() {
    let hcr = HookCheckResult {
        hook_name: "pre-merge".into(),
        passed: true,
        diagnostics: Vec::new(),
    };
    let json = serde_json::to_string(&hcr).unwrap();
    let restored: HookCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(hcr, restored);
}

#[test]
fn hook_diagnostic_serde() {
    let diag = HookDiagnostic {
        property_violated: FormalProperty::Monotonicity,
        counterexample: Some(Counterexample {
            property: FormalProperty::Monotonicity,
            policy_id: PolicyId::new("p"),
            violating_nodes: vec!["n1".into()],
            description: "problem".into(),
            merge_path: Vec::new(),
        }),
        policy_ids: vec![PolicyId::new("p")],
        severity: DiagnosticSeverity::Error,
    };
    let json = serde_json::to_string(&diag).unwrap();
    let restored: HookDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, restored);
}

#[test]
fn hook_diagnostic_no_counterexample() {
    let diag = HookDiagnostic {
        property_violated: FormalProperty::PrecedenceStability,
        counterexample: None,
        policy_ids: vec![],
        severity: DiagnosticSeverity::Warning,
    };
    let json = serde_json::to_string(&diag).unwrap();
    let restored: HookDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, restored);
}

// ===========================================================================
// CompilerError
// ===========================================================================

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
fn compiler_error_too_large_display() {
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
        diagnostics: vec![HookDiagnostic {
            property_violated: FormalProperty::Monotonicity,
            counterexample: None,
            policy_ids: vec![],
            severity: DiagnosticSeverity::Error,
        }],
    };
    let s = e.to_string();
    assert!(s.contains("pre-merge"));
    assert!(s.contains("1 diagnostics"));
}

#[test]
fn compiler_error_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(CompilerError::EmptyPolicy {
        policy_id: PolicyId::new("p"),
    });
    assert!(!e.to_string().is_empty());
}

#[test]
fn compiler_error_serde_all() {
    let errors: Vec<CompilerError> = vec![
        CompilerError::EmptyPolicy {
            policy_id: PolicyId::new("p1"),
        },
        CompilerError::PolicyTooLarge {
            policy_id: PolicyId::new("p2"),
            node_count: 99,
            max_nodes: 50,
        },
        CompilerError::HookFailed {
            hook_name: "test".into(),
            diagnostics: Vec::new(),
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let restored: CompilerError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, &restored);
    }
}

// ===========================================================================
// PolicyTheoremCompiler — construction
// ===========================================================================

#[test]
fn compiler_default_trait() {
    let c = PolicyTheoremCompiler::default();
    // Default should match new().
    let c2 = PolicyTheoremCompiler::new();
    let j1 = serde_json::to_string(&c).unwrap();
    let j2 = serde_json::to_string(&c2).unwrap();
    assert_eq!(j1, j2);
}

#[test]
fn compiler_serde() {
    let c = PolicyTheoremCompiler::with_limits(500, false);
    let json = serde_json::to_string(&c).unwrap();
    let restored: PolicyTheoremCompiler = serde_json::from_str(&json).unwrap();
    let j2 = serde_json::to_string(&restored).unwrap();
    assert_eq!(json, j2);
}

// ===========================================================================
// Compilation — valid policy
// ===========================================================================

#[test]
fn compile_valid_policy_all_pass() {
    let c = PolicyTheoremCompiler::new();
    let result = c.compile(&valid_policy()).unwrap();
    assert!(result.all_passed);
    assert!(result.counterexamples.is_empty());
    assert!(!result.witnesses.is_empty());
    assert_eq!(result.policy_id, PolicyId::new("test-policy-1"));
}

#[test]
fn compile_valid_has_six_passes() {
    let c = PolicyTheoremCompiler::new();
    let result = c.compile(&valid_policy()).unwrap();
    // 6 passes: type-check, monotonicity, non-interference,
    // merge-determinism, precedence-stability, attenuation-legality
    assert_eq!(result.pass_results.len(), 6);
    assert!(result.pass_results.iter().all(|p| p.is_ok()));
}

#[test]
fn compile_without_precedence_has_five_passes() {
    let c = PolicyTheoremCompiler::with_limits(10_000, false);
    let result = c.compile(&valid_policy()).unwrap();
    assert_eq!(result.pass_results.len(), 5);
    assert!(result.all_passed);
}

// ===========================================================================
// Compilation — error cases
// ===========================================================================

#[test]
fn compile_empty_policy_error() {
    let c = PolicyTheoremCompiler::new();
    let ir = PolicyIr {
        nodes: Vec::new(),
        ..valid_policy()
    };
    let err = c.compile(&ir).unwrap_err();
    assert!(matches!(err, CompilerError::EmptyPolicy { .. }));
}

#[test]
fn compile_too_large_error() {
    let c = PolicyTheoremCompiler::with_limits(2, true);
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
    let err = c.compile(&ir).unwrap_err();
    assert!(matches!(
        err,
        CompilerError::PolicyTooLarge {
            node_count: 3,
            max_nodes: 2,
            ..
        }
    ));
}

#[test]
fn compile_exactly_at_max_nodes_succeeds() {
    let c = PolicyTheoremCompiler::with_limits(2, true);
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
                vec![grant("b", "net.egress", "z")],
            ),
        ],
        ..valid_policy()
    };
    let result = c.compile(&ir).unwrap();
    assert!(result.all_passed);
}

// ===========================================================================
// Compilation — monotonicity pass (via compile)
// ===========================================================================

#[test]
fn compile_union_without_claim_violates_monotonicity() {
    let c = PolicyTheoremCompiler::new();
    let ir = PolicyIr {
        nodes: vec![simple_node(
            "n1",
            MergeOperator::Union,
            vec![grant("ext-A", "fs.read", "zone-1")],
        )],
        ..valid_policy()
    };
    let result = c.compile(&ir).unwrap();
    assert!(!result.all_passed);
    assert!(
        result
            .counterexamples
            .iter()
            .any(|cx| cx.property == FormalProperty::Monotonicity)
    );
}

#[test]
fn compile_union_with_monotonicity_claim_passes() {
    let c = PolicyTheoremCompiler::new();
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
    let result = c.compile(&ir).unwrap();
    assert!(result.all_passed);
}

#[test]
fn compile_attenuation_preserves_monotonicity() {
    let c = PolicyTheoremCompiler::new();
    let base = simple_node(
        "base",
        MergeOperator::Intersection,
        vec![
            grant("ext-A", "fs.read", "z"),
            grant("ext-A", "fs.write", "z"),
        ],
    );
    let att = simple_node(
        "att",
        MergeOperator::Attenuation,
        vec![grant("ext-A", "fs.read", "z")],
    );
    let ir = PolicyIr {
        nodes: vec![base, att],
        ..valid_policy()
    };
    let result = c.compile(&ir).unwrap();
    // Attenuation doesn't break monotonicity (only Union does).
    assert!(
        !result
            .counterexamples
            .iter()
            .any(|cx| cx.property == FormalProperty::Monotonicity)
    );
}

// ===========================================================================
// Compilation — type-check pass (via compile)
// ===========================================================================

#[test]
fn compile_undefined_capability_fails_type_check() {
    let c = PolicyTheoremCompiler::new();
    let ir = PolicyIr {
        nodes: vec![simple_node(
            "n1",
            MergeOperator::Intersection,
            vec![grant("ext-A", "does.not.exist", "zone-1")],
        )],
        ..valid_policy()
    };
    let result = c.compile(&ir).unwrap();
    assert!(!result.all_passed);
    // The type-check uses AttenuationLegality as its property marker.
    assert!(
        result
            .counterexamples
            .iter()
            .any(|cx| cx.description.contains("undefined capabilities"))
    );
}

#[test]
fn compile_zero_lifetime_grant_fails_type_check() {
    let c = PolicyTheoremCompiler::new();
    let mut g = grant("ext-A", "fs.read", "zone-1");
    g.lifetime_epochs = 0;
    let ir = PolicyIr {
        nodes: vec![simple_node("n1", MergeOperator::Intersection, vec![g])],
        ..valid_policy()
    };
    let result = c.compile(&ir).unwrap();
    assert!(!result.all_passed);
    assert!(
        result
            .counterexamples
            .iter()
            .any(|cx| cx.description.contains("zero-lifetime"))
    );
}

// ===========================================================================
// Compilation — non-interference pass (via compile)
// ===========================================================================

#[test]
fn compile_non_interference_disjoint_passes() {
    let c = PolicyTheoremCompiler::new();
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
    let result = c.compile(&ir).unwrap();
    assert!(result.all_passed);
}

#[test]
fn compile_non_interference_shared_subject_fails() {
    let c = PolicyTheoremCompiler::new();
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
    let result = c.compile(&ir).unwrap();
    assert!(!result.all_passed);
    assert!(
        result
            .counterexamples
            .iter()
            .any(|cx| cx.property == FormalProperty::NonInterference)
    );
}

#[test]
fn compile_no_non_interference_claims_passes() {
    // If no NI claims exist, the pass should succeed vacuously.
    let c = PolicyTheoremCompiler::new();
    let result = c.compile(&valid_policy()).unwrap();
    assert!(
        result
            .witnesses
            .iter()
            .any(|w| w.property == FormalProperty::NonInterference)
    );
}

// ===========================================================================
// Compilation — merge determinism pass (via compile)
// ===========================================================================

#[test]
fn compile_precedence_duplicate_priorities_fails_merge_determinism() {
    let c = PolicyTheoremCompiler::new();
    let mut n1 = simple_node(
        "n1",
        MergeOperator::Precedence,
        vec![grant("a", "fs.read", "z")],
    );
    n1.priority = 5;
    let mut n2 = simple_node(
        "n2",
        MergeOperator::Precedence,
        vec![grant("b", "net.egress", "z")],
    );
    n2.priority = 5; // duplicate!
    let ir = PolicyIr {
        nodes: vec![n1, n2],
        ..valid_policy()
    };
    let result = c.compile(&ir).unwrap();
    assert!(!result.all_passed);
    assert!(
        result
            .counterexamples
            .iter()
            .any(|cx| cx.property == FormalProperty::MergeDeterminism)
    );
}

#[test]
fn compile_precedence_distinct_priorities_passes() {
    let c = PolicyTheoremCompiler::new();
    let mut n1 = simple_node(
        "n1",
        MergeOperator::Precedence,
        vec![grant("a", "fs.read", "z")],
    );
    n1.priority = 1;
    let mut n2 = simple_node(
        "n2",
        MergeOperator::Precedence,
        vec![grant("b", "net.egress", "z")],
    );
    n2.priority = 2;
    let ir = PolicyIr {
        nodes: vec![n1, n2],
        ..valid_policy()
    };
    let result = c.compile(&ir).unwrap();
    // merge-determinism passes, but precedence-stability also needs non-zero.
    assert!(
        !result
            .counterexamples
            .iter()
            .any(|cx| cx.property == FormalProperty::MergeDeterminism)
    );
}

// ===========================================================================
// Compilation — precedence stability pass (via compile)
// ===========================================================================

#[test]
fn compile_precedence_zero_priority_fails_stability() {
    let c = PolicyTheoremCompiler::new();
    let n = simple_node(
        "n1",
        MergeOperator::Precedence,
        vec![grant("a", "fs.read", "z")],
    );
    // priority defaults to 0
    let ir = PolicyIr {
        nodes: vec![n],
        ..valid_policy()
    };
    let result = c.compile(&ir).unwrap();
    assert!(!result.all_passed);
    assert!(
        result
            .counterexamples
            .iter()
            .any(|cx| cx.property == FormalProperty::PrecedenceStability)
    );
}

// ===========================================================================
// Compilation — attenuation legality pass (via compile)
// ===========================================================================

#[test]
fn compile_attenuation_escalation_fails() {
    let c = PolicyTheoremCompiler::new();
    let base = simple_node(
        "base",
        MergeOperator::Intersection,
        vec![grant("ext-A", "fs.read", "z")],
    );
    let att = simple_node(
        "escalation",
        MergeOperator::Attenuation,
        vec![grant("ext-A", "policy.write", "z")], // not in base
    );
    let ir = PolicyIr {
        nodes: vec![base, att],
        ..valid_policy()
    };
    let result = c.compile(&ir).unwrap();
    assert!(!result.all_passed);
    assert!(
        result
            .counterexamples
            .iter()
            .any(|cx| cx.property == FormalProperty::AttenuationLegality)
    );
}

#[test]
fn compile_attenuation_subset_passes() {
    let c = PolicyTheoremCompiler::new();
    let base = simple_node(
        "base",
        MergeOperator::Intersection,
        vec![
            grant("ext-A", "fs.read", "z"),
            grant("ext-A", "fs.write", "z"),
        ],
    );
    let att = simple_node(
        "att",
        MergeOperator::Attenuation,
        vec![grant("ext-A", "fs.read", "z")],
    );
    let ir = PolicyIr {
        nodes: vec![base, att],
        ..valid_policy()
    };
    let result = c.compile(&ir).unwrap();
    // Attenuation legality should pass.
    assert!(
        !result
            .counterexamples
            .iter()
            .any(|cx| cx.property == FormalProperty::AttenuationLegality
                && cx.description.contains("outside base"))
    );
}

// ===========================================================================
// Compilation — multiple violations
// ===========================================================================

#[test]
fn compile_multiple_violations_reported() {
    let c = PolicyTheoremCompiler::new();
    // Union without claim (mono fail) + undefined cap (type-check fail)
    let ir = PolicyIr {
        nodes: vec![simple_node(
            "n1",
            MergeOperator::Union,
            vec![grant("ext-A", "does.not.exist", "z")],
        )],
        ..valid_policy()
    };
    let result = c.compile(&ir).unwrap();
    assert!(!result.all_passed);
    assert!(result.counterexamples.len() >= 2);
}

// ===========================================================================
// Compilation — determinism
// ===========================================================================

#[test]
fn compile_deterministic_output() {
    let c = PolicyTheoremCompiler::new();
    let ir = valid_policy();
    let r1 = c.compile(&ir).unwrap();
    let r2 = c.compile(&ir).unwrap();
    assert_eq!(
        serde_json::to_string(&r1).unwrap(),
        serde_json::to_string(&r2).unwrap()
    );
}

#[test]
fn compilation_result_serde() {
    let c = PolicyTheoremCompiler::new();
    let result = c.compile(&valid_policy()).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let restored = serde_json::from_str::<serde_json::Value>(&json).unwrap();
    assert!(restored.is_object());
}

// ===========================================================================
// Machine-check hooks — pre_merge
// ===========================================================================

#[test]
fn pre_merge_both_valid() {
    let mut hooks = MachineCheckHooks::new(PolicyTheoremCompiler::new());
    let a = valid_policy();
    let b = PolicyIr {
        policy_id: PolicyId::new("policy-2"),
        ..valid_policy()
    };
    let result = hooks.pre_merge_check(&a, &b).unwrap();
    assert!(result.passed);
    assert!(result.diagnostics.is_empty());
    assert_eq!(result.hook_name, "pre-merge");
}

#[test]
fn pre_merge_one_policy_violation() {
    let mut hooks = MachineCheckHooks::new(PolicyTheoremCompiler::new());
    let good = valid_policy();
    let bad = PolicyIr {
        policy_id: PolicyId::new("bad"),
        nodes: vec![simple_node(
            "n1",
            MergeOperator::Union,
            vec![grant("ext-A", "fs.read", "z")],
        )],
        ..valid_policy()
    };
    let result = hooks.pre_merge_check(&good, &bad).unwrap();
    assert!(!result.passed);
    assert!(!result.diagnostics.is_empty());
}

#[test]
fn pre_merge_both_policies_violation() {
    let mut hooks = MachineCheckHooks::new(PolicyTheoremCompiler::new());
    let bad1 = PolicyIr {
        policy_id: PolicyId::new("bad1"),
        nodes: vec![simple_node(
            "n1",
            MergeOperator::Union,
            vec![grant("a", "fs.read", "z")],
        )],
        ..valid_policy()
    };
    let bad2 = PolicyIr {
        policy_id: PolicyId::new("bad2"),
        nodes: vec![simple_node(
            "n1",
            MergeOperator::Union,
            vec![grant("b", "net.egress", "z")],
        )],
        ..valid_policy()
    };
    let result = hooks.pre_merge_check(&bad1, &bad2).unwrap();
    assert!(!result.passed);
    // Both policies should produce diagnostics.
    assert!(result.diagnostics.len() >= 2);
}

#[test]
fn pre_merge_empty_policy_returns_error() {
    let mut hooks = MachineCheckHooks::new(PolicyTheoremCompiler::new());
    let good = valid_policy();
    let empty = PolicyIr {
        nodes: Vec::new(),
        ..valid_policy()
    };
    let err = hooks.pre_merge_check(&good, &empty).unwrap_err();
    assert!(matches!(err, CompilerError::EmptyPolicy { .. }));
}

// ===========================================================================
// Machine-check hooks — pre_deployment
// ===========================================================================

#[test]
fn pre_deployment_valid() {
    let mut hooks = MachineCheckHooks::new(PolicyTheoremCompiler::new());
    let result = hooks.pre_deployment_check(&valid_policy()).unwrap();
    assert!(result.passed);
    assert_eq!(result.hook_name, "pre-deployment");
}

#[test]
fn pre_deployment_with_violations() {
    let mut hooks = MachineCheckHooks::new(PolicyTheoremCompiler::new());
    let ir = PolicyIr {
        nodes: vec![simple_node(
            "n1",
            MergeOperator::Union,
            vec![grant("a", "fs.read", "z")],
        )],
        ..valid_policy()
    };
    let result = hooks.pre_deployment_check(&ir).unwrap();
    assert!(!result.passed);
    assert!(!result.diagnostics.is_empty());
    assert!(
        result
            .diagnostics
            .iter()
            .all(|d| d.severity == DiagnosticSeverity::Error)
    );
}

// ===========================================================================
// Machine-check hooks — runtime
// ===========================================================================

#[test]
fn runtime_check_valid() {
    let mut hooks = MachineCheckHooks::new(PolicyTheoremCompiler::new());
    let result = hooks.runtime_check(&valid_policy()).unwrap();
    assert!(result.passed);
    assert_eq!(result.hook_name, "runtime");
}

#[test]
fn runtime_check_empty_policy_error() {
    let mut hooks = MachineCheckHooks::new(PolicyTheoremCompiler::new());
    let ir = PolicyIr {
        nodes: Vec::new(),
        ..valid_policy()
    };
    let err = hooks.runtime_check(&ir).unwrap_err();
    assert!(matches!(err, CompilerError::EmptyPolicy { .. }));
}

#[test]
fn runtime_check_monotonicity_violation() {
    let mut hooks = MachineCheckHooks::new(PolicyTheoremCompiler::new());
    let ir = PolicyIr {
        nodes: vec![simple_node(
            "n1",
            MergeOperator::Union,
            vec![grant("a", "fs.read", "z")],
        )],
        ..valid_policy()
    };
    let result = hooks.runtime_check(&ir).unwrap();
    assert!(!result.passed);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|d| d.property_violated == FormalProperty::Monotonicity)
    );
    assert!(
        result
            .diagnostics
            .iter()
            .all(|d| d.severity == DiagnosticSeverity::Fatal)
    );
}

#[test]
fn runtime_check_attenuation_violation() {
    let mut hooks = MachineCheckHooks::new(PolicyTheoremCompiler::new());
    let base = simple_node(
        "base",
        MergeOperator::Intersection,
        vec![grant("a", "fs.read", "z")],
    );
    let escalation = simple_node(
        "esc",
        MergeOperator::Attenuation,
        vec![grant("a", "policy.write", "z")],
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
            .any(|d| d.property_violated == FormalProperty::AttenuationLegality)
    );
}

#[test]
fn runtime_check_both_mono_and_attenuation_violations() {
    let mut hooks = MachineCheckHooks::new(PolicyTheoremCompiler::new());
    // Union without claim (mono) + attenuation escalation
    let base = simple_node(
        "base",
        MergeOperator::Union,
        vec![grant("a", "fs.read", "z")],
    );
    let esc = simple_node(
        "esc",
        MergeOperator::Attenuation,
        vec![grant("a", "policy.write", "z")],
    );
    let ir = PolicyIr {
        nodes: vec![base, esc],
        ..valid_policy()
    };
    let result = hooks.runtime_check(&ir).unwrap();
    assert!(!result.passed);
    assert_eq!(result.diagnostics.len(), 2);
}

// ===========================================================================
// Machine-check hooks — history
// ===========================================================================

#[test]
fn hook_history_accumulates() {
    let mut hooks = MachineCheckHooks::new(PolicyTheoremCompiler::new());
    let ir = valid_policy();
    hooks.pre_deployment_check(&ir).unwrap();
    hooks.runtime_check(&ir).unwrap();
    assert_eq!(hooks.hook_history().len(), 2);
    assert_eq!(hooks.hook_history()[0].hook_name, "pre-deployment");
    assert_eq!(hooks.hook_history()[1].hook_name, "runtime");
}

#[test]
fn hook_history_includes_all_types() {
    let mut hooks = MachineCheckHooks::new(PolicyTheoremCompiler::new());
    let ir = valid_policy();
    let ir2 = PolicyIr {
        policy_id: PolicyId::new("p2"),
        ..valid_policy()
    };
    hooks.pre_merge_check(&ir, &ir2).unwrap();
    hooks.pre_deployment_check(&ir).unwrap();
    hooks.runtime_check(&ir).unwrap();
    assert_eq!(hooks.hook_history().len(), 3);
}

// ===========================================================================
// PolicyValidationReceipt
// ===========================================================================

#[test]
fn receipt_from_valid_compilation() {
    let c = PolicyTheoremCompiler::new();
    let result = c.compile(&valid_policy()).unwrap();
    let sk = signing_key();
    let vk = sk.verification_key();

    let receipt = PolicyValidationReceipt::from_compilation(
        &result,
        [0xAA; 32],
        SecurityEpoch::from_raw(1),
        1_000_000_000,
        &vk,
    );
    assert_eq!(receipt.policy_id, PolicyId::new("test-policy-1"));
    assert!(!receipt.properties_verified.is_empty());
    assert_eq!(receipt.witness_count, result.witnesses.len() as u32);
    assert_eq!(receipt.compiler_version, "1.0.0");
    assert_eq!(receipt.timestamp_ns, 1_000_000_000);
    assert_eq!(receipt.policy_hash, [0xAA; 32]);
}

#[test]
fn receipt_unsigned_fails_verify() {
    let c = PolicyTheoremCompiler::new();
    let result = c.compile(&valid_policy()).unwrap();
    let sk = signing_key();
    let vk = sk.verification_key();

    let receipt = PolicyValidationReceipt::from_compilation(
        &result,
        [0; 32],
        SecurityEpoch::from_raw(1),
        0,
        &vk,
    );
    assert!(!receipt.verify());
}

#[test]
fn receipt_sign_and_verify() {
    let c = PolicyTheoremCompiler::new();
    let result = c.compile(&valid_policy()).unwrap();
    let sk = signing_key();
    let vk = sk.verification_key();

    let mut receipt = PolicyValidationReceipt::from_compilation(
        &result,
        [0x11; 32],
        SecurityEpoch::from_raw(2),
        500,
        &vk,
    );
    assert!(!receipt.verify());
    receipt.sign(&sk);
    assert!(receipt.verify());
}

#[test]
fn receipt_tampered_policy_hash_fails_verify() {
    let c = PolicyTheoremCompiler::new();
    let result = c.compile(&valid_policy()).unwrap();
    let sk = signing_key();
    let vk = sk.verification_key();

    let mut receipt = PolicyValidationReceipt::from_compilation(
        &result,
        [0xBB; 32],
        SecurityEpoch::from_raw(1),
        0,
        &vk,
    );
    receipt.sign(&sk);
    assert!(receipt.verify());
    receipt.policy_hash = [0xFF; 32];
    assert!(!receipt.verify());
}

#[test]
fn receipt_tampered_timestamp_fails_verify() {
    let c = PolicyTheoremCompiler::new();
    let result = c.compile(&valid_policy()).unwrap();
    let sk = signing_key();
    let vk = sk.verification_key();

    let mut receipt = PolicyValidationReceipt::from_compilation(
        &result,
        [0xCC; 32],
        SecurityEpoch::from_raw(1),
        1000,
        &vk,
    );
    receipt.sign(&sk);
    assert!(receipt.verify());
    receipt.timestamp_ns = 9999;
    assert!(!receipt.verify());
}

#[test]
fn receipt_wrong_signer_key_fails_verify() {
    let c = PolicyTheoremCompiler::new();
    let result = c.compile(&valid_policy()).unwrap();
    let sk = signing_key();
    let vk = sk.verification_key();

    let mut receipt = PolicyValidationReceipt::from_compilation(
        &result,
        [0xDD; 32],
        SecurityEpoch::from_raw(1),
        0,
        &vk,
    );
    receipt.sign(&sk);
    assert!(receipt.verify());

    // Replace the signer key with a different one.
    let other_sk = SigningKey::from_bytes([99u8; 32]);
    receipt.signer = other_sk.verification_key();
    assert!(!receipt.verify());
}

#[test]
fn receipt_serde_roundtrip() {
    let c = PolicyTheoremCompiler::new();
    let result = c.compile(&valid_policy()).unwrap();
    let sk = signing_key();
    let vk = sk.verification_key();

    let mut receipt = PolicyValidationReceipt::from_compilation(
        &result,
        [0xEE; 32],
        SecurityEpoch::from_raw(3),
        12345,
        &vk,
    );
    receipt.sign(&sk);

    let json = serde_json::to_string(&receipt).unwrap();
    let restored: PolicyValidationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, restored);
    assert!(restored.verify());
}

// ===========================================================================
// Integration scenarios
// ===========================================================================

#[test]
fn full_lifecycle_compile_sign_verify() {
    // Compile, generate receipt, sign, serialize, deserialize, verify.
    let compiler = PolicyTheoremCompiler::new();
    let ir = valid_policy();
    let result = compiler.compile(&ir).unwrap();
    assert!(result.all_passed);

    let sk = signing_key();
    let vk = sk.verification_key();
    let mut receipt = PolicyValidationReceipt::from_compilation(
        &result,
        [0x42; 32],
        SecurityEpoch::from_raw(5),
        999_999,
        &vk,
    );
    receipt.sign(&sk);
    assert!(receipt.verify());

    let json = serde_json::to_string(&receipt).unwrap();
    let restored: PolicyValidationReceipt = serde_json::from_str(&json).unwrap();
    assert!(restored.verify());
    assert_eq!(restored.properties_verified, receipt.properties_verified);
}

#[test]
fn hooks_then_receipt_workflow() {
    let compiler = PolicyTheoremCompiler::new();
    let mut hooks = MachineCheckHooks::new(compiler.clone());
    let ir = valid_policy();

    // Pre-deployment check passes.
    let check = hooks.pre_deployment_check(&ir).unwrap();
    assert!(check.passed);

    // Then compile and generate receipt.
    let result = compiler.compile(&ir).unwrap();
    let sk = signing_key();
    let vk = sk.verification_key();
    let mut receipt = PolicyValidationReceipt::from_compilation(
        &result,
        [0x77; 32],
        SecurityEpoch::from_raw(1),
        0,
        &vk,
    );
    receipt.sign(&sk);
    assert!(receipt.verify());
}

#[test]
fn large_policy_compilation() {
    let compiler = PolicyTheoremCompiler::new();
    let nodes: Vec<PolicyIrNode> = (0..100)
        .map(|i| {
            simple_node(
                &format!("node-{i}"),
                MergeOperator::Intersection,
                vec![grant(
                    &format!("ext-{i}"),
                    if i % 2 == 0 { "fs.read" } else { "net.egress" },
                    &format!("zone-{i}"),
                )],
            )
        })
        .collect();
    let ir = PolicyIr {
        nodes,
        ..valid_policy()
    };
    let result = compiler.compile(&ir).unwrap();
    assert!(result.all_passed);
}

#[test]
fn mixed_merge_operators_compilation() {
    let compiler = PolicyTheoremCompiler::new();
    let base_intersection = simple_node(
        "base",
        MergeOperator::Intersection,
        vec![
            grant("ext-A", "fs.read", "z"),
            grant("ext-A", "fs.write", "z"),
            grant("ext-A", "net.egress", "z"),
        ],
    );
    let att = simple_node(
        "att",
        MergeOperator::Attenuation,
        vec![grant("ext-A", "fs.read", "z")],
    );
    let mut prec1 = simple_node(
        "prec1",
        MergeOperator::Precedence,
        vec![grant("ext-B", "fs.read", "z")],
    );
    prec1.priority = 10;
    let mut prec2 = simple_node(
        "prec2",
        MergeOperator::Precedence,
        vec![grant("ext-C", "net.egress", "z")],
    );
    prec2.priority = 20;
    let ir = PolicyIr {
        nodes: vec![base_intersection, att, prec1, prec2],
        ..valid_policy()
    };
    let result = compiler.compile(&ir).unwrap();
    assert!(result.all_passed);
}

#[test]
fn node_with_all_constraint_types() {
    let compiler = PolicyTheoremCompiler::new();
    let mut n = simple_node(
        "n1",
        MergeOperator::Intersection,
        vec![grant("ext-A", "fs.read", "z")],
    );
    n.constraints = vec![
        Constraint::Invariant("safety".into()),
        Constraint::Precondition("authorized".into()),
        Constraint::Postcondition("logged".into()),
    ];
    let ir = PolicyIr {
        nodes: vec![n],
        ..valid_policy()
    };
    let result = compiler.compile(&ir).unwrap();
    assert!(result.all_passed);
}

#[test]
fn node_with_decision_point_compiles() {
    let compiler = PolicyTheoremCompiler::new();
    let mut n = simple_node(
        "n1",
        MergeOperator::Intersection,
        vec![grant("ext-A", "fs.read", "z")],
    );
    n.decision_point = Some(DecisionPoint {
        threshold: 2,
        action_map: {
            let mut m = BTreeMap::new();
            m.insert("risk-high".into(), "deny".into());
            m.insert("risk-low".into(), "allow".into());
            m
        },
        fallback: "deny".into(),
    });
    let ir = PolicyIr {
        nodes: vec![n],
        ..valid_policy()
    };
    let result = compiler.compile(&ir).unwrap();
    assert!(result.all_passed);
}
