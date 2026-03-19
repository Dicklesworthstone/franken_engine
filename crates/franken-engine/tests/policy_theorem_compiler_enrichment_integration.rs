#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

//! Enrichment integration tests for the `policy_theorem_compiler` module.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::policy_theorem_compiler::*;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn cap(name: &str) -> Capability {
    Capability::new(name)
}

fn pid(id: &str) -> PolicyId {
    PolicyId::new(id)
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
        policy_id: pid("test-policy"),
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

// ===========================================================================
// Capability enrichment
// ===========================================================================

#[test]
fn capability_display_matches_name() {
    let c = cap("fs.read");
    assert_eq!(c.to_string(), "fs.read");
    assert_eq!(c.as_str(), "fs.read");
}

#[test]
fn capability_ordering() {
    assert!(cap("a") < cap("b"));
    assert!(cap("fs.read") < cap("fs.write"));
}

#[test]
fn capability_clone_eq() {
    let a = cap("net.egress");
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn capability_serde_roundtrip() {
    let c = cap("policy.write");
    let json = serde_json::to_string(&c).expect("serialize");
    let restored: Capability = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(c, restored);
}

// ===========================================================================
// PolicyId enrichment
// ===========================================================================

#[test]
fn policy_id_display() {
    let p = pid("my-policy-42");
    assert_eq!(p.to_string(), "my-policy-42");
    assert_eq!(p.as_str(), "my-policy-42");
}

#[test]
fn policy_id_ordering() {
    assert!(pid("a") < pid("b"));
}

#[test]
fn policy_id_serde_roundtrip() {
    let p = pid("test");
    let json = serde_json::to_string(&p).expect("serialize");
    let restored: PolicyId = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(p, restored);
}

// ===========================================================================
// MergeOperator enrichment
// ===========================================================================

#[test]
fn merge_operator_all_display_distinct() {
    let ops = [
        MergeOperator::Union,
        MergeOperator::Intersection,
        MergeOperator::Attenuation,
        MergeOperator::Precedence,
    ];
    let displays: BTreeSet<String> = ops.iter().map(|o| o.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn merge_operator_serde_roundtrip() {
    for op in [
        MergeOperator::Union,
        MergeOperator::Intersection,
        MergeOperator::Attenuation,
        MergeOperator::Precedence,
    ] {
        let json = serde_json::to_string(&op).expect("serialize");
        let restored: MergeOperator = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(op, restored);
    }
}

// ===========================================================================
// FormalProperty enrichment
// ===========================================================================

#[test]
fn formal_property_all_display_distinct() {
    let props = [
        FormalProperty::Monotonicity,
        FormalProperty::NonInterference,
        FormalProperty::AttenuationLegality,
        FormalProperty::MergeDeterminism,
        FormalProperty::PrecedenceStability,
    ];
    let displays: BTreeSet<String> = props.iter().map(|p| p.to_string()).collect();
    assert_eq!(displays.len(), 5);
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
        let json = serde_json::to_string(&prop).expect("serialize");
        let restored: FormalProperty = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(prop, restored);
    }
}

// ===========================================================================
// Constraint enrichment
// ===========================================================================

#[test]
fn constraint_all_variants_serde() {
    let constraints = vec![
        Constraint::Invariant("always true".into()),
        Constraint::Precondition("before apply".into()),
        Constraint::Postcondition("after apply".into()),
        Constraint::NonInterferenceClaim {
            domain_a: "a".into(),
            domain_b: "b".into(),
        },
    ];
    for c in &constraints {
        let json = serde_json::to_string(c).expect("serialize");
        let restored: Constraint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*c, restored);
    }
}

// ===========================================================================
// DecisionPoint enrichment
// ===========================================================================

#[test]
fn decision_point_serde_roundtrip() {
    let mut action_map = BTreeMap::new();
    action_map.insert("condition_a".into(), "action_x".into());
    action_map.insert("condition_b".into(), "action_y".into());
    let dp = DecisionPoint {
        threshold: 3,
        action_map,
        fallback: "default_action".into(),
    };
    let json = serde_json::to_string(&dp).expect("serialize");
    let restored: DecisionPoint = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(dp, restored);
}

// ===========================================================================
// PolicyIrNode enrichment
// ===========================================================================

#[test]
fn policy_ir_node_with_decision_point() {
    let mut node = simple_node(
        "n1",
        MergeOperator::Precedence,
        vec![grant("user", "fs.read", "scope")],
    );
    node.priority = 5;
    let mut action_map = BTreeMap::new();
    action_map.insert("high_risk".into(), "deny".into());
    node.decision_point = Some(DecisionPoint {
        threshold: 2,
        action_map,
        fallback: "allow".into(),
    });
    assert_eq!(node.priority, 5);
    assert!(node.decision_point.is_some());
}

#[test]
fn policy_ir_node_serde_roundtrip() {
    let mut node = simple_node(
        "n1",
        MergeOperator::Intersection,
        vec![grant("s", "fs.read", "z")],
    );
    node.property_claims.insert(FormalProperty::Monotonicity);
    node.constraints.push(Constraint::Invariant("test".into()));
    let json = serde_json::to_string(&node).expect("serialize");
    let restored: PolicyIrNode = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(node, restored);
}

// ===========================================================================
// PolicyIr enrichment
// ===========================================================================

#[test]
fn policy_ir_granted_capabilities() {
    let ir = valid_policy();
    let granted = ir.granted_capabilities();
    assert!(granted.contains(&cap("fs.read")));
    assert!(granted.contains(&cap("net.egress")));
    assert!(!granted.contains(&cap("fs.write")));
}

#[test]
fn policy_ir_subjects() {
    let ir = valid_policy();
    let subjects = ir.subjects();
    assert!(subjects.contains("ext-A"));
    assert!(subjects.contains("ext-B"));
}

#[test]
fn policy_ir_serde_roundtrip() {
    let ir = valid_policy();
    let json = serde_json::to_string(&ir).expect("serialize");
    let restored: PolicyIr = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ir, restored);
}

// ===========================================================================
// Compiler — compile enrichment
// ===========================================================================

#[test]
fn compile_valid_policy_all_passed() {
    let compiler = PolicyTheoremCompiler::new();
    let result = compiler.compile(&valid_policy()).expect("compile");
    assert!(result.all_passed);
    assert!(result.counterexamples.is_empty());
    assert!(!result.witnesses.is_empty());
}

#[test]
fn compile_empty_policy_error() {
    let compiler = PolicyTheoremCompiler::new();
    let ir = PolicyIr {
        nodes: vec![],
        ..valid_policy()
    };
    let err = compiler.compile(&ir).unwrap_err();
    assert!(matches!(err, CompilerError::EmptyPolicy { .. }));
}

#[test]
fn compile_too_large_policy_error() {
    let compiler = PolicyTheoremCompiler::with_limits(2, true);
    let mut ir = valid_policy();
    ir.nodes.push(simple_node(
        "n3",
        MergeOperator::Intersection,
        vec![grant("ext-C", "fs.write", "zone-3")],
    ));
    let err = compiler.compile(&ir).unwrap_err();
    assert!(matches!(err, CompilerError::PolicyTooLarge { .. }));
}

#[test]
fn compile_union_without_monotonicity_claim_fails() {
    let compiler = PolicyTheoremCompiler::new();
    let ir = PolicyIr {
        nodes: vec![simple_node(
            "n1",
            MergeOperator::Union,
            vec![grant("ext-A", "fs.read", "zone-1")],
        )],
        ..valid_policy()
    };
    let result = compiler.compile(&ir).expect("compile");
    assert!(!result.all_passed);
    assert!(!result.counterexamples.is_empty());
}

#[test]
fn compile_union_with_monotonicity_claim_passes() {
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
    let result = compiler.compile(&ir).expect("compile");
    assert!(result.all_passed);
}

// ===========================================================================
// Compiler — precedence stability enrichment
// ===========================================================================

#[test]
fn precedence_zero_priority_fails_stability() {
    let compiler = PolicyTheoremCompiler::new();
    let node = simple_node(
        "n1",
        MergeOperator::Precedence,
        vec![grant("ext-A", "fs.read", "zone-1")],
    );
    let ir = PolicyIr {
        nodes: vec![node],
        ..valid_policy()
    };
    let result = compiler.compile(&ir).expect("compile");
    // Precedence with priority 0 should fail precedence-stability
    assert!(!result.all_passed);
}

#[test]
fn precedence_distinct_priorities_passes() {
    let compiler = PolicyTheoremCompiler::new();
    let mut n1 = simple_node(
        "n1",
        MergeOperator::Precedence,
        vec![grant("ext-A", "fs.read", "zone-1")],
    );
    n1.priority = 1;
    n1.property_claims.insert(FormalProperty::Monotonicity);
    let mut n2 = simple_node(
        "n2",
        MergeOperator::Precedence,
        vec![grant("ext-B", "net.egress", "zone-2")],
    );
    n2.priority = 2;
    n2.property_claims.insert(FormalProperty::Monotonicity);
    let ir = PolicyIr {
        nodes: vec![n1, n2],
        ..valid_policy()
    };
    let result = compiler.compile(&ir).expect("compile");
    assert!(result.all_passed);
}

#[test]
fn precedence_duplicate_priorities_fail_merge_determinism() {
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
    let result = compiler.compile(&ir).expect("compile");
    assert!(!result.all_passed);
}

// ===========================================================================
// Compiler — without precedence stability enrichment
// ===========================================================================

#[test]
fn compile_without_precedence_stability_skips_pass() {
    let compiler = PolicyTheoremCompiler::with_limits(10_000, false);
    let node = simple_node(
        "n1",
        MergeOperator::Precedence,
        vec![grant("ext-A", "fs.read", "zone-1")],
    );
    // priority=0 would fail precedence-stability, but it's not required
    let ir = PolicyIr {
        nodes: vec![node],
        ..valid_policy()
    };
    let result = compiler.compile(&ir).expect("compile");
    // Should still have at least the other passes' results
    assert!(result.pass_results.len() >= 4);
}

// ===========================================================================
// Compiler — attenuation legality enrichment
// ===========================================================================

#[test]
fn attenuation_within_base_authority_passes() {
    let compiler = PolicyTheoremCompiler::new();
    let base = simple_node(
        "base",
        MergeOperator::Intersection,
        vec![grant("ext-A", "fs.read", "zone-1")],
    );
    let att = simple_node(
        "att",
        MergeOperator::Attenuation,
        vec![grant("ext-B", "fs.read", "zone-2")],
    );
    let ir = PolicyIr {
        nodes: vec![base, att],
        ..valid_policy()
    };
    let result = compiler.compile(&ir).expect("compile");
    assert!(result.all_passed);
}

#[test]
fn attenuation_outside_base_authority_fails() {
    let compiler = PolicyTheoremCompiler::new();
    // Base only grants fs.read
    let base = simple_node(
        "base",
        MergeOperator::Intersection,
        vec![grant("ext-A", "fs.read", "zone-1")],
    );
    // Attenuation tries to grant fs.write which isn't in base
    let att = simple_node(
        "att",
        MergeOperator::Attenuation,
        vec![grant("ext-B", "fs.write", "zone-2")],
    );
    let ir = PolicyIr {
        nodes: vec![base, att],
        ..valid_policy()
    };
    let result = compiler.compile(&ir).expect("compile");
    assert!(!result.all_passed);
}

// ===========================================================================
// PassResult enrichment
// ===========================================================================

#[test]
fn pass_result_ok_is_ok() {
    let pr = PassResult::Ok(PropertyWitness {
        property: FormalProperty::Monotonicity,
        policy_id: pid("p"),
        explanation: "ok".into(),
        nodes_examined: 1,
        pass_name: "mono".into(),
    });
    assert!(pr.is_ok());
    assert!(!pr.is_failed());
}

#[test]
fn pass_result_failed_is_failed() {
    let pr = PassResult::Failed(Counterexample {
        property: FormalProperty::Monotonicity,
        policy_id: pid("p"),
        violating_nodes: vec!["n1".into()],
        description: "violation".into(),
        merge_path: vec![],
    });
    assert!(pr.is_failed());
    assert!(!pr.is_ok());
}

// ===========================================================================
// MachineCheckHooks enrichment
// ===========================================================================

#[test]
fn pre_deployment_check_valid_policy_passes() {
    let compiler = PolicyTheoremCompiler::new();
    let mut hooks = MachineCheckHooks::new(compiler);
    let ir = valid_policy();
    let result = hooks.pre_deployment_check(&ir).expect("check");
    assert!(result.passed);
    assert!(result.diagnostics.is_empty());
}

#[test]
fn runtime_check_valid_policy_passes() {
    let compiler = PolicyTheoremCompiler::new();
    let mut hooks = MachineCheckHooks::new(compiler);
    let ir = valid_policy();
    let result = hooks.runtime_check(&ir).expect("check");
    assert!(result.passed);
}

#[test]
fn runtime_check_empty_policy_error() {
    let compiler = PolicyTheoremCompiler::new();
    let mut hooks = MachineCheckHooks::new(compiler);
    let ir = PolicyIr {
        nodes: vec![],
        ..valid_policy()
    };
    let err = hooks.runtime_check(&ir).unwrap_err();
    assert!(matches!(err, CompilerError::EmptyPolicy { .. }));
}

#[test]
fn hook_history_accumulates() {
    let compiler = PolicyTheoremCompiler::new();
    let mut hooks = MachineCheckHooks::new(compiler);
    let ir = valid_policy();
    hooks.pre_deployment_check(&ir).expect("check1");
    hooks.runtime_check(&ir).expect("check2");
    assert_eq!(hooks.hook_history().len(), 2);
    assert_eq!(hooks.hook_history()[0].hook_name, "pre-deployment");
    assert_eq!(hooks.hook_history()[1].hook_name, "runtime");
}

#[test]
fn pre_merge_check_two_valid_policies_passes() {
    let compiler = PolicyTheoremCompiler::new();
    let mut hooks = MachineCheckHooks::new(compiler);
    let a = valid_policy();
    let b = PolicyIr {
        policy_id: pid("policy-b"),
        ..valid_policy()
    };
    let result = hooks.pre_merge_check(&a, &b).expect("check");
    assert!(result.passed);
}

// ===========================================================================
// DiagnosticSeverity enrichment
// ===========================================================================

#[test]
fn diagnostic_severity_display_all() {
    assert_eq!(DiagnosticSeverity::Warning.to_string(), "warning");
    assert_eq!(DiagnosticSeverity::Error.to_string(), "error");
    assert_eq!(DiagnosticSeverity::Fatal.to_string(), "fatal");
}

#[test]
fn diagnostic_severity_ordering() {
    assert!(DiagnosticSeverity::Warning < DiagnosticSeverity::Error);
    assert!(DiagnosticSeverity::Error < DiagnosticSeverity::Fatal);
}

// ===========================================================================
// PolicyValidationReceipt enrichment
// ===========================================================================

#[test]
fn receipt_sign_and_verify() {
    let compiler = PolicyTheoremCompiler::new();
    let ir = valid_policy();
    let result = compiler.compile(&ir).expect("compile");
    let key = SigningKey::from_bytes([42u8; 32]);
    let vk = key.verification_key();
    let mut receipt = PolicyValidationReceipt::from_compilation(
        &result,
        [0u8; 32],
        SecurityEpoch::from_raw(1),
        12345,
        &vk,
    );
    assert!(!receipt.verify()); // unsigned
    receipt.sign(&key);
    assert!(receipt.verify()); // signed
}

#[test]
fn receipt_fields_populated() {
    let compiler = PolicyTheoremCompiler::new();
    let ir = valid_policy();
    let result = compiler.compile(&ir).expect("compile");
    let key = SigningKey::from_bytes([42u8; 32]);
    let vk = key.verification_key();
    let receipt = PolicyValidationReceipt::from_compilation(
        &result,
        [42u8; 32],
        SecurityEpoch::from_raw(5),
        99999,
        &vk,
    );
    assert_eq!(receipt.policy_id, pid("test-policy"));
    assert_eq!(receipt.policy_hash, [42u8; 32]);
    assert_eq!(receipt.epoch, SecurityEpoch::from_raw(5));
    assert_eq!(receipt.timestamp_ns, 99999);
    assert_eq!(receipt.compiler_version, "1.0.0");
    assert!(!receipt.properties_verified.is_empty());
}

// ===========================================================================
// CompilerError enrichment
// ===========================================================================

#[test]
fn compiler_error_display_all() {
    let e1 = CompilerError::EmptyPolicy {
        policy_id: pid("p1"),
    };
    assert!(e1.to_string().contains("empty policy"));

    let e2 = CompilerError::PolicyTooLarge {
        policy_id: pid("p2"),
        node_count: 100,
        max_nodes: 50,
    };
    assert!(e2.to_string().contains("too large"));

    let e3 = CompilerError::HookFailed {
        hook_name: "pre-merge".into(),
        diagnostics: vec![],
    };
    assert!(e3.to_string().contains("pre-merge"));
}

#[test]
fn compiler_error_serde_roundtrip() {
    let errors = vec![
        CompilerError::EmptyPolicy {
            policy_id: pid("p"),
        },
        CompilerError::PolicyTooLarge {
            policy_id: pid("p"),
            node_count: 10,
            max_nodes: 5,
        },
        CompilerError::HookFailed {
            hook_name: "hook".into(),
            diagnostics: vec![],
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let restored: CompilerError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, restored);
    }
}

// ===========================================================================
// Compilation result enrichment
// ===========================================================================

#[test]
fn compilation_result_serde_roundtrip() {
    let compiler = PolicyTheoremCompiler::new();
    let result = compiler.compile(&valid_policy()).expect("compile");
    let json = serde_json::to_string(&result).expect("serialize");
    let restored: CompilationResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(result, restored);
}

#[test]
fn compilation_result_witnesses_match_passes() {
    let compiler = PolicyTheoremCompiler::new();
    let result = compiler.compile(&valid_policy()).expect("compile");
    assert_eq!(
        result.witnesses.len(),
        result.pass_results.iter().filter(|p| p.is_ok()).count()
    );
}
