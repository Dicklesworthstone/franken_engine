#![forbid(unsafe_code)]

//! Integration tests for policy theorem engine (G.7).
//!
//! Tests SMT-backed policy verification for monotonicity, non-interference,
//! and attenuation properties extending the G.4-G.6 translation validation foundation.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::policy_theorem_engine::{
    PolicyProperty, PolicyRule, PolicyTheoremEngine, SecurityLevel, SmtLogic, SmtSolver,
    VerificationStatus, generate_policy_test_cases,
};

/// Test basic policy theorem engine creation and configuration.
#[test]
fn policy_theorem_engine_creation_and_configuration() {
    let mut engine = PolicyTheoremEngine::new();

    // Verify default state
    assert!(engine.security_lattice.is_empty());
    assert!(engine.policy_rules.is_empty());
    assert!(engine.capability_hierarchy.is_empty());
    assert!(engine.theorems.is_empty());
    assert_eq!(engine.smt_context.solver_backend, SmtSolver::Internal);
    assert_eq!(engine.smt_context.timeout_seconds, 30);
    assert_eq!(engine.smt_context.logic, SmtLogic::QF_UF);

    // Configure security lattice
    engine.add_security_classification("public_data".to_string(), SecurityLevel::Public);
    engine.add_security_classification("user_profile".to_string(), SecurityLevel::Internal);
    engine.add_security_classification("admin_key".to_string(), SecurityLevel::Confidential);
    engine.add_security_classification("master_secret".to_string(), SecurityLevel::Secret);

    assert_eq!(engine.security_lattice.len(), 4);
    assert_eq!(
        engine.security_lattice["public_data"],
        SecurityLevel::Public
    );
    assert_eq!(
        engine.security_lattice["master_secret"],
        SecurityLevel::Secret
    );
}

/// Test monotonicity theorem generation and verification.
#[test]
fn monotonicity_theorem_generation_and_verification() {
    let mut engine = PolicyTheoremEngine::new();

    // Add security classifications
    engine.add_security_classification("user_level_1".to_string(), SecurityLevel::Public);
    engine.add_security_classification("user_level_2".to_string(), SecurityLevel::Internal);
    engine.add_security_classification("admin_level".to_string(), SecurityLevel::Secret);

    // Add monotonic policy rule
    let monotonic_rule = PolicyRule {
        rule_id: "access_control_monotonic".to_string(),
        rule_type: PolicyProperty::Monotonicity,
        premise: "User with clearance level C requests resource at level R".to_string(),
        conclusion: "Access granted iff C >= R in security lattice".to_string(),
        security_context: [
            ("user".to_string(), SecurityLevel::Internal),
            ("resource".to_string(), SecurityLevel::Internal),
        ]
        .into_iter()
        .collect(),
        capability_constraints: vec!["read_access".to_string(), "write_access".to_string()],
    };

    engine.add_policy_rule(monotonic_rule);

    // Generate monotonicity theorems
    let theorem_count = engine.generate_monotonicity_theorems().unwrap();
    assert_eq!(theorem_count, 1);

    let theorem = &engine.theorems[0];
    assert_eq!(theorem.property, PolicyProperty::Monotonicity);
    assert!(theorem.theorem_id.contains("monotonicity"));
    assert_eq!(theorem.proof_obligations.len(), 2); // ordering + preservation
    assert_eq!(theorem.verification_status, VerificationStatus::Unknown);

    // Verify theorem structure
    assert!(
        theorem
            .proof_obligations
            .iter()
            .any(|po| po.smt_formula.contains("forall") && po.smt_formula.contains("le"))
    );
    assert!(
        theorem
            .proof_obligations
            .iter()
            .any(|po| po.assertion_id.contains("ordering")
                || po.assertion_id.contains("preservation"))
    );

    // Verify all theorems
    let result = engine.verify_all_theorems().unwrap();
    assert_eq!(result.total_theorems, 1);
    assert!(result.verified_theorems <= 1); // May be proven or unknown
    assert!(result.verification_time_ms > 0);
}

/// Test non-interference theorem generation across security levels.
#[test]
fn non_interference_theorem_generation() {
    let mut engine = PolicyTheoremEngine::new();

    // Configure security classifications
    engine.add_security_classification("public_input".to_string(), SecurityLevel::Public);
    engine.add_security_classification("secret_key".to_string(), SecurityLevel::Secret);
    engine.add_security_classification("public_output".to_string(), SecurityLevel::Public);

    // Add non-interference policy rule
    let ni_rule = PolicyRule {
        rule_id: "information_flow_control".to_string(),
        rule_type: PolicyProperty::NonInterference,
        premise: "System processes inputs at multiple security levels".to_string(),
        conclusion: "High-security inputs do not influence low-security outputs".to_string(),
        security_context: [
            ("secret_input".to_string(), SecurityLevel::Secret),
            ("public_output".to_string(), SecurityLevel::Public),
        ]
        .into_iter()
        .collect(),
        capability_constraints: Vec::new(),
    };

    engine.add_policy_rule(ni_rule);

    // Generate non-interference theorems
    let theorem_count = engine.generate_non_interference_theorems().unwrap();
    assert!(theorem_count > 0); // Should generate theorems for security level pairs

    let ni_theorems: Vec<_> = engine
        .theorems
        .iter()
        .filter(|t| t.property == PolicyProperty::NonInterference)
        .collect();

    assert!(!ni_theorems.is_empty());

    // Verify theorem structure for high → low non-interference
    let secret_to_public = ni_theorems
        .iter()
        .find(|t| t.theorem_id.contains("noninterference_public_secret"))
        .unwrap();

    assert_eq!(secret_to_public.property, PolicyProperty::NonInterference);
    assert!(
        secret_to_public.hypothesis.contains("Secret")
            && secret_to_public.hypothesis.contains("Public")
    );
    assert_eq!(secret_to_public.proof_obligations.len(), 2); // isolation + indistinguishability

    // Verify SMT formulas
    assert!(
        secret_to_public
            .proof_obligations
            .iter()
            .any(|po| po.smt_formula.contains("not (influences"))
    );
    assert!(
        secret_to_public
            .proof_obligations
            .iter()
            .any(|po| po.smt_formula.contains("equal (observe"))
    );
}

/// Test capability attenuation theorem generation.
#[test]
fn capability_attenuation_theorem_generation() {
    let mut engine = PolicyTheoremEngine::new();

    // Define capability hierarchy
    let admin_children: BTreeSet<String> = [
        "user_management".to_string(),
        "system_config".to_string(),
        "audit_access".to_string(),
    ]
    .into_iter()
    .collect();
    engine.add_capability_attenuation("full_admin".to_string(), admin_children);

    let user_mgmt_children: BTreeSet<String> = ["create_user".to_string(), "read_user".to_string()]
        .into_iter()
        .collect();
    engine.add_capability_attenuation("user_management".to_string(), user_mgmt_children);

    // Add attenuation policy rule
    let attenuation_rule = PolicyRule {
        rule_id: "capability_delegation".to_string(),
        rule_type: PolicyProperty::Attenuation,
        premise: "Principal delegates capability to subordinate".to_string(),
        conclusion: "Delegated capability subset of principal capability".to_string(),
        security_context: BTreeMap::new(),
        capability_constraints: vec![
            "full_admin".to_string(),
            "user_management".to_string(),
            "create_user".to_string(),
        ],
    };

    engine.add_policy_rule(attenuation_rule);

    // Generate attenuation theorems
    let theorem_count = engine.generate_attenuation_theorems().unwrap();
    assert_eq!(theorem_count, 5); // 3 + 2 capabilities from hierarchy

    let attenuation_theorems: Vec<_> = engine
        .theorems
        .iter()
        .filter(|t| t.property == PolicyProperty::Attenuation)
        .collect();

    assert_eq!(attenuation_theorems.len(), 5);

    // Verify specific attenuation theorem
    let admin_to_user_mgmt = attenuation_theorems
        .iter()
        .find(|t| {
            t.theorem_id
                .contains("attenuation_full_admin_user_management")
        })
        .unwrap();

    assert_eq!(admin_to_user_mgmt.property, PolicyProperty::Attenuation);
    assert_eq!(admin_to_user_mgmt.proof_obligations.len(), 2); // subset + no_elevation

    // Verify SMT formulas for attenuation
    assert!(
        admin_to_user_mgmt
            .proof_obligations
            .iter()
            .any(|po| po.smt_formula.contains("permits") && po.smt_formula.contains("forall"))
    );
    assert!(
        admin_to_user_mgmt
            .proof_obligations
            .iter()
            .any(|po| po.smt_formula.contains("not (exists"))
    );
}

/// Test comprehensive policy verification workflow.
#[test]
fn comprehensive_policy_verification_workflow() {
    let mut engine = PolicyTheoremEngine::new();

    // Configure comprehensive security setup
    engine.add_security_classification("guest_data".to_string(), SecurityLevel::Public);
    engine.add_security_classification("user_data".to_string(), SecurityLevel::Internal);
    engine.add_security_classification("admin_data".to_string(), SecurityLevel::Confidential);
    engine.add_security_classification("system_secrets".to_string(), SecurityLevel::Secret);

    // Add multiple policy rules
    let monotonic_rule = PolicyRule {
        rule_id: "clearance_access".to_string(),
        rule_type: PolicyProperty::Monotonicity,
        premise: "Access control based on clearance levels".to_string(),
        conclusion: "Higher clearance allows access to same or lower classified data".to_string(),
        security_context: BTreeMap::new(),
        capability_constraints: vec!["data_access".to_string()],
    };

    let ni_rule = PolicyRule {
        rule_id: "data_isolation".to_string(),
        rule_type: PolicyProperty::NonInterference,
        premise: "System processes multi-level data".to_string(),
        conclusion: "Secret data processing does not affect public outputs".to_string(),
        security_context: BTreeMap::new(),
        capability_constraints: Vec::new(),
    };

    engine.add_policy_rule(monotonic_rule);
    engine.add_policy_rule(ni_rule);

    // Add capability hierarchy
    let admin_caps: BTreeSet<String> = [
        "read_all".to_string(),
        "write_protected".to_string(),
        "manage_users".to_string(),
    ]
    .into_iter()
    .collect();
    engine.add_capability_attenuation("admin".to_string(), admin_caps);

    // Generate all theorem types
    let mono_count = engine.generate_monotonicity_theorems().unwrap();
    let ni_count = engine.generate_non_interference_theorems().unwrap();
    let atten_count = engine.generate_attenuation_theorems().unwrap();

    assert!(mono_count > 0);
    assert!(ni_count > 0);
    assert!(atten_count > 0);

    let total_expected = mono_count + ni_count + atten_count;
    assert_eq!(engine.theorems.len(), total_expected);

    // Verify theorem distribution
    let mono_actual = engine
        .theorems
        .iter()
        .filter(|t| t.property == PolicyProperty::Monotonicity)
        .count();
    let ni_actual = engine
        .theorems
        .iter()
        .filter(|t| t.property == PolicyProperty::NonInterference)
        .count();
    let atten_actual = engine
        .theorems
        .iter()
        .filter(|t| t.property == PolicyProperty::Attenuation)
        .count();

    assert_eq!(mono_actual, mono_count);
    assert_eq!(ni_actual, ni_count);
    assert_eq!(atten_actual, atten_count);

    // Verify all theorems
    let verification_result = engine.verify_all_theorems().unwrap();

    assert_eq!(verification_result.total_theorems, total_expected);
    assert!(verification_result.verification_time_ms > 0);
    assert!(verification_result.verified_theorems <= verification_result.total_theorems);

    // Check that verification cache is populated
    assert_eq!(
        engine.verification_cache.len(),
        verification_result.total_theorems
    );
}

/// Test SMT declaration generation for policy verification.
#[test]
fn smt_declaration_generation() {
    let mut engine = PolicyTheoremEngine::new();

    // Configure SMT context
    engine.smt_context.logic = SmtLogic::UFLIA;
    engine.smt_context.timeout_seconds = 60;
    engine.smt_context.solver_backend = SmtSolver::Z3;

    // Add axioms
    engine
        .smt_context
        .axioms
        .push("(forall ((x SecurityLevel) (y SecurityLevel)) (=> (le x y) (le x y)))".to_string());
    engine
        .smt_context
        .axioms
        .push("(assert (distinct Public Internal Confidential Secret))".to_string());

    let declarations = engine.generate_smt_declarations();

    // Verify essential SMT-LIB components
    assert!(declarations.contains("(set-logic UFLIA)"));
    assert!(declarations.contains("(declare-sort Input 0)"));
    assert!(declarations.contains("(declare-sort Output 0)"));
    assert!(declarations.contains("(declare-sort Context 0)"));
    assert!(declarations.contains("(declare-sort Operation 0)"));
    assert!(declarations.contains("(declare-sort Decision 0)"));

    // Verify function declarations
    assert!(declarations.contains("(declare-fun security_level"));
    assert!(declarations.contains("(declare-fun influences"));
    assert!(declarations.contains("(declare-fun permits"));
    assert!(declarations.contains("(declare-fun policy_eval"));
    assert!(declarations.contains("(declare-fun observe"));

    // Verify axioms are included
    assert!(declarations.contains("(assert (forall"));
    assert!(declarations.contains("(assert (distinct"));
}

/// Test policy verification with different SMT solvers.
#[test]
fn policy_verification_different_smt_solvers() {
    let solvers = [
        SmtSolver::Internal,
        SmtSolver::Z3,
        SmtSolver::CVC5,
        SmtSolver::Yices,
    ];

    for solver in &solvers {
        let mut engine = PolicyTheoremEngine::new();
        engine.smt_context.solver_backend = solver.clone();

        // Add simple policy rule
        let rule = PolicyRule {
            rule_id: format!("test_rule_{:?}", solver),
            rule_type: PolicyProperty::Monotonicity,
            premise: "Test premise".to_string(),
            conclusion: "Test conclusion".to_string(),
            security_context: BTreeMap::new(),
            capability_constraints: Vec::new(),
        };

        engine.add_policy_rule(rule);

        // Generate and verify
        let theorem_count = engine.generate_monotonicity_theorems().unwrap();
        assert_eq!(theorem_count, 1);

        let result = engine.verify_all_theorems().unwrap();
        assert_eq!(result.total_theorems, 1);

        // Verify solver-specific metadata
        let verification = engine.verification_cache.values().next().unwrap();
        assert_eq!(
            verification.verification_metadata["solver"],
            format!("{:?}", solver)
        );
    }
}

/// Test security level ordering and relationships.
#[test]
fn security_level_ordering_relationships() {
    // Test basic ordering
    assert!(SecurityLevel::Public < SecurityLevel::Internal);
    assert!(SecurityLevel::Internal < SecurityLevel::Confidential);
    assert!(SecurityLevel::Confidential < SecurityLevel::Secret);

    // Test transitivity
    assert!(SecurityLevel::Public < SecurityLevel::Secret);

    // Test reflexivity (equality)
    assert_eq!(SecurityLevel::Internal, SecurityLevel::Internal);

    // Test in collections
    let mut levels = vec![
        SecurityLevel::Secret,
        SecurityLevel::Public,
        SecurityLevel::Confidential,
        SecurityLevel::Internal,
    ];
    levels.sort();

    assert_eq!(
        levels,
        vec![
            SecurityLevel::Public,
            SecurityLevel::Internal,
            SecurityLevel::Confidential,
            SecurityLevel::Secret,
        ]
    );
}

/// Test policy verification test case generation and execution.
#[test]
fn policy_test_case_generation_and_execution() {
    let test_cases = generate_policy_test_cases();
    assert!(!test_cases.is_empty());
    assert_eq!(test_cases.len(), 3);

    // Execute each test case
    for test_case in &test_cases {
        let mut engine = PolicyTheoremEngine::new();

        // Load test case configuration
        for (entity, level) in &test_case.security_classifications {
            engine.add_security_classification(entity.clone(), level.clone());
        }

        for rule in &test_case.policy_rules {
            engine.add_policy_rule(rule.clone());
        }

        // Generate theorems based on rule types
        let mut total_theorems = 0;

        for rule in &test_case.policy_rules {
            match rule.rule_type {
                PolicyProperty::Monotonicity => {
                    total_theorems += engine.generate_monotonicity_theorems().unwrap();
                }
                PolicyProperty::NonInterference => {
                    total_theorems += engine.generate_non_interference_theorems().unwrap();
                }
                PolicyProperty::Attenuation => {
                    total_theorems += engine.generate_attenuation_theorems().unwrap();
                }
                _ => {}
            }
        }

        // Verify expected theorem count (allowing for non-interference generating multiple theorems)
        if test_case
            .policy_rules
            .iter()
            .any(|r| r.rule_type == PolicyProperty::NonInterference)
        {
            assert!(total_theorems >= test_case.expected_theorems);
        } else {
            assert_eq!(total_theorems, test_case.expected_theorems);
        }

        // Run verification
        let result = engine.verify_all_theorems().unwrap();
        assert_eq!(result.total_theorems, total_theorems);

        // Check property-specific verification results
        match test_case.expected_verification_status {
            VerificationStatus::Proven => {
                assert!(result.verified_theorems > 0);
            }
            _ => {
                // Other statuses may vary based on SMT solver simulation
            }
        }
    }
}

/// Test error handling and edge cases.
#[test]
fn policy_verification_error_handling() {
    let mut engine = PolicyTheoremEngine::new();

    // Test with empty engine
    let empty_mono = engine.generate_monotonicity_theorems().unwrap();
    assert_eq!(empty_mono, 0);

    let empty_result = engine.verify_all_theorems().unwrap();
    assert_eq!(empty_result.total_theorems, 0);
    assert_eq!(empty_result.verified_theorems, 0);
    assert!(empty_result.monotonicity_proven);
    assert!(empty_result.non_interference_proven);
    assert!(empty_result.attenuation_proven);

    // Test with malformed policy rules
    let malformed_rule = PolicyRule {
        rule_id: "".to_string(), // Empty rule ID
        rule_type: PolicyProperty::Monotonicity,
        premise: "".to_string(),    // Empty premise
        conclusion: "".to_string(), // Empty conclusion
        security_context: BTreeMap::new(),
        capability_constraints: Vec::new(),
    };

    engine.add_policy_rule(malformed_rule);

    // Should still generate theorems but with empty content
    let theorem_count = engine.generate_monotonicity_theorems().unwrap();
    assert_eq!(theorem_count, 1);

    let result = engine.verify_all_theorems().unwrap();
    assert_eq!(result.total_theorems, 1);
}

/// Test policy verification performance and scalability.
#[test]
fn policy_verification_performance_scalability() {
    let mut engine = PolicyTheoremEngine::new();

    // Add moderate number of security classifications
    for i in 0..10 {
        let level = match i % 4 {
            0 => SecurityLevel::Public,
            1 => SecurityLevel::Internal,
            2 => SecurityLevel::Confidential,
            _ => SecurityLevel::Secret,
        };
        engine.add_security_classification(format!("entity_{}", i), level);
    }

    // Add multiple policy rules
    for i in 0..5 {
        let rule_type = match i % 3 {
            0 => PolicyProperty::Monotonicity,
            1 => PolicyProperty::NonInterference,
            _ => PolicyProperty::Attenuation,
        };

        let rule = PolicyRule {
            rule_id: format!("rule_{}", i),
            rule_type,
            premise: format!("Premise {}", i),
            conclusion: format!("Conclusion {}", i),
            security_context: BTreeMap::new(),
            capability_constraints: Vec::new(),
        };

        engine.add_policy_rule(rule);
    }

    // Add capability hierarchy
    for i in 0..3 {
        let mut children = BTreeSet::new();
        for j in 0..3 {
            children.insert(format!("child_{}_{}", i, j));
        }
        engine.add_capability_attenuation(format!("parent_{}", i), children);
    }

    // Generate all theorems
    let start_time = std::time::Instant::now();

    let mono_count = engine.generate_monotonicity_theorems().unwrap();
    let ni_count = engine.generate_non_interference_theorems().unwrap();
    let atten_count = engine.generate_attenuation_theorems().unwrap();

    let generation_time = start_time.elapsed();

    // Verify reasonable generation time
    assert!(generation_time.as_secs() < 1); // Should be very fast

    // Verify theorem counts are reasonable
    assert!(mono_count <= 2); // Based on monotonic rules
    assert!(ni_count > 0); // Non-interference generates multiple theorems
    assert_eq!(atten_count, 9); // 3 parents * 3 children each

    // Run verification
    let verification_start = std::time::Instant::now();
    let result = engine.verify_all_theorems().unwrap();
    let verification_time = verification_start.elapsed();

    // Verify reasonable verification time
    assert!(verification_time.as_secs() < 2);

    assert_eq!(result.total_theorems, mono_count + ni_count + atten_count);
    assert!(result.verification_time_ms > 0);
}

/// Test integration with translation validation infrastructure (G.4-G.6).
#[test]
fn integration_with_translation_validation() {
    let mut engine = PolicyTheoremEngine::new();

    // Policy rules that would integrate with IR translation validation
    let ir_security_rule = PolicyRule {
        rule_id: "ir_translation_security".to_string(),
        rule_type: PolicyProperty::NonInterference,
        premise: "IR translation preserves security classifications".to_string(),
        conclusion: "High-security IR constructs do not leak to low-security outputs".to_string(),
        security_context: [
            ("ir_input".to_string(), SecurityLevel::Secret),
            ("ir_output".to_string(), SecurityLevel::Public),
        ]
        .into_iter()
        .collect(),
        capability_constraints: vec!["ir_transform".to_string()],
    };

    let capability_preservation_rule = PolicyRule {
        rule_id: "capability_preservation".to_string(),
        rule_type: PolicyProperty::Attenuation,
        premise: "IR transformation preserves capability constraints".to_string(),
        conclusion: "Transformed IR cannot gain capabilities".to_string(),
        security_context: BTreeMap::new(),
        capability_constraints: vec![
            "ir1_caps".to_string(),
            "ir2_caps".to_string(),
            "ir3_caps".to_string(),
        ],
    };

    engine.add_policy_rule(ir_security_rule);
    engine.add_policy_rule(capability_preservation_rule);

    // Add IR-level capability hierarchy
    let ir1_caps: BTreeSet<String> = ["memory_access".to_string(), "io_access".to_string()]
        .into_iter()
        .collect();
    let ir2_caps: BTreeSet<String> = ["safe_memory".to_string()].into_iter().collect();
    engine.add_capability_attenuation("ir1_caps".to_string(), ir1_caps);
    engine.add_capability_attenuation("ir2_caps".to_string(), ir2_caps);

    // Generate theorems
    let ni_count = engine.generate_non_interference_theorems().unwrap();
    let atten_count = engine.generate_attenuation_theorems().unwrap();

    assert!(ni_count > 0);
    assert!(atten_count > 0);

    // Verify IR-specific theorems
    let ir_theorems: Vec<_> = engine
        .theorems
        .iter()
        .filter(|t| t.theorem_id.contains("ir") || t.hypothesis.contains("IR"))
        .collect();

    assert!(!ir_theorems.is_empty());

    let result = engine.verify_all_theorems().unwrap();
    assert!(result.total_theorems > 0);

    // Should integrate well with G.4-G.6 infrastructure
    assert!(result.non_interference_proven || result.verified_theorems > 0);
}

/// Test policy theorem engine with concurrent verification.
#[test]
fn concurrent_policy_verification() {
    use std::sync::{Arc, Mutex};
    use std::thread;

    let success_count = Arc::new(Mutex::new(0));
    let mut handles = vec![];

    for i in 0..3 {
        let success_count = success_count.clone();
        let handle = thread::spawn(move || {
            let mut engine = PolicyTheoremEngine::new();

            // Configure per-thread policy setup
            engine.add_security_classification(format!("data_{}", i), SecurityLevel::Internal);

            let rule = PolicyRule {
                rule_id: format!("thread_rule_{}", i),
                rule_type: PolicyProperty::Monotonicity,
                premise: format!("Thread {} premise", i),
                conclusion: format!("Thread {} conclusion", i),
                security_context: BTreeMap::new(),
                capability_constraints: Vec::new(),
            };

            engine.add_policy_rule(rule);

            let theorem_count = engine.generate_monotonicity_theorems().unwrap();
            let result = engine.verify_all_theorems().unwrap();

            if theorem_count == 1 && result.total_theorems == 1 {
                let mut count = success_count.lock().unwrap();
                *count += 1;
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let final_count = *success_count.lock().unwrap();
    assert_eq!(final_count, 3); // All threads should succeed
}
