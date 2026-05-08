//! Adoption gate validation tests for shadow daemon governance.
//!
//! These tests validate that documentation claims remain truthful and that
//! mutation policy enforcement prevents aspirational or mutation-capable claims.

use frankenengine_engine::shadow_adoption_gates::*;
use std::fs;

/// Test that adoption gates correctly identify blocked capabilities
#[test]
fn test_adoption_gates_block_premature_claims() {
    println!("🚦 Testing adoption gate enforcement...");

    let gates = ShadowAdoptionGates::with_default_gates();
    let gated_capabilities = gates.get_gated_capabilities();

    // Should block autonomous mutation until no_mock_drill is green
    assert!(
        gated_capabilities.contains("autonomous_live_mutation"),
        "Autonomous mutation should be gated until no_mock_drill passes"
    );

    // Should block production status until no_mock_drill is green
    assert!(
        gated_capabilities.contains("production_daemon_status"),
        "Production daemon status should be gated until no_mock_drill passes"
    );

    // Should block operator replacement until no_mock_drill is green
    assert!(
        gated_capabilities.contains("operator_replacement"),
        "Operator replacement should be gated until no_mock_drill passes"
    );

    // Advisory capabilities should NOT be gated
    assert!(
        !gated_capabilities.contains("safe_operator_ui"),
        "Safe operator UI should not be gated (advisory contract is green)"
    );

    assert!(
        !gated_capabilities.contains("bounded_advisory_mode"),
        "Bounded advisory mode should not be gated (advisory contract is green)"
    );

    println!("✅ Adoption gates correctly block premature capabilities");
}

/// Test that documentation claim validator catches aspirational claims
#[test]
fn test_documentation_claim_validator_blocks_aspirational_claims() {
    println!("📝 Testing documentation claim validation...");

    let validator = DocumentationClaimValidator::new();

    // Should catch autonomous mutation claims
    let violations = validator.validate_documentation_text(
        "The shadow daemon provides autonomous mutation capabilities for live environments."
    );
    assert!(!violations.is_empty(), "Should detect autonomous mutation claim");
    assert_eq!(violations[0].claim_type, "autonomous_live_mutation");

    // Should catch production daemon claims
    let violations = validator.validate_documentation_text(
        "Deploy the shadow daemon in production for automated operations."
    );
    assert!(!violations.is_empty(), "Should detect production daemon claim");
    assert_eq!(violations[0].claim_type, "production_daemon_status");

    // Should catch operator replacement claims
    let violations = validator.validate_documentation_text(
        "The shadow daemon can replace operators for routine tasks."
    );
    assert!(!violations.is_empty(), "Should detect operator replacement claim");
    assert_eq!(violations[0].claim_type, "operator_replacement");

    // Should allow bounded advisory claims
    let violations = validator.validate_documentation_text(
        "The shadow daemon provides advisory recommendations that operators can review and execute manually."
    );
    assert!(violations.is_empty(), "Should allow advisory-only claims");

    println!("✅ Documentation claim validator blocks aspirational claims");
}

/// Test mutation policy enforcement blocks dangerous commands
#[test]
fn test_mutation_policy_enforcement_blocks_dangerous_commands() {
    println!("🔒 Testing mutation policy enforcement...");

    // Should block direct mutation commands
    let dangerous_commands = [
        "br update task-123",
        "git commit -m 'auto-update'",
        "rch exec 'cargo build'",
        "agent-mail send --to all",
        "queue submit job.json",
    ];

    for cmd in &dangerous_commands {
        let result = validate_operator_action_command(cmd);
        assert!(
            matches!(result, CommandValidation::ForbiddenMutation { .. }),
            "Should block dangerous command: {}",
            cmd
        );
    }

    // Should block indirect mutations
    let indirect_mutations = [
        "echo 'test' && br status",
        "report.sh && git add .",
        "echo $(br list)",
        "echo `rch status`",
    ];

    for cmd in &indirect_mutations {
        let result = validate_operator_action_command(cmd);
        assert!(
            matches!(result, CommandValidation::ForbiddenMutation { .. }),
            "Should block indirect mutation: {}",
            cmd
        );
    }

    // Should block dangerous flags
    let dangerous_flags = [
        "cleanup.sh --execute",
        "deploy --force",
        "update --auto",
        "sync --yes",
    ];

    for cmd in &dangerous_flags {
        let result = validate_operator_action_command(cmd);
        assert!(
            matches!(result, CommandValidation::ForbiddenMutation { .. }),
            "Should block dangerous flag: {}",
            cmd
        );
    }

    println!("✅ Mutation policy enforcement blocks dangerous commands");
}

/// Test that advisory commands are allowed
#[test]
fn test_advisory_commands_are_allowed() {
    println!("✅ Testing advisory command validation...");

    let advisory_commands = [
        "shadow-daemon refresh --source evidence-journal",
        "shadow-daemon investigate-drift --journal journal-001",
        "echo 'Check shadow daemon status'",
        "cat /path/to/report.json",
        "grep 'error' /var/log/shadow.log",
        "shadow-daemon status --format json",
        "less /tmp/recommendations.txt",
    ];

    for cmd in &advisory_commands {
        let result = validate_operator_action_command(cmd);
        assert_eq!(
            result,
            CommandValidation::Advisory,
            "Advisory command should be allowed: {}",
            cmd
        );
    }

    println!("✅ Advisory commands are correctly allowed");
}

/// Test README content compliance with adoption gates
#[test]
fn test_readme_content_compliance() {
    println!("📄 Testing README compliance with adoption gates...");

    // Read the main README
    let readme_content = fs::read_to_string("/data/projects/franken_engine/README.md")
        .expect("Should be able to read README.md");

    let validator = DocumentationClaimValidator::new();
    let violations = validator.validate_documentation_text(&readme_content);

    // Check for specific problematic patterns
    let readme_lower = readme_content.to_lowercase();

    // Should not claim autonomous live mutation
    assert!(
        !(readme_lower.contains("autonomous") && readme_lower.contains("mutation")),
        "README should not claim autonomous mutation capabilities until gates are green"
    );

    // Should not claim production daemon status
    let production_daemon_patterns = [
        "production shadow daemon",
        "production-ready daemon",
        "deploy daemon in production",
    ];

    for pattern in &production_daemon_patterns {
        assert!(
            !readme_lower.contains(pattern),
            "README should not claim production daemon status: found '{}'",
            pattern
        );
    }

    // Should not claim operator replacement
    let operator_replacement_patterns = [
        "replace operators",
        "replaces human operators",
        "automatic operator replacement",
    ];

    for pattern in &operator_replacement_patterns {
        assert!(
            !readme_lower.contains(pattern),
            "README should not claim operator replacement: found '{}'",
            pattern
        );
    }

    // Report any violations found by the validator
    if !violations.is_empty() {
        for violation in &violations {
            println!(
                "⚠️  Documentation violation: {} in '{}'",
                violation.claim_type, violation.violation_text
            );
        }
        panic!(
            "README contains {} gated claims that should not be present until adoption gates are green",
            violations.len()
        );
    }

    println!("✅ README content complies with adoption gate restrictions");
}

/// Test shadow daemon contract documentation compliance
#[test]
fn test_shadow_daemon_contract_compliance() {
    println!("📋 Testing shadow daemon contract compliance...");

    // Read shadow daemon contract documentation
    let contract_content = fs::read_to_string("/data/projects/franken_engine/docs/SWARM_AUTOPILOT_SHADOW_DAEMON_CONTRACT.md")
        .expect("Should be able to read shadow daemon contract");

    let validator = DocumentationClaimValidator::new();
    let violations = validator.validate_documentation_text(&contract_content);

    // Contract should explicitly state advisory-only nature
    let contract_lower = contract_content.to_lowercase();
    assert!(
        contract_lower.contains("advisory"),
        "Shadow daemon contract should explicitly mention advisory nature"
    );

    assert!(
        contract_lower.contains("not execute") || contract_lower.contains("must not"),
        "Shadow daemon contract should explicitly forbid execution"
    );

    // Should not contain problematic claims
    assert!(
        violations.is_empty(),
        "Shadow daemon contract contains gated claims: {:?}",
        violations
    );

    println!("✅ Shadow daemon contract complies with advisory-only restrictions");
}

/// Test proof state documentation accuracy
#[test]
fn test_proof_state_documentation_accuracy() {
    println!("🔍 Testing proof state documentation accuracy...");

    // Read proof state documentation
    let proof_state_content = fs::read_to_string("/data/projects/franken_engine/docs/SHADOW_DAEMON_PROOF_STATE.md")
        .expect("Should be able to read proof state documentation");

    // Should clearly state advisory-only status
    assert!(
        proof_state_content.contains("ADVISORY-ONLY"),
        "Proof state should clearly state advisory-only status"
    );

    // Should identify blocked capabilities
    assert!(
        proof_state_content.contains("BLOCKED CAPABILITIES"),
        "Proof state should identify blocked capabilities"
    );

    // Should list promotion requirements
    assert!(
        proof_state_content.contains("Promotion Requirements") ||
        proof_state_content.contains("promotion requirements"),
        "Proof state should document promotion requirements"
    );

    // Should mention current gate status
    assert!(
        proof_state_content.contains("Gate Status") ||
        proof_state_content.contains("gate status"),
        "Proof state should document current gate status"
    );

    println!("✅ Proof state documentation accurately reflects current status");
}

/// Test handoff contracts maintain advisory-only semantics
#[test]
fn test_handoff_contracts_advisory_semantics() {
    println!("🤝 Testing handoff contracts maintain advisory semantics...");

    // Read handoff contracts documentation
    let handoff_content = fs::read_to_string("/data/projects/franken_engine/docs/handoff_contracts.md")
        .expect("Should be able to read handoff contracts");

    // Should emphasize advisory-only semantics
    assert!(
        handoff_content.contains("advisory-only") || handoff_content.contains("advisory only"),
        "Handoff contracts should emphasize advisory-only semantics"
    );

    // Should forbid direct mutations
    assert!(
        handoff_content.contains("must not mutate") ||
        handoff_content.contains("cannot mutate") ||
        handoff_content.contains("no direct mutations"),
        "Handoff contracts should forbid direct mutations"
    );

    // Should mention command preview only
    assert!(
        handoff_content.contains("preview") || handoff_content.contains("display"),
        "Handoff contracts should emphasize command preview only"
    );

    println!("✅ Handoff contracts maintain advisory-only semantics");
}

/// Test that gate status changes affect capability blocking
#[test]
fn test_gate_status_affects_capability_blocking() {
    println!("🔄 Testing gate status affects capability blocking...");

    let mut gates = ShadowAdoptionGates::with_default_gates();

    // Initially, autonomous_live_mutation should be gated
    assert!(gates.is_capability_gated("autonomous_live_mutation"));

    // Simulate no_mock_drill gate turning green
    for gate in &mut gates.gates {
        if gate.gate_id == "no_mock_drill" {
            gate.status = GateStatus::Green;
            gate.failure_reason = None;
        }
    }

    // Now autonomous_live_mutation should not be gated
    assert!(!gates.is_capability_gated("autonomous_live_mutation"));

    // Other capabilities should also be unblocked
    assert!(!gates.is_capability_gated("production_daemon_status"));
    assert!(!gates.is_capability_gated("operator_replacement"));

    // All gates should now be green
    assert!(gates.all_gates_green());

    println!("✅ Gate status changes correctly affect capability blocking");
}

/// Test comprehensive mutation policy validation
#[test]
fn test_comprehensive_mutation_policy_validation() {
    println!("🛡️ Testing comprehensive mutation policy validation...");

    // Test various shell escape attempts
    let shell_escapes = [
        "echo $(br list)",
        "echo `git status`",
        "$(rch exec 'date')",
        "`agent-mail check`",
    ];

    for cmd in &shell_escapes {
        let result = validate_operator_action_command(cmd);
        assert!(
            matches!(result, CommandValidation::ForbiddenMutation { command, .. } if command == "shell_escape"),
            "Should block shell escape: {}",
            cmd
        );
    }

    // Test complex chained commands
    let chained_commands = [
        "echo 'Starting' && br update task && echo 'Done'",
        "ls -la; git add .; echo 'Added'",
        "report.sh || rch status",
        "echo 'test'\tbr\tstatus",
        "echo 'test'\t\tbr\t\tstatus",
    ];

    for cmd in &chained_commands {
        let result = validate_operator_action_command(cmd);
        assert!(
            matches!(result, CommandValidation::ForbiddenMutation { .. }),
            "Should block chained command with mutation: {}",
            cmd
        );
    }

    // Test edge cases that should be allowed
    let edge_cases = [
        "echo 'Remember to run: br status'", // Mention but don't execute
        "# br status - run this manually",    // Comment
        "grep 'br status' logfile.txt",      // Search for pattern
        "print('Use br status to check')",   // Code string
    ];

    for cmd in &edge_cases {
        let result = validate_operator_action_command(cmd);
        assert_eq!(
            result,
            CommandValidation::Advisory,
            "Should allow edge case: {}",
            cmd
        );
    }

    println!("✅ Comprehensive mutation policy validation working correctly");
}

/// Integration test: Full adoption gate workflow
#[test]
fn test_full_adoption_gate_workflow() {
    println!("🔄 Testing full adoption gate workflow...");

    // Initialize gates
    let gates = ShadowAdoptionGates::with_default_gates();
    let summary = gates.get_summary();

    // Should have appropriate initial state
    assert!(summary.total_gates >= 5, "Should have at least 5 adoption gates");
    assert!(summary.red_gates > 0, "Should have some red gates initially");
    assert!(!summary.all_green, "Should not be all green initially");

    // Gated capabilities should be blocked
    let gated_capabilities = gates.get_gated_capabilities();
    assert!(!gated_capabilities.is_empty(), "Should have gated capabilities");

    // Validator should catch violations
    let validator = DocumentationClaimValidator::new();
    let violations = validator.validate_documentation_text(
        "The shadow daemon provides autonomous live mutation and production deployment capabilities."
    );
    assert!(!violations.is_empty(), "Should detect multiple violations");

    // Command validation should work
    assert_eq!(
        validate_operator_action_command("shadow-daemon status"),
        CommandValidation::Advisory
    );

    assert!(matches!(
        validate_operator_action_command("br update task-123"),
        CommandValidation::ForbiddenMutation { .. }
    ));

    println!("✅ Full adoption gate workflow functioning correctly");
}

/// Test that the bounded advisory contract is correctly validated
#[test]
fn test_bounded_advisory_contract_validation() {
    println!("📋 Testing bounded advisory contract validation...");

    let validator = DocumentationClaimValidator::new();

    // These advisory-only claims should pass validation
    let valid_advisory_claims = [
        "The shadow daemon provides advisory recommendations for operators.",
        "Commands are displayed as preview text only for manual execution.",
        "All operations require operator review and manual execution.",
        "The system generates recommendations that operators can evaluate.",
        "Advisory-only interface prevents direct system mutations.",
        "Operators receive actionable insights without automatic execution.",
    ];

    for claim in &valid_advisory_claims {
        let violations = validator.validate_documentation_text(claim);
        assert!(
            violations.is_empty(),
            "Valid advisory claim should not trigger violations: '{}'",
            claim
        );
    }

    // These mutation-capable claims should fail validation
    let invalid_mutation_claims = [
        "The shadow daemon autonomously executes mutations.",
        "Production deployment with automatic execution capabilities.",
        "The daemon can replace operator decision-making.",
        "Autonomous live mutation of system state.",
        "Production-ready daemon for unattended operation.",
    ];

    for claim in &invalid_mutation_claims {
        let violations = validator.validate_documentation_text(claim);
        assert!(
            !violations.is_empty(),
            "Invalid mutation claim should trigger violations: '{}'",
            claim
        );
    }

    println!("✅ Bounded advisory contract validation working correctly");
}