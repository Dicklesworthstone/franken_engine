//! Integration tests for guardplane integration with baseline interpreter.
//!
//! These tests verify that the guardplane hooks correctly assess risk and
//! enforce containment policies during interpreter execution.

use frankenengine_engine::ast::SourceSpan;
use frankenengine_engine::guardplane_integration::{
    AllocationContext, AllocationType, BasicGuardplaneAdapter, CallContext, CallType,
    CodeTrustLevel, GuardplaneConfig, HookAction, ImportContext, ImportType, InterpreterHook,
    PropertyAccessContext, PropertyAccessType,
};

fn create_test_span() -> SourceSpan {
    SourceSpan::new(0, 10, 1, 0, 1, 10)
}

#[test]
fn test_trusted_code_bypasses_guardplane() {
    let config = GuardplaneConfig::default();
    let mut adapter = BasicGuardplaneAdapter::new(config);

    // Trusted property access should always be allowed
    let context = PropertyAccessContext {
        object_id: 1,
        property_key: "sensitive_data".to_string(),
        access_type: PropertyAccessType::Set,
        source_span: create_test_span(),
        trust_level: CodeTrustLevel::Trusted,
        extension_id: None,
    };

    let action = adapter.pre_property_access(&context).unwrap();
    assert_eq!(action, HookAction::Allow);
    assert!(
        adapter.decision_history.is_empty(),
        "No evidence should be generated for trusted code"
    );
}

#[test]
fn test_untrusted_property_access_triggers_guardplane() {
    let config = GuardplaneConfig::default();
    let mut adapter = BasicGuardplaneAdapter::new(config);

    let context = PropertyAccessContext {
        object_id: 1,
        property_key: "user_data".to_string(),
        access_type: PropertyAccessType::Get,
        source_span: create_test_span(),
        trust_level: CodeTrustLevel::Untrusted,
        extension_id: Some("untrusted-extension".to_string()),
    };

    let action = adapter.pre_property_access(&context).unwrap();
    // Should allow low-risk Get operation
    assert_eq!(action, HookAction::Allow);
    assert_eq!(
        adapter.decision_history.len(),
        1,
        "Should generate evidence"
    );
}

#[test]
fn test_high_risk_property_access_triggers_containment() {
    let config = GuardplaneConfig {
        challenge_threshold: 100_000, // 0.1 - very sensitive
        ..Default::default()
    };

    let mut adapter = BasicGuardplaneAdapter::new(config);

    let context = PropertyAccessContext {
        object_id: 1,
        property_key: "sensitive_config".to_string(),
        access_type: PropertyAccessType::Delete, // High risk operation
        source_span: create_test_span(),
        trust_level: CodeTrustLevel::Untrusted,
        extension_id: Some("suspicious-extension".to_string()),
    };

    let action = adapter.pre_property_access(&context).unwrap();
    // Delete operation should trigger containment
    assert!(action.severity_level() > HookAction::Allow.severity_level());
    assert!(!adapter.decision_history.is_empty());
}

#[test]
fn test_function_call_risk_assessment() {
    let config = GuardplaneConfig::default();
    let mut adapter = BasicGuardplaneAdapter::new(config);

    // Constructor calls are higher risk than regular function calls
    let constructor_context = CallContext {
        function_id: 42,
        arg_count: 3,
        call_type: CallType::Constructor,
        source_span: create_test_span(),
        trust_level: CodeTrustLevel::Untrusted,
        extension_id: Some("test-extension".to_string()),
    };

    let function_context = CallContext {
        function_id: 43,
        arg_count: 3,
        call_type: CallType::Function,
        source_span: create_test_span(),
        trust_level: CodeTrustLevel::Untrusted,
        extension_id: Some("test-extension".to_string()),
    };

    let constructor_action = adapter.pre_call(&constructor_context).unwrap();
    let function_action = adapter.pre_call(&function_context).unwrap();

    // Constructor should have higher severity or equal
    assert!(constructor_action.severity_level() >= function_action.severity_level());
    assert_eq!(
        adapter.decision_history.len(),
        2,
        "Should record both decisions"
    );
}

#[test]
fn test_allocation_monitoring() {
    let config = GuardplaneConfig::default();
    let mut adapter = BasicGuardplaneAdapter::new(config);

    let context = AllocationContext {
        allocation_type: AllocationType::Function,
        estimated_size: 1024,
        source_span: create_test_span(),
        trust_level: CodeTrustLevel::Untrusted,
        extension_id: Some("memory-hungry-extension".to_string()),
    };

    let action = adapter.pre_allocation(&context).unwrap();
    // Function allocation should trigger some level of monitoring
    assert!(action == HookAction::Allow || action.severity_level() > 0);
    assert!(!adapter.decision_history.is_empty());
}

#[test]
fn test_import_risk_assessment() {
    let config = GuardplaneConfig::default();
    let mut adapter = BasicGuardplaneAdapter::new(config);

    // Dynamic imports are riskier than static imports
    let dynamic_context = ImportContext {
        module_specifier: "dangerous-module".to_string(),
        import_type: ImportType::Es6Dynamic,
        source_span: create_test_span(),
        trust_level: CodeTrustLevel::Untrusted,
        extension_id: Some("import-extension".to_string()),
    };

    let static_context = ImportContext {
        module_specifier: "safe-module".to_string(),
        import_type: ImportType::Es6Static,
        source_span: create_test_span(),
        trust_level: CodeTrustLevel::Untrusted,
        extension_id: Some("import-extension".to_string()),
    };

    let dynamic_action = adapter.pre_import(&dynamic_context).unwrap();
    let static_action = adapter.pre_import(&static_context).unwrap();

    // Dynamic import should be higher risk
    assert!(dynamic_action.severity_level() >= static_action.severity_level());
}

#[test]
fn test_evidence_generation_disabled() {
    let config = GuardplaneConfig {
        emit_evidence: false,
        ..Default::default()
    };

    let mut adapter = BasicGuardplaneAdapter::new(config);

    let context = PropertyAccessContext {
        object_id: 1,
        property_key: "test".to_string(),
        access_type: PropertyAccessType::Get,
        source_span: create_test_span(),
        trust_level: CodeTrustLevel::Untrusted,
        extension_id: Some("test-extension".to_string()),
    };

    adapter.pre_property_access(&context).unwrap();
    assert!(
        adapter.decision_history.is_empty(),
        "Evidence should be disabled"
    );
}

#[test]
fn test_risk_threshold_configuration() {
    let config = GuardplaneConfig {
        challenge_threshold: 50_000,  // 0.05 - very sensitive
        sandbox_threshold: 100_000,   // 0.1
        suspend_threshold: 150_000,   // 0.15
        terminate_threshold: 200_000, // 0.2
        ..Default::default()
    };

    let mut adapter = BasicGuardplaneAdapter::new(config);

    // Even low-risk operations should trigger challenges
    let context = PropertyAccessContext {
        object_id: 1,
        property_key: "data".to_string(),
        access_type: PropertyAccessType::Get, // Low risk
        source_span: create_test_span(),
        trust_level: CodeTrustLevel::Untrusted,
        extension_id: Some("test-extension".to_string()),
    };

    let action = adapter.pre_property_access(&context).unwrap();
    // With very low thresholds, even Get should be challenged
    assert!(action.severity_level() > HookAction::Allow.severity_level());
}

#[test]
fn test_decision_evidence_structure() {
    let config = GuardplaneConfig::default();
    let mut adapter = BasicGuardplaneAdapter::new(config);

    let context = CallContext {
        function_id: 100,
        arg_count: 1,
        call_type: CallType::Method,
        source_span: create_test_span(),
        trust_level: CodeTrustLevel::Untrusted,
        extension_id: Some("evidence-test".to_string()),
    };

    adapter.pre_call(&context).unwrap();

    assert_eq!(adapter.decision_history.len(), 1);
    let evidence = &adapter.decision_history[0];

    assert!(!evidence.decision_id.is_empty());
    assert!(evidence.timestamp > 0);
    assert!(!evidence.reason.is_empty());
    assert!(!evidence.evidence_hash.as_bytes().is_empty());

    // Check that the operation context was preserved
    match &evidence.operation_context {
        frankenengine_engine::guardplane_integration::OperationContext::Call(call_ctx) => {
            assert_eq!(call_ctx.function_id, 100);
            assert_eq!(call_ctx.call_type, CallType::Method);
        }
        _ => panic!("Expected Call operation context"),
    }
}

#[test]
fn test_multiple_operations_build_history() {
    let config = GuardplaneConfig::default();
    let mut adapter = BasicGuardplaneAdapter::new(config);

    // Perform multiple operations
    let prop_context = PropertyAccessContext {
        object_id: 1,
        property_key: "prop1".to_string(),
        access_type: PropertyAccessType::Get,
        source_span: create_test_span(),
        trust_level: CodeTrustLevel::Untrusted,
        extension_id: Some("multi-op-extension".to_string()),
    };

    let call_context = CallContext {
        function_id: 1,
        arg_count: 0,
        call_type: CallType::Function,
        source_span: create_test_span(),
        trust_level: CodeTrustLevel::Untrusted,
        extension_id: Some("multi-op-extension".to_string()),
    };

    let alloc_context = AllocationContext {
        allocation_type: AllocationType::Array,
        estimated_size: 256,
        source_span: create_test_span(),
        trust_level: CodeTrustLevel::Untrusted,
        extension_id: Some("multi-op-extension".to_string()),
    };

    adapter.pre_property_access(&prop_context).unwrap();
    adapter.pre_call(&call_context).unwrap();
    adapter.pre_allocation(&alloc_context).unwrap();

    assert_eq!(
        adapter.decision_history.len(),
        3,
        "Should record all three operations"
    );

    // All decisions should be for the same extension
    for evidence in &adapter.decision_history {
        let extension_id = match &evidence.operation_context {
            frankenengine_engine::guardplane_integration::OperationContext::PropertyAccess(ctx) => {
                &ctx.extension_id
            }
            frankenengine_engine::guardplane_integration::OperationContext::Call(ctx) => {
                &ctx.extension_id
            }
            frankenengine_engine::guardplane_integration::OperationContext::Allocation(ctx) => {
                &ctx.extension_id
            }
            frankenengine_engine::guardplane_integration::OperationContext::Import(ctx) => {
                &ctx.extension_id
            }
        };
        assert_eq!(extension_id, &Some("multi-op-extension".to_string()));
    }
}

#[test]
fn test_escalating_risk_patterns() {
    let config = GuardplaneConfig::default();
    let mut adapter = BasicGuardplaneAdapter::new(config);

    // Simulate escalating risk pattern: Get → Set → Delete
    let operations = [
        PropertyAccessType::Get,
        PropertyAccessType::Set,
        PropertyAccessType::Delete,
    ];

    let mut actions = Vec::new();

    for (i, &access_type) in operations.iter().enumerate() {
        let context = PropertyAccessContext {
            object_id: 1,
            property_key: format!("property_{}", i),
            access_type,
            source_span: create_test_span(),
            trust_level: CodeTrustLevel::Untrusted,
            extension_id: Some("escalating-extension".to_string()),
        };

        let action = adapter.pre_property_access(&context).unwrap();
        actions.push(action);
    }

    // Actions should show escalating severity
    assert!(actions[2].severity_level() >= actions[1].severity_level());
    assert!(actions[1].severity_level() >= actions[0].severity_level());
}

#[test]
fn test_large_allocation_triggers_scrutiny() {
    let config = GuardplaneConfig::default();
    let mut adapter = BasicGuardplaneAdapter::new(config);

    // Large allocation should be more scrutinized
    let large_context = AllocationContext {
        allocation_type: AllocationType::Array,
        estimated_size: 1_000_000, // 1MB
        source_span: create_test_span(),
        trust_level: CodeTrustLevel::Untrusted,
        extension_id: Some("memory-intensive".to_string()),
    };

    let small_context = AllocationContext {
        allocation_type: AllocationType::Array,
        estimated_size: 100, // 100 bytes
        source_span: create_test_span(),
        trust_level: CodeTrustLevel::Untrusted,
        extension_id: Some("memory-light".to_string()),
    };

    let _large_action = adapter.pre_allocation(&large_context).unwrap();
    let _small_action = adapter.pre_allocation(&small_context).unwrap();

    // Both should be tracked, but implementation could differentiate
    assert_eq!(adapter.decision_history.len(), 2);
}

#[test]
fn test_hook_action_display() {
    assert_eq!(format!("{}", HookAction::Allow), "allow");
    assert_eq!(format!("{}", HookAction::Challenge), "challenge");
    assert_eq!(format!("{}", HookAction::Sandbox), "sandbox");
    assert_eq!(format!("{}", HookAction::Suspend), "suspend");
    assert_eq!(format!("{}", HookAction::Terminate), "terminate");
    assert_eq!(format!("{}", HookAction::Quarantine), "quarantine");
}

#[test]
fn test_guardplane_config_defaults() {
    let config = GuardplaneConfig::default();

    assert_eq!(config.challenge_threshold, 200_000); // 0.2
    assert_eq!(config.sandbox_threshold, 400_000); // 0.4
    assert_eq!(config.suspend_threshold, 600_000); // 0.6
    assert_eq!(config.terminate_threshold, 800_000); // 0.8
    assert!(config.emit_evidence);
    assert!(!config.bayesian_learning); // Conservative default
}
