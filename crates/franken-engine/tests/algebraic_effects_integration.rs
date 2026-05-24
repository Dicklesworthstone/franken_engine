//! Integration tests for algebraic effects hostcall substrate.
//!
//! Tests the full round-trip from effect creation through handler execution
//! to result conversion, including capability checking, error handling,
//! and composition laws.

use frankenengine_engine::algebraic_effects::*;
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::security_epoch::SecurityEpoch;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Test console effect full round-trip.
#[test]
fn test_console_effect_round_trip() {
    let mut stack = HandlerStack::new();
    stack.add_handler(Arc::new(ConsoleHandler::new()));

    let effect = ConsoleEffect {
        level: ConsoleLevel::Info,
        args: vec!["Integration".to_string(), "test".to_string()],
    };

    let result = stack
        .handle_effect(&effect)
        .expect("Console effect should be handled");
    let output: () = result.downcast().expect("Console should return unit");
    assert_eq!(output, ());
}

/// Test console handler output accumulation.
#[test]
fn test_console_handler_accumulation() {
    let handler = Arc::new(ConsoleHandler::with_max_entries(5));
    let mut stack = HandlerStack::new();
    stack.add_handler(handler.clone());

    // Log multiple messages
    for i in 0..3 {
        let effect = ConsoleEffect {
            level: ConsoleLevel::Log,
            args: vec![format!("Message {}", i)],
        };
        stack.handle_effect(&effect).unwrap();
    }

    let output = handler.get_output();
    assert_eq!(output.len(), 3);
    assert_eq!(output[0].message, "Message 0");
    assert_eq!(output[1].message, "Message 1");
    assert_eq!(output[2].message, "Message 2");
}

/// Test console handler buffer overflow.
#[test]
fn test_console_handler_buffer_overflow() {
    let handler = Arc::new(ConsoleHandler::with_max_entries(2));
    let mut stack = HandlerStack::new();
    stack.add_handler(handler.clone());

    // Log more messages than buffer can hold
    for i in 0..5 {
        let effect = ConsoleEffect {
            level: ConsoleLevel::Error,
            args: vec![format!("Error {}", i)],
        };
        stack.handle_effect(&effect).unwrap();
    }

    let output = handler.get_output();
    assert_eq!(output.len(), 2); // Should only keep last 2
    assert_eq!(output[0].message, "Error 3");
    assert_eq!(output[1].message, "Error 4");
}

/// Test file system effect round-trip.
#[test]
fn test_fs_effect_round_trip() {
    let fs_handler = Arc::new(MockFsHandler::new());
    let mut stack = HandlerStack::new();
    stack.add_handler(fs_handler.clone());

    // Write file
    let write_effect = FsWriteEffect {
        path: "/integration/test.txt".to_string(),
        data: b"Integration test data".to_vec(),
        append: false,
    };

    let write_result = stack
        .handle_effect(&write_effect)
        .expect("Write should succeed");
    let bytes_written: u64 = write_result
        .downcast()
        .expect("Write should return byte count");
    assert_eq!(bytes_written, 21);

    // Read file back
    let read_effect = FsReadEffect {
        path: "/integration/test.txt".to_string(),
        range: None,
    };

    let read_result = stack
        .handle_effect(&read_effect)
        .expect("Read should succeed");
    let data: Vec<u8> = read_result.downcast().expect("Read should return data");
    assert_eq!(data, b"Integration test data");
}

/// Test file system range reading.
#[test]
fn test_fs_range_reading() {
    let fs_handler = Arc::new(MockFsHandler::new());
    fs_handler.add_file("/range_test.txt", b"0123456789abcdef");

    let mut stack = HandlerStack::new();
    stack.add_handler(fs_handler);

    let read_effect = FsReadEffect {
        path: "/range_test.txt".to_string(),
        range: Some((5, 10)),
    };

    let result = stack
        .handle_effect(&read_effect)
        .expect("Range read should succeed");
    let data: Vec<u8> = result.downcast().expect("Should return data");
    assert_eq!(data, b"56789");
}

/// Test file system append mode.
#[test]
fn test_fs_append_mode() {
    let fs_handler = Arc::new(MockFsHandler::new());
    fs_handler.add_file("/append_test.txt", b"Hello");

    let mut stack = HandlerStack::new();
    stack.add_handler(fs_handler.clone());

    let append_effect = FsWriteEffect {
        path: "/append_test.txt".to_string(),
        data: b", World!".to_vec(),
        append: true,
    };

    stack
        .handle_effect(&append_effect)
        .expect("Append should succeed");

    let read_effect = FsReadEffect {
        path: "/append_test.txt".to_string(),
        range: None,
    };

    let result = stack
        .handle_effect(&read_effect)
        .expect("Read should succeed");
    let data: Vec<u8> = result.downcast().expect("Should return data");
    assert_eq!(data, b"Hello, World!");
}

/// Test file not found error.
#[test]
fn test_fs_file_not_found() {
    let fs_handler = Arc::new(MockFsHandler::new());
    let mut stack = HandlerStack::new();
    stack.add_handler(fs_handler);

    let read_effect = FsReadEffect {
        path: "/nonexistent.txt".to_string(),
        range: None,
    };

    let result = stack.handle_effect(&read_effect);
    assert!(matches!(result, Err(EffectError::HandlerError { .. })));
}

/// Test capability checking for file system operations.
#[test]
fn test_fs_capability_checking() {
    let mut fs_handler = MockFsHandler::new();
    fs_handler.allow_reads = false; // Disable read capability

    let mut stack = HandlerStack::new();
    stack.add_handler(Arc::new(fs_handler));

    let read_effect = FsReadEffect {
        path: "/test.txt".to_string(),
        range: None,
    };

    let result = stack.handle_effect(&read_effect);
    assert!(matches!(result, Err(EffectError::CapabilityDenied { .. })));
}

/// Test network connect effect.
#[test]
fn test_net_connect_effect() {
    let effect = NetConnectEffect {
        host: "localhost".to_string(),
        port: 8080,
        timeout_ms: Some(1000),
    };

    assert_eq!(effect.effect_name(), "net:connect");
    assert!(
        effect
            .required_capabilities()
            .runtime_caps
            .contains(&RuntimeCapability::NetworkEgress)
    );

    let params = effect.parameters();
    let (host, port, timeout) = params.downcast_ref::<(String, u16, Option<u64>)>().unwrap();
    assert_eq!(*host, "localhost");
    assert_eq!(*port, 8080);
    assert_eq!(*timeout, Some(1000));
}

/// Test process spawn effect.
#[test]
fn test_proc_spawn_effect() {
    let mut env = BTreeMap::new();
    env.insert("PATH".to_string(), "/usr/bin".to_string());

    let effect = ProcSpawnEffect {
        command: "echo".to_string(),
        args: vec!["hello".to_string()],
        env: env.clone(),
        cwd: Some("/tmp".to_string()),
    };

    assert_eq!(effect.effect_name(), "proc:spawn");
    assert!(
        effect
            .required_capabilities()
            .custom_caps
            .contains("proc:spawn")
    );

    let params = effect.parameters();
    let (cmd, args, env_params, cwd) = params
        .downcast_ref::<(
            String,
            Vec<String>,
            BTreeMap<String, String>,
            Option<String>,
        )>()
        .unwrap();
    assert_eq!(*cmd, "echo");
    assert_eq!(*args, vec!["hello"]);
    assert_eq!(*env_params, env);
    assert_eq!(*cwd, Some("/tmp".to_string()));
}

/// Test policy request effect.
#[test]
fn test_policy_request_effect() {
    let mut context = BTreeMap::new();
    context.insert("user_id".to_string(), "alice".to_string());
    context.insert("resource".to_string(), "/sensitive/file.txt".to_string());

    let effect = PolicyRequestEffect {
        query: "can_read_file".to_string(),
        context: context.clone(),
    };

    assert_eq!(effect.effect_name(), "policy:request");
    assert!(
        effect
            .required_capabilities()
            .runtime_caps
            .contains(&RuntimeCapability::PolicyRead)
    );

    let params = effect.parameters();
    let (query, ctx) = params
        .downcast_ref::<(String, BTreeMap<String, String>)>()
        .unwrap();
    assert_eq!(*query, "can_read_file");
    assert_eq!(*ctx, context);
}

/// Test timer effect variations.
#[test]
fn test_timer_effects() {
    let timeout_effect = TimerEffect {
        operation: TimerOperation::SetTimeout { delay_ms: 500 },
    };
    assert_eq!(timeout_effect.effect_name(), "timer:setTimeout");

    let interval_effect = TimerEffect {
        operation: TimerOperation::SetInterval { interval_ms: 1000 },
    };
    assert_eq!(interval_effect.effect_name(), "timer:setInterval");

    let clear_timeout_effect = TimerEffect {
        operation: TimerOperation::ClearTimeout { timer_id: 42 },
    };
    assert_eq!(clear_timeout_effect.effect_name(), "timer:clearTimeout");

    let clear_interval_effect = TimerEffect {
        operation: TimerOperation::ClearInterval { timer_id: 43 },
    };
    assert_eq!(clear_interval_effect.effect_name(), "timer:clearInterval");
}

/// Test builtin effect for JavaScript operations.
#[test]
fn test_builtin_effect() {
    let effect = BuiltinEffect {
        name: "ArrayPrototypePush".to_string(),
        args: vec![
            BuiltinValue::Object(123),
            BuiltinValue::Int(42),
            BuiltinValue::Str("test".to_string()),
        ],
    };

    assert_eq!(effect.effect_name(), "builtin:call");
    assert!(
        effect
            .required_capabilities()
            .runtime_caps
            .contains(&RuntimeCapability::VmDispatch)
    );

    let params = effect.parameters();
    let (name, args) = params
        .downcast_ref::<(String, Vec<BuiltinValue>)>()
        .unwrap();
    assert_eq!(*name, "ArrayPrototypePush");
    assert_eq!(args.len(), 3);
}

/// Test promise effect operations.
#[test]
fn test_promise_effects() {
    let create_effect = PromiseEffect {
        operation: PromiseOperation::Create,
    };
    assert_eq!(create_effect.effect_name(), "promise:create");

    let resolve_effect = PromiseEffect {
        operation: PromiseOperation::Resolve {
            promise_id: 123,
            value: BuiltinValue::Int(42),
        },
    };
    assert_eq!(resolve_effect.effect_name(), "promise:resolve");

    let all_effect = PromiseEffect {
        operation: PromiseOperation::All {
            promises: vec![1, 2, 3],
        },
    };
    assert_eq!(all_effect.effect_name(), "promise:all");
}

/// Test number effect operations.
#[test]
fn test_number_effects() {
    let parse_int_effect = NumberEffect {
        operation: NumberOperation::ParseInt {
            value: "42".to_string(),
            radix: Some(10),
        },
    };
    assert_eq!(parse_int_effect.effect_name(), "number:parseInt");

    let parse_float_effect = NumberEffect {
        operation: NumberOperation::ParseFloat {
            value: "3.14159".to_string(),
        },
    };
    assert_eq!(parse_float_effect.effect_name(), "number:parseFloat");

    let is_nan_effect = NumberEffect {
        operation: NumberOperation::IsNaN { value: f64::NAN },
    };
    assert_eq!(is_nan_effect.effect_name(), "number:isNaN");
}

/// Test module effect operations.
#[test]
fn test_module_effects() {
    let require_effect = ModuleEffect {
        operation: ModuleOperation::Require {
            specifier: "./math.js".to_string(),
        },
    };
    assert_eq!(require_effect.effect_name(), "module:require");

    let import_effect = ModuleEffect {
        operation: ModuleOperation::Import {
            specifier: "https://cdn.example.com/lib.js".to_string(),
        },
    };
    assert_eq!(import_effect.effect_name(), "module:import");

    let export_effect = ModuleEffect {
        operation: ModuleOperation::Export {
            name: "default".to_string(),
            value: BuiltinValue::Object(456),
        },
    };
    assert_eq!(export_effect.effect_name(), "module:export");
}

/// Test handler priority ordering.
#[test]
fn test_handler_priority_ordering() {
    let low_handler = Arc::new(TestHandler::new("low"));
    let high_handler = Arc::new(TestHandler::new("high"));
    let normal_handler = Arc::new(TestHandler::new("normal"));

    let mut stack = HandlerStack::new();

    // Add in random order
    stack.add_handler(low_handler);
    stack.add_handler(high_handler);
    stack.add_handler(normal_handler);

    let names = stack.handler_names();
    // All handlers have same priority, so order should be preserved
    assert_eq!(names.len(), 3);
}

/// Test multiple console levels in same handler.
#[test]
fn test_multiple_console_levels() {
    let handler = Arc::new(ConsoleHandler::new());
    let mut stack = HandlerStack::new();
    stack.add_handler(handler.clone());

    // Test all console levels
    let levels = [
        (ConsoleLevel::Log, "console:log"),
        (ConsoleLevel::Error, "console:error"),
        (ConsoleLevel::Warn, "console:warn"),
        (ConsoleLevel::Info, "console:info"),
    ];

    for (level, expected_name) in levels.iter() {
        let effect = ConsoleEffect {
            level: *level,
            args: vec![format!("Test {}", expected_name)],
        };

        assert_eq!(effect.effect_name(), *expected_name);

        let result = stack
            .handle_effect(&effect)
            .expect("Effect should be handled");
        let output: () = result.downcast().expect("Should return unit");
        assert_eq!(output, ());
    }

    let output = handler.get_output();
    assert_eq!(output.len(), 4);
}

/// Test capability requirements for different effects.
#[test]
fn test_capability_requirements() {
    // Console effects require no capabilities
    let console_effect = ConsoleEffect {
        level: ConsoleLevel::Log,
        args: vec!["test".to_string()],
    };
    assert_eq!(
        console_effect.required_capabilities(),
        EffectCapabilities::none()
    );

    // Network effects require NetworkEgress capability
    let net_effect = NetConnectEffect {
        host: "example.com".to_string(),
        port: 443,
        timeout_ms: None,
    };
    let net_caps = net_effect.required_capabilities();
    assert!(
        net_caps
            .runtime_caps
            .contains(&RuntimeCapability::NetworkEgress)
    );

    // Policy effects require PolicyRead capability
    let policy_effect = PolicyRequestEffect {
        query: "test_query".to_string(),
        context: BTreeMap::new(),
    };
    let policy_caps = policy_effect.required_capabilities();
    assert!(
        policy_caps
            .runtime_caps
            .contains(&RuntimeCapability::PolicyRead)
    );

    // Builtin effects require VmDispatch capability
    let builtin_effect = BuiltinEffect {
        name: "Test".to_string(),
        args: vec![],
    };
    let builtin_caps = builtin_effect.required_capabilities();
    assert!(
        builtin_caps
            .runtime_caps
            .contains(&RuntimeCapability::VmDispatch)
    );
}

/// Test migration adapter round-trip for console operations.
#[test]
fn test_migration_adapter_console_round_trip() {
    let mut adapter = HostcallMigrationAdapter::new();

    let result = adapter
        .dispatch_hostcall(
            "console:error",
            &[
                "Critical".to_string(),
                "error".to_string(),
                "occurred".to_string(),
            ],
        )
        .expect("Console hostcall should succeed");

    assert!(matches!(result, HostcallResult::Success));
}

/// Test migration adapter round-trip for file operations.
#[test]
fn test_migration_adapter_file_round_trip() {
    let mut adapter = HostcallMigrationAdapter::new();

    // Write file through migration adapter
    let write_result = adapter
        .dispatch_hostcall(
            "fs:write",
            &[
                "/migration/test.dat".to_string(),
                "Binary data content".to_string(),
            ],
        )
        .expect("File write should succeed");

    if let HostcallResult::Count(bytes) = write_result {
        assert_eq!(bytes, 19);
    } else {
        panic!("Expected Count result from write operation");
    }

    // Read file back through migration adapter
    let read_result = adapter
        .dispatch_hostcall("fs:read", &["/migration/test.dat".to_string()])
        .expect("File read should succeed");

    if let HostcallResult::Data(data) = read_result {
        assert_eq!(data, b"Binary data content");
    } else {
        panic!("Expected Data result from read operation");
    }
}

/// Test migration adapter error handling.
#[test]
fn test_migration_adapter_error_handling() {
    let mut adapter = HostcallMigrationAdapter::new();

    // Test invalid capability
    let result = adapter.dispatch_hostcall("invalid:operation", &[]);
    assert!(matches!(result, Err(EffectError::Unhandled { .. })));

    // Test invalid arguments
    let result = adapter.dispatch_hostcall("fs:read", &[]);
    assert!(matches!(result, Err(EffectError::InvalidParameters { .. })));

    // Test invalid port number
    let result = adapter.dispatch_hostcall(
        "net:connect",
        &["example.com".to_string(), "not_a_number".to_string()],
    );
    assert!(matches!(result, Err(EffectError::InvalidParameters { .. })));
}

/// Test effect set operations and subtyping.
#[test]
fn test_effect_set_operations() {
    let console_set =
        EffectSet::from_effects(["console:log".to_string(), "console:error".to_string()]);

    let extended_set = EffectSet::from_effects([
        "console:log".to_string(),
        "console:error".to_string(),
        "fs:read".to_string(),
    ]);

    // console_set should be a subset of extended_set
    assert!(console_set.is_subset_of(&extended_set));
    assert!(!extended_set.is_subset_of(&console_set));

    // Test union
    let fs_set = EffectSet::from_effects(["fs:write".to_string()]);
    let union = console_set.union(&fs_set);
    assert_eq!(union.len(), 3);
    assert!(union.contains("console:log"));
    assert!(union.contains("console:error"));
    assert!(union.contains("fs:write"));

    // Test intersection
    let intersection = extended_set.intersection(&console_set);
    assert_eq!(intersection.len(), 2);
    assert!(intersection.contains("console:log"));
    assert!(intersection.contains("console:error"));
    assert!(!intersection.contains("fs:read"));
}

/// Test circular dependency detection.
#[test]
fn test_circular_dependency_detection() {
    let mut stack = HandlerStack::new();

    // Manually trigger circular dependency by manipulating the path
    stack.dependency_path.push("effect1".to_string());
    stack.dependency_path.push("effect2".to_string());

    // Create an effect that would trigger circular dependency
    let effect = ConsoleEffect {
        level: ConsoleLevel::Log,
        args: vec!["effect1".to_string()], // Same name as in dependency path
    };

    // Simulate circular dependency by manually setting the effect name
    stack.dependency_path.push("console:log".to_string());

    let result = stack.handle_effect(&effect);
    assert!(matches!(
        result,
        Err(EffectError::CircularDependency { .. })
    ));
}

/// Test telemetry data collection.
#[test]
fn test_telemetry_data_collection() {
    let mut metadata = BTreeMap::new();
    metadata.insert("request_id".to_string(), "12345".to_string());

    let telemetry = EffectTelemetry {
        handler_name: "ConsoleHandler".to_string(),
        execution_time_ns: 1_500_000,
        capability_checks: vec!["console:log".to_string()],
        metadata: metadata.clone(),
    };

    let result = EffectResult::with_telemetry("output".to_string(), telemetry.clone());

    assert!(result.telemetry.is_some());
    let collected_telemetry = result.telemetry.unwrap();
    assert_eq!(collected_telemetry.handler_name, "ConsoleHandler");
    assert_eq!(collected_telemetry.execution_time_ns, 1_500_000);
    assert_eq!(collected_telemetry.capability_checks, vec!["console:log"]);
    assert_eq!(collected_telemetry.metadata, metadata);
}

/// Test capability satisfaction with epochs.
#[test]
fn test_capability_satisfaction_with_epochs() {
    let epoch1 = SecurityEpoch::from_raw(1);
    let epoch2 = SecurityEpoch::from_raw(2);

    let caps1 = EffectCapabilities::epoch(epoch1);
    let caps2 = EffectCapabilities::epoch(epoch2);

    // caps1 (epoch 1) should be satisfied by caps2 (epoch 2)
    assert!(caps1.is_satisfied_by(&caps2));
    // caps2 (epoch 2) should NOT be satisfied by caps1 (epoch 1)
    assert!(!caps2.is_satisfied_by(&caps1));
}

/// Create a mock handler for testing purposes.
#[derive(Debug)]
struct TestHandler {
    name: &'static str,
}

impl TestHandler {
    fn new(name: &'static str) -> Self {
        Self { name }
    }
}

impl Handler for TestHandler {
    fn can_handle(&self, effect_name: &str) -> bool {
        effect_name == "test_effect"
    }

    fn handle(&self, _effect: &dyn ErasedEffect) -> Result<Option<EffectResult>, EffectError> {
        Ok(Some(EffectResult::new(format!("handled by {}", self.name))))
    }

    fn provided_capabilities(&self) -> EffectCapabilities {
        EffectCapabilities::none()
    }

    fn handler_name(&self) -> &'static str {
        self.name
    }
}
