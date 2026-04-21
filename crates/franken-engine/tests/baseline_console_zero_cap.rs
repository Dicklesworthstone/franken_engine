#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use frankenengine_engine::baseline_interpreter::{InterpreterConfig, QuickJsLane};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir3Instruction, Ir3Module, IrHeader, IrLevel, IrSchemaVersion, RegRange,
};

fn module_for_console_caps(console_caps: &[&str]) -> Ir3Module {
    let mut instructions = Vec::new();
    let mut constant_pool = Vec::new();

    for (index, cap) in console_caps.iter().enumerate() {
        constant_pool.push(format!("message-{cap}"));
        instructions.push(Ir3Instruction::LoadStr {
            dst: 0,
            pool_index: index as u32,
        });
        instructions.push(Ir3Instruction::HostCall {
            capability: CapabilityTag((*cap).to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 0,
        });
    }
    instructions.push(Ir3Instruction::Halt);

    Ir3Module {
        header: IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir3,
            source_hash: None,
            source_label: "baseline-console-zero-cap".to_string(),
        },
        instructions,
        constant_pool,
        function_table: Vec::new(),
        specialization: None,
        required_capabilities: Vec::new(),
    }
}

#[test]
fn zero_console_cap_drops_all_builtin_and_direct_console_levels() {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.max_console_entries = 0;
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::VmDispatch]);
    let lane = QuickJsLane::with_config(config);

    for caps in [
        [
            "builtin:ConsoleLog",
            "builtin:ConsoleError",
            "builtin:ConsoleWarn",
            "builtin:ConsoleInfo",
        ],
        ["console:log", "console:error", "console:warn", "console:info"],
    ] {
        let result = lane
            .execute(&module_for_console_caps(&caps), "console-zero-cap")
            .expect("zero console cap must not panic or fail execution");

        assert!(
            result.console_output.is_empty(),
            "zero max_console_entries must drop all output for {caps:?}"
        );
    }
}
