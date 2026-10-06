#![forbid(unsafe_code)]

//! bd-9vouw.202: registers are reused inside an expression, not only at a
//! statement's end. A class or object literal assigned to a member
//! (`internals.Base = class { ... }`, `exports.api = { ... }`) keeps the
//! assignment target on the lowering value stack, so the stack never
//! emptied between members and every member's temporaries took fresh
//! registers: about five per class method and two per object-literal method.
//! joi 17 (a 70-method `internals.Base = class`), commonmark 0.31 and
//! mathjs 13 failed at load with "register 256 out of bounds (max 256)".
//! `const Base = class { ... }` (empty stack) was unaffected.
//!
//! The execution line is Node v22.2.0's output (Bun 1.4.2 prints the same).

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};

fn class_methods(count: usize) -> String {
    (0..count)
        .map(|i| format!("m{i}() {{ return {i}; }}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn object_methods(count: usize) -> String {
    (0..count)
        .map(|i| format!("f{i}() {{ return {i}; }}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The main frame's register count for `source` (script goal).
fn main_frame_size(source: &str) -> u32 {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("source parses");
    let ir0 = Ir0Module::from_syntax_tree(tree, "register_reuse.js");
    let context = LoweringContext::new("trace-regs", "decision-regs", "policy-regs");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("source lowers");
    output.ir3.function_table[0].frame_size
}

#[test]
fn member_assigned_literals_reuse_registers_per_member() {
    // 30 or 120 members need the same frame, no larger than a declared
    // class's (whose stack is empty between members).
    let class_small = format!(
        "const o = {{}};\no.k = class {{ {} }};\n",
        class_methods(30)
    );
    let class_large = format!(
        "const o = {{}};\no.k = class {{ {} }};\n",
        class_methods(120)
    );
    let object_small = format!("const o = {{}};\no.k = {{ {} }};\n", object_methods(30));
    let object_large = format!("const o = {{}};\no.k = {{ {} }};\n", object_methods(120));
    let declared = format!("const K = class {{ {} }};\n", class_methods(120));
    let declared_size = main_frame_size(&declared);
    for (small, large) in [(class_small, class_large), (object_small, object_large)] {
        let (small, large) = (main_frame_size(&small), main_frame_size(&large));
        assert_eq!(small, large, "frame grows with the member count");
        assert!(large <= declared_size + 8, "{large} vs {declared_size}");
    }
}

#[test]
fn large_member_assigned_classes_and_object_literals_run() {
    let methods = class_methods(150);
    let getters = (0..150)
        .map(|i| format!("get g{i}() {{ return {i}; }}"))
        .collect::<Vec<_>>()
        .join(" ");
    let api = object_methods(300);
    let source = format!(
        "const internals = {{}};\ninternals.Base = class {{ {methods} }};\ninternals.Getters = class {{ {getters} }};\ninternals.api = {{ {api} }};\nfunction inner() {{\n  const o = {{}};\n  o.k = class {{ {methods} }};\n  o.api = {{ {api} }};\n  return new o.k().m149() + o.api.f299();\n}}\nconsole.log(new internals.Base().m149(), new internals.Getters().g149, internals.api.f299(), inner());\n"
    );
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let package = ExtensionPackage {
            extension_id: "register-reuse".to_string(),
            source: source.clone(),
            source_file: None,
            module_root: None,
            capabilities: vec!["builtin".to_string()],
            version: "1.0.0".to_string(),
            metadata: Default::default(),
        };
        let lines: Vec<String> = ExecutionOrchestrator::new(OrchestratorConfig {
            force_lane: Some(lane),
            parse_goal: ParseGoal::Script,
            ..OrchestratorConfig::default()
        })
        .execute(&package)
        .unwrap_or_else(|error| panic!("{lane:?}: {error}"))
        .console_output
        .into_iter()
        .map(|line| line.message)
        .collect();
        assert_eq!(lines, ["149 149 299 448"], "{lane:?}");
    }
}

/// `count` declarations `var e{i} = "s{i}";`, one per line.
fn string_vars(count: usize) -> String {
    (0..count)
        .map(|i| format!("  var e{i} = \"s{i}\";\n"))
        .collect()
}

/// The lowered frame sizes of every function of `source` (script goal).
fn frame_sizes(source: &str) -> Vec<u32> {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("source parses");
    let ir0 = Ir0Module::from_syntax_tree(tree, "register_reuse.js");
    let context = LoweringContext::new("trace-regs", "decision-regs", "policy-regs");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("source lowers");
    output
        .ir3
        .function_table
        .iter()
        .map(|function| function.frame_size)
        .collect()
}

/// bd-9vouw.214: function locals written before they are read take a
/// register only from their first reference to their last, but nothing
/// bounded how many were live at once. Rollup inlines an entity table as
/// thousands of `var Aacute = "..."` in its factory function and reads every
/// one again in `var entities = { Aacute: Aacute, ... }`; commonmark 0.31
/// (joi and mathjs too, still failing after bd-9vouw.202) failed at load with
/// "register 256 out of bounds (max 256)". The locals past the frame's
/// budget now take the spill route, so frames stay within 256 registers.
#[test]
fn simultaneously_live_short_lived_locals_fit_the_frame_bd_9vouw_214() {
    let entries = |count: usize| {
        (0..count)
            .map(|i| format!("e{i}: e{i}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let table = format!(
        "function entities() {{\n{}  return {{ {} }};\n}}\nconsole.log(Object.keys(entities()).length);\n",
        string_vars(2200),
        entries(2200)
    );
    let sizes = frame_sizes(&table);
    assert!(
        sizes.iter().all(|size| *size <= 256),
        "frame sizes {sizes:?}"
    );

    let pushes = (0..300)
        .map(|i| format!("  out.push(e{i});\n"))
        .collect::<String>();
    let source = format!(
        "function entities() {{\n{decls}  return {{ {entries} }};\n}}\nfunction pushes() {{\n{decls}  var out = [];\n{pushes}  return out;\n}}\nvar o = entities();\nvar a = pushes();\nconsole.log(Object.keys(o).length, o.e299, a.length, a[150]);\n",
        decls = string_vars(300),
        entries = entries(300)
    );
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let package = ExtensionPackage {
            extension_id: "register-reuse".to_string(),
            source: source.clone(),
            source_file: None,
            module_root: None,
            capabilities: vec!["builtin".to_string()],
            version: "1.0.0".to_string(),
            metadata: Default::default(),
        };
        let lines: Vec<String> = ExecutionOrchestrator::new(OrchestratorConfig {
            force_lane: Some(lane),
            parse_goal: ParseGoal::Script,
            ..OrchestratorConfig::default()
        })
        .execute(&package)
        .unwrap_or_else(|error| panic!("{lane:?}: {error}"))
        .console_output
        .into_iter()
        .map(|line| line.message)
        .collect();
        assert_eq!(lines, ["300 s299 300 s150"], "{lane:?}");
    }
}
