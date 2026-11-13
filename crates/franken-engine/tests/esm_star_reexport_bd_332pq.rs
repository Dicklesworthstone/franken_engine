#![forbid(unsafe_code)]

//! `export * from m` and `export * as ns from m` (bd-332pq) through the
//! shipped module pipeline: real files under a module root, executed on both
//! lanes. Original fixtures use Node v22.2.0; binding-identity regressions use
//! Node v24.22.1, except the explicitly documented direct namespace diamond.

use std::path::Path;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};

/// Modules every case can re-export.
const LIBRARY: &[(&str, &str)] = &[
    ("lib/a.mjs", "export const a = 1;\nexport default 'A';\n"),
    (
        "lib/b.mjs",
        "export const b = 2;\nexport function f() { return 'f'; }\n",
    ),
];

fn run(root: &Path, lane: LaneChoice) -> Result<Vec<String>, String> {
    let entry = root.join("app.mjs");
    let package = ExtensionPackage {
        extension_id: "esm-star-reexport".to_string(),
        source: std::fs::read_to_string(&entry).expect("entry source"),
        source_file: Some(entry.display().to_string()),
        module_root: Some(root.display().to_string()),
        capabilities: vec!["module_load".to_string(), "builtin".to_string()],
        version: "1.0.0".to_string(),
        metadata: Default::default(),
    };
    ExecutionOrchestrator::new(OrchestratorConfig {
        force_lane: Some(lane),
        parse_goal: ParseGoal::Module,
        ..OrchestratorConfig::default()
    })
    .execute(&package)
    .map(|result| {
        result
            .console_output
            .into_iter()
            .map(|line| line.message)
            .collect()
    })
    .map_err(|error| error.to_string())
}

fn assert_output(files: &[(&str, &str)], expected: &[&str]) {
    let root = tempfile::tempdir().expect("module root");
    for (name, source) in LIBRARY.iter().chain(files) {
        let path = root.path().join(name);
        std::fs::create_dir_all(path.parent().expect("fixture parent")).expect("fixture directory");
        std::fs::write(path, source).expect("fixture file");
    }
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let actual = run(root.path(), lane).unwrap_or_else(|error| panic!("{lane:?}: {error}"));
        assert_eq!(actual, expected, "{lane:?}");
    }
}

/// A barrel re-exports every name of each source; `default` is not re-exported.
#[test]
fn barrel_named_and_namespace() {
    assert_output(
        &[
            (
                "lib/index.mjs",
                "export * from './a.mjs';\nexport * from './b.mjs';\n",
            ),
            (
                "app.mjs",
                "import { a, b, f } from './lib/index.mjs';\nimport * as ns from './lib/index.mjs';\nconsole.log(a, b, f());\nconsole.log(Object.keys(ns).sort().join(','), 'default' in ns);\n",
            ),
        ],
        &["1 2 f", "a,b,f false"],
    );
}

/// `export * as A` binds A to the source's namespace object, default included.
#[test]
fn star_as_namespace() {
    assert_output(
        &[
            ("lib/index.mjs", "export * as A from './a.mjs';\n"),
            (
                "app.mjs",
                "import { A } from './lib/index.mjs';\nconsole.log(A.a, A.default);\n",
            ),
        ],
        &["1 A"],
    );
}

/// The module's own export wins over a star name declared before it.
#[test]
fn own_export_shadows_star_after() {
    assert_output(
        &[
            (
                "lib/index.mjs",
                "export * from './a.mjs';\nexport const a = 'own';\n",
            ),
            (
                "app.mjs",
                "import { a } from './lib/index.mjs';\nconsole.log(a);\n",
            ),
        ],
        &["own"],
    );
}

/// The module's own export wins over a star name declared after it.
#[test]
fn own_export_shadows_star_before() {
    assert_output(
        &[
            (
                "lib/index.mjs",
                "export const a = 'own';\nexport * from './a.mjs';\n",
            ),
            (
                "app.mjs",
                "import { a } from './lib/index.mjs';\nconsole.log(a);\n",
            ),
        ],
        &["own"],
    );
}

/// Two star sources with different `dup` bindings: the name is ambiguous and not exported.
#[test]
fn ambiguous_name_is_not_exported() {
    assert_output(
        &[
            ("lib/x.mjs", "export const dup = 1;\n"),
            (
                "lib/y.mjs",
                "export const dup = 2;\nexport const y = 'y';\n",
            ),
            (
                "lib/index.mjs",
                "export * from './x.mjs';\nexport * from './y.mjs';\n",
            ),
            (
                "app.mjs",
                "import * as ns from './lib/index.mjs';\nconsole.log('dup' in ns, ns.y);\n",
            ),
        ],
        &["false y"],
    );
}

/// One binding reached through two star paths is not ambiguous.
#[test]
fn diamond_is_not_ambiguous() {
    assert_output(
        &[
            ("lib/d1.mjs", "export * from './a.mjs';\n"),
            ("lib/d2.mjs", "export * from './a.mjs';\n"),
            (
                "lib/index.mjs",
                "export * from './d1.mjs';\nexport * from './d2.mjs';\n",
            ),
            (
                "app.mjs",
                "import { a } from './lib/index.mjs';\nconsole.log(a);\n",
            ),
        ],
        &["1"],
    );
}

/// Distinct bindings are ambiguous even when their initial values compare
/// equal, including NaN and two locals holding the same object reference.
#[test]
fn equal_values_do_not_merge_distinct_star_bindings() {
    assert_output(
        &[
            ("lib/shared.mjs", "export const token = {};"),
            (
                "lib/left.mjs",
                "import { token } from './shared.mjs'; export let same = 1; export const nan = NaN; export const zero = 0; export const object = token; export function left() { same = 2; }",
            ),
            (
                "lib/right.mjs",
                "import { token } from './shared.mjs'; export let same = 1; export const nan = NaN; export const zero = 0; export const object = token; export function right() { same = 3; }",
            ),
            (
                "lib/index.mjs",
                "export * from './left.mjs'; export * from './right.mjs';",
            ),
            (
                "app.mjs",
                "import * as ns from './lib/index.mjs'; console.log('same' in ns, 'nan' in ns, 'zero' in ns, 'object' in ns); ns.left(); ns.right(); console.log('same' in ns, Object.keys(ns).sort().join(','));",
            ),
        ],
        &["false false false false", "false left,right"],
    );
}

/// Both renamed exports ultimately denote the same local cell. A named
/// re-export and an imported-then-exported alias preserve that identity.
#[test]
fn renamed_diamond_preserves_one_binding_and_live_updates() {
    assert_output(
        &[
            (
                "lib/source.mjs",
                "let count = 1; export { count as first, count as second }; export function bump() { count++; }",
            ),
            (
                "lib/left.mjs",
                "export { first as shared, bump } from './source.mjs';",
            ),
            (
                "lib/right.mjs",
                "import { second } from './source.mjs'; export { second as shared }; export { bump } from './source.mjs';",
            ),
            (
                "lib/index.mjs",
                "export * from './left.mjs'; export * from './right.mjs';",
            ),
            (
                "app.mjs",
                "import { shared, bump } from './lib/index.mjs'; import * as ns from './lib/index.mjs'; console.log(shared, ns.shared, Object.keys(ns).sort().join(',')); bump(); console.log(shared, ns.shared);",
            ),
        ],
        &["1 1 bump,shared", "2 2"],
    );
}

#[test]
fn named_default_function_and_class_aliases_share_binding_identity() {
    assert_output(
        &[
            (
                "lib/function.mjs",
                "export default function current() { return 1; } export { current as alias }; export function replace() { current = () => 2; }",
            ),
            (
                "lib/class.mjs",
                "export default class Item { value() { return 4; } } export { Item as alias };",
            ),
            (
                "lib/left.mjs",
                "export { default as callable, replace } from './function.mjs'; export { default as Type } from './class.mjs';",
            ),
            (
                "lib/right.mjs",
                "export { alias as callable, replace } from './function.mjs'; export { alias as Type } from './class.mjs';",
            ),
            (
                "lib/index.mjs",
                "export * from './left.mjs'; export * from './right.mjs';",
            ),
            (
                "app.mjs",
                "import { callable, replace, Type } from './lib/index.mjs'; console.log(callable(), new Type().value()); replace(); console.log(callable());",
            ),
        ],
        &["1 4", "2"],
    );
}

#[test]
fn default_expression_and_local_export_are_distinct_bindings() {
    assert_output(
        &[
            (
                "lib/source.mjs",
                "export let value = 1; export default value; export function bump() { value++; }",
            ),
            (
                "lib/left.mjs",
                "export { default as shared } from './source.mjs';",
            ),
            (
                "lib/right.mjs",
                "export { value as shared } from './source.mjs';",
            ),
            (
                "lib/index.mjs",
                "export * from './left.mjs'; export * from './right.mjs';",
            ),
            (
                "app.mjs",
                "import * as ns from './lib/index.mjs'; import { bump } from './lib/source.mjs'; console.log('shared' in ns); bump(); console.log('shared' in ns);",
            ),
        ],
        &["false", "false"],
    );
}

#[test]
fn imported_alias_is_visible_before_its_later_export_clause() {
    assert_output(
        &[
            (
                "lib/source.mjs",
                "export let value = 1; export function bump() { value++; }",
            ),
            (
                "lib/bridge.mjs",
                "import { value, bump } from './source.mjs'; import * as loop from './loop.mjs'; console.log('bridge', loop.alias); export { value as alias, bump };",
            ),
            ("lib/loop.mjs", "export * from './bridge.mjs';"),
            (
                "app.mjs",
                "import { alias, bump } from './lib/bridge.mjs'; import * as loop from './lib/loop.mjs'; console.log(alias, loop.alias); bump(); console.log(alias, loop.alias);",
            ),
        ],
        &["bridge 1", "1 1", "2 2"],
    );
}

#[test]
fn initialized_lexical_is_visible_before_its_later_export_clause() {
    assert_output(
        &[
            (
                "lib/source.mjs",
                "import * as loop from './loop.mjs'; let value = 1; console.log(loop.alias); export { value as alias };",
            ),
            ("lib/loop.mjs", "export * from './source.mjs';"),
            (
                "app.mjs",
                "import { alias } from './lib/source.mjs'; console.log(alias);",
            ),
        ],
        &["1", "1"],
    );
}

#[test]
fn cyclic_named_alias_stays_uninitialized_until_source_initializes() {
    assert_output(
        &[
            (
                "lib/source.mjs",
                "import { alias, read } from './bridge.mjs'; try { console.log(alias); } catch (error) { console.log(error.name); } export let value = 1; console.log(alias, read());",
            ),
            (
                "lib/bridge.mjs",
                "import { value } from './source.mjs'; export { value as alias }; export function read() { return value; }",
            ),
            (
                "app.mjs",
                "import { value } from './lib/source.mjs'; console.log(value);",
            ),
        ],
        &["ReferenceError", "1 1", "1"],
    );
}

#[test]
fn export_ir_linkage_is_versioned_validated_and_hash_bound() {
    use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::hash_tiers::ContentHash;
    use frankenengine_engine::ir_contract::{
        CapabilityTag, Ir3Instruction, Ir3Module, IrErrorCode, IrSchemaVersion, RegRange,
        verify_ir3_specialization,
    };

    let mut module = Ir3Module::new(ContentHash::compute(b"export-linkage"), "linkage.mjs");
    module.constant_pool = vec!["exported".into(), "local".into()];
    module.instructions = vec![
        Ir3Instruction::LoadInt { dst: 0, value: 7 },
        Ir3Instruction::ExportBinding {
            name_pool_index: 0,
            src: 0,
            local_name_pool_index: None,
            namespace_reexport: false,
        },
        Ir3Instruction::Halt,
    ];
    verify_ir3_specialization(&module).expect("current synthetic exports remain valid");
    let synthetic_hash = module.content_hash();
    if let Ir3Instruction::ExportBinding {
        local_name_pool_index,
        ..
    } = &mut module.instructions[1]
    {
        *local_name_pool_index = Some(1);
    }
    let local_hash = module.content_hash();
    assert_ne!(synthetic_hash, local_hash);
    if let Ir3Instruction::ExportBinding {
        namespace_reexport, ..
    } = &mut module.instructions[1]
    {
        *namespace_reexport = true;
    }
    assert_ne!(local_hash, module.content_hash());
    if let Ir3Instruction::ExportBinding {
        local_name_pool_index,
        ..
    } = &mut module.instructions[1]
    {
        *local_name_pool_index = Some(99);
    }
    assert_eq!(
        verify_ir3_specialization(&module).unwrap_err().code,
        IrErrorCode::InvalidSpecializationLinkage
    );

    module.instructions[1] = Ir3Instruction::ExportBinding {
        name_pool_index: 0,
        src: 0,
        local_name_pool_index: None,
        namespace_reexport: false,
    };
    module.instructions.insert(
        1,
        Ir3Instruction::HostCall {
            capability: CapabilityTag("console:log".to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
    );
    let current_module = module.clone();
    module.header.schema_version = IrSchemaVersion {
        major: 0,
        minor: 18,
        patch: 0,
    };
    let error =
        verify_ir3_specialization(&module).expect_err("old exports require regenerated linkage");
    assert_eq!(error.code, IrErrorCode::SchemaVersionMismatch);
    assert!(error.message.contains("regenerate or re-lower"));
    for mut config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
        ]
        .into_iter()
        .collect();
        let mut current = InterpreterCore::new(config.clone(), "current-export");
        let result = current
            .execute(&current_module)
            .expect("current synthetic artifact actually executes");
        assert_eq!(result.console_output.len(), 1);
        assert_eq!(result.console_output[0].message, "7");
        let mut core = InterpreterCore::new(config, "old-export");
        let error = core
            .execute(&module)
            .expect_err("direct execution also rejects old exports");
        assert!(error.to_string().contains("regenerate or re-lower"));
        assert!(core.console_output().is_empty());
    }
    module.instructions = vec![Ir3Instruction::Halt];
    verify_ir3_specialization(&module).expect("old non-export IR remains accepted");
}

/// Two direct namespace re-exports denote the same distinguished source
/// namespace binding, even though each has a separate lowering temporary.
/// This expectation follows ES2020 ResolveExport step 7.a.ii.2, which returns
/// (importedModule, "*namespace*") for both paths:
/// https://tc39.es/ecma262/2020/#sec-resolveexport
/// Node v24.22.1 rejects this graph as ambiguous, so it is not this test's oracle.
#[test]
fn namespace_reexport_diamond_uses_source_namespace_identity() {
    assert_output(
        &[
            (
                "lib/source.mjs",
                "export let value = 1; export function bump() { value++; }",
            ),
            ("lib/left.mjs", "export * as shared from './source.mjs';"),
            ("lib/right.mjs", "export * as shared from './source.mjs';"),
            (
                "lib/index.mjs",
                "export * from './left.mjs'; export * from './right.mjs';",
            ),
            (
                "app.mjs",
                "import { shared } from './lib/index.mjs'; import * as source from './lib/source.mjs'; console.log(shared === source, shared.value); source.bump(); console.log(shared.value);",
            ),
        ],
        &["true 1", "2"],
    );
}

/// Under the ES2020 module contract, an imported namespace re-export is a
/// local binding. Its value equals a direct namespace re-export's value,
/// but the two bindings must still conflict. (ES2026 changes this rule.)
#[test]
fn namespace_import_reexport_retains_local_binding_identity() {
    assert_output(
        &[
            ("lib/source.mjs", "export const value = 1;"),
            ("lib/left.mjs", "export * as shared from './source.mjs';"),
            (
                "lib/right.mjs",
                "import * as namespace from './source.mjs'; export { namespace as shared };",
            ),
            (
                "lib/index.mjs",
                "export * from './left.mjs'; export * from './right.mjs';",
            ),
            (
                "app.mjs",
                "import * as index from './lib/index.mjs'; import { shared as left } from './lib/left.mjs'; import { shared as right } from './lib/right.mjs'; console.log(left === right, 'shared' in index);",
            ),
        ],
        &["true false"],
    );
}

/// An explicit indirect export wins over both star sources, independent of
/// the declaration's source order and the sources' equal current values.
#[test]
fn explicit_named_reexport_shadows_ambiguous_star_sources() {
    assert_output(
        &[
            ("lib/left.mjs", "export let value = 1;"),
            ("lib/right.mjs", "export let value = 1;"),
            (
                "lib/owner.mjs",
                "export let own = 7; export function bump() { own++; }",
            ),
            (
                "lib/index.mjs",
                "export * from './left.mjs'; export * from './right.mjs'; export { own as value, bump } from './owner.mjs';",
            ),
            (
                "app.mjs",
                "import { value, bump } from './lib/index.mjs'; console.log(value); bump(); console.log(value);",
            ),
        ],
        &["7", "8"],
    );
}

/// The cycle installs its star edge before the source lexical declaration
/// runs. Initial publication and later mutation must both reach that edge.
#[test]
fn cyclic_star_reexport_discovers_late_lexical_binding() {
    assert_output(
        &[
            (
                "lib/source.mjs",
                "import * as loop from './loop.mjs'; export let value = 1; export function bump() { value++; } export function readLoop() { return loop.value; }",
            ),
            ("lib/loop.mjs", "export * from './source.mjs';"),
            (
                "app.mjs",
                "import { value, bump, readLoop } from './lib/source.mjs'; import * as loop from './lib/loop.mjs'; console.log(value, loop.value, readLoop()); bump(); console.log(value, loop.value, readLoop());",
            ),
        ],
        &["1 1 1", "2 2 2"],
    );
}

/// A later source makes a provisional name ambiguous. All downstream
/// namespaces in a star cycle must withdraw it, including a second hop.
#[test]
fn star_ambiguity_withdraws_transitively_through_cycles() {
    assert_output(
        &[
            (
                "lib/left.mjs",
                "export const duplicate = 1; export const left = 'left';",
            ),
            (
                "lib/right.mjs",
                "export const duplicate = 1; export const right = 'right';",
            ),
            (
                "lib/index.mjs",
                "export * from './left.mjs'; export * from './loop.mjs'; export * from './right.mjs';",
            ),
            (
                "lib/loop.mjs",
                "export * from './index.mjs'; export * from './tail.mjs';",
            ),
            ("lib/tail.mjs", "export * from './loop.mjs';"),
            (
                "app.mjs",
                "import * as index from './lib/index.mjs'; import * as loop from './lib/loop.mjs'; import * as tail from './lib/tail.mjs'; console.log('duplicate' in index, 'duplicate' in loop, 'duplicate' in tail); console.log(Object.keys(index).sort().join(','), Object.keys(loop).sort().join(','), Object.keys(tail).sort().join(','));",
            ),
        ],
        &["false false false", "left,right left,right left,right"],
    );
}

/// Minified star exports (no spaces) as bundlers emit them.
#[test]
fn minified_star_exports() {
    assert_output(
        &[
            (
                "lib/index.mjs",
                "export*from'./a.mjs';export*as B from\"./b.mjs\"\n",
            ),
            (
                "app.mjs",
                "import{a,B}from'./lib/index.mjs';console.log(a,B.b,B.f())\n",
            ),
        ],
        &["1 2 f"],
    );
}

/// bd-9vouw.218: a named import or export list may end with one comma, as
/// prettier lays out every multi-line list (`import {\n  a,\n  b,\n} from`);
/// the parser read the trailing comma as an empty entry, so date-fns 4 and
/// superjson did not parse. Expected line is Node v22.2.0's output.
#[test]
fn named_import_and_export_lists_take_a_trailing_comma_bd_9vouw_218() {
    assert_output(
        &[
            (
                "lib/c.mjs",
                "const x = 1, y = 2;\nexport {\n  x,\n  y as why,\n};\nexport { a as aa, } from './a.mjs';\n",
            ),
            (
                "app.mjs",
                "import {\n  x,\n  why,\n  aa,\n} from './lib/c.mjs';\nimport A, { a, } from './lib/a.mjs';\nimport { b, f, } from './lib/b.mjs';\nconsole.log(x, why, aa, A, a, b, f());\n",
            ),
        ],
        &["1 2 1 A 1 2 f"],
    );
}

/// bd-9vouw.222: an importer sees the value the exporting module's own
/// evaluation left in an exported binding, not the one it had where the
/// export clause stands: TypeScript namespaces (`export var util;
/// (function (util) { ... })(util || (util = {}));`, zod 3's ESM build), later
/// assignments, loops, destructuring and `??=`, through named imports and
/// the namespace object. They were undefined. Writes after the module has
/// evaluated are still not visible (full live bindings: BRIDGE-17.1).
/// Expected line is Node v22.2.0's output.
#[test]
fn exports_carry_the_values_the_module_assigned_bd_9vouw_222() {
    assert_output(
        &[
            (
                "lib/ns.mjs",
                "export var u;\n(function (u) { u.a = 1; })(u || (u = {}));\nexport var w;\nw = { b: 2 };\nexport var y;\nfor (y = 0; y < 3; y++);\nexport var z;\n[z] = [7];\nexport var q;\n({ q } = { q: 8 });\nexport var r;\nr ??= 9;\nlet hidden = 'h0';\nhidden = 'h1';\nexport { hidden as renamed };\n",
            ),
            (
                "app.mjs",
                "import { u, w, y, z, q, r, renamed } from './lib/ns.mjs';\nimport * as all from './lib/ns.mjs';\nconsole.log(typeof u, u.a, w.b, y, z, q, r, renamed, all.w.b, all.renamed);\n",
            ),
        ],
        &["object 1 2 3 7 8 9 h1 2 h1"],
    );
}
