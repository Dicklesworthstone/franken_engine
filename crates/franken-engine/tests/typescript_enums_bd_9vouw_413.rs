//! bd-9vouw.413: TypeScript enums written across lines (the usual
//! formatting), `const enum`, `declare enum` (erased), merged declarations,
//! members whose initializers name earlier members or follow a computed
//! value, and the reverse mapping of numeric members (`Color[5] ===
//! "Green"`) behave as TypeScript compiles them; the enum object is a
//! plain mutable object. The engine lowered only an enum written on one
//! line, to a frozen object without the reverse mapping, and left the
//! others to fail when run. The line is Bun 1.4.2's for the same file (Node
//! v22.2.0 does not run TypeScript).

use std::process::Command;

fn assert_native_output(source: &str, expected: &[&str]) {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::ir_contract::Ir0Module;
    use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};
    use frankenengine_engine::ts_normalization::prepare_source_entry_for_public_entrypoints;

    let prepared = prepare_source_entry_for_public_entrypoints(
        source,
        "enum-execution.ts",
        "enum-trace",
        "enum-decision",
        "enum-policy",
    )
    .expect("public TypeScript ingestion");
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: prepared.source_label,
                text: prepared.prepared_source,
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("enum output parses as JavaScript");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "enum-execution.ts"),
        &LoweringContext::new("enum-trace", "enum-decision", "enum-policy"),
    )
    .expect("enum program lowers")
    .ir3;
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
        let mut core = InterpreterCore::new(config, "enum-execution");
        let result = core.execute(&module).expect("native enum execution");
        let actual: Vec<&str> = result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect();
        assert_eq!(actual, expected);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn exported_namespace_enums_merge_and_keep_local_identity() {
    assert_native_output(
        r#"
        const events = [];
        namespace App {
            const bias = 2;
            export enum Phase {
                Ready = (events.push(App.Phase === Phase), Math.max(bias, 1)),
                Busy = Ready + 1,
                Shorthand = ({Ready}).Ready,
            }
            export namespace Phase {
                export const description = 'phase'; export const Math = 3;
                export function unqualified() { return Ready; }
            }
            export function local() { return Phase; }
        }
        namespace App { export enum Phase { Done = Busy + 1 } }
        namespace App.Tools { export enum Flag { A = 1, B = 2, Both = A | B } }
        const retained = App.local();
        console.log(App.Phase.Ready, App.Phase.Busy, App.Phase.Done,
                    App.Phase.description, App.Tools.Flag.Both, events.join(','), App.Phase.Shorthand);
        const publicApp: any = App;
        publicApp.Phase = {};
        console.log(App.local() === retained, App.Phase === retained);
        enum State { Ready = 2 }
        namespace State {
            export function read() { return State.Ready; }
            export function unqualified() { return Ready; }
        }
        console.log(State.read());
        try { State.unqualified(); } catch (error) { console.log(error instanceof ReferenceError); }
        try { retained.unqualified(); } catch (error) { console.log(error instanceof ReferenceError); }
    "#,
        &["2 3 4 phase 3 true 2", "true false", "2", "true", "true"],
    );
}

#[test]
fn inline_function_and_block_enums_have_lexical_lifetimes() {
    assert_native_output(
        r#"
        const E = 90; const readers = [];
        function make(seed: number) { enum E { A = seed, B = A + 1 } enum E { C = B + 1 } return E; }
        for (let i = 0; i < 3; i++) {
            enum E { A = i, B = A + 1 }
            readers.push(() => E.B);
        }
        const a = make(4); const b = make(8);
        console.log(E, a.A, a.C, b.C, a === b, readers.map(read => read()).join(','));
        { enum Local { A = 1 } }
        console.log(typeof Local);
    "#,
        &["90 4 6 10 false 1,2,3", "undefined"],
    );
}

#[test]
fn enum_initializers_keep_lexical_shadows_and_hygienic_helpers() {
    assert_native_output(
        r#"
        const __enum = 10, __enum_next = 20, __value = 30, __franken_enum_0 = 40;
        const A = 99;
        const text = 'enum Fake { A }';
        const pattern = /enum Fake { A }/;
        const object = { enum() { return text; } };
        enum Real {
            A = __enum + __enum_next + __value + __franken_enum_0,
            Shadow = ((A: number) => A + 1)(4),
            Captured = (() => A)(),
            Shorthand = ({ A }).A,
            'a-b' = 7,
            '\u0051' = 8,
            Escaped = Q + 1,
        }
        console.log(Real.A, Real.Shadow, Real.Captured, Real.Shorthand,
                    Real['a-b'], Real.Q, Real.Escaped, pattern.test(object.enum()));
    "#,
        &["100 5 100 99 7 8 9 true"],
    );
}

#[test]
fn enum_object_shorthand_keeps_typescripts_ordinary_lexical_lookup() {
    assert_native_output(
        r#"
        let caught = false;
        try { enum E { A = 1, B = ({ A }).A } }
        catch (error) { caught = error instanceof ReferenceError; }
        console.log(caught);
    "#,
        &["true"],
    );
}

#[test]
fn enum_constant_initializers_fold_but_computed_closures_observe_live_members() {
    assert_native_output(
        r#"
        enum Mode {
            A = 1,
            Mask = 1 << 4,
            Changed = ((Mode as any).A = 7),
            Folded = A + 2,
            Qualified = Mode.A + 3,
            Observed = (() => A)(),
            Text = 'mode',
            Alias = Text + '!',
            Duplicate = 16,
        }
        enum Mode { Later = Folded + 2 }
        console.log(Mode.A, Mode.Mask, Mode.Folded, Mode.Qualified, Mode.Observed,
                    Mode.Alias, Mode[16], Mode.Later, Object.isFrozen(Mode));
    "#,
        &["7 16 3 4 7 mode! Duplicate 5 false"],
    );
}

#[test]
fn typescript_enums_lower_to_typescripts_enum_objects() {
    let root = tempfile::tempdir().expect("temp dir");
    let input = root.path().join("enums.ts");
    let report = root.path().join("report.json");
    std::fs::write(
        &input,
        r#"enum Color {
  Red,
  Green = 5,
  Blue, // trailing comment
}
enum Status {
  Active = "active",
  /* block */ Inactive = "inactive",
}
const enum Bits { A = 1 << 0, B = 1 << 1, AB = A | B }
enum E { X, Y }
enum E { Z = 9 }
enum Weird { "a-b" = 1, delete = 2, Weird = 3, c }
declare enum Ambient { Q }
enum Empty { }
enum Expr {
  Len = "abc".length,
  Next,
}
console.log(JSON.stringify([Color.Red, Color.Green, Color.Blue, Color[5], Color[6], Status.Active, Status.Inactive, Bits.AB, E.Y, E[1], E.Z, E[9], Weird["a-b"], Weird.delete, Weird.Weird, Weird.c, Weird[4], typeof Ambient, Object.keys(Empty).length, Expr.Len, Expr.Next, Expr[4], Object.isFrozen(Color)]));
"#,
    )
    .expect("write enums.ts");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            input.to_str().expect("utf8 path"),
            "--extension-id",
            "ts-enums",
            "--out",
            report.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("frankenctl should execute");
    assert!(
        output.status.success(),
        "frankenctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).expect("read report")).expect("json");
    let lines: Vec<&str> = report["console_output"]
        .as_array()
        .expect("console_output")
        .iter()
        .filter_map(|entry| entry["message"].as_str())
        .collect();
    assert_eq!(
        lines,
        [
            "[0,5,6,\"Green\",\"Blue\",\"active\",\"inactive\",3,1,\"Y\",9,\"Z\",1,2,3,4,\"c\",\"undefined\",0,3,4,\"Next\",false]"
        ]
    );
}
