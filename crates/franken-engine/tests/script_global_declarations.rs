//! Classic Script declarations use the realm's global object record. Lexical
//! declarations, modules, and function locals keep their own environments.

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::InterpreterError;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig, OrchestratorError,
};

fn run(source: &str, goal: ParseGoal) -> Result<Vec<String>, OrchestratorError> {
    let package = ExtensionPackage {
        extension_id: "script-global-declarations".to_string(),
        source: source.to_string(),
        source_file: None,
        module_root: None,
        capabilities: vec!["builtin".to_string()],
        version: "1.0.0".to_string(),
        metadata: Default::default(),
    };
    ExecutionOrchestrator::new(OrchestratorConfig {
        parse_goal: goal,
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
}

fn is_native_type_error(error: &OrchestratorError) -> bool {
    matches!(
        error.primary_error(),
        OrchestratorError::Interpreter(InterpreterError::TypeError { .. })
    )
}

fn assert_script_output(source: &str, expected: &[&str]) {
    let actual =
        run(source, ParseGoal::Script).unwrap_or_else(|error| panic!("Script failed: {error}"));
    assert_eq!(actual, expected);
}

#[test]
fn script_var_and_function_declarations_create_ordinary_global_properties() {
    assert_script_output(
        r#"
console.log(typeof declaredFunction, globalThis.declaredFunction === declaredFunction, globalThis.declaredVar);
var declaredVar = 12;
function declaredFunction() { return declaredVar; }
let lexicalLet = 1;
const lexicalConst = 2;
class LexicalClass {}
const vd = Object.getOwnPropertyDescriptor(globalThis, 'declaredVar');
const fd = Object.getOwnPropertyDescriptor(globalThis, 'declaredFunction');
console.log(globalThis.declaredVar, declaredFunction(), vd.value, vd.writable, vd.enumerable, vd.configurable, 'get' in vd);
console.log(fd.value === declaredFunction, fd.writable, fd.enumerable, fd.configurable, 'get' in fd);
console.log(Object.hasOwn(globalThis, 'lexicalLet'), Object.hasOwn(globalThis, 'lexicalConst'), Object.hasOwn(globalThis, 'LexicalClass'));
console.log(delete globalThis.declaredVar, delete globalThis.declaredFunction);
"#,
        &[
            "function true undefined",
            "12 12 12 true true false false",
            "true true true false false",
            "false false false",
            "false false",
        ],
    );
}

#[test]
fn global_object_and_identifier_writes_are_shared_through_nested_closures() {
    assert_script_output(
        r#"
var counter = 1;
function readCounter() { return counter; }
function makeIncrementer() { return function() { return counter++; }; }
const increment = makeIncrementer();
globalThis.counter = 4;
console.log(counter, readCounter(), increment(), counter, globalThis.counter);
counter += 3;
console.log(globalThis.counter, readCounter());
globalThis.readCounter = function() { return 'replacement'; };
console.log(readCounter());
"#,
        &["4 4 4 5 5", "8 8", "replacement"],
    );
}

#[test]
fn same_named_block_functions_share_one_global_declaration() {
    assert_script_output(
        r#"
console.log(typeof repeated);
try {
    missingDeclaration;
    function repeated() { return 1; }
} catch (error) { console.log(error.name); }
try {
    function repeated() { return 2; }
    console.log(repeated(), globalThis.repeated === repeated);
} catch (error) { console.log(error.name); }
console.log('after');
"#,
        &["undefined", "ReferenceError", "2 true", "after"],
    );
}

#[test]
fn block_vars_hoist_and_shadowed_locals_do_not_alias_global_properties() {
    assert_script_output(
        r#"
console.log(Object.hasOwn(globalThis, 'blockVar'), globalThis.blockVar);
if (true) { var blockVar = 7; }
var shadow = 1;
function localCapture() { let shadow = 20; return () => ++shadow; }
const local = localCapture();
{ let shadow = 30; console.log(shadow); }
console.log(local(), local(), shadow, globalThis.shadow, blockVar);
var shadow;
console.log(shadow, globalThis.shadow);
"#,
        &["true undefined", "30", "21 22 1 1 7", "1 1"],
    );
}

#[test]
fn global_assignments_observe_property_descriptors_and_strict_functions() {
    assert_script_output(
        r#"
var protectedGlobal = 3;
Object.defineProperty(globalThis, 'protectedGlobal', { writable: false });
protectedGlobal = 8;
console.log(protectedGlobal, globalThis.protectedGlobal);
function strictWriter() { 'use strict'; protectedGlobal = 9; }
try { strictWriter(); } catch (error) { console.log(error.name); }
console.log(protectedGlobal, globalThis.protectedGlobal);
var undefined = 7;
console.log(undefined, globalThis.undefined);
"#,
        &["3 3", "TypeError", "3 3", "undefined undefined"],
    );
}

#[test]
fn module_var_and_function_bindings_remain_private() {
    let source = r#"
var moduleVar = 3;
function moduleFunction() { return moduleVar; }
console.log(moduleFunction(), Object.hasOwn(globalThis, 'moduleVar'), Object.hasOwn(globalThis, 'moduleFunction'));
"#;
    assert_eq!(run(source, ParseGoal::Module).unwrap(), ["3 false false"]);
}

#[test]
fn a_function_cannot_replace_a_restricted_global_property() {
    // ES GlobalDeclarationInstantiation throws TypeError when
    // CanDeclareGlobalFunction is false (Node's vm adapter differs here).
    let error = run("function Infinity() {}", ParseGoal::Script)
        .expect_err("a nonconfigurable, nonwritable global rejects a function declaration");
    assert!(error.to_string().contains("TypeError"), "{error}");
}

#[test]
fn script_declarations_of_materialized_globals_use_the_object_record() {
    assert_script_output(
        r#"
var Date;
var Math;
var Promise;
console.log(Date === globalThis.Date, Math === globalThis.Math, Promise === globalThis.Promise);
console.log(new Date(0).constructor === Date, Date.prototype.constructor === Date);
function readMaterializedGlobals() { return [Date, Math, Promise]; }
globalThis.Date = 10;
globalThis.Math = 20;
globalThis.Promise = 30;
console.log(Date, Math, Promise, readMaterializedGlobals().join(','));
Date = 40;
console.log(globalThis.Date, readMaterializedGlobals().join(','));
"#,
        &[
            "true true true",
            "true true",
            "10 20 30 10,20,30",
            "40 40,20,30",
        ],
    );
}

#[test]
fn global_compound_assignment_reads_its_accessor_before_the_rhs() {
    assert_script_output(
        r#"
var Date;
let right = 2;
const log = [];
Object.defineProperty(globalThis, 'Date', {
    get() { right = 10; log.push('get'); return 1; },
    set(value) { log.push('set:' + value); },
    configurable: true
});
console.log(Date += right, log.join(','), right);
"#,
        &["11 get,set:11 10"],
    );
}

#[test]
fn global_logical_assignment_returns_the_saved_value_without_an_extra_get() {
    assert_script_output(
        r#"
var Date;
let reads = 0;
const writes = [];
Object.defineProperty(globalThis, 'Date', {
    get() { reads++; return 1; },
    set(value) { writes.push(value); },
    configurable: true
});
console.log(Date ||= 9, reads, writes.length);
console.log(Date &&= 7, reads, writes.join(','));
Object.defineProperty(globalThis, 'Date', { get() { reads++; return undefined; } });
console.log(Date ??= 8, reads, writes.join(','));
"#,
        &["1 1 0", "7 2 7", "8 3 7,8"],
    );
}

#[test]
fn strict_script_initializers_preserve_exact_directive_semantics() {
    for directive in [
        "'use strict';",
        "/* lead */ 'use strict'\n",
        "'other'; 'use strict';",
    ] {
        let source = format!("{directive} var undefined = 1;");
        let error = run(&source, ParseGoal::Script)
            .expect_err("strict initialization must reject the readonly global");
        assert!(is_native_type_error(&error), "{source}: {error}");
    }
    for prefix in [
        "'use\\x20strict';",
        "('use strict');",
        "'use strict' + '';",
        "var before; 'use strict';",
    ] {
        assert_script_output(
            &format!("{prefix} var undefined = 1; console.log(typeof undefined);"),
            &["undefined"],
        );
    }
}

#[test]
fn strict_initializer_error_checks_reject_a_misleading_reference_error() {
    let error =
        run("notATypeError;", ParseGoal::Script).expect_err("the missing identifier must fail");
    assert!(matches!(
        error.primary_error(),
        OrchestratorError::Interpreter(InterpreterError::UndefinedBinding { name })
            if name == "notATypeError"
    ));
    assert!(error.to_string().contains("TypeError"), "{error}");
    assert!(!is_native_type_error(&error), "{error}");
}

#[test]
fn generated_function_wrapper_and_locals_do_not_become_script_globals() {
    assert_script_output(
        r#"
const created = Function('value', 'var local = value; return local;');
console.log(created(9), Object.hasOwn(globalThis, 'local'), Object.hasOwn(globalThis, 'anonymous'));
"#,
        &["9 false false"],
    );
}

#[test]
fn declared_globals_delete_their_actual_properties_and_typeof_tolerates_removal() {
    assert_script_output(
        r#"
var Math;
var Date;
var kept = 3;
function keptFunction() {}
function removeDate() { return delete Date; }
function localShadow() { var Math = 5; return [delete Math, Math].join(':'); }
console.log(delete Math, typeof Math, Object.hasOwn(globalThis, 'Math'));
console.log(localShadow(), delete kept, kept, delete keptFunction, typeof keptFunction);
console.log(removeDate(), typeof Date, Object.hasOwn(globalThis, 'Date'));
Math = 7;
console.log(Math, globalThis.Math, Object.getOwnPropertyDescriptor(globalThis, 'Math').configurable);
"#,
        &[
            "true undefined false",
            "false:5 false 3 false function",
            "true undefined false",
            "7 7 true",
        ],
    );
}

#[test]
fn strict_class_computed_keys_do_not_change_the_surrounding_script_mode() {
    assert_script_output(
        r#"
var protectedGlobal = 3;
Object.defineProperty(globalThis, 'protectedGlobal', { writable: false });
try { class C { [protectedGlobal = 5]() {} } } catch (error) { console.log(error.name); }
protectedGlobal = 7;
console.log(protectedGlobal, globalThis.protectedGlobal);
"#,
        &["TypeError", "3 3"],
    );
}
