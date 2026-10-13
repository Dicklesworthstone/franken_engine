//! bd-9vouw.383: String.prototype.toLocaleLowerCase and toLocaleUpperCase
//! are their own function objects, named for themselves; they map case as
//! toLowerCase/toUpperCase do under the root locale. They were the same
//! functions as toLowerCase/toUpperCase, so their `name` was wrong and
//! `toLocaleLowerCase === toLowerCase` held. The lines are Node v22.2.0's
//! output for the same program.

use frankenengine_engine::HybridRouter;

#[test]
fn string_locale_case_methods_are_distinct_named_functions() {
    let source = r#"
var p = String.prototype;
console.log([p.toLocaleLowerCase.name, p.toLocaleUpperCase.name, p.toLowerCase.name, p.toUpperCase.name, p.toLocaleLowerCase.length, p.toLocaleUpperCase.length].join());
console.log([p.toLocaleLowerCase === p.toLowerCase, p.toLocaleUpperCase === p.toUpperCase, p.toLocaleLowerCase === p.toLocaleLowerCase, "a".toLocaleUpperCase === p.toLocaleUpperCase].join());
console.log(["ÀB".toLocaleLowerCase(), "àb".toLocaleUpperCase("en-US"), p.toLocaleUpperCase.call(12), Object.getOwnPropertyDescriptor(p, "toLocaleLowerCase").value.name].join());
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(
        lines,
        [
            "toLocaleLowerCase,toLocaleUpperCase,toLowerCase,toUpperCase,0,0",
            "false,false,true,true",
            "àb,ÀB,12,toLocaleLowerCase",
        ]
    );
}
