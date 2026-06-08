//! Diagnostic for bd-g0aok: named function declarations don't bind their own name.
use frankenengine_engine::HybridRouter;
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};

fn ev(src: &str) -> String {
    let mut e = HybridRouter::default();
    match e.eval(src) {
        Ok(o) => format!("OK={}", o.value),
        Err(err) => format!("ERR={err}"),
    }
}

#[test]
fn g0aok_isolation() {
    eprintln!(
        "decl outer call    : {}",
        ev("function f() { return 7; } f();")
    );
    eprintln!(
        "decl self-recursion: {}",
        ev("function f(n) { return n <= 1 ? 1 : n * f(n - 1); } f(5);")
    );
    eprintln!(
        "expr-name recursion: {}",
        ev("let f = function g(n) { return n <= 1 ? 1 : n * g(n - 1); }; f(5);")
    );
    eprintln!("arrow (control)    : {}", ev("let f = (n) => n + 1; f(4);"));
    eprintln!(
        "decl ref after decl: {}",
        ev("function f() { return 7; } let x = f; x();")
    );
}

#[test]
fn g0aok_ir_dump() {
    let src = "function f(n) { return n <= 1 ? 1 : n * f(n - 1); } f(5);";
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let (pr, _ev) = parser.parse_with_event_ir(src, ParseGoal::Script, &opts);
    let tree = pr.expect("parse ok");
    let ir0 = Ir0Module::from_syntax_tree(tree, "g0aok");
    let ctx = LoweringContext::new("t", "d", "p");
    let out = lower_ir0_to_ir3(&ir0, &ctx).expect("lower ok");
    let ir3 = &out.ir3;
    eprintln!("=== function_table ===");
    for (i, f) in ir3.function_table.iter().enumerate() {
        eprintln!(
            "fn[{i}] name={:?} entry={:?} arity={}",
            f.name, f.entry, f.arity
        );
    }
    eprintln!("=== instructions ===");
    for (i, ins) in ir3.instructions.iter().enumerate() {
        eprintln!("{i:4}: {ins:?}");
    }
}
