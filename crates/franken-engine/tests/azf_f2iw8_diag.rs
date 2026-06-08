//! Diagnostic for bd-f2iw8: default parameters not applied.
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
fn f2iw8_isolation() {
    eprintln!(
        "arrow default, no arg : {}",
        ev("let f = (x = 5) => x; f();")
    );
    eprintln!(
        "arrow default, arg    : {}",
        ev("let f = (x = 5) => x; f(9);")
    );
    eprintln!(
        "fn-decl default, noarg: {}",
        ev("function f(x = 5) { return x; } f();")
    );
    eprintln!(
        "fn-decl plain, arg    : {}",
        ev("function f(x) { return x; } f(7);")
    );
    eprintln!(
        "two defaults          : {}",
        ev("let f = (a = 1, b = 2) => a + b; f();")
    );
    eprintln!(
        "default uses literal   : {}",
        ev("let f = (x = 3 + 4) => x; f();")
    );
}

#[test]
fn f2iw8_ir_dump() {
    let src = "let f = (x = 5) => x; f();";
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let (pr, _ev) = parser.parse_with_event_ir(src, ParseGoal::Script, &opts);
    let tree = pr.expect("parse ok");
    let ir0 = Ir0Module::from_syntax_tree(tree, "f2iw8");
    let ctx = LoweringContext::new("t", "d", "p");
    let out = lower_ir0_to_ir3(&ir0, &ctx).expect("lower ok");
    let ir3 = &out.ir3;
    eprintln!("=== function_table ===");
    for (i, f) in ir3.function_table.iter().enumerate() {
        eprintln!(
            "fn[{i}] name={:?} entry={:?} arity={} frame_size={}",
            f.name, f.entry, f.arity, f.frame_size
        );
    }
    eprintln!("=== instructions ===");
    for (i, ins) in ir3.instructions.iter().enumerate() {
        eprintln!("{i:4}: {ins:?}");
    }
}
