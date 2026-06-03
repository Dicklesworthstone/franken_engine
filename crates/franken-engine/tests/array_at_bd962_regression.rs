//! Regression: Array.prototype.at (ES2022) — element access with negative
//! indices, out-of-range => undefined. Found missing by OliveLake eval-probe;
//! implemented in baseline_interpreter.rs (array_prototype_method seam).
use frankenengine_engine::HybridRouter;
fn ev(s: &str) -> String { let mut e = HybridRouter::default(); match e.eval(s) { Ok(o) => o.value, Err(x) => format!("ERR:{x}") } }
#[test] fn array_at_positive() { assert_eq!(ev("[10,20,30].at(0)"), "10"); }
#[test] fn array_at_negative() { assert_eq!(ev("[10,20,30].at(-1)"), "30"); }
#[test] fn array_at_negative_two() { assert_eq!(ev("[10,20,30].at(-2)"), "20"); }
#[test] fn array_at_out_of_range_high() { assert_eq!(ev("[1,2,3].at(5)"), "undefined"); }
#[test] fn array_at_out_of_range_low() { assert_eq!(ev("[1,2,3].at(-9)"), "undefined"); }
#[test] fn array_at_default_index() { assert_eq!(ev("[7,8].at()"), "7"); }
