//! A comma sequence or an argument list longer than the 256-register frame:
//! the minified UMD export list of simple-statistics
//! (`r.mean=m,r.median=n,...`, ~150 assignments) and any call with 300
//! literal arguments failed with "register 256 out of bounds (max 256)",
//! because the sequence desugars to a call with one argument per operand and
//! a call staged every argument in a register. Long sequences now nest in
//! chunks, and an argument list over 128 is built as an array and passed like
//! a spread (staged out of band past the frame, bd-9vouw.50). Expected values
//! are Node v22.2.0's output.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value
}

#[test]
fn long_sequences_and_argument_lists_run() {
    let functions: String = (0..300)
        .map(|i| format!("function f{i}(x){{return x+{i};}}\n"))
        .collect();
    let exports = (0..300)
        .map(|i| format!("r.f{i}=f{i}"))
        .collect::<Vec<_>>()
        .join(",");
    let sequence = (0..200)
        .map(|i| format!("log.push({i})"))
        .collect::<Vec<_>>()
        .join(",");
    let arguments = (0..300)
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let source = format!(
        "var out={{}}; (function(r){{{functions}{exports};}})(out);\n\
         var log=[]; var v=({sequence},'last');\n\
         function f(){{ return arguments.length + ':' + arguments[299]; }}\n\
         function C(){{ this.n = arguments.length; }}\n\
         var o={{m:function(){{ return arguments.length; }}}};\n\
         [Object.keys(out).length, out.f299(1), v, log.length, log[0], log[199], \
         f({arguments}), Math.max({arguments}), new C({arguments}).n, o.m({arguments}), \
         o?.m({arguments})].join(' ');"
    );
    assert_eq!(
        eval(&source),
        "300 300 last 200 0 199 300:299 299 300 300 300"
    );
}
