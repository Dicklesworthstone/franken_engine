//! GentleLark probe — hunt for parser-only-fixable ES2017+ syntax gaps while
//! baseline/lowering are contended. Read-only; new file. Run with --nocapture.

use frankenengine_engine::HybridRouter;

fn ev(src: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(src) {
        Ok(o) => o.value,
        Err(e) => {
            let s = format!("{e}");
            format!("ERR: {}", s.split(" [trace_id").next().unwrap_or(&s))
        }
    }
}

#[test]
fn gl_probe() {
    let cases: &[(&str, &str, &str)] = &[
        ("return_seq", "function f(){return 1,2,3;} f()", "3"),
        (
            "throw_seq_caught",
            "let r=0;try{throw (1,2,3);}catch(e){r=e;} r",
            "3",
        ),
        ("logical_and_assign", "let a=1; a&&=5; a", "5"),
        ("logical_or_assign", "let a=0; a||=7; a", "7"),
        ("nullish_assign", "let a=null; a??=9; a", "9"),
        ("nullish_assign_skip", "let a=2; a??=9; a", "2"),
        ("nullish_coalesce", "let a=null; a??3", "3"),
        ("optional_index", "let o={a:[10]}; o?.a?.[0]", "10"),
        (
            "optional_call_undef",
            "let o={}; typeof o.f?.()",
            "undefined",
        ),
        ("exponent", "2**10", "1024"),
        ("exponent_assign", "let a=2; a**=3; a", "8"),
        ("class_getter", "class C{get x(){return 4;}} new C().x", "4"),
        (
            "class_setter",
            "class C{set x(v){this._v=v;} get x(){return this._v;}} let c=new C(); c.x=8; c.x",
            "8",
        ),
        ("class_static_field", "class C{static n=5;} C.n", "5"),
        ("class_instance_field", "class C{n=6;} new C().n", "6"),
        (
            "class_private_field",
            "class C{#n=7; get(){return this.#n;}} new C().get()",
            "7",
        ),
        (
            "class_static_method",
            "class C{static f(){return 11;}} C.f()",
            "11",
        ),
        (
            "generator_method",
            "let o={*g(){yield 1;yield 2;}}; let it=o.g(); it.next().value",
            "1",
        ),
        (
            "class_generator",
            "class C{*g(){yield 9;}} new C().g().next().value",
            "9",
        ),
        (
            "computed_class_method",
            "let k='m'; class C{[k](){return 3;}} new C().m()",
            "3",
        ),
        (
            "trailing_comma_call",
            "function f(a,b){return a+b;} f(1,2,)",
            "3",
        ),
        ("trailing_comma_array", "[1,2,3,].length", "3"),
        (
            "trailing_comma_params",
            "function f(a,b,){return a+b;} f(1,2)",
            "3",
        ),
        (
            "for_of_entries",
            "let s=0; for(const x of [1,2,3]){s+=x;} s",
            "6",
        ),
        (
            "for_in_obj",
            "let s='';for(const k in {a:1,b:2}){s+=k;} s",
            "ab",
        ),
        (
            "spread_obj_literal",
            "let o={a:1}; let p={...o,b:2}; p.a+p.b",
            "3",
        ),
        ("destructure_array_default", "let [a=5,b=6]=[1]; a+b", "7"),
        (
            "destructure_obj_rename",
            "let {a:x,b:y}={a:1,b:2}; x+y",
            "3",
        ),
        ("destructure_nested", "let {a:{b}}={a:{b:9}}; b", "9"),
        (
            "destructure_rest_obj",
            "let {a,...rest}={a:1,b:2,c:3}; rest.b+rest.c",
            "5",
        ),
        (
            "destructure_rest_arr",
            "let [a,...rest]=[1,2,3]; rest.length",
            "2",
        ),
        (
            "default_param_expr",
            "function f(a,b=a*2){return b;} f(3)",
            "6",
        ),
        (
            "arrow_destructure_param",
            "let f=({a,b})=>a+b; f({a:1,b:2})",
            "3",
        ),
        ("arrow_default_param", "let f=(a=10)=>a; f()", "10"),
        ("comma_seq_paren", "let x=(1,2,3); x", "3"),
        (
            "chained_methods",
            "[1,2,3].map(x=>x*2).filter(x=>x>2).reduce((a,b)=>a+b,0)",
            "10",
        ),
        ("template_expr", "let a=2,b=3; `${a+b}`", "5"),
        ("template_nested", "let a=1; `x${`y${a}`}z`", "xy1z"),
        ("void_op", "typeof void 0", "undefined"),
        (
            "comma_in_for",
            "let s=0; for(let i=0,j=3;i<j;i++,j--){s++;} s",
            "2",
        ),
        (
            "labeled_continue",
            "let s=0; outer: for(let i=0;i<3;i++){for(let j=0;j<3;j++){if(j===1)continue outer; s++;}} s",
            "3",
        ),
        ("do_while", "let i=0; do{i++;}while(i<3); i", "3"),
        (
            "switch_fallthrough",
            "let r=0; switch(2){case 1:r+=1;case 2:r+=2;case 3:r+=3;break;default:r+=99;} r",
            "5",
        ),
        ("ternary_assign", "let a=1; let b=a>0?'pos':'neg'; b", "pos"),
        ("new_no_paren", "function F(){this.x=5;} new F().x", "5"),
        ("array_holes", "[1,,3].length", "3"),
        ("unicode_escape_id", "let \\u0061=5; a", "5"),
        (
            "getter_in_obj_computed",
            "let k='v'; let o={get [k](){return 8;}}; o.v",
            "8",
        ),
    ];
    let mut fails = Vec::new();
    for (name, src, expect) in cases {
        let got = ev(src);
        let ok = &got == expect || (expect.contains("or") && expect.contains(&got));
        if !ok {
            println!("FAIL {name}: got [{got}] want [{expect}]  src=`{src}`");
            fails.push(*name);
        } else {
            println!("ok   {name} = {got}");
        }
    }
    println!("\n=== {} FAILS / {} cases ===", fails.len(), cases.len());
    for f in &fails {
        println!("  FAIL: {f}");
    }
}
