//! The reference fixture is run under Node separately; these tests execute Rust.
use frankenengine_engine::HybridRouter;

#[test]
fn reverse_observes_live_pairs_accessors_prototypes_and_partial_errors() {
    let cases: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/array_storage/sparse_reverse.json"
    )).unwrap();
    for case in cases.as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let outcome = HybridRouter::default().eval(case["source"].as_str().unwrap())
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert_eq!(outcome.value, case["expected"].as_str().unwrap(), "{name}");
    }
}

#[test]
fn maximum_length_reverse_finishes_without_visiting_billions_of_holes() {
    // Specification-derived extreme case; the shared reference fixture uses
    // smaller lengths to keep Node reference execution bounded.
    let source = r#"(()=>{
        const a=[];a.length=4294967295;a[7]='x';a[4294967294]='y';a[2147483647]='middle';
        const r=a.reverse();
        return [r===a,a.length,Object.keys(a).join(','),a[0],a[4294967287],a[2147483647]].join('|');
    })()"#;
    let outcome = HybridRouter::default().eval(source).expect("native sparse reverse");
    assert_eq!(outcome.value, "true|4294967295|0,2147483647,4294967287|y|x|middle");
}

#[test]
fn observable_proxy_pairs_cannot_bypass_or_catch_the_work_budget() {
    let source = r#"(()=>{
        const a=[];a.length=4294967295;
        const p=new Proxy(a,{has(){return false}});
        try{Array.prototype.reverse.call(p)}catch(e){return 'caught'}
        return 'unreachable';
    })()"#;
    let error = HybridRouter::default().eval(source).expect_err("observable holes consume native work");
    assert!(format!("{error:?}").to_ascii_lowercase().contains("budget"), "{error:?}");
}
