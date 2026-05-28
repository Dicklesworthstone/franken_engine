#![forbid(unsafe_code)]

use std::path::Path;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};

// golden_diag lives under tests/_support/ (bd-ub6x8.18); pulled in via #[path]
// so cargo does not compile it as a standalone integration-test binary.
#[path = "_support/golden_diag.rs"]
mod golden_diag;

struct LoweringGoldenCase {
    name: &'static str,
    source: &'static str,
    goal: ParseGoal,
}

const UPDATE_GOLDENS_ENV: &str = "UPDATE_GOLDENS";

fn render_lowered_ir3(case: &LoweringGoldenCase) -> String {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse_with_options(case.source, case.goal, &ParserOptions::default())
        .expect("golden lowering source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, format!("golden-lowering-{}.js", case.name));
    let context = LoweringContext::new(
        format!("trace-golden-lowering-{}", case.name),
        format!("decision-golden-lowering-{}", case.name),
        "policy-golden-lowering",
    );
    let output = lower_ir0_to_ir3(&ir0, &context).expect("golden lowering source should lower");

    let mut rendered = String::new();
    rendered.push_str("# franken-engine lowering IR3 golden\n");
    rendered.push_str("# Update with:\n");
    rendered.push_str(
        "#   UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test golden_lowering\n",
    );
    rendered.push_str("# Then review and commit the diff under tests/golden/lowering/.\n");
    rendered.push_str(&format!("case: {}\n", case.name));
    rendered.push_str(&format!("goal: {:?}\n", case.goal));
    rendered.push_str("source:\n");
    for line in case.source.lines() {
        rendered.push_str("  ");
        rendered.push_str(line);
        rendered.push('\n');
    }
    rendered.push('\n');

    rendered.push_str("constant_pool:\n");
    if output.ir3.constant_pool.is_empty() {
        rendered.push_str("  <empty>\n");
    } else {
        for (index, value) in output.ir3.constant_pool.iter().enumerate() {
            // serde_json on String is byte-for-byte the same as Debug for ASCII
            // payloads but uses the stable JSON-escape contract for non-ASCII
            // (bd-ub6x8.9.2: Debug is not a stability contract).
            let encoded = serde_json::to_string(value)
                .expect("String should always serialize via serde_json");
            rendered.push_str(&format!("  [{index:04}] {encoded}\n"));
        }
    }
    rendered.push('\n');

    rendered.push_str("instructions:\n");
    for (index, instruction) in output.ir3.instructions.iter().enumerate() {
        rendered.push_str(&format!(
            "  {index:04}: {}\n",
            render_instruction(instruction)
        ));
    }

    rendered
}

fn render_instruction(instruction: &Ir3Instruction) -> String {
    // Ir3Instruction derives Serialize; the JSON form is the stability
    // contract. The previous `{instruction:?}` rendering coupled all 6
    // lowering goldens to derive(Debug) field order + variant naming, so any
    // unrelated edit to Ir3Instruction's Debug shape would silently break
    // every fixture (bd-ub6x8.9.2).
    serde_json::to_string(instruction)
        .expect("Ir3Instruction derives Serialize, JSON encoding cannot fail")
}

/// Assert IR3 lowering output matches golden file.
/// UPDATE_GOLDENS + read-or-panic + .actual sweep is delegated to
/// golden_diag::GoldenDiag (bd-ub6x8.3).
fn assert_lowering_golden(case: &LoweringGoldenCase) {
    let golden_path = Path::new("tests/golden/lowering").join(format!("{}.txt", case.name));
    let actual = render_lowered_ir3(case);
    golden_diag::GoldenDiag {
        framework_name: "Lowering IR3 golden",
        regen_env_var: UPDATE_GOLDENS_ENV,
    }
    .assert_golden_match(&actual, &golden_path, case.name, None);
}

#[test]
fn golden_lowering_optional_chaining() {
    assert_lowering_golden(&LoweringGoldenCase {
        name: "optional_chaining",
        source: "null?.value;\n",
        goal: ParseGoal::Script,
    });
}

#[test]
fn golden_lowering_nullish_coalescing() {
    assert_lowering_golden(&LoweringGoldenCase {
        name: "nullish_coalescing",
        source: "null ?? 42;\n",
        goal: ParseGoal::Script,
    });
}

#[test]
fn golden_lowering_try_catch() {
    assert_lowering_golden(&LoweringGoldenCase {
        name: "try_catch",
        source: "try { throw 1; } catch (error) { error; }\n",
        goal: ParseGoal::Script,
    });
}

#[test]
fn golden_lowering_async_function() {
    assert_lowering_golden(&LoweringGoldenCase {
        name: "async_function",
        source: "async function load() { return 1; }\n",
        goal: ParseGoal::Script,
    });
}

#[test]
fn golden_lowering_generator_function() {
    assert_lowering_golden(&LoweringGoldenCase {
        name: "generator_function",
        source: "function* gen() { yield 1; }\n",
        goal: ParseGoal::Script,
    });
}

#[test]
fn golden_lowering_for_of_destructuring() {
    assert_lowering_golden(&LoweringGoldenCase {
        name: "for_of_destructuring",
        source: "for (const [first] of pairs) { first; }\n",
        goal: ParseGoal::Script,
    });
}
