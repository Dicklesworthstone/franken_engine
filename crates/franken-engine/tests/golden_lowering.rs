#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser, ParserOptions};

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
            rendered.push_str(&format!("  [{index:04}] {value:?}\n"));
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
    format!("{instruction:?}")
}

fn assert_lowering_golden(case: &LoweringGoldenCase) {
    let golden_path = Path::new("tests/golden/lowering").join(format!("{}.txt", case.name));
    let actual = render_lowered_ir3(case);

    if std::env::var_os(UPDATE_GOLDENS_ENV).is_some() {
        fs::create_dir_all(
            golden_path
                .parent()
                .expect("golden path should have a parent"),
        )
        .expect("golden directory should be creatable");
        fs::write(&golden_path, &actual).expect("golden file should be writable");
        eprintln!("[GOLDEN] Updated {}", golden_path.display());
        return;
    }

    let expected = fs::read_to_string(&golden_path).unwrap_or_else(|_| {
        panic!(
            "Golden file missing: {}\n\
             Set {UPDATE_GOLDENS_ENV}=1 and rerun:\n\
             cargo test -p frankenengine-engine --test golden_lowering\n\
             Then review and commit: git diff tests/golden/lowering/\n\n\
             Current output:\n{actual}",
            golden_path.display()
        )
    });

    if actual != expected {
        let actual_path = golden_path.with_extension("actual");
        fs::write(&actual_path, &actual).expect("actual golden output should be writable");
        panic!(
            "GOLDEN MISMATCH: {}\n\
             Expected: {}\n\
             Actual:   {}\n\
             Update with {UPDATE_GOLDENS_ENV}=1 only after reviewing the IR3 diff.",
            case.name,
            golden_path.display(),
            actual_path.display()
        );
    }
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
