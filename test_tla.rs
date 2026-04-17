use frankenengine_engine::{parser, ast::ParseGoal};

fn main() {
    // Test parsing top-level await in module context
    let source = "const data = await fetchData();";

    println!("Testing top-level await parsing...");

    let result = parser::parse(source, ParseGoal::Module);
    match result {
        Ok(tree) => {
            println!("✓ Parsed successfully as module!");
            println!("AST: {:#?}", tree);
        }
        Err(e) => {
            println!("✗ Parse failed: {:#?}", e);
        }
    }

    // Test same code as script (should fail)
    println!("\nTesting same code as script...");
    let result_script = parser::parse(source, ParseGoal::Script);
    match result_script {
        Ok(tree) => {
            println!("✓ Parsed as script (unexpected!)");
            println!("AST: {:#?}", tree);
        }
        Err(e) => {
            println!("✗ Parse failed as script: {:#?}", e);
        }
    }
}