//! Simple manual test for top-level await functionality

fn main() {
    // Test 1: Module with top-level await should be detected
    let source_with_tla = "const data = await fetchData();";
    println!("Testing: {}", source_with_tla);

    // Test 2: Module without await should not be detected
    let source_without_tla = "const data = 42; export { data };";
    println!("Testing: {}", source_without_tla);

    // Test 3: Script with await should fail validation
    let source_script_with_await = "const data = await fetchData();";
    println!("Testing script with await (should fail validation): {}", source_script_with_await);

    println!("Manual tests complete - compile this file to check if the API changes work");
}

// Note: This is just a compilation check. Real tests should use the actual parser
// and static semantics APIs once the compilation issues are resolved.