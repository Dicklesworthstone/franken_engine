#![forbid(unsafe_code)]

//! Golden artifact tests for AST and parser output.
//!
//! Covers deterministic parsing of JavaScript/TypeScript source code into
//! canonical AST structures, ensuring parser stability and deterministic
//! compilation pipeline. Tests cover basic expressions, complex statements,
//! declarations, module syntax, JSX/TSX, error recovery, and diagnostic output.

use std::fs;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

// Hoisted scrub patterns (bd-ub6x8.13). The canonical_hash regex is fixed;
// the span-field regex is shared across the 6 span fields by anchoring the
// field name as a capture group instead of formatting one regex per field.
static SCRUB_CANONICAL_HASH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""canonical_hash":\s*"[^"]+""#).unwrap());
static SCRUB_SPAN_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#""(start_offset|end_offset|start_line|start_column|end_line|end_column)":\s*[0-9]+"#,
    )
    .unwrap()
});

use frankenengine_engine::ast::{ParseGoal, SyntaxTree};
use frankenengine_engine::parser::{
    CanonicalEs2020Parser, ParseError, ParserBudget, ParserMode, ParserOptions,
};

// ---------------------------------------------------------------------------
// Test helpers and sample code snippets
// ---------------------------------------------------------------------------

fn sample_parser() -> CanonicalEs2020Parser {
    CanonicalEs2020Parser
}

fn default_parser_options() -> ParserOptions {
    ParserOptions::default()
}

#[allow(dead_code)]
fn budget_limited_options() -> ParserOptions {
    ParserOptions {
        mode: ParserMode::ScalarReference,
        budget: ParserBudget {
            max_source_bytes: 1000,
            max_token_count: 100,
            max_recursion_depth: 10,
        },
    }
}

// ---------------------------------------------------------------------------
// Golden artifact tests for AST parser output
// ---------------------------------------------------------------------------

/// Scrub dynamic values from AST JSON for deterministic comparison.
fn scrub_ast_dynamic_fields(json: &str) -> String {
    let mut scrubbed = SCRUB_CANONICAL_HASH
        .replace_all(json, r#""canonical_hash": "[CANONICAL_HASH]""#)
        .into_owned();
    // Replace every "<span_field>": <int> with "<SPAN_FIELD>": "[<SPAN_FIELD>]"
    // in one pass over the input using a single capture-group regex.
    scrubbed = SCRUB_SPAN_FIELD
        .replace_all(&scrubbed, |caps: &regex::Captures<'_>| {
            let field = &caps[1];
            format!(r#""{field}": "[{}]""#, field.to_uppercase())
        })
        .into_owned();
    scrubbed
}

/// Assert AST structure matches golden file with scrubbed dynamic values.
fn assert_ast_golden(test_name: &str, tree: &SyntaxTree) {
    let golden_path = Path::new("tests/golden/ast_parser").join(format!("{test_name}.golden"));

    let actual = serde_json::to_string_pretty(tree).expect("SyntaxTree should serialize to JSON");

    let scrubbed_actual = scrub_ast_dynamic_fields(&actual);

    // UPDATE MODE: overwrite golden with scrubbed actual output
    if std::env::var("UPDATE_GOLDENS").is_ok() {
        fs::create_dir_all(golden_path.parent().unwrap()).unwrap();
        fs::write(&golden_path, &scrubbed_actual).unwrap();
        eprintln!("[GOLDEN] Updated: {}", golden_path.display());
        return;
    }

    // COMPARE MODE: diff scrubbed actual vs golden
    let expected = fs::read_to_string(&golden_path).unwrap_or_else(|_| {
        panic!(
            "Golden file missing: {}\n\
             Run with UPDATE_GOLDENS=1 to create it\n\
             Then review and commit: git diff tests/golden/ast_parser/",
            golden_path.display()
        )
    });

    if scrubbed_actual != expected {
        let actual_path = golden_path.with_extension("actual");
        fs::write(&actual_path, &scrubbed_actual).unwrap();

        panic!(
            "GOLDEN MISMATCH: {test_name}\n\n\
             Expected: {}\n\
             Actual: {}\n\n\
             To update: UPDATE_GOLDENS=1 cargo test -- {test_name}\n\
             To review: diff {} {}",
            expected,
            scrubbed_actual,
            golden_path.display(),
            actual_path.display(),
        );
    }

    // Sweep any stale .actual sibling left by a prior failing run (bd-ub6x8.7).
    let _ = fs::remove_file(golden_path.with_extension("actual"));
}

/// Assert parse error matches golden file with scrubbed dynamic values.
fn assert_parse_error_golden(test_name: &str, error: &ParseError) {
    let golden_path =
        Path::new("tests/golden/ast_parser").join(format!("{test_name}_error.golden"));

    let actual = serde_json::to_string_pretty(error).expect("ParseError should serialize to JSON");

    let scrubbed_actual = scrub_ast_dynamic_fields(&actual);

    // UPDATE MODE: overwrite golden with scrubbed actual output
    if std::env::var("UPDATE_GOLDENS").is_ok() {
        fs::create_dir_all(golden_path.parent().unwrap()).unwrap();
        fs::write(&golden_path, &scrubbed_actual).unwrap();
        eprintln!("[GOLDEN] Updated: {}", golden_path.display());
        return;
    }

    // COMPARE MODE: diff scrubbed actual vs golden
    let expected = fs::read_to_string(&golden_path).unwrap_or_else(|_| {
        panic!(
            "Golden file missing: {}\n\
             Run with UPDATE_GOLDENS=1 to create it\n\
             Then review and commit: git diff tests/golden/ast_parser/",
            golden_path.display()
        )
    });

    if scrubbed_actual != expected {
        let actual_path = golden_path.with_extension("actual");
        fs::write(&actual_path, &scrubbed_actual).unwrap();

        panic!(
            "GOLDEN MISMATCH: {test_name}\n\n\
             Expected: {}\n\
             Actual: {}\n\n\
             To update: UPDATE_GOLDENS=1 cargo test -- {test_name}\n\
             To review: diff {} {}",
            expected,
            scrubbed_actual,
            golden_path.display(),
            actual_path.display(),
        );
    }

    // Sweep any stale .actual sibling left by a prior failing run (bd-ub6x8.7).
    let _ = fs::remove_file(golden_path.with_extension("actual"));
}

// ---------------------------------------------------------------------------
// Golden test cases covering different AST structures
// ---------------------------------------------------------------------------

#[test]
fn golden_ast_basic_literals() {
    let parser = sample_parser();
    let opts = default_parser_options();
    let source = "42;\n'hello';\ntrue;\nfalse;\nnull;\nundefined;\n";

    let tree = parser
        .parse_with_options(source, ParseGoal::Script, &opts)
        .expect("Should parse basic literals");

    assert_ast_golden("basic_literals", &tree);
}

#[test]
fn golden_ast_binary_expressions() {
    let parser = sample_parser();
    let opts = default_parser_options();
    let source = "1 + 2;\nx * y;\na && b;\nc || d;\ne === f;\ng !== h;\n";

    let tree = parser
        .parse_with_options(source, ParseGoal::Script, &opts)
        .expect("Should parse binary expressions");

    assert_ast_golden("binary_expressions", &tree);
}

#[test]
fn golden_ast_function_declaration() {
    let parser = sample_parser();
    let opts = default_parser_options();
    let source = "function add(a, b) {\n  return a + b;\n}\n";

    let tree = parser
        .parse_with_options(source, ParseGoal::Script, &opts)
        .expect("Should parse function declaration");

    assert_ast_golden("function_declaration", &tree);
}

#[test]
fn golden_ast_variable_declarations() {
    let parser = sample_parser();
    let opts = default_parser_options();
    let source = "var x = 1;\nlet y = 2;\nconst z = 3;\n";

    let tree = parser
        .parse_with_options(source, ParseGoal::Script, &opts)
        .expect("Should parse variable declarations");

    assert_ast_golden("variable_declarations", &tree);
}

#[test]
fn golden_ast_control_flow() {
    let parser = sample_parser();
    let opts = default_parser_options();
    let source = r#"
if (condition) {
  console.log("true");
} else {
  console.log("false");
}

for (let i = 0; i < 10; i++) {
  process(i);
}

while (running) {
  work();
}
"#;

    let tree = parser
        .parse_with_options(source, ParseGoal::Script, &opts)
        .expect("Should parse control flow statements");

    assert_ast_golden("control_flow", &tree);
}

#[test]
fn golden_ast_try_catch_finally() {
    let parser = sample_parser();
    let opts = default_parser_options();
    let source = r#"
try {
  riskyOperation();
} catch (error) {
  handleError(error);
} finally {
  cleanup();
}
"#;

    let tree = parser
        .parse_with_options(source, ParseGoal::Script, &opts)
        .expect("Should parse try/catch/finally");

    assert_ast_golden("try_catch_finally", &tree);
}

#[test]
fn golden_ast_module_import_export() {
    let parser = sample_parser();
    let opts = default_parser_options();
    let source = r#"
import defaultExport from "module-name";
import { export1, export2 } from "module-name";
import { export1 as alias1 } from "module-name";
import * as name from "module-name";

export default function() {}
export { name1, name2 };
export const config = {};
"#;

    let tree = parser
        .parse_with_options(source, ParseGoal::Module, &opts)
        .expect("Should parse module import/export");

    assert_ast_golden("module_import_export", &tree);
}

#[test]
fn golden_ast_class_declaration() {
    let parser = sample_parser();
    let opts = default_parser_options();
    let source = r#"
class Rectangle {
  constructor(width, height) {
    this.width = width;
    this.height = height;
  }

  get area() {
    return this.width * this.height;
  }

  static create(size) {
    return new Rectangle(size, size);
  }
}
"#;

    let tree = parser
        .parse_with_options(source, ParseGoal::Script, &opts)
        .expect("Should parse class declaration");

    assert_ast_golden("class_declaration", &tree);
}

#[test]
fn golden_ast_object_destructuring() {
    let parser = sample_parser();
    let opts = default_parser_options();
    let source = r#"
const { a, b, c = defaultValue } = object;
const [x, y, ...rest] = array;
const { nested: { prop } } = deepObject;
"#;

    let tree = parser
        .parse_with_options(source, ParseGoal::Script, &opts)
        .expect("Should parse object destructuring");

    assert_ast_golden("object_destructuring", &tree);
}

#[test]
fn golden_ast_arrow_functions() {
    let parser = sample_parser();
    let opts = default_parser_options();
    let source = r#"
const simple = x => x * 2;
const withParens = (x, y) => x + y;
const withBody = (x) => {
  const result = x * 2;
  return result;
};
const async = async (x) => await process(x);
"#;

    let tree = parser
        .parse_with_options(source, ParseGoal::Script, &opts)
        .expect("Should parse arrow functions");

    assert_ast_golden("arrow_functions", &tree);
}

#[test]
fn golden_ast_template_literals() {
    let parser = sample_parser();
    let opts = default_parser_options();
    let source = r#"
const basic = `Hello, world!`;
const withVariable = `Hello, ${name}!`;
const multiline = `
  Line 1
  Line 2
  Value: ${value}
`;
"#;

    let tree = parser
        .parse_with_options(source, ParseGoal::Script, &opts)
        .expect("Should parse template literals");

    assert_ast_golden("template_literals", &tree);
}

// ---------------------------------------------------------------------------
// Golden test cases for error conditions
// ---------------------------------------------------------------------------

#[test]
fn golden_parse_error_empty_source() {
    let parser = sample_parser();
    let opts = default_parser_options();

    let error = parser
        .parse_with_options("", ParseGoal::Script, &opts)
        .expect_err("Should fail on empty source");

    assert_parse_error_golden("empty_source", &error);
}

#[test]
fn golden_parse_error_budget_exceeded() {
    let parser = sample_parser();
    let opts = ParserOptions {
        mode: ParserMode::ScalarReference,
        budget: ParserBudget {
            max_source_bytes: 10, // Very small limit
            max_token_count: 100,
            max_recursion_depth: 10,
        },
    };

    let large_source = "const x = 1; const y = 2; const z = 3;"; // Exceeds 10 bytes
    let error = parser
        .parse_with_options(large_source, ParseGoal::Script, &opts)
        .expect_err("Should fail on budget exceeded");

    assert_parse_error_golden("budget_exceeded", &error);
}

// ---------------------------------------------------------------------------
// Unit tests for AST structure consistency
// ---------------------------------------------------------------------------

#[test]
fn ast_canonical_hash_deterministic() {
    let parser = sample_parser();
    let opts = default_parser_options();
    let source = "const x = 42;";

    let tree1 = parser
        .parse_with_options(source, ParseGoal::Script, &opts)
        .unwrap();
    let tree2 = parser
        .parse_with_options(source, ParseGoal::Script, &opts)
        .unwrap();

    assert_eq!(tree1.canonical_hash(), tree2.canonical_hash());
    assert!(tree1.canonical_hash().starts_with("sha256:"));
}

#[test]
fn ast_parse_goal_affects_structure() {
    let parser = sample_parser();
    let opts = default_parser_options();
    let source = "export const x = 42;";

    let script_result = parser.parse_with_options(source, ParseGoal::Script, &opts);
    let module_result = parser.parse_with_options(source, ParseGoal::Module, &opts);

    // Script goal should fail on export
    assert!(script_result.is_err());
    // Module goal should succeed
    let tree = module_result.unwrap();
    assert_eq!(tree.goal, ParseGoal::Module);
}

#[test]
fn ast_serde_roundtrip() {
    let parser = sample_parser();
    let opts = default_parser_options();
    let source = "function test(a, b) { return a + b; }";

    let original = parser
        .parse_with_options(source, ParseGoal::Script, &opts)
        .unwrap();

    let json = serde_json::to_string(&original).unwrap();
    let restored: SyntaxTree = serde_json::from_str(&json).unwrap();

    // Canonical hashes should match after serde roundtrip
    assert_eq!(original.canonical_hash(), restored.canonical_hash());
    assert_eq!(original.goal, restored.goal);
    assert_eq!(original.body.len(), restored.body.len());
}

#[test]
fn ast_complex_nested_structure() {
    let parser = sample_parser();
    let opts = default_parser_options();
    let source = r#"
class ApiClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.interceptors = [];
  }

  async request(method, endpoint, data = null) {
    const url = `${this.baseUrl}/${endpoint}`;
    const options = {
      method,
      headers: { 'Content-Type': 'application/json' },
      ...(data && { body: JSON.stringify(data) })
    };

    try {
      const response = await fetch(url, options);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      return await response.json();
    } catch (error) {
      this.handleError(error);
      throw error;
    }
  }

  handleError(error) {
    console.error('API Error:', error.message);
    this.interceptors.forEach(interceptor => {
      if (interceptor.onError) {
        interceptor.onError(error);
      }
    });
  }
}

export default ApiClient;
"#;

    let tree = parser
        .parse_with_options(source, ParseGoal::Module, &opts)
        .expect("Should parse complex nested structure");

    assert_ast_golden("complex_nested_structure", &tree);
}

#[test]
fn ast_parser_constants_consistency() {
    use frankenengine_engine::ast::{
        CANONICAL_AST_CONTRACT_VERSION, CANONICAL_AST_HASH_ALGORITHM, CANONICAL_AST_HASH_PREFIX,
        CANONICAL_AST_SCHEMA_VERSION,
    };

    let parser = sample_parser();
    let opts = default_parser_options();
    let source = "const test = 42;";

    let tree = parser
        .parse_with_options(source, ParseGoal::Script, &opts)
        .unwrap();

    // Verify constants match tree methods
    assert_eq!(
        SyntaxTree::canonical_contract_version(),
        CANONICAL_AST_CONTRACT_VERSION
    );
    assert_eq!(
        SyntaxTree::canonical_schema_version(),
        CANONICAL_AST_SCHEMA_VERSION
    );
    assert_eq!(
        SyntaxTree::canonical_hash_algorithm(),
        CANONICAL_AST_HASH_ALGORITHM
    );
    assert_eq!(
        SyntaxTree::canonical_hash_prefix(),
        CANONICAL_AST_HASH_PREFIX
    );

    // Verify hash has expected prefix
    assert!(tree.canonical_hash().starts_with(CANONICAL_AST_HASH_PREFIX));
}
