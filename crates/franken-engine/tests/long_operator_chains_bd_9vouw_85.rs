//! Long flat chains of binary, logical, and comma operators (bd-9vouw.85).
//!
//! Flat left-associative chains (`+`, `&&`, `||`, `??`, `,`) must charge the
//! parser recursion budget per nesting level rather than per operator term,
//! traverse left spines iteratively across AST/canonical/static/lowering
//! passes without stack overflow, and reuse registers in O(1) frame width on
//! the fixed 256-register lane. Expected values match Node v22.2.0.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, QuickJsLane};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser_api_stability::parse_script;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn eval_with_budget(source: &str, budget: u64) -> String {
    match HybridRouter::default().eval_with_instruction_budget(source, budget) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(source: &str, node: &str) {
    assert_eq!(eval_to_string(source), node, "must match Node v22.2.0");
}

fn fixed_lane_eval_and_frame(source: &str, instruction_budget: u64) -> (String, u32) {
    let tree = parse_script(source).expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "long_operator_chains_bd_9vouw_85.js");
    let context = LoweringContext::new("chain-trace", "chain-decision", "chain-policy");
    let module = lower_ir0_to_ir3(&ir0, &context)
        .expect("source should lower")
        .ir3;
    let frame_size = module.function_table[0].frame_size;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.instruction_budget = instruction_budget;
    config.granted_capabilities.extend([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]);
    let value = match QuickJsLane::with_config(config).execute(&module, "chain-trace") {
        Ok(result) => result.value.to_string(),
        Err(err) => format!("ERROR: {err}"),
    };
    (value, frame_size)
}

#[test]
fn three_hundred_additions() {
    check(
        r#"const q = 1; String(q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q);"#,
        "300",
    );
}

#[test]
fn three_hundred_string_concatenations() {
    check(
        r#"const s = '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9' + '0' + '1' + '2' + '3' + '4' + '5' + '6' + '7' + '8' + '9'; String([s.length, s.slice(0, 12)]);"#,
        "300,012345678901",
    );
}

#[test]
fn three_hundred_logical_ands() {
    check(
        r#"const t = true; String(t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t && t);"#,
        "true",
    );
}

#[test]
fn mixed_subtraction_and_addition_stay_left_associative() {
    check(
        r#"String(- 1 + 2 - 3 + 4 - 5 + 6 - 7 + 8 - 9 + 10 - 11 + 12 - 13 + 14 - 15 + 16 - 17 + 18 - 19 + 20 - 21 + 22 - 23 + 24 - 25 + 26 - 27 + 28 - 29 + 30 - 31 + 32 - 33 + 34 - 35 + 36 - 37 + 38 - 39 + 40 - 41 + 42 - 43 + 44 - 45 + 46 - 47 + 48 - 49 + 50 - 51 + 52 - 53 + 54 - 55 + 56 - 57 + 58 - 59 + 60 - 61 + 62 - 63 + 64 - 65 + 66 - 67 + 68 - 69 + 70 - 71 + 72 - 73 + 74 - 75 + 76 - 77 + 78 - 79 + 80 - 81 + 82 - 83 + 84 - 85 + 86 - 87 + 88 - 89 + 90 - 91 + 92 - 93 + 94 - 95 + 96 - 97 + 98 - 99 + 100 - 101 + 102 - 103 + 104 - 105 + 106 - 107 + 108 - 109 + 110 - 111 + 112 - 113 + 114 - 115 + 116 - 117 + 118 - 119 + 120 - 121 + 122 - 123 + 124 - 125 + 126 - 127 + 128 - 129 + 130 - 131 + 132 - 133 + 134 - 135 + 136 - 137 + 138 - 139 + 140 - 141 + 142 - 143 + 144 - 145 + 146 - 147 + 148 - 149 + 150 - 151 + 152 - 153 + 154 - 155 + 156 - 157 + 158 - 159 + 160 - 161 + 162 - 163 + 164 - 165 + 166 - 167 + 168 - 169 + 170 - 171 + 172 - 173 + 174 - 175 + 176 - 177 + 178 - 179 + 180 - 181 + 182 - 183 + 184 - 185 + 186 - 187 + 188 - 189 + 190 - 191 + 192 - 193 + 194 - 195 + 196 - 197 + 198 - 199 + 200 - 201 + 202 - 203 + 204 - 205 + 206 - 207 + 208 - 209 + 210 - 211 + 212 - 213 + 214 - 215 + 216 - 217 + 218 - 219 + 220 - 221 + 222 - 223 + 224 - 225 + 226 - 227 + 228 - 229 + 230 - 231 + 232 - 233 + 234 - 235 + 236 - 237 + 238 - 239 + 240 - 241 + 242 - 243 + 244 - 245 + 246 - 247 + 248 - 249 + 250 - 251 + 252 - 253 + 254 - 255 + 256 - 257 + 258 - 259 + 260 - 261 + 262 - 263 + 264 - 265 + 266 - 267 + 268 - 269 + 270 - 271 + 272 - 273 + 274 - 275 + 276 - 277 + 278 - 279 + 280 - 281 + 282 - 283 + 284 - 285 + 286 - 287 + 288 - 289 + 290 - 291 + 292 - 293 + 294 - 295 + 296 - 297 + 298 - 299 + 300);"#,
        "150",
    );
}

#[test]
fn three_hundred_comma_sequence() {
    check(
        r#"let n = 0; const r = (n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1, n = n + 1); String([n, r]);"#,
        "300,300",
    );
}

#[test]
fn nine_hundred_additions() {
    let source = format!("const q = 1; String({});", vec!["q"; 900].join(" + "));
    check(&source, "900");
}

#[test]
fn ten_thousand_term_addition_logical_and_comma_chains_match_node() {
    let add_source = format!("const q = 1; String({});", vec!["q"; 10_000].join(" + "));
    assert_eq!(eval_with_budget(&add_source, 500_000), "10000");
    let (add_fixed, add_frame) = fixed_lane_eval_and_frame(&add_source, 500_000);
    assert_eq!(add_fixed, "10000");
    assert!(
        add_frame <= 256,
        "10,000-term + chain must fit 256-register frame (got {add_frame})"
    );

    let and_source = format!(
        "const t = true; String({});",
        vec!["t"; 10_000].join(" && ")
    );
    assert_eq!(eval_with_budget(&and_source, 500_000), "true");
    let (and_fixed, and_frame) = fixed_lane_eval_and_frame(&and_source, 500_000);
    assert_eq!(and_fixed, "true");
    assert!(
        and_frame <= 256,
        "10,000-term && chain must fit 256-register frame (got {and_frame})"
    );

    let or_source = format!(
        "const f = false; String({} || 'end');",
        vec!["f"; 9_999].join(" || ")
    );
    assert_eq!(eval_with_budget(&or_source, 500_000), "end");
    let (or_fixed, or_frame) = fixed_lane_eval_and_frame(&or_source, 500_000);
    assert_eq!(or_fixed, "end");
    assert!(
        or_frame <= 256,
        "10,000-term || chain must fit 256-register frame (got {or_frame})"
    );

    let comma_source = format!(
        "let n = 0; const r = ({}); String([n, r]);",
        vec!["++n"; 10_000].join(", ")
    );
    assert_eq!(eval_with_budget(&comma_source, 500_000), "10000,10000");
    let (comma_fixed, comma_frame) = fixed_lane_eval_and_frame(&comma_source, 500_000);
    assert_eq!(comma_fixed, "10000,10000");
    assert!(
        comma_frame <= 256,
        "10,000-term comma chain must fit 256-register frame (got {comma_frame})"
    );
}

#[test]
fn logical_and_comma_chains_reuse_registers_and_preserve_short_circuit_semantics() {
    let (_, small_and_frame) = fixed_lane_eval_and_frame(
        &format!("const t = true; String({});", vec!["t"; 10].join(" && ")),
        100_000,
    );
    let (large_and_val, large_and_frame) = fixed_lane_eval_and_frame(
        &format!("const t = true; String({});", vec!["t"; 400].join(" && ")),
        100_000,
    );
    assert_eq!(large_and_val, "true");
    assert_eq!(
        small_and_frame, large_and_frame,
        "flat && chains must keep O(1) register width ({small_and_frame} vs {large_and_frame})"
    );

    let (_, small_comma_frame) = fixed_lane_eval_and_frame(
        &format!(
            "let n = 0; const r = ({}); String([n, r]);",
            vec!["n = n + 1"; 10].join(", ")
        ),
        100_000,
    );
    let (large_comma_val, large_comma_frame) = fixed_lane_eval_and_frame(
        &format!(
            "let n = 0; const r = ({}); String([n, r]);",
            vec!["n = n + 1"; 400].join(", ")
        ),
        100_000,
    );
    assert_eq!(large_comma_val, "400,400");
    assert_eq!(
        small_comma_frame, large_comma_frame,
        "flat comma chains must keep O(1) register width ({small_comma_frame} vs {large_comma_frame})"
    );

    // Planted short-circuit & evaluation-order check: stopping at term 250 must
    // not evaluate terms 251..400, and must return the exact falsy/truthy/non-nullish value.
    let mut terms: Vec<String> = (0..250).map(|_| "(hits++, true)".to_string()).collect();
    terms.push("(hits++, 0)".to_string());
    terms.extend((0..150).map(|_| "(hits++, true)".to_string()));
    let short_and = format!(
        "let hits = 0; const v = {}; String([hits, v]);",
        terms.join(" && ")
    );
    check(&short_and, "251,0");

    let mut or_terms: Vec<String> = (0..250).map(|_| "(hits++, '')".to_string()).collect();
    or_terms.push("(hits++, 'picked')".to_string());
    or_terms.extend((0..150).map(|_| "(hits++, 'late')".to_string()));
    let short_or = format!(
        "let hits = 0; const v = {}; String([hits, v]);",
        or_terms.join(" || ")
    );
    check(&short_or, "251,picked");

    let mut nullish_terms: Vec<String> = (0..250).map(|_| "(hits++, null)".to_string()).collect();
    nullish_terms.push("(hits++, 0)".to_string());
    nullish_terms.extend((0..150).map(|_| "(hits++, 99)".to_string()));
    let short_nullish = format!(
        "let hits = 0; const v = {}; String([hits, v]);",
        nullish_terms.join(" ?? ")
    );
    check(&short_nullish, "251,0");
}

#[test]
fn nesting_past_recursion_budget_still_fails_closed() {
    let nested = format!("String({}1{});", "(".repeat(300), ")".repeat(300));
    let result = eval_to_string(&nested);
    assert!(result.contains("recursion budget exceeded"), "{result}");
}
