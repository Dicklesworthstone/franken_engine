use franken_engine_deterministic_derive::Deterministic;
use std::collections::HashMap;

#[derive(Deterministic)]
struct MultipleViolations {
    float_val: f64,                     // Non-deterministic: f64
    map_val: HashMap<String, i32>,      // Non-deterministic: HashMap
    ptr_val: *const i32,                // Non-deterministic: raw pointer
}

fn main() {}