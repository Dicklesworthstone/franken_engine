use franken_engine_deterministic_derive::Deterministic;
use std::collections::HashMap;

#[derive(Deterministic)]
struct WithNestedHashMap {
    maps: Vec<HashMap<String, i32>>,  // Vec containing HashMap should fail
}

fn main() {}