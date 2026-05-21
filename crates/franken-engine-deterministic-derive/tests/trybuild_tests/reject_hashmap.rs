use franken_engine_deterministic_derive::Deterministic;
use std::collections::HashMap;

#[derive(Deterministic)]
struct WithHashMap {
    map: HashMap<String, i32>,
}

fn main() {}