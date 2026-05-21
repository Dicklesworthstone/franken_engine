use franken_engine_deterministic_derive::Deterministic;
use std::collections::HashSet;

#[derive(Deterministic)]
struct WithHashSet {
    set: HashSet<i32>,
}

fn main() {}