use franken_engine_deterministic_derive::Deterministic;

#[derive(Deterministic)]
struct WithF64 {
    value: f64,
}

fn main() {}