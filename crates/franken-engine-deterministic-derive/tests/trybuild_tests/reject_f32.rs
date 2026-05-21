use franken_engine_deterministic_derive::Deterministic;

#[derive(Deterministic)]
struct WithF32 {
    value: f32,
}

fn main() {}