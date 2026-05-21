use franken_engine_deterministic_derive::Deterministic;

#[derive(Deterministic)]
enum WithF64Enum {
    Variant1,
    Variant2(f64),  // This should fail - enum variant contains non-deterministic type
}

fn main() {}