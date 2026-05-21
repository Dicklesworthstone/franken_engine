use franken_engine_deterministic_derive::Deterministic;

// This struct contains f64 and should not be Deterministic
struct NonDeterministicInner {
    value: f64,
}

#[derive(Deterministic)]
struct WithTransitive {
    inner: NonDeterministicInner,  // This should fail because NonDeterministicInner doesn't implement Deterministic
}

fn main() {}