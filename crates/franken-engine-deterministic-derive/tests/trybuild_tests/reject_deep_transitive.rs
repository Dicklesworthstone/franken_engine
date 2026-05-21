use franken_engine_deterministic_derive::Deterministic;

// Deep transitive containment chain
struct Level3NonDeterministic {
    value: f64,
}

struct Level2Container {
    inner: Level3NonDeterministic,
}

struct Level1Container {
    inner: Level2Container,
}

#[derive(Deterministic)]
struct RootContainer {
    data: Level1Container,  // This should fail due to deep transitive non-deterministic containment
}

fn main() {}