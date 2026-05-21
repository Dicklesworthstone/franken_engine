use franken_engine_deterministic_derive::Deterministic;

#[derive(Deterministic)]
struct WithConstPtr {
    ptr: *const i32,
}

fn main() {}