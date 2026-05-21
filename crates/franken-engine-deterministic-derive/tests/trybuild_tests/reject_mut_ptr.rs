use franken_engine_deterministic_derive::Deterministic;

#[derive(Deterministic)]
struct WithMutPtr {
    ptr: *mut i32,
}

fn main() {}