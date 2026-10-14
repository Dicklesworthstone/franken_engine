//! Core-only before/after microbenchmark; not an end-to-end V8 comparison.
//! Run the same example on the base revision and each patch in --release.

use std::cmp::Ordering;
use std::hint::black_box;
use std::time::Instant;

use frankenengine_core::js_string::JsString;

fn order_code(order: Ordering) -> u64 {
    match order {
        Ordering::Less => 0,
        Ordering::Equal => 1,
        Ordering::Greater => 2,
    }
}

fn measure(
    name: &str,
    inputs: Vec<(JsString, JsString)>,
    expected: u64,
    operation: impl Fn(&JsString, &JsString) -> u64,
) {
    // Every pair was built before the clock starts. Each rope is visited
    // once, so a previous iteration cannot hide its first-read join cost.
    let start = Instant::now();
    for (left, right) in &inputs {
        assert_eq!(black_box(operation(black_box(left), black_box(right))), expected);
    }
    let elapsed = start.elapsed().as_nanos();
    println!(
        "{{\"case\":\"{name}\",\"scope\":\"core_only\",\"iterations\":{},\"elapsed_ns\":{elapsed},\"ns_per_iteration\":{}}}",
        inputs.len(),
        elapsed / inputs.len() as u128,
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rounds = std::env::args()
        .nth(1)
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(64);
    if !(1..=1024).contains(&rounds) {
        return Err("iterations must be in 1..=1024".into());
    }
    let body = JsString::from("x".repeat(1024 * 1024));
    let a = JsString::from("a".repeat(1024));
    let b = JsString::from("b".repeat(1024));
    let fresh = || (0..rounds).map(|_| (a.concat(&body), b.concat(&body))).collect();
    let length = a.utf16_len() + body.utf16_len();

    measure("utf16_count_fresh_rope", fresh(), length as u64, |left, _| {
        left.encode_utf16().count() as u64
    });
    measure("utf16_nth_fresh_rope", fresh(), u64::from(b'x'), |left, _| {
        u64::from(left.encode_utf16().nth(length - 1).expect("last unit"))
    });
    measure("byte_order_early_mismatch", fresh(), 0, |left, right| {
        order_code(left.cmp(right))
    });
    measure("byte_order_shared_root", fresh(), 1, |left, _| {
        order_code(left.cmp(&left.clone()))
    });

    let astral = JsString::from("\u{1f600}".repeat(256));
    let bmp = JsString::from("\u{ff5a}".repeat(512));
    let unicode_pairs = (0..rounds)
        .map(|_| (astral.concat(&body), bmp.concat(&body)))
        .collect();
    measure("utf16_order_early_mismatch", unicode_pairs, 0, |left, right| {
        order_code(left.utf16_cmp(right))
    });

    let expected_sum = (1024 * u64::from(b'a')) + (1024 * 1024 * u64::from(b'x'));
    measure("utf16_fold_complete_rope", fresh(), expected_sum, |left, _| {
        left.encode_utf16().fold(0_u64, |sum, unit| sum + u64::from(unit))
    });

    let flat_a = JsString::from(format!("{}a", "x".repeat(1024 * 1024)));
    let flat_b = JsString::from(format!("{}b", "x".repeat(1024 * 1024)));
    let flat_pairs = (0..rounds).map(|_| (flat_a.clone(), flat_b.clone())).collect();
    measure("flat_order_control", flat_pairs, 0, |left, right| {
        order_code(left.cmp(right))
    });
    Ok(())
}
