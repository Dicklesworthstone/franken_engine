#![forbid(unsafe_code)]
//! Run with `--release --test js_string_hotpath_bench -- --ignored --nocapture`.
//! This file uses only pre-existing public APIs so the identical benchmark can
//! be copied to an unmodified worktree. It is not an engine-vs-V8 comparison.

use std::hint::black_box;
use std::time::Instant;

use frankenengine_core::js_string::JsString;

fn measure(name: &str, units: usize, iterations: usize, mut operation: impl FnMut() -> usize) {
    for _ in 0..8 {
        black_box(operation());
    }
    let start = Instant::now();
    let mut checksum = 0_usize;
    for _ in 0..iterations {
        checksum = checksum.wrapping_add(black_box(operation()));
    }
    let elapsed = start.elapsed();
    black_box(checksum);
    println!(
        "{}",
        serde_json::json!({
            "benchmark": name,
            "units": units,
            "iterations": iterations,
            "elapsed_ns": elapsed.as_nanos(),
            "ns_per_operation": elapsed.as_nanos() as f64 / iterations as f64,
            "checksum": checksum,
        })
    );
}

#[test]
#[ignore = "release-mode comparative microbenchmark; no timing assertions in CI"]
fn string_hotpath_matrix() {
    // Record constructor overhead too: eager metadata trades a construction
    // scan and one usize per JsString for constant-time repeated reads.
    println!(
        "{}",
        serde_json::json!({"js_string_size_bytes": std::mem::size_of::<JsString>()})
    );
    for size in [64, 4096, 16384] {
        let ascii = "a".repeat(size);
        let unicode_source = "😀".repeat(size / 2);
        let text = JsString::from(ascii.as_str());
        let unicode = JsString::from(unicode_source.as_str());
        let suffix = JsString::from("needle");
        let searchable = JsString::from(format!("{ascii}needle"));
        let unicode_suffix = JsString::from("é中😀");
        let unicode_searchable = JsString::from(format!("{unicode_source}é中😀"));
        let mut exact_units = vec![0x61; size];
        exact_units[size - 1] = 0xd800;
        let exact = JsString::from_code_units(&exact_units);
        let empty = JsString::empty();
        measure("construct_ascii", size, 1024, || {
            black_box(JsString::from(black_box(ascii.as_str()))).len()
        });
        measure("construct_unicode", size, 1024, || {
            black_box(JsString::from(black_box(unicode_source.as_str()))).len()
        });
        measure("clone", size, 4096, || {
            black_box(black_box(&text).clone()).len()
        });
        measure("length_ascii", size, 4096, || black_box(&text).utf16_len());
        measure("length_unicode", size, 4096, || {
            black_box(&unicode).utf16_len()
        });
        measure("iterator_count_unicode", size, 4096, || {
            black_box(&unicode).encode_utf16().count()
        });
        let mut index = 0;
        measure("random_index_ascii", size, 4096, || {
            index = (index + 127) % size;
            usize::from(
                black_box(&text)
                    .encode_utf16()
                    .nth(black_box(index))
                    .unwrap(),
            )
        });
        measure("random_index_exact", size, 4096, || {
            index = (index + 127) % size;
            usize::from(
                black_box(&exact)
                    .encode_utf16()
                    .nth(black_box(index))
                    .unwrap(),
            )
        });
        measure("sequential_units_ascii", size, 128, || {
            black_box(&text)
                .encode_utf16()
                .fold(0_usize, |acc, unit| acc.wrapping_add(usize::from(unit)))
        });
        measure("suffix_index_of", size, 1024, || {
            black_box(&searchable)
                .utf16_index_of(black_box(&suffix), 0)
                .unwrap()
        });
        measure("suffix_last_index_of", size, 1024, || {
            black_box(&searchable)
                .utf16_last_index_of(black_box(&suffix), usize::MAX)
                .unwrap()
        });
        measure("unicode_suffix_index_of", size, 1024, || {
            black_box(&unicode_searchable)
                .utf16_index_of(black_box(&unicode_suffix), 0)
                .unwrap()
        });
        measure("unicode_suffix_last_index_of", size, 1024, || {
            black_box(&unicode_searchable)
                .utf16_last_index_of(black_box(&unicode_suffix), usize::MAX)
                .unwrap()
        });
        measure("unicode_absent_index_of", size, 1024, || {
            usize::from(
                black_box(&unicode)
                    .utf16_index_of(black_box(&unicode_suffix), 0)
                    .is_some(),
            )
        });
        measure("empty_concat", size, 1024, || {
            black_box(black_box(&text).concat(black_box(&empty))).len()
        });
        measure("code_point_elements", size, 16, || {
            black_box(black_box(&text).code_point_elements()).len()
        });
        measure("code_point_elements_unicode", size, 16, || {
            black_box(black_box(&unicode).code_point_elements()).len()
        });
    }
}
