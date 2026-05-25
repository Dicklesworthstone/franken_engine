//! PERF-H4.4 (bd-o4cbn.5.4): determinism / byte-identical canonical-encoding tests.
//!
//! Canonical encoding is the load-bearing input to **every** content hash in the
//! project — a 1-byte regression here changes every downstream hash and breaks
//! replay, evidence ledgers, and the claim-matrix bindings. These tests pin the
//! encoded bytes against a committed golden corpus and prove the buffer-reuse
//! paths shipped in bd-o4cbn.5.3 (`encode_value_into` / `EncodeBufferPool`) are
//! byte-identical to the allocating `encode_value` across recursion, dirty
//! buffers, long reuse runs, and separate threads.
//!
//! Goldens live in `tests/golden/deterministic_serde/*.json`, each holding
//! `{ "value": <CanonicalValue>, "expected_sha256_hex": "<hex>" }`. To
//! intentionally regenerate them (e.g. after a deliberate format change), run:
//!
//! ```bash
//! BLESS_GOLDEN=1 cargo test --test deterministic_serde_golden
//! ```
//!
//! API note: the bead draft referenced an aspirational `encode_into_with_buffer`
//! returning `Result`; the shipped API (bd-o4cbn.5.3) is the infallible
//! `encode_value_into(buf, value)` plus the allocating `encode_value(value)`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use frankenengine_engine::deterministic_serde::{
    CanonicalF64, CanonicalValue, EncodeBufferPool, encode_value, encode_value_into,
};
use proptest::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize)]
struct GoldenPair {
    value: CanonicalValue,
    expected_sha256_hex: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn goldens_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/deterministic_serde")
}

fn s(x: &str) -> CanonicalValue {
    CanonicalValue::String(x.to_string())
}

/// Build a left-nested Object chain of the given depth (each level a single-key
/// Map wrapping the previous), terminating in a `"leaf"` string. Used to stress
/// the recursive additive encoder.
fn nested_object(depth: usize) -> CanonicalValue {
    let mut v = s("leaf");
    for i in 0..depth {
        let mut m = BTreeMap::new();
        m.insert(format!("k{i}"), v);
        v = CanonicalValue::Map(m);
    }
    v
}

/// A varied, deterministic value keyed off `i` for reuse/throughput tests.
fn make_test_value(i: usize) -> CanonicalValue {
    let mut m = BTreeMap::new();
    m.insert("id".to_string(), CanonicalValue::U64(i as u64));
    m.insert("name".to_string(), CanonicalValue::String(format!("entry-{i}")));
    m.insert("flag".to_string(), CanonicalValue::Bool(i % 2 == 0));
    m.insert(
        "data".to_string(),
        CanonicalValue::Bytes(vec![i as u8; i % 17]),
    );
    m.insert(
        "score".to_string(),
        CanonicalValue::Float(CanonicalF64::new(i as f64 * 1.5)),
    );
    CanonicalValue::Map(m)
}

/// The hand-authored golden corpus: `(filename, shape)`. Covers trivial values,
/// integer/string/unicode edges, empty/large containers, deep recursion, the
/// canonical key-sort invariant, and a realistic evidence-shaped record.
fn golden_corpus() -> Vec<(&'static str, CanonicalValue)> {
    let array_mixed = CanonicalValue::Array(vec![
        CanonicalValue::Null,
        CanonicalValue::Bool(true),
        CanonicalValue::I64(42),
        s("x"),
    ]);

    let object_single = {
        let mut m = BTreeMap::new();
        m.insert("k".to_string(), s("v"));
        CanonicalValue::Map(m)
    };

    // Keys inserted in a deliberately non-sorted order; the BTreeMap + encoder
    // must emit them in lexicographic order regardless.
    let object_keys_sorted = {
        let mut m = BTreeMap::new();
        for k in ["zeta", "mu", "alpha", "beta"] {
            m.insert(k.to_string(), CanonicalValue::U64(1));
        }
        CanonicalValue::Map(m)
    };

    let array_of_objects = {
        let mut a = BTreeMap::new();
        a.insert("name".to_string(), s("a"));
        a.insert("n".to_string(), CanonicalValue::U64(1));
        let mut b = BTreeMap::new();
        b.insert("name".to_string(), s("b"));
        b.insert("n".to_string(), CanonicalValue::U64(2));
        CanonicalValue::Array(vec![CanonicalValue::Map(a), CanonicalValue::Map(b)])
    };

    let unicode_keys = {
        let mut m = BTreeMap::new();
        m.insert("café".to_string(), s("hot"));
        m.insert("naïve".to_string(), CanonicalValue::Bool(false));
        m.insert("🎷".to_string(), CanonicalValue::U64(9));
        CanonicalValue::Map(m)
    };

    let max_payload = CanonicalValue::String("a".repeat(64 * 1024));

    let real_evidence_entry = {
        let mut m = BTreeMap::new();
        m.insert("schema".to_string(), s("evidence.v1"));
        m.insert("epoch".to_string(), CanonicalValue::U64(7));
        m.insert("verdict".to_string(), s("approved"));
        m.insert("confidence".to_string(), CanonicalValue::I64(950_000));
        m.insert(
            "digest".to_string(),
            CanonicalValue::Bytes((0u8..32).collect()),
        );
        let mut tags = BTreeMap::new();
        tags.insert("lane".to_string(), s("baseline"));
        tags.insert("origin".to_string(), s("hostcall"));
        m.insert("tags".to_string(), CanonicalValue::Map(tags));
        m.insert(
            "trace".to_string(),
            CanonicalValue::Array(vec![CanonicalValue::U64(1), CanonicalValue::U64(2)]),
        );
        CanonicalValue::Map(m)
    };

    vec![
        ("01_null.json", CanonicalValue::Null),
        ("02_bool_true.json", CanonicalValue::Bool(true)),
        ("03_bool_false.json", CanonicalValue::Bool(false)),
        ("04_int_zero.json", CanonicalValue::I64(0)),
        ("05_int_negative.json", CanonicalValue::I64(-1)),
        ("06_int_max.json", CanonicalValue::I64(i64::MAX)),
        ("07_string_empty.json", s("")),
        ("08_string_ascii.json", s("frankenengine")),
        ("09_string_unicode.json", s("naïve café 🎷")),
        ("10_array_empty.json", CanonicalValue::Array(vec![])),
        ("11_array_mixed.json", array_mixed),
        ("12_object_empty.json", CanonicalValue::Map(BTreeMap::new())),
        ("13_object_single.json", object_single),
        ("14_object_nested_depth_5.json", nested_object(5)),
        ("15_object_nested_depth_100.json", nested_object(100)),
        ("16_object_keys_sorted.json", object_keys_sorted),
        ("17_array_of_objects.json", array_of_objects),
        ("18_unicode_keys.json", unicode_keys),
        ("19_max_payload.json", max_payload),
        ("20_real_evidence_entry.json", real_evidence_entry),
    ]
}

fn blessing() -> bool {
    std::env::var("BLESS_GOLDEN").is_ok()
}

fn run_golden(name: &str, value: &CanonicalValue) {
    let buf = encode_value(value);
    let live_hash = sha256_hex(&buf);
    let path = goldens_dir().join(name);

    if blessing() {
        std::fs::create_dir_all(goldens_dir()).expect("create goldens dir");
        let pair = GoldenPair {
            value: value.clone(),
            expected_sha256_hex: live_hash,
        };
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&pair).expect("serialize golden"),
        )
        .expect("write golden");
        return;
    }

    let content = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "missing golden {}; regenerate with BLESS_GOLDEN=1",
            path.display()
        )
    });
    let pair: GoldenPair = serde_json::from_str(&content).expect("parse golden");

    // (a) Encoder stability: the *stored* value must still encode to the stored hash.
    let stored_hash = sha256_hex(&encode_value(&pair.value));
    assert_eq!(
        stored_hash, pair.expected_sha256_hex,
        "canonical encoding for {name} produced an unexpected hash. \
         If intentional, re-run with BLESS_GOLDEN=1; otherwise this is a \
         load-bearing content_hash regression.",
    );
    // (b) Constructor stability: the live in-code shape must match the committed golden.
    assert_eq!(
        live_hash, pair.expected_sha256_hex,
        "live constructor for {name} diverged from the committed golden value",
    );
}

// ---------------------------------------------------------------------------
// 1. Golden corpus byte-identical (regression guard for every content_hash)
// ---------------------------------------------------------------------------

#[test]
fn canonical_encoding_byte_identical_against_golden() {
    for (name, value) in golden_corpus() {
        run_golden(name, &value);
    }

    if !blessing() {
        let count = std::fs::read_dir(goldens_dir())
            .expect("goldens dir must exist")
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("json"))
            .count();
        assert!(count >= 20, "expected at least 20 golden files; found {count}");
    }
}

// ---------------------------------------------------------------------------
// 2. Property test: pool-encoded matches fresh-buffer-encoded
// ---------------------------------------------------------------------------

fn any_canonical_value() -> impl Strategy<Value = CanonicalValue> {
    let leaf = prop_oneof![
        Just(CanonicalValue::Null),
        any::<bool>().prop_map(CanonicalValue::Bool),
        any::<u64>().prop_map(CanonicalValue::U64),
        any::<i64>().prop_map(CanonicalValue::I64),
        any::<f64>().prop_map(|f| CanonicalValue::Float(CanonicalF64::new(f))),
        ".*".prop_map(CanonicalValue::String),
        proptest::collection::vec(any::<u8>(), 0..32).prop_map(CanonicalValue::Bytes),
    ];
    leaf.prop_recursive(4, 48, 6, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..6).prop_map(CanonicalValue::Array),
            proptest::collection::btree_map(".*", inner, 0..6).prop_map(CanonicalValue::Map),
        ]
    })
}

proptest! {
    #[test]
    fn pool_matches_fresh(value in any_canonical_value()) {
        let mut pool = EncodeBufferPool::new();
        let from_pool = pool.encode(&value).to_vec();
        let from_fresh = encode_value(&value);
        prop_assert_eq!(from_pool, from_fresh);
    }
}

// ---------------------------------------------------------------------------
// 3. Dirty-buffer safety
// ---------------------------------------------------------------------------

#[test]
fn dirty_buffer_does_not_leak_into_output() {
    let mut buf = b"prior junk bytes that must be cleared".to_vec();
    let value = s("hello");
    encode_value_into(&mut buf, &value);
    assert_eq!(buf, encode_value(&value), "buffer must be cleared at entry");
}

// ---------------------------------------------------------------------------
// 4. Reentrancy / deep nesting regression (H4.2 corrected this risk)
// ---------------------------------------------------------------------------

#[test]
fn deeply_nested_object_encodes_correctly() {
    let v = nested_object(100);
    let legacy = encode_value(&v);

    // Start with a small capacity so the encode must grow the buffer mid-walk;
    // byte-identity to the legacy path proves growth did not corrupt anything.
    let mut pool = EncodeBufferPool::with_capacity(8);
    let pooled = pool.encode(&v).to_vec();

    assert_eq!(legacy, pooled, "pooled deep-nesting encode diverged");
    assert!(
        pooled.len() > 8,
        "encoded length {} must exceed the initial pool capacity (proves mid-encode growth)",
        pooled.len()
    );
}

// ---------------------------------------------------------------------------
// 5. Sequential reuse correctness (1000 cycles through one pool)
// ---------------------------------------------------------------------------

#[test]
fn sequential_pool_reuse_correctness() {
    let mut pool = EncodeBufferPool::new();
    let values: Vec<CanonicalValue> = (0..50usize).map(make_test_value).collect();
    for _ in 0..1_000 {
        for v in &values {
            let from_pool = pool.encode(v).to_vec();
            assert_eq!(from_pool, encode_value(v), "pool encoding diverged on reuse");
        }
    }
}

// ---------------------------------------------------------------------------
// 6. Cross-version: a hand-pinned byte vector for a known shape.
//    (The broader legacy `deterministic_serde` unit suite also continues to run.)
// ---------------------------------------------------------------------------

#[test]
fn known_shape_has_stable_encoding() {
    // Bool(true) is the simplest tagged value: [TAG_BOOL, 0x01]. Whatever the
    // tag byte is, encoding must be exactly 2 bytes and stable across the two
    // entry points.
    let v = CanonicalValue::Bool(true);
    let a = encode_value(&v);
    let mut buf = Vec::new();
    encode_value_into(&mut buf, &v);
    assert_eq!(a, buf);
    assert_eq!(a.len(), 2, "Bool encodes to tag + 1 payload byte");
    assert_eq!(a[1], 0x01, "true payload byte");
}

// ---------------------------------------------------------------------------
// 7. Concurrent pools on separate threads are independent
// ---------------------------------------------------------------------------

#[test]
fn pools_on_separate_threads_are_independent() {
    use std::thread;
    let handles: Vec<_> = (0..8)
        .map(|tid| {
            thread::spawn(move || {
                let mut pool = EncodeBufferPool::new();
                for i in 0..1_000i64 {
                    let v = CanonicalValue::I64((tid as i64 * 1_000) + i);
                    let from_pool = pool.encode(&v).to_vec();
                    assert_eq!(from_pool, encode_value(&v), "thread pool diverged");
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("thread must not panic");
    }
}
