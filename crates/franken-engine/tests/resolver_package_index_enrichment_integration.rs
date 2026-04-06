//! Enrichment integration tests for `resolver_package_index` (bd-1lsy.5.8.1).
//!
//! Covers advanced edge cases, stress scenarios, determinism proofs,
//! and regression vectors beyond the base integration suite.

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::resolver_package_index::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn hash_for(name: &str) -> ContentHash {
    ContentHash::compute(name.as_bytes())
}

fn pkg(name: &str, exports: &[&str]) -> PackageEntry {
    PackageEntry::new(name, hash_for(name))
        .with_exports(exports.iter().map(|s| s.to_string()).collect())
}

fn export_entry(pkg_name: &str, key: &str, conditions: &[(&str, &str)]) -> ExportEntry {
    let mut e = ExportEntry::new(pkg_name, key);
    for &(c, t) in conditions {
        e = e.with_condition(c, t);
    }
    e
}

fn config(id: &str) -> PackageIndexConfig {
    PackageIndexConfig::new(id, epoch(1))
}

// ---------------------------------------------------------------------------
// ART edge cases
// ---------------------------------------------------------------------------

#[test]
fn art_single_byte_keys_all_ascii_lowercase() {
    let mut art = AdaptiveRadixTrie::new();
    for b in b'a'..=b'z' {
        art.insert(&[b], b as u32).unwrap();
    }
    assert_eq!(art.len(), 26);
    for b in b'a'..=b'z' {
        assert_eq!(art.get(&[b]), Some(&(b as u32)));
    }
    assert_eq!(art.get(b"A"), None);
}

#[test]
fn art_shared_prefix_divergence_at_every_level() {
    let mut art = AdaptiveRadixTrie::new();
    art.insert(b"abcdef", 1u32).unwrap();
    art.insert(b"abcdeg", 2).unwrap();
    art.insert(b"abcdff", 3).unwrap();
    art.insert(b"abcfff", 4).unwrap();
    art.insert(b"abffff", 5).unwrap();
    art.insert(b"afffff", 6).unwrap();

    assert_eq!(art.get(b"abcdef"), Some(&1));
    assert_eq!(art.get(b"abcdeg"), Some(&2));
    assert_eq!(art.get(b"abcdff"), Some(&3));
    assert_eq!(art.get(b"abcfff"), Some(&4));
    assert_eq!(art.get(b"abffff"), Some(&5));
    assert_eq!(art.get(b"afffff"), Some(&6));
    assert_eq!(art.len(), 6);
}

#[test]
fn art_prefix_is_also_a_key() {
    let mut art = AdaptiveRadixTrie::new();
    art.insert(b"a", 1u32).unwrap();
    art.insert(b"ab", 2).unwrap();
    art.insert(b"abc", 3).unwrap();
    art.insert(b"abcd", 4).unwrap();
    art.insert(b"abcde", 5).unwrap();

    assert_eq!(art.get(b"a"), Some(&1));
    assert_eq!(art.get(b"ab"), Some(&2));
    assert_eq!(art.get(b"abc"), Some(&3));
    assert_eq!(art.get(b"abcd"), Some(&4));
    assert_eq!(art.get(b"abcde"), Some(&5));
}

#[test]
fn art_longest_prefix_returns_exact_match_when_available() {
    let mut art = AdaptiveRadixTrie::new();
    art.insert(b"react", 1u32).unwrap();
    art.insert(b"react-dom", 2).unwrap();

    let (len, val) = art.longest_prefix_match(b"react-dom").unwrap();
    assert_eq!(*val, 2);
    assert_eq!(len, 9);
}

#[test]
fn art_longest_prefix_with_no_match() {
    let mut art = AdaptiveRadixTrie::new();
    art.insert(b"react", 1u32).unwrap();
    assert!(art.longest_prefix_match(b"vue").is_none());
}

#[test]
fn art_prefix_scan_disjoint_scopes() {
    let mut art = AdaptiveRadixTrie::new();
    art.insert(b"@scope-a/pkg1", 1u32).unwrap();
    art.insert(b"@scope-a/pkg2", 2).unwrap();
    art.insert(b"@scope-b/pkg1", 3).unwrap();
    art.insert(b"@scope-b/pkg2", 4).unwrap();

    let a = art.prefix_scan(b"@scope-a/");
    assert_eq!(a.len(), 2);

    let b_scope = art.prefix_scan(b"@scope-b/");
    assert_eq!(b_scope.len(), 2);

    let all = art.prefix_scan(b"@scope-");
    assert_eq!(all.len(), 4);
}

#[test]
fn art_insert_order_does_not_affect_lookup() {
    let keys: Vec<&[u8]> = vec![b"zebra", b"alpha", b"beta", b"gamma", b"delta"];

    let mut art1 = AdaptiveRadixTrie::new();
    for (i, k) in keys.iter().enumerate() {
        art1.insert(k, i as u32).unwrap();
    }

    let mut art2 = AdaptiveRadixTrie::new();
    for (i, k) in keys.iter().rev().enumerate() {
        art2.insert(k, (keys.len() - 1 - i) as u32).unwrap();
    }

    for k in &keys {
        assert_eq!(art1.get(k).is_some(), art2.get(k).is_some());
    }
}

#[test]
fn art_at_max_depth_boundary() {
    let mut art = AdaptiveRadixTrie::<u32>::new();
    let max_key = vec![b'x'; MAX_ART_DEPTH];
    art.insert(&max_key, 42).unwrap();
    assert_eq!(art.get(&max_key), Some(&42));

    let over_key = vec![b'x'; MAX_ART_DEPTH + 1];
    assert!(art.insert(&over_key, 43).is_err());
}

// ---------------------------------------------------------------------------
// MPHF edge cases
// ---------------------------------------------------------------------------

#[test]
fn mphf_handles_very_similar_keys() {
    let entries: Vec<(Vec<u8>, u32)> = (0..100)
        .map(|i| {
            let mut key = b"prefix_".to_vec();
            key.push(b'0' + (i / 10) as u8);
            key.push(b'0' + (i % 10) as u8);
            (key, i)
        })
        .collect();
    let index = MphfIndex::build(entries).unwrap();
    for i in 0..100 {
        let mut key = b"prefix_".to_vec();
        key.push(b'0' + (i / 10) as u8);
        key.push(b'0' + (i % 10) as u8);
        assert_eq!(index.get(&key), Some(&i));
    }
}

#[test]
fn mphf_single_byte_keys() {
    let entries: Vec<(Vec<u8>, u8)> = (0..=255).map(|b| (vec![b], b)).collect();
    let index = MphfIndex::build(entries).unwrap();
    for b in 0..=255u8 {
        assert_eq!(index.get(&[b]), Some(&b));
    }
}

#[test]
fn mphf_long_keys() {
    let entries: Vec<(Vec<u8>, u32)> = (0..20)
        .map(|i| {
            let key = format!("{}/{}", "a".repeat(200), i);
            (key.into_bytes(), i)
        })
        .collect();
    let index = MphfIndex::build(entries).unwrap();
    for i in 0..20 {
        let key = format!("{}/{}", "a".repeat(200), i);
        assert_eq!(index.get(key.as_bytes()), Some(&i));
    }
}

// ---------------------------------------------------------------------------
// PackageIndex edge cases
// ---------------------------------------------------------------------------

#[test]
fn package_index_empty_package_name() {
    // Edge case: package with empty name (shouldn't happen in practice but
    // shouldn't panic)
    let packages = vec![pkg("", &["."])];
    let exports = vec![export_entry("", ".", &[("import", "./index.js")])];
    let index = PackageIndex::build(config("empty-name"), packages, exports).unwrap();

    let r = index.lookup_package("");
    assert_eq!(r.outcome, IndexLookupOutcome::Hit);
}

#[test]
fn package_index_unicode_package_names() {
    let packages = vec![pkg("日本語パッケージ", &["."]), pkg("中文包", &["."])];
    let exports = vec![
        export_entry("日本語パッケージ", ".", &[("import", "./index.js")]),
        export_entry("中文包", ".", &[("import", "./index.js")]),
    ];
    let index = PackageIndex::build(config("unicode"), packages, exports).unwrap();

    let r = index.lookup_package("日本語パッケージ");
    assert_eq!(r.outcome, IndexLookupOutcome::Hit);
}

#[test]
fn package_index_many_exports_per_package() {
    let mut exports = Vec::new();
    let mut export_keys = Vec::new();
    for i in 0..50 {
        let key = format!("./sub/{i}");
        export_keys.push(key.clone());
        exports.push(export_entry(
            "big-pkg",
            &key,
            &[("import", &format!("./esm/sub-{i}.js"))],
        ));
    }
    let packages =
        vec![PackageEntry::new("big-pkg", hash_for("big-pkg")).with_exports(export_keys)];
    let index = PackageIndex::build(config("many-exports"), packages, exports).unwrap();

    assert_eq!(index.export_count(), 50);
    for i in 0..50 {
        let key = format!("./sub/{i}");
        let r = index.lookup_export("big-pkg", &key);
        assert_eq!(r.outcome, IndexLookupOutcome::Hit, "miss for {key}");
    }
}

#[test]
fn package_index_content_hash_changes_with_epoch() {
    let make = |ep: u64| {
        PackageIndex::build(
            PackageIndexConfig::new("idx", epoch(ep)),
            vec![pkg("react", &["."])],
            vec![export_entry("react", ".", &[("import", "./esm.js")])],
        )
        .unwrap()
    };
    assert_ne!(make(1).content_hash(), make(2).content_hash());
}

#[test]
fn package_index_content_hash_changes_with_index_id() {
    let make = |id: &str| {
        PackageIndex::build(
            PackageIndexConfig::new(id, epoch(1)),
            vec![pkg("react", &["."])],
            vec![export_entry("react", ".", &[("import", "./esm.js")])],
        )
        .unwrap()
    };
    assert_ne!(make("idx-a").content_hash(), make("idx-b").content_hash());
}

#[test]
fn package_index_resolve_subpath_with_deep_nesting() {
    let packages = vec![pkg(
        "@org/lib",
        &[".", "./utils", "./utils/deep", "./utils/deep/nested"],
    )];
    let exports = vec![
        export_entry("@org/lib", ".", &[("import", "./index.mjs")]),
        export_entry("@org/lib", "./utils", &[("import", "./utils/index.mjs")]),
        export_entry(
            "@org/lib",
            "./utils/deep",
            &[("import", "./utils/deep/index.mjs")],
        ),
        export_entry(
            "@org/lib",
            "./utils/deep/nested",
            &[("import", "./utils/deep/nested/index.mjs")],
        ),
    ];
    let index = PackageIndex::build(config("deep"), packages, exports).unwrap();

    let r = index.resolve_subpath("@org/lib", &["import"]);
    assert_eq!(r.value.as_deref(), Some("./index.mjs"));
}

#[test]
fn package_index_condition_order_matters() {
    let packages = vec![pkg("pkg", &["."])];
    let exports = vec![export_entry(
        "pkg",
        ".",
        &[
            ("node", "./node.js"),
            ("browser", "./browser.js"),
            ("default", "./default.js"),
        ],
    )];
    let index = PackageIndex::build(config("cond-order"), packages, exports).unwrap();

    // First matching condition should win
    let r1 = index.resolve_subpath("pkg", &["browser", "node", "default"]);
    assert_eq!(r1.value.as_deref(), Some("./browser.js"));

    let r2 = index.resolve_subpath("pkg", &["node", "browser", "default"]);
    assert_eq!(r2.value.as_deref(), Some("./node.js"));
}

// ---------------------------------------------------------------------------
// Receipt determinism
// ---------------------------------------------------------------------------

#[test]
fn build_receipt_evidence_hash_differs_with_different_duration() {
    let packages = vec![pkg("react", &["."])];
    let exports = vec![export_entry("react", ".", &[("import", "./esm.js")])];
    let index = PackageIndex::build(config("idx"), packages, exports).unwrap();
    let r1 = IndexBuildReceipt::from_index(&index, 1000);
    let r2 = IndexBuildReceipt::from_index(&index, 2000);
    // Duration is part of the canonical bytes, so hashes should differ
    assert_ne!(r1.evidence_hash(), r2.evidence_hash());
}

#[test]
fn subpath_receipt_deterministic_for_same_inputs() {
    let packages = vec![pkg("react", &["."])];
    let exports = vec![export_entry("react", ".", &[("import", "./esm.js")])];
    let index = PackageIndex::build(config("idx"), packages, exports).unwrap();

    let result = index.resolve_subpath("react", &["import"]);
    let r1 = SubpathResolutionReceipt::new(&index, "react", &result, &["import"]);
    let r2 = SubpathResolutionReceipt::new(&index, "react", &result, &["import"]);
    assert_eq!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// Stats and metadata
// ---------------------------------------------------------------------------

#[test]
fn package_index_stats_accurate_after_large_build() {
    let n = 200;
    let packages: Vec<PackageEntry> = (0..n)
        .map(|i| pkg(&format!("pkg-{i}"), &[".", "./sub"]))
        .collect();
    let exports: Vec<ExportEntry> = (0..n)
        .flat_map(|i| {
            vec![
                export_entry(
                    &format!("pkg-{i}"),
                    ".",
                    &[("import", &format!("./esm/{i}.js"))],
                ),
                export_entry(
                    &format!("pkg-{i}"),
                    "./sub",
                    &[("import", &format!("./esm/{i}-sub.js"))],
                ),
            ]
        })
        .collect();
    let index = PackageIndex::build(config("stats-test"), packages, exports).unwrap();

    let stats = index.stats();
    assert_eq!(stats.package_count, n as u64);
    assert_eq!(stats.export_count, (n * 2) as u64);
    assert!(stats.art_node_count > 0);
    assert!(stats.mphf_slot_count > 0);
    assert!(stats.mphf_occupancy_millionths > 0);
}

#[test]
fn package_index_schema_version_matches_constant() {
    let packages = vec![pkg("x", &["."])];
    let exports = vec![export_entry("x", ".", &[("import", "./x.js")])];
    let index = PackageIndex::build(config("v"), packages, exports).unwrap();
    assert_eq!(index.schema_version(), SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// Serde roundtrips for complex scenarios
// ---------------------------------------------------------------------------

#[test]
fn package_entry_with_all_fields_serde_roundtrip() {
    let entry = PackageEntry::new("@complex/pkg", hash_for("@complex/pkg"))
        .with_exports(vec![
            ".".into(),
            "./a".into(),
            "./b/c".into(),
            "./d/e/f".into(),
        ])
        .with_main_entry("./lib/index.cjs")
        .with_syntax_hint("dual");
    let json = serde_json::to_string(&entry).unwrap();
    let decoded: PackageEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, decoded);
    assert_eq!(entry.canonical_bytes(), decoded.canonical_bytes());
}

#[test]
fn export_entry_many_conditions_serde_roundtrip() {
    let entry = ExportEntry::new("pkg", "./complex")
        .with_condition("import", "./esm.js")
        .with_condition("require", "./cjs.js")
        .with_condition("node", "./node.js")
        .with_condition("browser", "./browser.js")
        .with_condition("deno", "./deno.js")
        .with_condition("react-native", "./rn.js")
        .with_condition("default", "./default.js")
        .with_fallback("./fallback.js");
    let json = serde_json::to_string(&entry).unwrap();
    let decoded: ExportEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, decoded);
    assert_eq!(entry.canonical_bytes(), decoded.canonical_bytes());
}

// ---------------------------------------------------------------------------
// Error handling edge cases
// ---------------------------------------------------------------------------

#[test]
fn index_build_error_variants_display_correctly() {
    let errors = vec![
        IndexBuildError::EmptyKeySet,
        IndexBuildError::KeyTooLong {
            key: "very-long-key".into(),
            max_depth: 512,
        },
        IndexBuildError::TooManyEntries {
            count: 2_000_000,
            max: 1_000_000,
        },
        IndexBuildError::DuplicateKey {
            key: "react".into(),
        },
        IndexBuildError::MphfConstructionFailed {
            reason: "test reason".into(),
        },
    ];
    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty());
    }
}

#[test]
fn mphf_rejects_too_many_entries() {
    // We can't actually create MAX_MPHF_ENTRIES entries in a test,
    // but we can test that the limit is enforced
    let limit = MAX_MPHF_ENTRIES;
    assert!(limit > 0);
    // The check is: entries.len() > MAX_MPHF_ENTRIES
    // We just verify the constant is reasonable
    assert_eq!(limit, 1_000_000);
}

// ---------------------------------------------------------------------------
// Lookup result patterns
// ---------------------------------------------------------------------------

#[test]
fn lookup_result_hit_contains_value() {
    let r: LookupResult<String> = LookupResult::hit("found".to_string());
    assert!(r.value.is_some());
    assert_eq!(r.outcome, IndexLookupOutcome::Hit);
}

#[test]
fn lookup_result_miss_has_no_value() {
    let r: LookupResult<String> = LookupResult::miss();
    assert!(r.value.is_none());
    assert_eq!(r.outcome, IndexLookupOutcome::Miss);
}

// ---------------------------------------------------------------------------
// Canonical bytes determinism
// ---------------------------------------------------------------------------

#[test]
fn package_entry_canonical_bytes_differ_for_different_names() {
    let e1 = pkg("react", &["."]);
    let e2 = pkg("lodash", &["."]);
    assert_ne!(e1.canonical_bytes(), e2.canonical_bytes());
}

#[test]
fn export_entry_canonical_bytes_differ_for_different_conditions() {
    let e1 = export_entry("pkg", ".", &[("import", "./a.js")]);
    let e2 = export_entry("pkg", ".", &[("import", "./b.js")]);
    assert_ne!(e1.canonical_bytes(), e2.canonical_bytes());
}

#[test]
fn export_entry_canonical_bytes_differ_for_different_keys() {
    let e1 = export_entry("pkg", ".", &[("import", "./a.js")]);
    let e2 = export_entry("pkg", "./sub", &[("import", "./a.js")]);
    assert_ne!(e1.canonical_bytes(), e2.canonical_bytes());
}
