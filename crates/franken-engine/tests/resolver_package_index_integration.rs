//! Integration tests for `resolver_package_index` module (bd-1lsy.5.8.1).
//!
//! Tests the ART/MPHF package index, export index, subpath resolution,
//! prefix scanning, evidence receipts, and serde roundtrips against
//! realistic npm-style package layouts.

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

fn export(pkg_name: &str, key: &str, conditions: &[(&str, &str)]) -> ExportEntry {
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
// ART integration scenarios
// ---------------------------------------------------------------------------

#[test]
fn art_handles_npm_scoped_package_hierarchy() {
    let mut art = AdaptiveRadixTrie::new();
    art.insert(b"@types/react", 1u32).unwrap();
    art.insert(b"@types/react-dom", 2).unwrap();
    art.insert(b"@types/node", 3).unwrap();
    art.insert(b"@emotion/react", 4).unwrap();
    art.insert(b"@emotion/styled", 5).unwrap();
    art.insert(b"react", 6).unwrap();
    art.insert(b"react-dom", 7).unwrap();

    assert_eq!(art.get(b"@types/react"), Some(&1));
    assert_eq!(art.get(b"@types/react-dom"), Some(&2));
    assert_eq!(art.get(b"@types/node"), Some(&3));
    assert_eq!(art.get(b"@emotion/react"), Some(&4));
    assert_eq!(art.get(b"@emotion/styled"), Some(&5));
    assert_eq!(art.get(b"react"), Some(&6));
    assert_eq!(art.get(b"react-dom"), Some(&7));

    let types = art.prefix_scan(b"@types/");
    assert_eq!(types.len(), 3);

    let emotion = art.prefix_scan(b"@emotion/");
    assert_eq!(emotion.len(), 2);
}

#[test]
fn art_longest_prefix_match_selects_most_specific() {
    let mut art = AdaptiveRadixTrie::new();
    art.insert(b"react", "react-root").unwrap();
    art.insert(b"react-dom", "react-dom-root").unwrap();
    art.insert(b"react-dom/server", "react-dom-server").unwrap();

    let (len, val) = art.longest_prefix_match(b"react-dom/server/node").unwrap();
    assert_eq!(*val, "react-dom-server");
    assert_eq!(len, 16); // "react-dom/server".len()

    let (len2, val2) = art.longest_prefix_match(b"react-dom/client").unwrap();
    assert_eq!(*val2, "react-dom-root");
    assert_eq!(len2, 9);

    let (len3, val3) = art.longest_prefix_match(b"react/jsx-runtime").unwrap();
    assert_eq!(*val3, "react-root");
    assert_eq!(len3, 5);
}

#[test]
fn art_handles_single_char_keys() {
    let mut art = AdaptiveRadixTrie::new();
    art.insert(b"a", 1).unwrap();
    art.insert(b"b", 2).unwrap();
    art.insert(b"ab", 3).unwrap();
    art.insert(b"abc", 4).unwrap();

    assert_eq!(art.get(b"a"), Some(&1));
    assert_eq!(art.get(b"b"), Some(&2));
    assert_eq!(art.get(b"ab"), Some(&3));
    assert_eq!(art.get(b"abc"), Some(&4));
    assert_eq!(art.get(b"abcd"), None);
}

#[test]
fn art_prefix_scan_returns_full_subtree() {
    let mut art = AdaptiveRadixTrie::new();
    for i in 0..50 {
        let key = format!("@scope/pkg-{i:03}");
        art.insert(key.as_bytes(), i).unwrap();
    }
    art.insert(b"other-pkg", 999).unwrap();

    let scoped = art.prefix_scan(b"@scope/");
    assert_eq!(scoped.len(), 50);

    let all = art.prefix_scan(b"");
    assert_eq!(all.len(), 51);
}

#[test]
fn art_empty_prefix_scan_returns_everything() {
    let mut art = AdaptiveRadixTrie::new();
    art.insert(b"react", 1).unwrap();
    art.insert(b"lodash", 2).unwrap();
    let all = art.prefix_scan(b"");
    assert_eq!(all.len(), 2);
}

#[test]
fn art_miss_returns_none() {
    let art = AdaptiveRadixTrie::<u32>::new();
    assert_eq!(art.get(b"anything"), None);
    assert!(art.longest_prefix_match(b"anything").is_none());
    assert!(art.prefix_scan(b"any").is_empty());
}

// ---------------------------------------------------------------------------
// MphfIndex integration scenarios
// ---------------------------------------------------------------------------

#[test]
fn mphf_handles_large_keyset() {
    let entries: Vec<(Vec<u8>, u32)> = (0..500)
        .map(|i| (format!("@scope/pkg-{i:04}").into_bytes(), i))
        .collect();
    let index = MphfIndex::build(entries).unwrap();
    assert_eq!(index.len(), 500);

    for i in 0..500 {
        let key = format!("@scope/pkg-{i:04}");
        assert_eq!(index.get(key.as_bytes()), Some(&i), "miss for key {key}");
    }
    assert_eq!(index.get(b"@scope/pkg-9999"), None);
}

#[test]
fn mphf_with_similar_keys() {
    let entries = vec![
        (b"react".to_vec(), 1),
        (b"react-dom".to_vec(), 2),
        (b"react-dom/server".to_vec(), 3),
        (b"react-dom/client".to_vec(), 4),
        (b"react/jsx-runtime".to_vec(), 5),
        (b"react/jsx-dev-runtime".to_vec(), 6),
    ];
    let index = MphfIndex::build(entries).unwrap();
    assert_eq!(index.get(b"react"), Some(&1));
    assert_eq!(index.get(b"react-dom"), Some(&2));
    assert_eq!(index.get(b"react-dom/server"), Some(&3));
    assert_eq!(index.get(b"react-dom/client"), Some(&4));
    assert_eq!(index.get(b"react/jsx-runtime"), Some(&5));
    assert_eq!(index.get(b"react/jsx-dev-runtime"), Some(&6));
    assert_eq!(index.get(b"react-native"), None);
}

#[test]
fn mphf_occupancy_within_bounds() {
    let entries: Vec<(Vec<u8>, u32)> = (0..100)
        .map(|i| (format!("key-{i}").into_bytes(), i))
        .collect();
    let index = MphfIndex::build(entries).unwrap();
    let occ = index.occupancy_millionths();
    assert!(occ > 0);
    assert!(occ <= MILLIONTHS);
}

// ---------------------------------------------------------------------------
// PackageIndex integration scenarios
// ---------------------------------------------------------------------------

#[test]
fn package_index_realistic_react_ecosystem() {
    let packages = vec![
        pkg("react", &[".", "./jsx-runtime", "./jsx-dev-runtime"])
            .with_main_entry("./index.js")
            .with_syntax_hint("esm"),
        pkg("react-dom", &[".", "./server", "./client"]).with_main_entry("./index.js"),
        pkg("@types/react", &["."]),
        pkg("@emotion/react", &[".", "./jsx-runtime"]),
        pkg("lodash", &["."])
            .with_main_entry("./lodash.js")
            .with_syntax_hint("cjs"),
    ];

    let exports = vec![
        export(
            "react",
            ".",
            &[
                ("import", "./esm/react.production.min.js"),
                ("require", "./cjs/react.production.min.js"),
            ],
        ),
        export(
            "react",
            "./jsx-runtime",
            &[("import", "./esm/react-jsx-runtime.production.min.js")],
        ),
        export(
            "react",
            "./jsx-dev-runtime",
            &[("import", "./esm/react-jsx-dev-runtime.development.js")],
        ),
        export(
            "react-dom",
            ".",
            &[("import", "./esm/react-dom.production.min.js")],
        ),
        export(
            "react-dom",
            "./server",
            &[("import", "./esm/react-dom-server.browser.production.min.js")],
        ),
        export(
            "react-dom",
            "./client",
            &[("import", "./esm/react-dom-client.production.min.js")],
        ),
        export("@types/react", ".", &[("import", "./index.d.ts")]),
        export(
            "@emotion/react",
            ".",
            &[("import", "./dist/emotion-react.esm.js")],
        ),
        export("lodash", ".", &[("require", "./lodash.js")]),
    ];

    let index = PackageIndex::build(config("react-ecosystem"), packages, exports).unwrap();

    // Package lookups
    let r = index.lookup_package("react");
    assert_eq!(r.outcome, IndexLookupOutcome::Hit);
    assert_eq!(r.value.as_ref().unwrap().export_keys.len(), 3);

    // Export lookups
    let e = index.lookup_export("react", "./jsx-runtime");
    assert_eq!(e.outcome, IndexLookupOutcome::Hit);
    let export_val = e.value.unwrap();
    assert_eq!(
        export_val.resolve_target(&["import"]),
        Some("./esm/react-jsx-runtime.production.min.js")
    );

    // Subpath resolution
    let sr = index.resolve_subpath("react", &["import"]);
    assert_eq!(sr.outcome, IndexLookupOutcome::Hit);
    assert_eq!(sr.value.as_deref(), Some("./esm/react.production.min.js"));

    let sr2 = index.resolve_subpath("react-dom/server", &["import"]);
    assert_eq!(sr2.outcome, IndexLookupOutcome::Hit);

    // Scoped package scan
    let types = index.packages_under_scope("@types/");
    assert_eq!(types.len(), 1);

    let emotion = index.packages_under_scope("@emotion/");
    assert_eq!(emotion.len(), 1);

    // Stats
    let stats = index.stats();
    assert_eq!(stats.package_count, 5);
    assert_eq!(stats.export_count, 9);
    assert!(stats.art_node_count > 0);
}

#[test]
fn package_index_main_entry_fallback_for_legacy_packages() {
    let packages = vec![
        pkg("underscore", &[]).with_main_entry("./underscore.js"),
        pkg("moment", &[]).with_main_entry("./moment.js"),
    ];
    let index = PackageIndex::build(config("legacy"), packages, vec![]).unwrap();

    let r1 = index.resolve_subpath("underscore", &["import"]);
    assert_eq!(r1.outcome, IndexLookupOutcome::Hit);
    assert_eq!(r1.value.as_deref(), Some("./underscore.js"));

    let r2 = index.resolve_subpath("moment", &["require"]);
    assert_eq!(r2.outcome, IndexLookupOutcome::Hit);
    assert_eq!(r2.value.as_deref(), Some("./moment.js"));
}

#[test]
fn package_index_condition_priority() {
    let packages = vec![pkg("pkg", &["."])];
    let exports = vec![
        ExportEntry::new("pkg", ".")
            .with_condition("import", "./esm.js")
            .with_condition("require", "./cjs.js")
            .with_condition("default", "./default.js")
            .with_fallback("./fallback.js"),
    ];
    let index = PackageIndex::build(config("cond"), packages, exports).unwrap();

    // First matching condition wins
    let r1 = index.resolve_subpath("pkg", &["import", "require"]);
    assert_eq!(r1.value.as_deref(), Some("./esm.js"));

    let r2 = index.resolve_subpath("pkg", &["require", "default"]);
    assert_eq!(r2.value.as_deref(), Some("./cjs.js"));

    let r3 = index.resolve_subpath("pkg", &["node", "default"]);
    assert_eq!(r3.value.as_deref(), Some("./default.js"));

    // Fallback when no condition matches
    let r4 = index.resolve_subpath("pkg", &["nonexistent"]);
    assert_eq!(r4.outcome, IndexLookupOutcome::Hit);
    assert_eq!(r4.value.as_deref(), Some("./fallback.js"));
}

#[test]
fn package_index_content_hash_changes_with_different_packages() {
    let make = |name: &str| {
        PackageIndex::build(
            config("idx"),
            vec![pkg(name, &["."])],
            vec![export(name, ".", &[("import", "./esm.js")])],
        )
        .unwrap()
    };
    let h1 = *make("react").content_hash();
    let h2 = *make("lodash").content_hash();
    assert_ne!(h1, h2);
}

#[test]
fn package_index_content_hash_stable_across_rebuilds() {
    let make = || {
        PackageIndex::build(
            config("idx"),
            vec![pkg("react", &["."])],
            vec![export("react", ".", &[("import", "./esm.js")])],
        )
        .unwrap()
    };
    assert_eq!(make().content_hash(), make().content_hash());
}

#[test]
fn package_index_many_packages() {
    let packages: Vec<PackageEntry> = (0..100)
        .map(|i| pkg(&format!("pkg-{i:03}"), &[".", "./sub"]))
        .collect();
    let exports: Vec<ExportEntry> = (0..100)
        .map(|i| {
            export(
                &format!("pkg-{i:03}"),
                ".",
                &[("import", &format!("./esm-{i}.js"))],
            )
        })
        .collect();
    let index = PackageIndex::build(config("large"), packages, exports).unwrap();

    assert_eq!(index.package_count(), 100);
    assert_eq!(index.export_count(), 100);

    for i in 0..100 {
        let name = format!("pkg-{i:03}");
        let r = index.lookup_package(&name);
        assert_eq!(r.outcome, IndexLookupOutcome::Hit);
    }
}

#[test]
fn package_index_miss_for_unknown_package() {
    let packages = vec![pkg("react", &["."])];
    let exports = vec![export("react", ".", &[("import", "./esm.js")])];
    let index = PackageIndex::build(config("idx"), packages, exports).unwrap();

    assert_eq!(
        index.lookup_package("vue").outcome,
        IndexLookupOutcome::Miss
    );
    assert_eq!(
        index.lookup_export("vue", ".").outcome,
        IndexLookupOutcome::Miss
    );
    assert_eq!(
        index.resolve_subpath("vue", &["import"]).outcome,
        IndexLookupOutcome::Miss
    );
}

// ---------------------------------------------------------------------------
// Evidence receipts
// ---------------------------------------------------------------------------

#[test]
fn build_receipt_captures_index_metadata() {
    let packages = vec![pkg("react", &["."]), pkg("lodash", &["."])];
    let exports = vec![
        export("react", ".", &[("import", "./esm.js")]),
        export("lodash", ".", &[("require", "./cjs.js")]),
    ];
    let index = PackageIndex::build(config("receipt-test"), packages, exports).unwrap();
    let receipt = IndexBuildReceipt::from_index(&index, 42_000);

    assert_eq!(receipt.index_id, "receipt-test");
    assert_eq!(receipt.package_count, 2);
    assert_eq!(receipt.export_count, 2);
    assert_eq!(receipt.build_duration_ns, 42_000);
    assert_eq!(receipt.component, COMPONENT);
    assert_eq!(receipt.policy_id, POLICY_ID);
    assert_eq!(receipt.schema_version, SCHEMA_VERSION);
}

#[test]
fn build_receipt_evidence_hash_is_deterministic() {
    let make = || {
        let packages = vec![pkg("react", &["."])];
        let exports = vec![export("react", ".", &[("import", "./esm.js")])];
        let index = PackageIndex::build(config("idx"), packages, exports).unwrap();
        IndexBuildReceipt::from_index(&index, 1000)
    };
    assert_eq!(make().evidence_hash(), make().evidence_hash());
}

#[test]
fn subpath_receipt_records_hit() {
    let packages = vec![pkg("react", &["."])];
    let exports = vec![export("react", ".", &[("import", "./esm.js")])];
    let index = PackageIndex::build(config("idx"), packages, exports).unwrap();

    let result = index.resolve_subpath("react", &["import"]);
    let receipt = SubpathResolutionReceipt::new(&index, "react", &result, &["import"]);

    assert_eq!(receipt.outcome, IndexLookupOutcome::Hit);
    assert_eq!(receipt.resolved_target.as_deref(), Some("./esm.js"));
    assert_eq!(receipt.specifier, "react");
    assert_eq!(receipt.conditions_tried, vec!["import"]);
    assert_eq!(receipt.schema_version, SCHEMA_VERSION);
}

#[test]
fn subpath_receipt_records_miss() {
    let packages = vec![pkg("react", &["."])];
    let exports = vec![export("react", ".", &[("import", "./esm.js")])];
    let index = PackageIndex::build(config("idx"), packages, exports).unwrap();

    let result = index.resolve_subpath("vue", &["import"]);
    let receipt = SubpathResolutionReceipt::new(&index, "vue", &result, &["import"]);

    assert_eq!(receipt.outcome, IndexLookupOutcome::Miss);
    assert!(receipt.resolved_target.is_none());
}

// ---------------------------------------------------------------------------
// Serde roundtrip integration
// ---------------------------------------------------------------------------

#[test]
fn package_entry_json_roundtrip() {
    let entry = pkg("@babel/core", &[".", "./transform", "./parse"])
        .with_main_entry("./lib/index.js")
        .with_syntax_hint("cjs");
    let json = serde_json::to_string_pretty(&entry).unwrap();
    let decoded: PackageEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, decoded);
}

#[test]
fn export_entry_json_roundtrip() {
    let entry = ExportEntry::new("react", "./jsx-runtime")
        .with_condition("import", "./esm/jsx-runtime.js")
        .with_condition("require", "./cjs/jsx-runtime.js")
        .with_fallback("./jsx-runtime.js");
    let json = serde_json::to_string_pretty(&entry).unwrap();
    let decoded: ExportEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, decoded);
}

#[test]
fn build_receipt_json_roundtrip() {
    let packages = vec![pkg("react", &["."]), pkg("lodash", &["."])];
    let exports = vec![
        export("react", ".", &[("import", "./esm.js")]),
        export("lodash", ".", &[("require", "./cjs.js")]),
    ];
    let index = PackageIndex::build(config("rt-test"), packages, exports).unwrap();
    let receipt = IndexBuildReceipt::from_index(&index, 5000);

    let json = serde_json::to_string_pretty(&receipt).unwrap();
    let decoded: IndexBuildReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, decoded);
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

#[test]
fn mphf_rejects_duplicate_keys() {
    let entries = vec![(b"react".to_vec(), 1u32), (b"react".to_vec(), 2)];
    let err = MphfIndex::build(entries).unwrap_err();
    assert!(matches!(err, IndexBuildError::DuplicateKey { .. }));
}

#[test]
fn mphf_rejects_empty_keyset() {
    let err = MphfIndex::<u32>::build(vec![]).unwrap_err();
    assert!(matches!(err, IndexBuildError::EmptyKeySet));
}

#[test]
fn art_rejects_oversized_keys() {
    let mut art = AdaptiveRadixTrie::<u32>::new();
    let long_key = vec![b'x'; MAX_ART_DEPTH + 1];
    let err = art.insert(&long_key, 1).unwrap_err();
    assert!(matches!(err, IndexBuildError::KeyTooLong { .. }));
}

// ---------------------------------------------------------------------------
// Index accessors
// ---------------------------------------------------------------------------

#[test]
fn index_accessors_return_correct_values() {
    let packages = vec![pkg("react", &["."])];
    let exports = vec![export("react", ".", &[("import", "./esm.js")])];
    let cfg = PackageIndexConfig::new("my-index-id", epoch(42));
    let index = PackageIndex::build(cfg, packages, exports).unwrap();

    assert_eq!(index.index_id(), "my-index-id");
    assert_eq!(index.build_epoch(), epoch(42));
    assert_eq!(index.schema_version(), SCHEMA_VERSION);
    assert_eq!(index.package_count(), 1);
    assert_eq!(index.export_count(), 1);
}

#[test]
fn index_build_error_display_messages() {
    let e1 = IndexBuildError::EmptyKeySet;
    assert!(e1.to_string().contains("empty"));

    let e2 = IndexBuildError::TooManyEntries {
        count: 2_000_000,
        max: 1_000_000,
    };
    assert!(e2.to_string().contains("2000000"));

    let e3 = IndexBuildError::DuplicateKey {
        key: "react".to_string(),
    };
    assert!(e3.to_string().contains("react"));
}

#[test]
fn lookup_outcome_as_str_values() {
    assert_eq!(IndexLookupOutcome::Hit.as_str(), "hit");
    assert_eq!(IndexLookupOutcome::Miss.as_str(), "miss");
    assert_eq!(IndexLookupOutcome::FallbackUsed.as_str(), "fallback_used");
}
