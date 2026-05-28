#![forbid(unsafe_code)]

//! Insta-crate adoption spike (bd-ub6x8.11).
//!
//! Demonstrates `insta::assert_snapshot!`, `assert_debug_snapshot!`, and
//! `Settings::add_filter` on the same deterministic inputs the legacy
//! `examples/golden_pattern.rs` and `tests/decode_golden_artifacts.rs`
//! helpers cover today (~13 inline `assert_golden` copies — tracked under
//! bd-ub6x8.3). The goal is to prove the toolchain works inside this
//! crate and to give future agents a concrete migration template; no
//! production code path runs here.
//!
//! ## How this maps onto the existing helpers
//!
//! | Hand-rolled today                              | `insta` equivalent                 |
//! |------------------------------------------------|------------------------------------|
//! | `assert_golden("name", &actual)`               | `assert_snapshot!("name", actual)` |
//! | `format!("{:?}", value)` baked into golden     | `assert_debug_snapshot!(value)`    |
//! | inline scrubbing regex (UUID / timestamp)      | `Settings::add_filter(regex, repl)`|
//! | `UPDATE_GOLDENS=1 cargo test`                  | `cargo insta review` (interactive) |
//! | `.actual` siblings on mismatch (bd-ub6x8.7)    | `.snap.new` siblings (insta-native)|
//!
//! ## Snapshot location
//!
//! By default `insta` writes snapshots beside the test source under
//! `crates/franken-engine/tests/snapshots/`. The directory does not yet
//! exist on a fresh checkout; `cargo test` creates it lazily under
//! `INSTA_UPDATE=auto` (the default), and `cargo insta review` walks
//! `.snap.new` files there.
//!
//! ## Adoption tradeoffs (recap for the migration bead)
//!
//! - (+) Single env: `INSTA_UPDATE=always` / `INSTA_FORCE_PASS=1` /
//!   interactive `cargo insta review`.
//! - (+) Built-in scrubbing via `Settings::add_filter` (regex →
//!   placeholder).
//! - (+) Unified-diff panic output, colorized.
//! - (+) Pending snapshots tracked per-file (`*.snap.new` next to the
//!   `.snap`).
//! - (–) New crate dep (`insta` only; `cargo-insta` CLI for the dev
//!   workflow stays separate so the crate itself does not depend on it).
//! - (–) Migration cost: ~20 existing `assert_golden` call sites need
//!   rewriting.

use insta::Settings;

// The three demos below are `#[ignore]` by default so a fresh checkout
// can run `cargo test` without first blessing the snapshots. To exercise
// them — and to author the initial snapshots — run:
//
//   INSTA_UPDATE=always cargo test -p frankenengine-engine \
//     --test insta_spike_demo -- --include-ignored
//
// then `cargo insta review` and commit `tests/snapshots/insta_spike_demo__*.snap`.

#[test]
#[ignore = "bless via INSTA_UPDATE=always cargo test ... -- --include-ignored (bd-ub6x8.11)"]
fn demo_assert_snapshot_against_deterministic_text() {
    let mut output = String::new();
    output.push_str("FrankenEngine Insta Spike Demo\n");
    output.push_str("==============================\n\n");

    let test_values = [42u64, 100, 255, 1000];
    for (i, value) in test_values.iter().enumerate() {
        output.push_str(&format!("Value {i}: {value:#x} ({value})\n"));
    }

    insta::assert_snapshot!("deterministic_text", output);
}

#[test]
#[ignore = "bless via INSTA_UPDATE=always cargo test ... -- --include-ignored (bd-ub6x8.11)"]
fn demo_assert_debug_snapshot_for_structured_data() {
    #[derive(Debug)]
    #[allow(dead_code)]
    struct ParsedRow {
        id: u32,
        label: &'static str,
        bytes: Vec<u8>,
    }

    let rows = vec![
        ParsedRow {
            id: 1,
            label: "alpha",
            bytes: vec![0x01, 0x02, 0x03],
        },
        ParsedRow {
            id: 7,
            label: "gamma",
            bytes: vec![0xff],
        },
    ];

    // `assert_debug_snapshot!` uses the type's `Debug` impl exactly the
    // way several legacy goldens already do — handy as a drop-in replacement
    // for the first wave of migration, *but* the same `Debug`-fragility
    // bd-ub6x8.9 / .9.1 caught still applies. Once a type is migrated,
    // prefer `assert_snapshot!` against a stable serializer (serde_json,
    // a `Display` impl, etc.).
    insta::assert_debug_snapshot!("structured_data_debug", rows);
}

#[test]
#[ignore = "bless via INSTA_UPDATE=always cargo test ... -- --include-ignored (bd-ub6x8.11)"]
fn demo_assert_snapshot_with_scrubbing_filters() {
    // Scrubbing is the legacy goldens' biggest source of incidental
    // complexity — `Settings::add_filter` makes it declarative.
    let mut settings = Settings::clone_current();
    settings.add_filter(r"trace-[0-9a-f]{8,}", "trace-[ID]");
    settings.add_filter(
        r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\b",
        "[TIMESTAMP]",
    );

    settings.bind(|| {
        let payload = "received trace-abcdef1234567890 at 2026-05-28T00:30:00Z";
        insta::assert_snapshot!("scrubbed_payload", payload);
    });
}
