//! Repository-wide unsafe-code prohibition truth gate
//! (bd-performance-conformance-bridge-tu32j.1.9).
//!
//! AGENTS.md requires unsafe code to be forbidden in repository code. The crate
//! roots now declare an UNCONDITIONAL `#![forbid(unsafe_code)]` (previously a
//! `cfg_attr(not(test), forbid(unsafe_code))` that exempted test builds so TEE
//! capability-detection tests could mutate process-global env with `unsafe`).
//! The compiler is the primary enforcement — `unsafe` anywhere, including
//! `cfg(test)` modules, now fails to build. This source-level gate additionally
//! guards the *contract* itself: it fails loudly if any franken-engine source
//! file re-weakens the attribute to the `cfg(test)`-exempt form or reintroduces
//! an `unsafe` block/fn/impl, so the exemption cannot silently return.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

fn engine_src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read engine src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// The `cfg(test)`-exempt weakening of the unsafe prohibition must never
/// reappear in any engine source file.
#[test]
fn no_source_file_reweakens_the_unsafe_prohibition() {
    let mut sources = Vec::new();
    rust_sources(&engine_src_dir(), &mut sources);
    assert!(!sources.is_empty(), "engine src must contain Rust sources");

    let mut offenders = Vec::new();
    for path in &sources {
        let text = std::fs::read_to_string(path).expect("read engine source");
        if text.contains("cfg_attr(not(test), forbid(unsafe_code))")
            || text.contains("cfg_attr(test, allow(unsafe_code))")
        {
            offenders.push(path.display().to_string());
        }
    }
    assert!(
        offenders.is_empty(),
        "these files re-weaken the unsafe prohibition to a cfg(test)-exempt form; \
         restore an unconditional #![forbid(unsafe_code)]:\n  {}",
        offenders.join("\n  ")
    );
}

/// No engine source file may contain an unsafe block, fn, impl, trait, or
/// extern form. This mirrors what the unconditional `#![forbid(unsafe_code)]`
/// enforces at compile time, but keeps the prohibition legible as an explicit,
/// fail-closed source contract that a reviewer can point to.
#[test]
fn no_source_file_contains_unsafe_constructs() {
    let mut sources = Vec::new();
    rust_sources(&engine_src_dir(), &mut sources);

    // These are the syntactic forms that introduce unsafe; the `unsafe_code`
    // lint identifier and doc/comment prose that merely mention "unsafe" are
    // deliberately not matched.
    const UNSAFE_FORMS: &[&str] = &[
        "unsafe {",
        "unsafe fn ",
        "unsafe impl ",
        "unsafe trait ",
        "unsafe extern ",
    ];

    let mut offenders = Vec::new();
    for path in &sources {
        let text = std::fs::read_to_string(path).expect("read engine source");
        for (line_no, line) in text.lines().enumerate() {
            if UNSAFE_FORMS.iter().any(|form| line.contains(form)) {
                offenders.push(format!("{}:{}", path.display(), line_no + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "engine source must be free of unsafe constructs (AGENTS.md), found:\n  {}",
        offenders.join("\n  ")
    );
}

/// The crate root retains the unconditional prohibition (not merely the
/// absence of the weakened form — the attribute must be present).
#[test]
fn crate_root_declares_unconditional_forbid() {
    let lib = std::fs::read_to_string(engine_src_dir().join("lib.rs")).expect("read lib.rs");
    assert!(
        lib.contains("#![forbid(unsafe_code)]"),
        "lib.rs must declare an unconditional #![forbid(unsafe_code)]"
    );
    assert!(
        !lib.contains("cfg_attr(not(test), forbid(unsafe_code))"),
        "lib.rs must not exempt test builds from the unsafe prohibition"
    );
}
