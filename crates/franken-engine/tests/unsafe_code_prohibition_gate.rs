//! Repository-wide unsafe-code prohibition truth gate
//! (bd-performance-conformance-bridge-tu32j.1.9).
//!
//! AGENTS.md requires unsafe code to be forbidden in repository code. Every
//! workspace crate root declares an UNCONDITIONAL `#![forbid(unsafe_code)]`
//! (previously `crates/franken-engine` used a
//! `cfg_attr(not(test), forbid(unsafe_code))` that exempted test builds, and
//! the first revision of this gate scanned only `src/`, missing the compiled
//! test targets where live `unsafe` env mutators survived). The compiler is
//! the primary enforcement — `unsafe` anywhere now fails to build. This
//! source-level gate additionally guards the *contract* itself across every
//! workspace Rust target: it fails loudly if any file re-weakens the attribute
//! to a cfg-relaxed form or reintroduces an `unsafe` block/fn/impl/trait/
//! extern boundary, so the exemption cannot silently return.
//!
//! Detector self-tests below inject every prohibited form — including forms
//! hidden inside comments, string literals, and raw strings, which must NOT
//! be flagged — so the scanner cannot silently rot into a false pass.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

/// Workspace member directories that hold Rust crates, relative to the
/// workspace root. Derived from the root `Cargo.toml` `[workspace] members`
/// list; keep in sync when a member is added.
const WORKSPACE_CRATE_DIRS: &[&str] = &[
    "crates/dp",
    "crates/franken-core",
    "crates/franken-engine",
    "crates/franken-engine-control-plane-integration-tests",
    "crates/franken-engine-deterministic-derive",
    "crates/franken-engine-deterministic-trait",
    "crates/franken-engine-fixed-layout-derive",
    "crates/franken-engine-test-support",
    "crates/franken-extension-host",
    "crates/franken-metamorphic",
];

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is `<root>/crates/<crate>`; the workspace root is
    // two levels up.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate manifest dir sits two levels under the workspace root")
        .to_path_buf()
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Collect every Rust source file under every workspace crate directory.
fn workspace_rust_sources() -> Vec<PathBuf> {
    let root = workspace_root();
    let mut sources = Vec::new();
    for crate_dir in WORKSPACE_CRATE_DIRS {
        rust_sources(&root.join(crate_dir), &mut sources);
    }
    sources
}

/// Blank the contents of raw strings (`r#"…"#`, `r##"…"##`, …) and block
/// comments (`/* … */`) across a whole file, replacing every blanked
/// non-newline byte with a space so line numbers stay accurate. Adversarial
/// probe tests legitimately embed unsafe source inside raw-string literals
/// as DATA (e.g. trusted_label_adversarial.rs compiles a recast probe); that
/// prose must not be mistaken for live code here, while real unsafe
/// constructs outside literals remain fully visible.
fn blank_span_prose(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0usize;
    while i < bytes.len() {
        // Raw string: 'r' followed by zero-or-more '#' then '"'. A bare `r`
        // identifier (e.g. `return`, `ptr`) fails the next-char check.
        if bytes[i] == b'r' && i + 1 < bytes.len() && (bytes[i + 1] == b'#' || bytes[i + 1] == b'"')
        {
            let mut hashes = 0usize;
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'"' {
                let mut k = j + 1;
                let mut closed = false;
                while k < bytes.len() {
                    if bytes[k] == b'"'
                        && k + hashes < bytes.len()
                        && bytes[k + 1..=k + hashes].iter().all(|b| *b == b'#')
                    {
                        k += 1 + hashes;
                        closed = true;
                        break;
                    }
                    if bytes[k] != b'\n' {
                        out[k] = b' ';
                    }
                    k += 1;
                }
                for blank in out.iter_mut().take(k).skip(i) {
                    if *blank != b'\n' {
                        *blank = b' ';
                    }
                }
                i = if closed { k } else { bytes.len() };
                continue;
            }
        }
        // Block comment.
        if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            let mut k = i + 2;
            let mut closed = false;
            while k + 1 < bytes.len() {
                if bytes[k] == b'*' && bytes[k + 1] == b'/' {
                    k += 2;
                    closed = true;
                    break;
                }
                if bytes[k] != b'\n' {
                    out[k] = b' ';
                }
                k += 1;
            }
            let end = k.min(bytes.len());
            for blank in out.iter_mut().take(end).skip(i) {
                if *blank != b'\n' {
                    *blank = b' ';
                }
            }
            i = if closed { end } else { bytes.len() };
            continue;
        }
        i += 1;
    }
    String::from_utf8(out).expect("blanking preserves UTF-8")
}

/// Remove line-comment tails and string-literal/char-literal contents from
/// `line` so prose mentions of the prohibited forms are not mistaken for
/// code, and code forms cannot hide behind comment or literal text. The
/// compile-time `#![forbid(unsafe_code)]` remains the primary enforcement,
/// so this scanner only needs to be sound for the forms the repository
/// actually uses, and the mutation fixtures below pin its behavior.
fn code_only(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if in_string {
            match c {
                '\\' => {
                    chars.next();
                }
                '"' => {
                    in_string = false;
                    out.push('"');
                }
                _ => {}
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push('"');
            }
            '\'' => {
                while let Some(inner) = chars.next() {
                    if inner == '\\' {
                        chars.next();
                    } else if inner == '\'' {
                        break;
                    }
                }
                out.push('\'');
            }
            '/' if chars.peek() == Some(&'/') => break,
            _ => out.push(c),
        }
    }
    out
}

/// True when `text` contains an unsafe construct outside raw strings,
/// string literals, and comments.
fn contains_unsafe_construct(text: &str) -> bool {
    let blanked = blank_span_prose(text);
    blanked
        .lines()
        .any(|line| UNSAFE_FORMS.iter().any(|form| code_only(line).contains(form)))
}

/// True when `text` re-weakens the prohibition to a cfg-relaxed form. The
/// relaxed attribute is a crate-root inner attribute, so only lines whose
/// code content starts with `#![cfg_attr(` count; prose inside strings or
/// comments never does.
fn weakens_prohibition(text: &str) -> bool {
    text.lines().any(|line| {
        let code = code_only(line);
        let trimmed = code.trim_start();
        trimmed.starts_with("#![cfg_attr(")
            && (trimmed.contains("not(test), forbid(unsafe_code)")
                || trimmed.contains("test, allow(unsafe_code)"))
    })
}

/// The syntactic forms that introduce unsafe code. The `unsafe_code` lint
/// identifier and doc/comment prose that merely mention "unsafe" are
/// deliberately not matched.
const UNSAFE_FORMS: &[&str] = &[
    "unsafe {",
    "unsafe fn ",
    "unsafe impl ",
    "unsafe trait ",
    "unsafe extern ",
];

/// The cfg-relaxed weakening of the unsafe prohibition must never reappear in
/// any workspace source file.
#[test]
fn no_source_file_reweakens_the_unsafe_prohibition() {
    let sources = workspace_rust_sources();
    let mut offenders = Vec::new();
    for path in &sources {
        let text = std::fs::read_to_string(path).expect("read workspace source");
        if weakens_prohibition(&text) {
            offenders.push(path.display().to_string());
        }
    }
    assert!(
        offenders.is_empty(),
        "these files re-weaken the unsafe prohibition to a cfg-relaxed form; \
         restore an unconditional #![forbid(unsafe_code)]:\n  {}",
        offenders.join("\n  ")
    );
}

/// No workspace source file may contain an unsafe block, fn, impl, trait, or
/// extern form. This mirrors what the unconditional `#![forbid(unsafe_code)]`
/// enforces at compile time, but keeps the prohibition legible as an explicit,
/// fail-closed source contract that a reviewer can point to.
#[test]
fn no_source_file_contains_unsafe_constructs() {
    let sources = workspace_rust_sources();

    let mut offenders = Vec::new();
    for path in &sources {
        let blanked = blank_span_prose(
            &std::fs::read_to_string(path).expect("read workspace source"),
        );
        for (line_no, line) in blanked.lines().enumerate() {
            if UNSAFE_FORMS.iter().any(|form| code_only(line).contains(form)) {
                offenders.push(format!("{}:{}", path.display(), line_no + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "workspace source must be free of unsafe constructs (AGENTS.md), found:\n  {}",
        offenders.join("\n  ")
    );
}

/// Every workspace crate root retains the unconditional prohibition (not
/// merely the absence of the weakened form — the attribute must be present).
#[test]
fn crate_roots_declare_unconditional_forbid() {
    let root = workspace_root();
    for crate_dir in WORKSPACE_CRATE_DIRS {
        let lib_rs = root.join(crate_dir).join("src").join("lib.rs");
        if !lib_rs.exists() {
            // Binary-only crates may legitimately lack src/lib.rs; their
            // main.rs is still covered by the construct scans above.
            continue;
        }
        let lib = std::fs::read_to_string(&lib_rs).expect("read crate lib.rs");
        assert!(
            lib.contains("#![forbid(unsafe_code)]"),
            "{} must declare an unconditional #![forbid(unsafe_code)]",
            lib_rs.display()
        );
        assert!(
            !weakens_prohibition(&lib),
            "{} must not exempt test builds from the unsafe prohibition",
            lib_rs.display()
        );
    }
}

// ---------------------------------------------------------------------------
// Mutation fixtures: each prohibited form must be rejected, and prose
// occurrences inside comments, string literals, or raw strings must not be
// flagged.
// ---------------------------------------------------------------------------

#[test]
fn detector_rejects_every_prohibited_unsafe_form() {
    let mutations: &[&str] = &[
        "fn f() { unsafe { std::env::remove_var(\"X\"); } }",
        "unsafe fn mutate_env(key: &str) {}",
        "unsafe impl Send for HostPtr {}",
        "unsafe trait RawEgress {}",
        "unsafe extern \"C\" { fn probe() -> i32; }",
        "#![cfg_attr(not(test), forbid(unsafe_code))]",
        "#![cfg_attr(test, allow(unsafe_code))]",
    ];
    for mutation in mutations {
        assert!(
            contains_unsafe_construct(mutation) || weakens_prohibition(mutation),
            "mutation fixture must be rejected: {mutation}"
        );
        assert!(
            weakens_prohibition(mutation) || code_only(mutation).contains("unsafe"),
            "comment/string stripping must not hide a real form: {mutation}"
        );
    }
}

#[test]
fn detector_does_not_flag_comment_or_string_prose() {
    let benign: &[&str] = &[
        "// unsafe { this is prose, not code }",
        "/// returns the `unsafe fn` documentation example",
        "let reason = \"no unsafe block here\";",
        "assert!(doc.contains(\"unsafe impl\"));",
        "let relaxed = \"cfg_attr(not(test), forbid(unsafe_code))\";",
    ];
    for sample in benign {
        assert!(
            !contains_unsafe_construct(sample),
            "comment/string prose must not be flagged as code: {sample}"
        );
        assert!(
            !weakens_prohibition(sample),
            "string-literal mention of the relaxed form must not fail the gate: {sample}"
        );
    }

    // Adversarial probes embed unsafe source inside raw strings as DATA; the
    // span blanking pass must keep that prose invisible to the scanner while
    // code outside the literal stays fully visible.
    let probe_fixture = r##"
fn wrap() {
    let probe = r#"unsafe { std::mem::transmute(forged) }"#;
    let _ = probe;
}
"##;
    assert!(
        !contains_unsafe_construct(probe_fixture),
        "raw-string embedded unsafe source must not be flagged"
    );

    let live_fixture = r##"
fn wrap() {
    let probe = r#"prose only"#;
    let _ = probe;
    let forged: Labeled<String> = unsafe { std::mem::transmute(raw) };
}
"##;
    assert!(
        contains_unsafe_construct(live_fixture),
        "live unsafe outside the raw string must still be flagged"
    );
}
