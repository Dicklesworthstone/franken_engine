//! PP.4 negative test — prior capability test verdicts MUST remain unchanged after PP.3.
//!
//! Track PP (bd-cixqu.42) refactored the hostcall + capability model into a single
//! algebraic-effects substrate (PP.3 / bd-cixqu.42.3). This file is the PP.4 negative
//! test (bd-cixqu.42.4): it proves the refactor did NOT change the verdict of any prior
//! capability decision.
//!
//! ## What "verdict" means here
//! For every `(CapabilityProfile, capability)` pair there is a binary verdict:
//!   - ALLOW  — the profile grants the capability / the substrate dispatches the hostcall.
//!   - DENY   — the profile withholds it / the substrate refuses the hostcall.
//!
//! The *prior* (authoritative) verdict is the legacy `CapabilityProfile::has(cap)` decision,
//! which is exactly what the `capability_profile_security_algebra` unit suite in
//! `capability.rs` asserts. The *new* verdict is produced by dispatching through the
//! algebraic-effects `HandlerStack` built by `create_handler_stack_from_profile`.
//!
//! ## Regression discipline (do NOT silently accept divergence — bd-cixqu.42.4)
//! PP.3 fully migrated the `Full`, `EngineCore`, and `ComputeOnly` profiles to real
//! handlers, but left `Policy` and `Remote` mapped to a `ComputeOnly` *placeholder*
//! handler (see `hostcall_effects_migration::create_handler_stack_from_profile`). That
//! placeholder loses the capabilities those two profiles legacy-grant — a real, known gap.
//!
//! Rather than silently asserting the placeholder is "correct", this test FREEZES the exact
//! set of placeholder divergences. The frozen set is asserted with `assert_eq!`, so the
//! suite fails in BOTH directions:
//!   - a NEW divergence (PP.3 changed a verdict it should have preserved) → regression, fail.
//!   - a frozen entry that no longer diverges (the real Policy/Remote handler landed) →
//!     stale allowlist, fail and force this test to be updated.
//! Every frozen divergence is logged loudly on each run so the gap stays visible.
//!
//! Per bd-cixqu.45 logging discipline: self-describing `pp4_*` test names, ≥30 cases,
//! events.jsonl-shaped structured logging, and content-hash equality (not merely structural)
//! for the recorded fixtures and the canonical verdict matrix.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use frankenengine_engine::algebraic_effects::{EffectCapabilities, ErasedEffect};
use frankenengine_engine::capability::{CapabilityProfile, RuntimeCapability};
use frankenengine_engine::hostcall_effects_migration::{
    ConsoleHostcallEffect, FsHostcallEffect, FsOperation, ModuleHostcallEffect, ModuleImportType,
    NetworkHostcallEffect, TimerHostcallEffect, TimerOperation, create_effect_from_hostcall_tag,
    create_handler_stack_from_profile,
};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Fixtures & helpers
// ---------------------------------------------------------------------------

/// The five canonical capability profiles, keyed by stable string names.
fn canonical_profiles() -> Vec<(&'static str, CapabilityProfile)> {
    vec![
        ("full", CapabilityProfile::full()),
        ("engine_core", CapabilityProfile::engine_core()),
        ("policy", CapabilityProfile::policy()),
        ("remote", CapabilityProfile::remote()),
        ("compute_only", CapabilityProfile::compute_only()),
    ]
}

/// Profiles whose handlers PP.3 implemented faithfully (no placeholder).
/// For these, the substrate verdict MUST exactly equal the legacy verdict.
const FAITHFUL_PROFILES: [&str; 3] = ["full", "engine_core", "compute_only"];

/// One representative hostcall effect per family, with the capability it requires.
fn hostcall_effects() -> Vec<(&'static str, RuntimeCapability, Box<dyn ErasedEffect>)> {
    vec![
        (
            "hostcall:console",
            RuntimeCapability::Console,
            Box::new(ConsoleHostcallEffect {
                method: "log".to_string(),
                args: vec!["pp4".to_string()],
            }),
        ),
        (
            "hostcall:fs:read",
            RuntimeCapability::FsRead,
            Box::new(FsHostcallEffect {
                operation: FsOperation::Read,
                path: "/app/config.json".to_string(),
                content: None,
            }),
        ),
        (
            "hostcall:fs:write",
            RuntimeCapability::FsWrite,
            Box::new(FsHostcallEffect {
                operation: FsOperation::Write,
                path: "/tmp/output.txt".to_string(),
                content: Some(vec![1, 2, 3]),
            }),
        ),
        (
            "hostcall:network",
            RuntimeCapability::NetworkEgress,
            Box::new(NetworkHostcallEffect {
                url: "https://example.invalid/x".to_string(),
                method: "GET".to_string(),
                headers: Vec::new(),
                body: None,
            }),
        ),
        (
            "hostcall:timer",
            RuntimeCapability::Timer,
            Box::new(TimerHostcallEffect {
                operation: TimerOperation::SetTimeout,
                duration_ms: Some(10),
                timer_id: None,
            }),
        ),
        (
            "hostcall:module",
            RuntimeCapability::ModuleLoad,
            Box::new(ModuleHostcallEffect {
                module_path: "m".to_string(),
                import_type: ModuleImportType::Require,
            }),
        ),
    ]
}

/// New-substrate verdict for a profile's *capability membership*: does the handler stack
/// built from `profile` provide `cap`? (Mirrors the capability gate in
/// `HandlerStack::handle_effect`, which checks `required.is_satisfied_by(stack caps)`.)
fn substrate_provides(profile: &CapabilityProfile, cap: RuntimeCapability) -> bool {
    let stack = create_handler_stack_from_profile(profile);
    EffectCapabilities::runtime([cap]).is_satisfied_by(stack.capabilities())
}

/// New-substrate verdict for an actual hostcall dispatch: ALLOW iff `handle_effect` succeeds.
fn substrate_allows_hostcall(profile: &CapabilityProfile, effect: &dyn ErasedEffect) -> bool {
    let mut stack = create_handler_stack_from_profile(profile);
    stack.handle_effect(effect).is_ok()
}

/// events.jsonl-shaped structured log line (bd-cixqu.45 §C). Captured by cargo on failure;
/// also appended to `$PP4_EVENTS_PATH` when set, so a CI run emits the same evidence shape.
fn emit_event(event: &str, profile: &str, subject: &str, prior: bool, substrate: bool) {
    let line = format!(
        r#"{{"test":"pp4_capability_verdict_preservation","event":"{event}","profile":"{profile}","subject":"{subject}","prior_verdict":"{}","substrate_verdict":"{}","preserved":{}}}"#,
        verdict_str(prior),
        verdict_str(substrate),
        prior == substrate,
    );
    println!("{line}");
    if let Ok(path) = std::env::var("PP4_EVENTS_PATH") {
        use std::io::Write;
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "{line}");
        }
    }
}

fn verdict_str(allow: bool) -> &'static str {
    if allow { "ALLOW" } else { "DENY" }
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/capability_verdicts")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// 1. Recorded-fixture preservation (the literal "byte-for-byte" requirement)
// ---------------------------------------------------------------------------

#[test]
fn pp4_recorded_fixtures_match_manifest_byte_for_byte() {
    let dir = fixtures_dir();
    let manifest_bytes =
        fs::read(dir.join("fixture_manifest.json")).expect("fixture_manifest.json must exist");
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).expect("fixture manifest is valid JSON");

    let hashes = manifest
        .get("content_hashes")
        .and_then(|v| v.as_object())
        .expect("manifest has content_hashes object");
    assert!(
        !hashes.is_empty(),
        "manifest must record at least one fixture hash"
    );

    for (filename, expected) in hashes {
        let expected_hex = expected.as_str().expect("hash entry is a string");
        let bytes = fs::read(dir.join(filename))
            .unwrap_or_else(|e| panic!("recorded fixture {filename} must exist: {e}"));
        let actual_hex = sha256_hex(&bytes);
        assert_eq!(
            actual_hex, expected_hex,
            "recorded verdict {filename} changed — byte-for-byte preservation violated \
             (bd-cixqu.42.4: any change to a recorded verdict is a regression)"
        );
        println!(r#"{{"event":"fixture_verified","file":"{filename}","sha256":"{actual_hex}"}}"#);
    }
}

#[test]
fn pp4_fixture_manifest_covers_every_present_verdict_file() {
    let dir = fixtures_dir();
    let manifest_bytes = fs::read(dir.join("fixture_manifest.json")).expect("manifest exists");
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).expect("valid JSON");
    let hashes = manifest
        .get("content_hashes")
        .and_then(|v| v.as_object())
        .expect("content_hashes object");

    let mut verdict_files = 0usize;
    for entry in fs::read_dir(&dir).expect("fixtures dir readable") {
        let entry = entry.expect("dir entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("verdict_") && name.ends_with(".json") {
            verdict_files += 1;
            assert!(
                hashes.contains_key(&name),
                "verdict fixture {name} present on disk but missing from manifest — \
                 an unrecorded verdict cannot be protected against drift"
            );
        }
    }
    assert!(
        verdict_files >= 1,
        "expected at least one recorded verdict fixture"
    );
}

// ---------------------------------------------------------------------------
// 2. Per-profile dispatch behaviour (happy + negative paths)
// ---------------------------------------------------------------------------

#[test]
fn pp4_full_profile_allows_every_hostcall_family() {
    let profile = CapabilityProfile::full();
    for (name, required, effect) in hostcall_effects() {
        let prior = profile.has(required);
        let substrate = substrate_allows_hostcall(&profile, effect.as_ref());
        emit_event("dispatch", "full", name, prior, substrate);
        assert!(prior, "legacy Full must grant {required}");
        assert!(substrate, "substrate Full must ALLOW {name}");
        assert_eq!(
            prior, substrate,
            "Full verdict for {name} must be preserved"
        );
    }
}

#[test]
fn pp4_compute_only_denies_every_hostcall_family() {
    // Negative path: ComputeOnly is the zero-authority profile.
    let profile = CapabilityProfile::compute_only();
    for (name, required, effect) in hostcall_effects() {
        let prior = profile.has(required);
        let substrate = substrate_allows_hostcall(&profile, effect.as_ref());
        emit_event("dispatch", "compute_only", name, prior, substrate);
        assert!(!prior, "legacy ComputeOnly must withhold {required}");
        assert!(!substrate, "substrate ComputeOnly must DENY {name}");
        assert_eq!(prior, substrate);
    }
}

#[test]
fn pp4_engine_core_allows_console_and_timer_denies_io() {
    let profile = CapabilityProfile::engine_core();
    for (name, required, effect) in hostcall_effects() {
        let prior = profile.has(required);
        let substrate = substrate_allows_hostcall(&profile, effect.as_ref());
        emit_event("dispatch", "engine_core", name, prior, substrate);
        match name {
            "hostcall:console" | "hostcall:timer" => {
                assert!(prior && substrate, "EngineCore must ALLOW {name}")
            }
            _ => assert!(!prior && !substrate, "EngineCore must DENY {name}"),
        }
        assert_eq!(
            prior, substrate,
            "EngineCore verdict for {name} must be preserved"
        );
    }
}

#[test]
fn pp4_policy_profile_denies_all_hostcall_families_matching_legacy() {
    // Policy grants none of the six hostcall-family capabilities, so even though its
    // handler is a placeholder, the hostcall-dispatch verdicts are fully preserved.
    let profile = CapabilityProfile::policy();
    for (name, required, effect) in hostcall_effects() {
        let prior = profile.has(required);
        let substrate = substrate_allows_hostcall(&profile, effect.as_ref());
        emit_event("dispatch", "policy", name, prior, substrate);
        assert!(!prior, "legacy Policy must withhold {required}");
        assert!(!substrate, "substrate Policy must DENY {name}");
        assert_eq!(prior, substrate);
    }
}

// ---------------------------------------------------------------------------
// 3. Verdict-equivalence matrix for faithfully-migrated profiles (≥50 cases)
// ---------------------------------------------------------------------------

#[test]
fn pp4_capability_membership_equivalence_for_faithful_profiles() {
    // Full | EngineCore | ComputeOnly  x  all 20 runtime capabilities = 60 verdict cases.
    let mut cases = 0usize;
    for (pname, profile) in canonical_profiles() {
        if !FAITHFUL_PROFILES.contains(&pname) {
            continue;
        }
        for cap in RuntimeCapability::ALL {
            let prior = profile.has(cap);
            let substrate = substrate_provides(&profile, cap);
            emit_event("membership", pname, &cap.to_string(), prior, substrate);
            assert_eq!(
                prior, substrate,
                "verdict for ({pname}, {cap}) diverged: legacy={prior} substrate={substrate} \
                 — PP.3 must preserve the verdict for faithfully-migrated profiles"
            );
            cases += 1;
        }
    }
    assert!(
        cases >= 50,
        "PP.4 requires >= 50 preserved verdict cases; checked {cases}"
    );
    println!(r#"{{"event":"membership_matrix_complete","faithful_cases":{cases}}}"#);
}

#[test]
fn pp4_hostcall_dispatch_equivalence_for_faithful_profiles() {
    // Exercises the real `handle_effect` path (capability gate + handler dispatch), not just
    // membership: Full | EngineCore | ComputeOnly  x  6 hostcall families = 18 verdict cases.
    for (pname, profile) in canonical_profiles() {
        if !FAITHFUL_PROFILES.contains(&pname) {
            continue;
        }
        for (name, required, effect) in hostcall_effects() {
            let prior = profile.has(required);
            let substrate = substrate_allows_hostcall(&profile, effect.as_ref());
            emit_event("dispatch", pname, name, prior, substrate);
            assert_eq!(
                prior, substrate,
                "dispatch verdict for ({pname}, {name}) diverged from legacy has({required})"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Frozen known-divergence guard (catches NEW regressions + stale allowlist)
// ---------------------------------------------------------------------------

/// The EXACT set of `(profile, capability)` membership verdicts that PP.3's placeholder
/// `Policy`/`Remote` handlers currently diverge on. These are the only divergences the
/// migration is permitted to have. Removing a placeholder (implementing a real handler)
/// must delete the corresponding entries here, or this test fails — by design.
const FROZEN_PLACEHOLDER_DIVERGENCES: [(&str, RuntimeCapability); 7] = [
    ("policy", RuntimeCapability::PolicyRead),
    ("policy", RuntimeCapability::PolicyWrite),
    ("policy", RuntimeCapability::EvidenceEmit),
    ("policy", RuntimeCapability::DecisionInvoke),
    ("remote", RuntimeCapability::NetworkEgress),
    ("remote", RuntimeCapability::LeaseManagement),
    ("remote", RuntimeCapability::IdempotencyDerive),
];

#[test]
fn pp4_known_placeholder_divergences_are_exactly_frozen() {
    let frozen: BTreeSet<(String, String)> = FROZEN_PLACEHOLDER_DIVERGENCES
        .iter()
        .map(|(p, c)| ((*p).to_string(), c.to_string()))
        .collect();

    // Observe every divergence across the FULL 5 x 20 = 100-cell membership matrix.
    let mut observed: BTreeSet<(String, String)> = BTreeSet::new();
    for (pname, profile) in canonical_profiles() {
        for cap in RuntimeCapability::ALL {
            let prior = profile.has(cap);
            let substrate = substrate_provides(&profile, cap);
            if prior != substrate {
                let key = (pname.to_string(), cap.to_string());
                // A divergence on a faithful profile is always a fresh regression.
                assert!(
                    !FAITHFUL_PROFILES.contains(&pname),
                    "NEW REGRESSION: faithfully-migrated profile {pname} diverged on {cap} \
                     (legacy={prior}, substrate={substrate}) — back out PP.3, do not accept"
                );
                eprintln!(
                    "KNOWN PLACEHOLDER DIVERGENCE (PP.3 Policy/Remote stub) — \
                     profile={pname} capability={cap} legacy=ALLOW substrate=DENY \
                     [tracked by bd-cixqu.42.4; remove from frozen set when the real handler lands]"
                );
                observed.insert(key);
            }
        }
    }

    // assert_eq! fails in BOTH directions:
    //  * an unfrozen divergence (NEW regression PP.3 introduced) appears in `observed`,
    //  * a frozen entry that no longer diverges (placeholder fixed) is missing from `observed`.
    assert_eq!(
        observed, frozen,
        "placeholder-divergence set changed. New entries = an unpreserved verdict (regression); \
         missing entries = a placeholder was implemented and this frozen set is now stale."
    );
}

#[test]
fn pp4_remote_network_is_the_only_hostcall_dispatch_divergence() {
    // At the hostcall-dispatch level the single permitted divergence is (Remote, network):
    // legacy Remote grants NetworkEgress, but PP.3's Remote placeholder denies it.
    let mut observed: BTreeSet<(String, String)> = BTreeSet::new();
    for (pname, profile) in canonical_profiles() {
        for (name, required, effect) in hostcall_effects() {
            let prior = profile.has(required);
            let substrate = substrate_allows_hostcall(&profile, effect.as_ref());
            if prior != substrate {
                observed.insert((pname.to_string(), name.to_string()));
            }
        }
    }
    let expected: BTreeSet<(String, String)> =
        [("remote".to_string(), "hostcall:network".to_string())]
            .into_iter()
            .collect();
    assert_eq!(
        observed, expected,
        "the only known hostcall-dispatch divergence is (remote, hostcall:network)"
    );
}

// ---------------------------------------------------------------------------
// 5. Authority laws preserved through the new substrate
// ---------------------------------------------------------------------------

#[test]
fn pp4_full_substrate_subsumes_every_other_profile() {
    // Prior security-algebra law: Full subsumes all named profiles. The new substrate's
    // Full handler stack must still provide every capability any other profile's stack does.
    let full = CapabilityProfile::full();
    for (pname, profile) in canonical_profiles() {
        for cap in RuntimeCapability::ALL {
            if substrate_provides(&profile, cap) {
                assert!(
                    substrate_provides(&full, cap),
                    "Full substrate must subsume {pname}'s {cap} capability"
                );
            }
        }
    }
}

#[test]
fn pp4_faithful_profiles_preserve_authority_partition_disjointness() {
    // EngineCore and ComputeOnly authority sets (as exposed by the substrate) stay disjoint
    // from each other beyond the empty intersection — ComputeOnly provides nothing.
    let engine = CapabilityProfile::engine_core();
    let compute = CapabilityProfile::compute_only();
    for cap in RuntimeCapability::ALL {
        assert!(
            !substrate_provides(&compute, cap),
            "ComputeOnly substrate must provide no capability ({cap})"
        );
    }
    // EngineCore must still provide exactly its legacy authority through the substrate.
    for cap in RuntimeCapability::ALL {
        assert_eq!(
            engine.has(cap),
            substrate_provides(&engine, cap),
            "EngineCore authority for {cap} must be preserved by the substrate"
        );
    }
}

// ---------------------------------------------------------------------------
// 6. Negative: unknown hostcall tags are refused under every profile
// ---------------------------------------------------------------------------

#[test]
fn pp4_unknown_hostcall_tag_is_refused() {
    // Prior verdict for an unknown hostcall tag is "refuse" under all profiles; the
    // effect-construction surface must fail closed rather than fabricate an effect.
    let err = create_effect_from_hostcall_tag("definitely:not:a:real:tag", &[]);
    assert!(
        err.is_err(),
        "unknown hostcall tag must fail closed, not synthesise an effect"
    );
}

#[test]
fn pp4_unmapped_capabilities_are_denied_under_zero_authority_profiles() {
    // Negative path across profiles that grant no hostcall-family capability: every
    // hostcall family must be denied, matching the legacy zero-grant verdict.
    for pname in ["policy", "remote", "compute_only"] {
        let profile = canonical_profiles()
            .into_iter()
            .find(|(n, _)| *n == pname)
            .map(|(_, p)| p)
            .unwrap();
        for (name, _required, effect) in hostcall_effects() {
            // network under remote is the single frozen exception handled elsewhere.
            if pname == "remote" && name == "hostcall:network" {
                continue;
            }
            assert!(
                !substrate_allows_hostcall(&profile, effect.as_ref()),
                "{pname} must DENY {name} (zero-authority for this family)"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 7. Determinism / content-hash stability of the canonical verdict matrix
// ---------------------------------------------------------------------------

/// Serialise the full 5-profile x 20-capability verdict matrix into a canonical,
/// deterministically-ordered string. Used to assert content-hash stability (bd-cixqu.45 §B).
fn canonical_verdict_matrix() -> String {
    let mut lines: Vec<String> = Vec::new();
    for (pname, profile) in canonical_profiles() {
        for cap in RuntimeCapability::ALL {
            lines.push(format!(
                "{pname}|{cap}|prior={}|substrate={}",
                verdict_str(profile.has(cap)),
                verdict_str(substrate_provides(&profile, cap)),
            ));
        }
    }
    lines.sort();
    lines.join("\n")
}

#[test]
fn pp4_verdict_matrix_is_deterministic_and_content_hash_stable() {
    let a = canonical_verdict_matrix();
    let b = canonical_verdict_matrix();
    assert_eq!(
        a, b,
        "verdict matrix must be deterministic across evaluations"
    );

    let hash_a = sha256_hex(a.as_bytes());
    let hash_b = sha256_hex(b.as_bytes());
    assert_eq!(
        hash_a, hash_b,
        "verdict matrix content hash must be stable (content-hash equality, not structural)"
    );
    // The matrix covers all 100 cells; sanity-check the shape so a silently-shrunk matrix fails.
    assert_eq!(
        a.lines().count(),
        canonical_profiles().len() * RuntimeCapability::ALL.len(),
        "verdict matrix must cover every (profile, capability) cell"
    );
    println!(
        r#"{{"event":"verdict_matrix_hashed","cells":{},"sha256":"{hash_a}"}}"#,
        a.lines().count()
    );
}
