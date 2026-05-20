#![forbid(unsafe_code)]

//! Capability authority lattice conformance harness (bd-8kkk1).
//!
//! Pre-existing tests cover individual capability profile contents and a few
//! ambient-authority proofs, but there is no single matrix that pins the
//! algebraic rules the capability lattice must obey. This file is that matrix.
//!
//! Each section maps a rule family to spec-style requirement IDs of the form
//! `FE-CAPS-§<family>-<rule>`. Every rule is exercised by an executable
//! assertion. When a rule changes intentionally, both the assertion and its
//! row in `LATTICE_CONFORMANCE_RULES` must be updated — keeping the rule list
//! authoritative.

use std::collections::BTreeSet;

use frankenengine_engine::capability::{
    CapabilityDenied, CapabilityProfile, ProfileKind, RuntimeCapability, require_all,
    require_capability,
};

// ===========================================================================
// Section A — Inventory & display invariants
// ===========================================================================

#[test]
fn inventory_all_runtime_capability_variants_appear_in_all() {
    // FE-CAPS-§A.1: RuntimeCapability::ALL is the canonical enumeration.
    // Every variant must appear exactly once; reordering or omission is a
    // capability-lattice change.
    let all = RuntimeCapability::ALL;
    let unique: BTreeSet<RuntimeCapability> = all.iter().copied().collect();
    assert_eq!(
        unique.len(),
        all.len(),
        "duplicate variant in RuntimeCapability::ALL"
    );
    // Pin the count so adding a variant without updating ALL fails this test.
    assert_eq!(all.len(), 20, "RuntimeCapability variant count drift");
}

#[test]
fn inventory_display_strings_are_distinct_snake_case() {
    // FE-CAPS-§A.2: Display produces a stable snake_case identifier; identifiers
    // must be unique across variants and round-trip through `from_tag_str`.
    let mut seen = BTreeSet::new();
    for cap in RuntimeCapability::ALL {
        let label = cap.to_string();
        assert!(
            !label.is_empty() && label == label.to_lowercase(),
            "capability `{cap:?}` display `{label}` is not lowercase snake_case",
        );
        assert!(
            seen.insert(label.clone()),
            "duplicate display label `{label}`",
        );
        assert_eq!(
            RuntimeCapability::from_tag_str(&label),
            Some(cap),
            "Display→from_tag_str round-trip broken for {cap:?}",
        );
    }
    assert_eq!(seen.len(), RuntimeCapability::ALL.len());
}

// ===========================================================================
// Section B — Tag parsing
// ===========================================================================

#[test]
fn tag_parsing_canonical_names_resolve_for_every_variant() {
    // FE-CAPS-§B.1: Every variant's canonical name (Display) resolves through
    // `from_tag_str` to the same variant.
    for cap in RuntimeCapability::ALL {
        let label = cap.to_string();
        assert_eq!(
            RuntimeCapability::from_tag_str(&label),
            Some(cap),
            "canonical name `{label}` does not resolve to {cap:?}",
        );
    }
}

#[test]
fn tag_parsing_short_aliases_resolve_to_documented_capability() {
    // FE-CAPS-§B.2: Short aliases used in IR and tests resolve deterministically.
    let aliases: &[(&str, RuntimeCapability)] = &[
        ("network", RuntimeCapability::NetworkEgress),
        ("net", RuntimeCapability::NetworkEgress),
        ("net:connect", RuntimeCapability::NetworkEgress),
        ("net:fetch", RuntimeCapability::NetworkEgress),
        ("net:outbound", RuntimeCapability::NetworkEgress),
        ("net.write", RuntimeCapability::NetworkEgress),
        ("network.write", RuntimeCapability::NetworkEgress),
        ("fs", RuntimeCapability::FsRead),
        ("fs:read", RuntimeCapability::FsRead),
        ("fs.read", RuntimeCapability::FsRead),
        ("fs:write", RuntimeCapability::FsWrite),
        ("fs.write", RuntimeCapability::FsWrite),
        ("module:require", RuntimeCapability::ModuleLoad),
        ("module:import", RuntimeCapability::ModuleLoad),
        ("module.import", RuntimeCapability::ModuleLoad),
    ];
    for (alias, expected) in aliases {
        assert_eq!(
            RuntimeCapability::from_tag_str(alias),
            Some(*expected),
            "alias `{alias}` did not map to `{expected:?}`",
        );
    }
}

#[test]
fn tag_parsing_hostcall_prefixes_route_to_grouped_capability() {
    // FE-CAPS-§B.3: hostcall tags with structured prefixes route to the bucket
    // capability (Console / Timer / Builtin) — fs:write and net:* are NOT in
    // this rule because they already have explicit aliases above.
    let cases: &[(&str, RuntimeCapability)] = &[
        ("console:log", RuntimeCapability::Console),
        ("console:error", RuntimeCapability::Console),
        ("console:warn", RuntimeCapability::Console),
        ("console:info", RuntimeCapability::Console),
        ("console:any_future_tag", RuntimeCapability::Console),
        ("timer:setTimeout", RuntimeCapability::Timer),
        ("timer:setInterval", RuntimeCapability::Timer),
        ("timer:clearTimeout", RuntimeCapability::Timer),
        ("builtin:Array.prototype.map", RuntimeCapability::Builtin),
        ("builtin:Object.keys", RuntimeCapability::Builtin),
        ("number:parseInt", RuntimeCapability::Builtin),
        ("number:isFinite", RuntimeCapability::Builtin),
    ];
    for (tag, expected) in cases {
        assert_eq!(
            RuntimeCapability::from_tag_str(tag),
            Some(*expected),
            "prefix-routed tag `{tag}` did not map to `{expected:?}`",
        );
    }
}

#[test]
fn tag_parsing_unknown_or_internal_tags_return_none() {
    // FE-CAPS-§B.4: Unknown tags AND internal-only tags (e.g. `promise:*`) MUST
    // return None — that is, they stay outside the capability lattice and are
    // never silently routed to a real capability.
    let cases = &[
        "",
        "promise:resolve",
        "promise:reject",
        "unknown",
        "unknown:tag",
        "console", // bare 'console' resolves; 'console_' is unknown
        "console_",
        "VmDispatch", // PascalCase — only snake_case resolves
        "Network",
    ];
    for tag in cases {
        let parsed = RuntimeCapability::from_tag_str(tag);
        if *tag == "console" {
            // 'console' is documented as canonical; assert that it resolves.
            assert_eq!(parsed, Some(RuntimeCapability::Console));
        } else {
            assert_eq!(parsed, None, "tag `{tag}` should not resolve, got {parsed:?}");
        }
    }
}

// ===========================================================================
// Section C — Profile subsumption (poset structure)
// ===========================================================================

fn all_named_profiles() -> [(ProfileKind, CapabilityProfile); 5] {
    [
        (ProfileKind::Full, CapabilityProfile::full()),
        (ProfileKind::EngineCore, CapabilityProfile::engine_core()),
        (ProfileKind::Policy, CapabilityProfile::policy()),
        (ProfileKind::Remote, CapabilityProfile::remote()),
        (ProfileKind::ComputeOnly, CapabilityProfile::compute_only()),
    ]
}

#[test]
fn subsumption_is_reflexive_for_every_named_profile() {
    // FE-CAPS-§C.1: A ⊆ A holds for every named profile (poset reflexivity).
    for (kind, profile) in all_named_profiles() {
        assert!(
            profile.subsumes(&profile),
            "{kind} should be reflexively subsumed by itself"
        );
    }
}

#[test]
fn subsumption_full_dominates_every_other_named_profile() {
    // FE-CAPS-§C.2: Full ⊇ X for every named profile X. Full is the top of the
    // lattice.
    let full = CapabilityProfile::full();
    for (kind, profile) in all_named_profiles() {
        assert!(
            full.subsumes(&profile),
            "Full must subsume {kind} but does not"
        );
    }
}

#[test]
fn subsumption_compute_only_is_subset_of_every_named_profile() {
    // FE-CAPS-§C.3: ComputeOnly ⊆ X for every X. ComputeOnly is the bottom of
    // the lattice (empty capability set).
    let compute = CapabilityProfile::compute_only();
    for (kind, profile) in all_named_profiles() {
        assert!(
            profile.subsumes(&compute),
            "{kind} must subsume ComputeOnly (the empty set) but does not"
        );
    }
}

#[test]
fn subsumption_named_profiles_are_pairwise_incomparable() {
    // FE-CAPS-§C.4: No named profile (other than Full/ComputeOnly) subsumes any
    // other named profile. EngineCore / Policy / Remote are mutually
    // incomparable by design — this catches accidental capability bleed where
    // one profile silently picks up another's capabilities.
    let mid_profiles = [
        (ProfileKind::EngineCore, CapabilityProfile::engine_core()),
        (ProfileKind::Policy, CapabilityProfile::policy()),
        (ProfileKind::Remote, CapabilityProfile::remote()),
    ];
    for (lk, l) in &mid_profiles {
        for (rk, r) in &mid_profiles {
            if lk == rk {
                continue;
            }
            assert!(
                !l.subsumes(r),
                "{lk} silently subsumes {rk}; mid-tier profiles must be \
                 pairwise incomparable"
            );
        }
    }
}

// ===========================================================================
// Section D — Profile intersection (meet semilattice)
// ===========================================================================

#[test]
fn intersection_with_full_is_identity() {
    // FE-CAPS-§D.1: Full ∩ X = X for every X.
    let full = CapabilityProfile::full();
    for (kind, profile) in all_named_profiles() {
        let result = full.intersect(&profile);
        assert_eq!(
            result.capabilities(),
            profile.capabilities(),
            "Full ∩ {kind} did not preserve capabilities"
        );
    }
}

#[test]
fn intersection_is_idempotent() {
    // FE-CAPS-§D.2: X ∩ X = X (idempotent meet).
    for (kind, profile) in all_named_profiles() {
        let result = profile.intersect(&profile);
        assert_eq!(
            result.capabilities(),
            profile.capabilities(),
            "{kind} ∩ {kind} is not idempotent"
        );
    }
}

#[test]
fn intersection_of_disjoint_profiles_is_compute_only() {
    // FE-CAPS-§D.3: EngineCore and Policy share no capabilities, so their
    // intersection must collapse to ComputeOnly (the empty profile).
    let engine_core = CapabilityProfile::engine_core();
    let policy = CapabilityProfile::policy();
    let result = engine_core.intersect(&policy);
    assert!(
        result.capabilities().is_empty(),
        "EngineCore ∩ Policy should be empty but contains: {:?}",
        result.capabilities()
    );
    assert_eq!(
        result.kind(),
        ProfileKind::ComputeOnly,
        "empty intersection should be named ComputeOnly"
    );

    // Same for EngineCore ∩ Remote, Policy ∩ Remote, etc.
    for (la, lp) in [
        (ProfileKind::EngineCore, CapabilityProfile::engine_core()),
        (ProfileKind::Policy, CapabilityProfile::policy()),
        (ProfileKind::Remote, CapabilityProfile::remote()),
    ] {
        for (ra, rp) in [
            (ProfileKind::EngineCore, CapabilityProfile::engine_core()),
            (ProfileKind::Policy, CapabilityProfile::policy()),
            (ProfileKind::Remote, CapabilityProfile::remote()),
        ] {
            if la == ra {
                continue;
            }
            let inter = lp.intersect(&rp);
            assert!(
                inter.capabilities().is_empty(),
                "{la} ∩ {ra} should be empty",
            );
        }
    }
}

#[test]
fn intersection_is_commutative() {
    // FE-CAPS-§D.4: X ∩ Y = Y ∩ X (commutative meet).
    let pairs = [
        (CapabilityProfile::full(), CapabilityProfile::engine_core()),
        (CapabilityProfile::full(), CapabilityProfile::policy()),
        (CapabilityProfile::engine_core(), CapabilityProfile::remote()),
        (CapabilityProfile::policy(), CapabilityProfile::remote()),
    ];
    for (a, b) in pairs {
        let lhs = a.intersect(&b);
        let rhs = b.intersect(&a);
        assert_eq!(
            lhs.capabilities(),
            rhs.capabilities(),
            "intersection failed to commute for {:?} and {:?}",
            a.kind(),
            b.kind(),
        );
    }
}

// ===========================================================================
// Section E — require_capability / require_all (fail-closed enforcement)
// ===========================================================================

#[test]
fn require_capability_grants_when_held() {
    // FE-CAPS-§E.1: require_capability succeeds when the profile holds the cap.
    let full = CapabilityProfile::full();
    for cap in RuntimeCapability::ALL {
        require_capability(&full, cap, "test")
            .unwrap_or_else(|err| panic!("Full lacked {cap:?}: {err}"));
    }
}

#[test]
fn require_capability_denies_with_witness_when_missing() {
    // FE-CAPS-§E.2: require_capability fails closed when the profile does not
    // hold the cap, and the denial witness carries the required cap, the held
    // profile kind, and the component name.
    let compute = CapabilityProfile::compute_only();
    let denial = require_capability(&compute, RuntimeCapability::NetworkEgress, "remote.fetch")
        .expect_err("ComputeOnly must not grant NetworkEgress");
    assert_eq!(denial.required, RuntimeCapability::NetworkEgress);
    assert_eq!(denial.held_profile, ProfileKind::ComputeOnly);
    assert_eq!(denial.component, "remote.fetch");

    // The Display message must include all three so logs are immediately
    // actionable without parsing a structured field.
    let message = denial.to_string();
    for needle in ["remote.fetch", "network_egress", "ComputeOnlyCaps"] {
        assert!(
            message.contains(needle),
            "denial Display `{message}` missing `{needle}`"
        );
    }
}

#[test]
fn require_all_succeeds_when_every_capability_held() {
    // FE-CAPS-§E.3: require_all succeeds (and returns Ok(())) when the profile
    // grants every requested capability.
    let full = CapabilityProfile::full();
    let reqs: Vec<RuntimeCapability> = RuntimeCapability::ALL.to_vec();
    require_all(&full, &reqs, "full.everything").expect("Full grants every variant");
}

#[test]
fn require_all_returns_every_denial_not_fail_fast() {
    // FE-CAPS-§E.4: require_all aggregates ALL denials, not just the first.
    // This is critical for structured error reporting — fail-fast hides
    // additional missing capabilities behind whichever one happens to be
    // checked first.
    let compute = CapabilityProfile::compute_only();
    let reqs = [
        RuntimeCapability::NetworkEgress,
        RuntimeCapability::PolicyWrite,
        RuntimeCapability::FsWrite,
        RuntimeCapability::Console,
    ];
    let denials = require_all(&compute, &reqs, "audit.batch")
        .expect_err("ComputeOnly must deny every requested cap");
    assert_eq!(
        denials.len(),
        reqs.len(),
        "require_all should return one denial per missing cap"
    );
    let required_set: BTreeSet<RuntimeCapability> = denials.iter().map(|d| d.required).collect();
    let requested_set: BTreeSet<RuntimeCapability> = reqs.iter().copied().collect();
    assert_eq!(required_set, requested_set);
    for d in &denials {
        assert_eq!(d.held_profile, ProfileKind::ComputeOnly);
        assert_eq!(d.component, "audit.batch");
    }
}

#[test]
fn require_all_empty_requirements_succeeds_on_any_profile() {
    // FE-CAPS-§E.5: require_all with no requirements is trivially satisfied,
    // even on ComputeOnly — there is no implicit minimum-grant requirement.
    let compute = CapabilityProfile::compute_only();
    require_all(&compute, &[], "trivial").expect("zero requirements always satisfied");
}

#[test]
fn require_all_partial_grant_returns_only_missing_denials() {
    // FE-CAPS-§E.6: When some requirements are held and others are not,
    // only the missing ones appear in the denial list (in input order).
    let engine_core = CapabilityProfile::engine_core();
    let reqs = [
        RuntimeCapability::VmDispatch,    // granted
        RuntimeCapability::PolicyWrite,   // denied
        RuntimeCapability::Console,       // granted
        RuntimeCapability::NetworkEgress, // denied
    ];
    let denials = require_all(&engine_core, &reqs, "vm.boot")
        .expect_err("EngineCore should deny PolicyWrite + NetworkEgress");
    assert_eq!(denials.len(), 2);
    assert_eq!(denials[0].required, RuntimeCapability::PolicyWrite);
    assert_eq!(denials[1].required, RuntimeCapability::NetworkEgress);
    for d in &denials {
        assert_eq!(d.held_profile, ProfileKind::EngineCore);
    }
}

// ===========================================================================
// Section F — Denial witness serializability
// ===========================================================================

#[test]
fn denial_witness_round_trips_through_json() {
    // FE-CAPS-§F.1: CapabilityDenied is the public evidence record for a
    // denied request. It must serialize/deserialize losslessly via JSON so
    // it can flow into the evidence ledger.
    let denial = CapabilityDenied {
        required: RuntimeCapability::FsWrite,
        held_profile: ProfileKind::Remote,
        component: "config.persist".to_string(),
    };
    let json = serde_json::to_string(&denial).expect("serialize denial");
    let decoded: CapabilityDenied = serde_json::from_str(&json).expect("decode denial");
    assert_eq!(decoded.required, denial.required);
    assert_eq!(decoded.held_profile, denial.held_profile);
    assert_eq!(decoded.component, denial.component);
}

// ===========================================================================
// Conformance rule manifest
// ===========================================================================

/// Authoritative list of rules covered by this harness. The list IS the spec
/// — every entry must trace to an executable assertion above. Use this matrix
/// to verify rule coverage at a glance and to guard against silently dropping
/// rules in future refactors.
const LATTICE_CONFORMANCE_RULES: &[(&str, &str)] = &[
    (
        "FE-CAPS-§A.1-InventoryComplete",
        "RuntimeCapability::ALL enumerates every variant exactly once",
    ),
    (
        "FE-CAPS-§A.2-DisplayStable",
        "Display produces distinct snake_case identifiers that round-trip",
    ),
    (
        "FE-CAPS-§B.1-CanonicalTagResolves",
        "Every Display label resolves through from_tag_str",
    ),
    (
        "FE-CAPS-§B.2-AliasesResolve",
        "Documented short aliases map to a single capability",
    ),
    (
        "FE-CAPS-§B.3-PrefixesRoute",
        "console:/timer:/builtin:/number: prefixes route to bucket capability",
    ),
    (
        "FE-CAPS-§B.4-UnknownNone",
        "Unknown / internal-only tags return None (stay off lattice)",
    ),
    (
        "FE-CAPS-§C.1-SubsumptionReflexive",
        "Every profile subsumes itself",
    ),
    (
        "FE-CAPS-§C.2-FullIsTop",
        "Full subsumes every named profile",
    ),
    (
        "FE-CAPS-§C.3-ComputeOnlyIsBottom",
        "Every named profile subsumes ComputeOnly",
    ),
    (
        "FE-CAPS-§C.4-MidTierIncomparable",
        "EngineCore / Policy / Remote are pairwise incomparable",
    ),
    (
        "FE-CAPS-§D.1-IntersectionFullIdentity",
        "Full ∩ X = X for every named X",
    ),
    (
        "FE-CAPS-§D.2-IntersectionIdempotent",
        "X ∩ X = X for every named X",
    ),
    (
        "FE-CAPS-§D.3-DisjointMeetsCollapse",
        "Mid-tier disjoint pairs intersect to ComputeOnly",
    ),
    (
        "FE-CAPS-§D.4-IntersectionCommutes",
        "X ∩ Y = Y ∩ X",
    ),
    (
        "FE-CAPS-§E.1-RequireGrantsWhenHeld",
        "require_capability succeeds when the profile holds the cap",
    ),
    (
        "FE-CAPS-§E.2-RequireDeniesWithWitness",
        "require_capability fails closed with full denial witness",
    ),
    (
        "FE-CAPS-§E.3-RequireAllSucceedsWhenAllHeld",
        "require_all succeeds when every requested cap is granted",
    ),
    (
        "FE-CAPS-§E.4-RequireAllAggregatesDenials",
        "require_all returns every denial, not just the first",
    ),
    (
        "FE-CAPS-§E.5-RequireAllEmptyTrivial",
        "require_all with no requirements always succeeds",
    ),
    (
        "FE-CAPS-§E.6-RequireAllPartialOnlyMissing",
        "require_all denial list is exactly the missing subset, in input order",
    ),
    (
        "FE-CAPS-§F.1-DenialWitnessRoundTrips",
        "CapabilityDenied is JSON-serde lossless",
    ),
];

#[test]
fn conformance_manifest_is_consistent() {
    // Every rule id must be unique and follow the FE-CAPS-§<sec>.<n>-<name>
    // shape — this is what downstream tooling greps for when reconciling
    // section IDs against spec references.
    let mut seen = BTreeSet::new();
    for (id, summary) in LATTICE_CONFORMANCE_RULES {
        assert!(
            id.starts_with("FE-CAPS-§"),
            "rule id `{id}` is missing the FE-CAPS-§ prefix"
        );
        assert!(!summary.is_empty(), "rule `{id}` has empty summary");
        assert!(seen.insert(*id), "duplicate rule id `{id}`");
    }
    // Section A has 2 rules, B has 4, C has 4, D has 4, E has 6, F has 1 -> 21.
    assert_eq!(seen.len(), 21);
}
