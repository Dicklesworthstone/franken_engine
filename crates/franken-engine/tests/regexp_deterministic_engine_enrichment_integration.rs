//! Enrichment integration tests for `regexp_deterministic_engine`.
//!
//! Covers: exhaustive enum serde roundtrips, display uniqueness, CharRange edge
//! cases, tail-risk boundary, cache LRU semantics, compile tier election with
//! config overrides, NFA accepting-path edge cases, error serde, evidence harness
//! artifacts, and UnicodeCategory short-form parsing.

use std::collections::BTreeSet;

use frankenengine_engine::regexp_deterministic_engine::{
    AutomataCache, AutomataTier, CharRange, CompilationReceipt, CompiledRegExp, DeclineReason,
    NfaProgram, NfaState, NfaTransition, REGEXP_ENGINE_COMPONENT, REGEXP_ENGINE_POLICY_ID,
    REGEXP_ENGINE_SCHEMA_VERSION, RegExpArtifactPaths, RegExpAstNode, RegExpCompileError,
    RegExpCompilerConfig, RegExpEvidenceEvent, RegExpEvidenceInventory, RegExpExpectedOutcome,
    RegExpFlag, RegExpRunManifest, RegExpSpecimen, RegExpSpecimenEvidence, RegExpSpecimenFamily,
    RegExpVerdict, TailRiskAssessment, UnicodeCategory, compile_regexp, regexp_corpus,
    run_regexp_corpus,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ── Helpers ─────────────────────────────────────────────────────────────

fn simple_ast() -> RegExpAstNode {
    RegExpAstNode::Literal('a')
}

fn empty_flags() -> BTreeSet<RegExpFlag> {
    BTreeSet::new()
}

fn default_config() -> RegExpCompilerConfig {
    RegExpCompilerConfig::default()
}

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn compile_simple() -> CompiledRegExp {
    compile_regexp(
        "a",
        &empty_flags(),
        &simple_ast(),
        &default_config(),
        epoch(),
    )
    .unwrap()
}

// ── RegExpFlag exhaustive ───────────────────────────────────────────────

#[test]
fn regexp_flag_all_variants_serde_roundtrip() {
    let mut displays = BTreeSet::new();
    for flag in RegExpFlag::ALL {
        let json = serde_json::to_string(flag).unwrap();
        let back: RegExpFlag = serde_json::from_str(&json).unwrap();
        assert_eq!(*flag, back);
        let s = flag.as_str();
        assert!(displays.insert(s.to_string()), "duplicate flag: {s}");
    }
    assert_eq!(displays.len(), 8);
}

#[test]
fn regexp_flag_from_char_roundtrips_all() {
    for flag in RegExpFlag::ALL {
        let c = flag.as_str().chars().next().unwrap();
        let recovered = RegExpFlag::from_char(c).unwrap();
        assert_eq!(*flag, recovered);
    }
}

#[test]
fn regexp_flag_from_char_invalid_returns_none() {
    for c in ['a', 'b', 'c', 'e', 'f', 'h', 'j', 'k', 'l', 'n', 'o', 'p'] {
        assert!(
            RegExpFlag::from_char(c).is_none(),
            "should reject char '{c}'"
        );
    }
}

// ── UnicodeCategory exhaustive ──────────────────────────────────────────

#[test]
fn unicode_category_all_variants_serde_roundtrip() {
    let mut displays = BTreeSet::new();
    for cat in UnicodeCategory::ALL {
        let json = serde_json::to_string(cat).unwrap();
        let back: UnicodeCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*cat, back);
        let s = cat.to_string();
        assert_eq!(s, cat.as_str());
        assert!(displays.insert(s.clone()), "duplicate category: {s}");
    }
    assert_eq!(displays.len(), 15);
}

#[test]
fn unicode_category_from_str_short_forms() {
    assert_eq!(
        UnicodeCategory::from_str_name("M"),
        Some(UnicodeCategory::Mark)
    );
    assert_eq!(
        UnicodeCategory::from_str_name("P"),
        Some(UnicodeCategory::Punctuation)
    );
    assert_eq!(
        UnicodeCategory::from_str_name("S"),
        Some(UnicodeCategory::Symbol)
    );
    assert_eq!(
        UnicodeCategory::from_str_name("C"),
        Some(UnicodeCategory::Other)
    );
}

#[test]
fn unicode_category_from_str_all_long_forms() {
    for cat in UnicodeCategory::ALL {
        let recovered = UnicodeCategory::from_str_name(cat.as_str());
        assert_eq!(recovered, Some(*cat), "failed for {}", cat.as_str());
    }
}

#[test]
fn unicode_category_from_str_unknown_returns_none() {
    assert_eq!(UnicodeCategory::from_str_name("XYZ"), None);
    assert_eq!(UnicodeCategory::from_str_name(""), None);
}

// ── AutomataTier exhaustive ─────────────────────────────────────────────

#[test]
fn automata_tier_all_variants_serde_and_display() {
    let mut displays = BTreeSet::new();
    for tier in AutomataTier::ALL {
        let json = serde_json::to_string(tier).unwrap();
        let back: AutomataTier = serde_json::from_str(&json).unwrap();
        assert_eq!(*tier, back);
        let s = tier.to_string();
        assert_eq!(s, tier.as_str());
        assert!(displays.insert(s.clone()), "duplicate tier: {s}");
    }
    assert_eq!(displays.len(), 4);
}

#[test]
fn automata_tier_usability() {
    assert!(AutomataTier::Dfa.is_usable());
    assert!(AutomataTier::BoundedNfa.is_usable());
    assert!(AutomataTier::InterpreterFallback.is_usable());
    assert!(!AutomataTier::Declined.is_usable());
}

// ── DeclineReason exhaustive ────────────────────────────────────────────

#[test]
fn decline_reason_all_variants_serde_and_display() {
    let all = [
        DeclineReason::NfaStateBudgetExceeded,
        DeclineReason::DfaStateBudgetExceeded,
        DeclineReason::CatastrophicBacktrackingRisk,
        DeclineReason::BackreferencePresent,
        DeclineReason::LookbehindPresent,
        DeclineReason::UnsupportedFeature,
        DeclineReason::EmptyPattern,
        DeclineReason::InvalidFlagCombination,
        DeclineReason::UnrecognizedUnicodeProperty,
        DeclineReason::CompilationBudgetExceeded,
    ];
    let mut displays = BTreeSet::new();
    for reason in &all {
        let json = serde_json::to_string(reason).unwrap();
        let back: DeclineReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, back);
        let s = reason.to_string();
        assert_eq!(s, reason.as_str());
        assert!(displays.insert(s.clone()), "duplicate reason: {s}");
    }
    assert_eq!(displays.len(), 10);
}

// ── RegExpSpecimenFamily exhaustive ─────────────────────────────────────

#[test]
fn specimen_family_all_variants_serde_and_display() {
    let mut displays = BTreeSet::new();
    for fam in RegExpSpecimenFamily::ALL {
        let json = serde_json::to_string(fam).unwrap();
        let back: RegExpSpecimenFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*fam, back);
        let s = fam.to_string();
        assert_eq!(s, fam.as_str());
        assert!(displays.insert(s.clone()), "duplicate family: {s}");
    }
    assert_eq!(displays.len(), 8);
}

// ── RegExpExpectedOutcome serde ─────────────────────────────────────────

#[test]
fn expected_outcome_all_variants_serde() {
    let all = [
        RegExpExpectedOutcome::FlagsAccepted,
        RegExpExpectedOutcome::FlagsRejected,
        RegExpExpectedOutcome::NfaBuilt,
        RegExpExpectedOutcome::TierDfa,
        RegExpExpectedOutcome::TierBoundedNfa,
        RegExpExpectedOutcome::TierInterpreter,
        RegExpExpectedOutcome::TierDeclined,
        RegExpExpectedOutcome::RiskSafe,
        RegExpExpectedOutcome::RiskCatastrophic,
        RegExpExpectedOutcome::CacheHit,
        RegExpExpectedOutcome::CacheMiss,
        RegExpExpectedOutcome::CacheEviction,
        RegExpExpectedOutcome::UnicodeCategoriesCollected,
        RegExpExpectedOutcome::ReceiptGenerated,
        RegExpExpectedOutcome::RoundtripPreserved,
    ];
    let mut set = BTreeSet::new();
    for outcome in &all {
        let json = serde_json::to_string(outcome).unwrap();
        let back: RegExpExpectedOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*outcome, back);
        set.insert(json);
    }
    assert_eq!(set.len(), 15);
}

// ── RegExpVerdict serde ─────────────────────────────────────────────────

#[test]
fn verdict_serde_roundtrip() {
    for v in [RegExpVerdict::Pass, RegExpVerdict::Fail] {
        let json = serde_json::to_string(&v).unwrap();
        let back: RegExpVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ── NfaTransition serde ─────────────────────────────────────────────────

#[test]
fn nfa_transition_all_variants_serde() {
    let variants = [
        NfaTransition::Char('x'),
        NfaTransition::Range(CharRange::range('a', 'z')),
        NfaTransition::Epsilon,
        NfaTransition::Any,
    ];
    let mut set = BTreeSet::new();
    for t in &variants {
        let json = serde_json::to_string(t).unwrap();
        let back: NfaTransition = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, back);
        set.insert(json);
    }
    assert_eq!(set.len(), 4);
}

// ── CharRange edge cases ────────────────────────────────────────────────

#[test]
fn char_range_unicode_contains() {
    let r = CharRange::range('\u{0400}', '\u{04FF}');
    assert!(r.contains('\u{0410}')); // Cyrillic А
    assert!(!r.contains('A'));
    assert_eq!(r.len(), 256);
}

#[test]
fn char_range_single_len_one() {
    let r = CharRange::single('Z');
    assert_eq!(r.len(), 1);
    assert!(!r.is_empty());
}

#[test]
fn char_range_empty_when_start_greater_than_end() {
    let r = CharRange {
        start: 'z',
        end: 'a',
    };
    assert!(r.is_empty());
    assert!(!r.contains('m'));
}

// ── TailRiskAssessment boundary ─────────────────────────────────────────

#[test]
fn tail_risk_safe_boundary() {
    let mut risk = TailRiskAssessment::safe();
    assert!(risk.is_safe());

    risk.risk_millionths = 99_999;
    assert!(risk.is_safe());

    risk.risk_millionths = 100_000;
    assert!(!risk.is_safe());
}

#[test]
fn tail_risk_catastrophic_overrides_low_risk() {
    let mut risk = TailRiskAssessment::safe();
    risk.catastrophic_possible = true;
    assert!(!risk.is_safe());
}

#[test]
fn tail_risk_serde_roundtrip() {
    let risk = TailRiskAssessment {
        risk_millionths: 500_000,
        catastrophic_possible: true,
        ambiguous_state_count: 42,
        max_quantifier_nesting: 7,
        has_overlapping_alternatives: true,
        summary: "elevated".to_string(),
    };
    let json = serde_json::to_string(&risk).unwrap();
    let back: TailRiskAssessment = serde_json::from_str(&json).unwrap();
    assert_eq!(risk, back);
}

// ── RegExpCompileError display + serde ───────────────────────────────────

#[test]
fn compile_error_all_variants_display_unique() {
    let errors = [
        RegExpCompileError::EmptyPattern,
        RegExpCompileError::InvalidFlagCombination {
            detail: "u+v".into(),
        },
        RegExpCompileError::NfaBudgetExceeded {
            states: 20000,
            budget: 10000,
        },
        RegExpCompileError::DfaBudgetExceeded {
            states: 60000,
            budget: 50000,
        },
        RegExpCompileError::CatastrophicRisk {
            detail: "nesting".into(),
        },
        RegExpCompileError::UnsupportedFeature {
            feature: "lookbehind".into(),
        },
        RegExpCompileError::CompilationTimeout,
    ];
    let mut displays = BTreeSet::new();
    for err in &errors {
        let s = err.to_string();
        assert!(!s.is_empty());
        assert!(displays.insert(s.clone()), "duplicate: {s}");
    }
    assert_eq!(displays.len(), 7);
}

#[test]
fn compile_error_serde_roundtrip() {
    let errors = [
        RegExpCompileError::EmptyPattern,
        RegExpCompileError::InvalidFlagCombination {
            detail: "test".into(),
        },
        RegExpCompileError::NfaBudgetExceeded {
            states: 100,
            budget: 50,
        },
        RegExpCompileError::DfaBudgetExceeded {
            states: 200,
            budget: 100,
        },
        RegExpCompileError::CatastrophicRisk {
            detail: "risk".into(),
        },
        RegExpCompileError::UnsupportedFeature {
            feature: "feat".into(),
        },
        RegExpCompileError::CompilationTimeout,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: RegExpCompileError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ── Compile tier election ───────────────────────────────────────────────

#[test]
fn compile_simple_literal_elects_dfa() {
    let compiled = compile_simple();
    assert_eq!(compiled.tier, AutomataTier::Dfa);
    assert!(compiled.receipt.decline_reasons.is_empty());
    assert_eq!(compiled.receipt.confidence_millionths, 950_000);
}

#[test]
fn compile_with_dfa_disabled_elects_bounded_nfa() {
    let mut config = default_config();
    config.enable_dfa = false;
    let compiled = compile_regexp("a", &empty_flags(), &simple_ast(), &config, epoch()).unwrap();
    assert_eq!(compiled.tier, AutomataTier::BoundedNfa);
    assert_eq!(compiled.receipt.confidence_millionths, 800_000);
}

#[test]
fn compile_empty_pattern_errors() {
    let result = compile_regexp(
        "",
        &empty_flags(),
        &simple_ast(),
        &default_config(),
        epoch(),
    );
    assert!(matches!(result, Err(RegExpCompileError::EmptyPattern)));
}

#[test]
fn compile_u_and_v_flags_errors() {
    let mut flags = BTreeSet::new();
    flags.insert(RegExpFlag::Unicode);
    flags.insert(RegExpFlag::UnicodeSets);
    let result = compile_regexp("a", &flags, &simple_ast(), &default_config(), epoch());
    assert!(matches!(
        result,
        Err(RegExpCompileError::InvalidFlagCombination { .. })
    ));
}

#[test]
fn compile_backreference_elects_interpreter() {
    let ast = RegExpAstNode::Concat(vec![
        RegExpAstNode::Group {
            index: 1,
            child: Box::new(RegExpAstNode::Literal('a')),
        },
        RegExpAstNode::Backreference(1),
    ]);
    let compiled =
        compile_regexp("(a)\\1", &empty_flags(), &ast, &default_config(), epoch()).unwrap();
    assert_eq!(compiled.tier, AutomataTier::InterpreterFallback);
    assert_eq!(compiled.receipt.confidence_millionths, 600_000);
    assert_eq!(compiled.receipt.capture_group_count, 1);
}

#[test]
fn compile_lookbehind_elects_interpreter() {
    let ast = RegExpAstNode::Concat(vec![
        RegExpAstNode::Lookbehind {
            child: Box::new(RegExpAstNode::Literal('a')),
            positive: true,
        },
        RegExpAstNode::Literal('b'),
    ]);
    let compiled =
        compile_regexp("(?<=a)b", &empty_flags(), &ast, &default_config(), epoch()).unwrap();
    assert_eq!(compiled.tier, AutomataTier::InterpreterFallback);
}

#[test]
fn compile_with_unicode_property_collects_categories() {
    let ast = RegExpAstNode::Concat(vec![
        RegExpAstNode::UnicodeProperty {
            property: UnicodeCategory::Lu,
            negated: false,
        },
        RegExpAstNode::UnicodeProperty {
            property: UnicodeCategory::Nd,
            negated: false,
        },
    ]);
    let compiled = compile_regexp(
        "\\p{Lu}\\p{Nd}",
        &empty_flags(),
        &ast,
        &default_config(),
        epoch(),
    )
    .unwrap();
    assert!(
        compiled
            .receipt
            .unicode_categories_used
            .contains(&UnicodeCategory::Lu)
    );
    assert!(
        compiled
            .receipt
            .unicode_categories_used
            .contains(&UnicodeCategory::Nd)
    );
}

#[test]
fn compile_deterministic_hashes() {
    let c1 = compile_simple();
    let c2 = compile_simple();
    assert_eq!(c1.content_hash, c2.content_hash);
    assert_eq!(c1.receipt.receipt_hash, c2.receipt.receipt_hash);
    assert_eq!(c1.receipt.automata_hash, c2.receipt.automata_hash);
}

// ── Receipt serde ───────────────────────────────────────────────────────

#[test]
fn compilation_receipt_serde_roundtrip() {
    let compiled = compile_simple();
    let json = serde_json::to_string(&compiled.receipt).unwrap();
    let back: CompilationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(compiled.receipt, back);
}

#[test]
fn compiled_regexp_serde_roundtrip() {
    let compiled = compile_simple();
    let json = serde_json::to_string(&compiled).unwrap();
    let back: CompiledRegExp = serde_json::from_str(&json).unwrap();
    assert_eq!(compiled, back);
}

// ── Cache LRU semantics ─────────────────────────────────────────────────

#[test]
fn cache_default_capacity() {
    let cache = AutomataCache::with_default_capacity();
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);
}

#[test]
fn cache_lru_eviction_order() {
    let config = default_config();
    let flags = empty_flags();
    let e = epoch();

    let mut cache = AutomataCache::new(2);

    // Insert A, B
    let ast_a = RegExpAstNode::Literal('a');
    let ca = compile_regexp("a", &flags, &ast_a, &config, e).unwrap();
    let hash_a = ca.content_hash.clone();
    cache.insert(ca);

    let ast_b = RegExpAstNode::Literal('b');
    let cb = compile_regexp("b", &flags, &ast_b, &config, e).unwrap();
    let hash_b = cb.content_hash.clone();
    cache.insert(cb);

    // Access A to make it most recently used
    assert!(cache.get(&hash_a).is_some());

    // Insert C — should evict B (least recently used)
    let ast_c = RegExpAstNode::Literal('c');
    let cc = compile_regexp("c", &flags, &ast_c, &config, e).unwrap();
    cache.insert(cc);

    assert_eq!(cache.len(), 2);
    assert!(cache.get(&hash_a).is_some(), "A should still be in cache");
    assert!(cache.get(&hash_b).is_none(), "B should have been evicted");
}

#[test]
fn cache_hit_rate_computation() {
    let mut cache = AutomataCache::new(10);
    assert_eq!(cache.hit_rate_millionths(), 0);

    cache.hits = 1;
    cache.misses = 3;
    assert_eq!(cache.hit_rate_millionths(), 250_000);

    cache.hits = 1;
    cache.misses = 0;
    assert_eq!(cache.hit_rate_millionths(), 1_000_000);
}

#[test]
fn cache_serde_roundtrip() {
    let cache = AutomataCache::new(42);
    let json = serde_json::to_string(&cache).unwrap();
    let back: AutomataCache = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), 0);
    assert!(back.is_empty());
}

// ── NFA edge cases ──────────────────────────────────────────────────────

#[test]
fn nfa_no_accepting_path_when_disconnected() {
    let nfa = NfaProgram {
        states: vec![
            NfaState {
                id: 0,
                transitions: vec![],
                is_accept: false,
            },
            NfaState {
                id: 1,
                transitions: vec![],
                is_accept: true,
            },
        ],
        start_state: 0,
        accept_states: {
            let mut s = BTreeSet::new();
            s.insert(1);
            s
        },
        state_count: 2,
    };
    assert!(!nfa.has_accepting_path());
}

#[test]
fn nfa_epsilon_closure_no_epsilon_returns_same_set() {
    let nfa = NfaProgram {
        states: vec![NfaState {
            id: 0,
            transitions: vec![(NfaTransition::Char('a'), 1)],
            is_accept: false,
        }],
        start_state: 0,
        accept_states: BTreeSet::new(),
        state_count: 1,
    };
    let initial = {
        let mut s = BTreeSet::new();
        s.insert(0);
        s
    };
    let closure = nfa.epsilon_closure(&initial);
    assert_eq!(closure.len(), 1);
    assert!(closure.contains(&0));
}

// ── Evidence harness artifacts serde ────────────────────────────────────

#[test]
fn specimen_serde_roundtrip() {
    let specimen = RegExpSpecimen {
        specimen_id: "test-001".into(),
        description: "test specimen".into(),
        family: RegExpSpecimenFamily::FlagValidation,
        expected_outcome: RegExpExpectedOutcome::FlagsAccepted,
    };
    let json = serde_json::to_string(&specimen).unwrap();
    let back: RegExpSpecimen = serde_json::from_str(&json).unwrap();
    assert_eq!(specimen, back);
}

#[test]
fn specimen_evidence_serde_roundtrip() {
    let evidence = RegExpSpecimenEvidence {
        specimen_id: "test-001".into(),
        family: RegExpSpecimenFamily::TierElection,
        expected_outcome: RegExpExpectedOutcome::TierDfa,
        verdict: RegExpVerdict::Pass,
        actual_outcome: "dfa".into(),
        error_detail: None,
        evidence_hash: "abc123".into(),
    };
    let json = serde_json::to_string(&evidence).unwrap();
    let back: RegExpSpecimenEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(evidence, back);
}

#[test]
fn evidence_inventory_serde_roundtrip() {
    let inventory = run_regexp_corpus();
    let json = serde_json::to_string(&inventory).unwrap();
    let back: RegExpEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inventory, back);
}

#[test]
fn evidence_event_serde_roundtrip() {
    let event = RegExpEvidenceEvent {
        schema_version: REGEXP_ENGINE_SCHEMA_VERSION.to_string(),
        component: REGEXP_ENGINE_COMPONENT.to_string(),
        event: "test_event".into(),
        policy_id: REGEXP_ENGINE_POLICY_ID.to_string(),
        specimen_id: Some("s1".into()),
        verdict: Some("Pass".into()),
        detail: Some("ok".into()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: RegExpEvidenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn run_manifest_serde_roundtrip() {
    let manifest = RegExpRunManifest {
        schema_version: "v1".into(),
        component: "test".into(),
        trace_id: "t1".into(),
        decision_id: "d1".into(),
        policy_id: "p1".into(),
        inventory_hash: "h1".into(),
        specimen_count: 10,
        pass_count: 9,
        fail_count: 1,
        contract_satisfied: false,
        artifact_paths: RegExpArtifactPaths {
            evidence_inventory: "/a.json".into(),
            run_manifest: "/b.json".into(),
            events_jsonl: "/c.jsonl".into(),
            commands_txt: "/d.txt".into(),
        },
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let back: RegExpRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

#[test]
fn artifact_paths_serde_roundtrip() {
    let paths = RegExpArtifactPaths {
        evidence_inventory: "a".into(),
        run_manifest: "b".into(),
        events_jsonl: "c".into(),
        commands_txt: "d".into(),
    };
    let json = serde_json::to_string(&paths).unwrap();
    let back: RegExpArtifactPaths = serde_json::from_str(&json).unwrap();
    assert_eq!(paths, back);
}

// ── Corpus invariants ───────────────────────────────────────────────────

#[test]
fn corpus_specimen_ids_unique() {
    let corpus = regexp_corpus();
    let mut ids = BTreeSet::new();
    for s in &corpus {
        assert!(ids.insert(&s.specimen_id), "duplicate: {}", s.specimen_id);
    }
}

#[test]
fn corpus_all_families_represented() {
    let corpus = regexp_corpus();
    let families: BTreeSet<_> = corpus.iter().map(|s| s.family).collect();
    for f in RegExpSpecimenFamily::ALL {
        assert!(families.contains(f), "missing family: {}", f.as_str());
    }
}

#[test]
fn corpus_run_deterministic() {
    let inv1 = run_regexp_corpus();
    let inv2 = run_regexp_corpus();
    assert_eq!(inv1.pass_count, inv2.pass_count);
    assert_eq!(inv1.fail_count, inv2.fail_count);
    assert_eq!(inv1.specimen_count, inv2.specimen_count);
}

#[test]
fn corpus_contract_satisfied() {
    let inventory = run_regexp_corpus();
    assert!(
        inventory.contract_satisfied(),
        "fail_count={}",
        inventory.fail_count
    );
}

// ── RegExpCompilerConfig serde ──────────────────────────────────────────

#[test]
fn compiler_config_serde_roundtrip() {
    let config = RegExpCompilerConfig {
        max_nfa_states: 5000,
        max_dfa_states: 25000,
        max_quantifier_nesting: 4,
        enable_dfa: false,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: RegExpCompilerConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ── Constants ───────────────────────────────────────────────────────────

#[test]
fn constants_nonempty_and_contain_module_name() {
    assert!(!REGEXP_ENGINE_SCHEMA_VERSION.is_empty());
    assert!(!REGEXP_ENGINE_COMPONENT.is_empty());
    assert!(!REGEXP_ENGINE_POLICY_ID.is_empty());
    assert!(REGEXP_ENGINE_COMPONENT.contains("regexp"));
}
