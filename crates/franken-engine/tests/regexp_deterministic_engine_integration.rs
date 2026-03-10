#![forbid(unsafe_code)]

//! Integration tests for regexp_deterministic_engine [RGC-312B]

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeSet;

use frankenengine_engine::regexp_deterministic_engine::{
    AutomataCache, AutomataTier, CharRange, CompilationReceipt, CompiledRegExp, DeclineReason,
    NfaProgram, NfaState, NfaTransition, REGEXP_ENGINE_COMPONENT, REGEXP_ENGINE_POLICY_ID,
    REGEXP_ENGINE_SCHEMA_VERSION, RegExpArtifactPaths, RegExpAstNode, RegExpCompileError,
    RegExpCompilerConfig, RegExpEvidenceEvent, RegExpEvidenceInventory, RegExpFlag,
    RegExpRunManifest, RegExpSpecimenFamily, RegExpVerdict, TailRiskAssessment, UnicodeCategory,
    compile_regexp, regexp_corpus, run_regexp_corpus,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Corpus structure
// ---------------------------------------------------------------------------

#[test]
fn corpus_non_empty() {
    assert!(!regexp_corpus().is_empty());
}

#[test]
fn corpus_ids_unique() {
    let corpus = regexp_corpus();
    let mut ids = BTreeSet::new();
    for s in &corpus {
        assert!(ids.insert(&s.specimen_id), "duplicate: {}", s.specimen_id);
    }
}

#[test]
fn corpus_descriptions_non_empty() {
    for s in &regexp_corpus() {
        assert!(!s.description.is_empty(), "empty desc: {}", s.specimen_id);
    }
}

#[test]
fn corpus_covers_all_families() {
    let corpus = regexp_corpus();
    let families: BTreeSet<_> = corpus.iter().map(|s| s.family).collect();
    for f in RegExpSpecimenFamily::ALL {
        assert!(families.contains(f), "missing family: {f}");
    }
}

// ---------------------------------------------------------------------------
// Evidence inventory
// ---------------------------------------------------------------------------

#[test]
fn inventory_contract_satisfied() {
    let inv = run_regexp_corpus();
    assert!(
        inv.contract_satisfied(),
        "fail_count={}, evidence: {:?}",
        inv.fail_count,
        inv.evidence
            .iter()
            .filter(|e| e.verdict == RegExpVerdict::Fail)
            .collect::<Vec<_>>()
    );
}

#[test]
fn inventory_counts_consistent() {
    let inv = run_regexp_corpus();
    assert_eq!(inv.specimen_count, inv.pass_count + inv.fail_count);
    assert_eq!(inv.specimen_count, inv.evidence.len() as u64);
}

#[test]
fn inventory_schema_version() {
    let inv = run_regexp_corpus();
    assert_eq!(inv.schema_version, REGEXP_ENGINE_SCHEMA_VERSION);
    assert_eq!(inv.component, REGEXP_ENGINE_COMPONENT);
}

#[test]
fn inventory_family_coverage_keys() {
    let inv = run_regexp_corpus();
    for f in RegExpSpecimenFamily::ALL {
        assert!(inv.family_coverage.contains_key(f.as_str()));
    }
}

#[test]
fn inventory_evidence_hashes_non_empty() {
    let inv = run_regexp_corpus();
    for ev in &inv.evidence {
        assert!(!ev.evidence_hash.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Flag validation
// ---------------------------------------------------------------------------

#[test]
fn flag_all_from_char_roundtrip() {
    for flag in RegExpFlag::ALL {
        let c = flag.as_str().chars().next().unwrap();
        assert_eq!(RegExpFlag::from_char(c), Some(*flag));
    }
}

#[test]
fn flag_unknown_char_none() {
    for c in ['x', 'z', '0', 'A'] {
        assert_eq!(RegExpFlag::from_char(c), None);
    }
}

#[test]
fn flag_u_v_mutually_exclusive() {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let ast = RegExpAstNode::Literal('a');
    let mut flags = BTreeSet::new();
    flags.insert(RegExpFlag::Unicode);
    flags.insert(RegExpFlag::UnicodeSets);
    assert!(compile_regexp("a", &flags, &ast, &config, epoch).is_err());
}

#[test]
fn flag_all_valid_combinations() {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let ast = RegExpAstNode::Literal('a');
    // g+i+m should be fine
    let mut flags = BTreeSet::new();
    flags.insert(RegExpFlag::Global);
    flags.insert(RegExpFlag::IgnoreCase);
    flags.insert(RegExpFlag::Multiline);
    assert!(compile_regexp("a", &flags, &ast, &config, epoch).is_ok());
}

// ---------------------------------------------------------------------------
// Compilation tiers
// ---------------------------------------------------------------------------

#[test]
fn simple_literal_compiles_to_dfa() {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let ast = RegExpAstNode::Literal('x');
    let compiled = compile_regexp("x", &BTreeSet::new(), &ast, &config, epoch).unwrap();
    assert_eq!(compiled.tier, AutomataTier::Dfa);
}

#[test]
fn backreference_forces_interpreter() {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let ast = RegExpAstNode::Concat(vec![
        RegExpAstNode::Group {
            index: 1,
            child: Box::new(RegExpAstNode::Literal('a')),
        },
        RegExpAstNode::Backreference(1),
    ]);
    let compiled = compile_regexp("(a)\\1", &BTreeSet::new(), &ast, &config, epoch).unwrap();
    assert_eq!(compiled.tier, AutomataTier::InterpreterFallback);
}

#[test]
fn lookbehind_forces_interpreter() {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let ast = RegExpAstNode::Lookbehind {
        child: Box::new(RegExpAstNode::Literal('a')),
        positive: true,
    };
    let compiled = compile_regexp("(?<=a)", &BTreeSet::new(), &ast, &config, epoch).unwrap();
    assert_eq!(compiled.tier, AutomataTier::InterpreterFallback);
}

#[test]
fn empty_pattern_rejected() {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let ast = RegExpAstNode::Literal('a');
    let result = compile_regexp("", &BTreeSet::new(), &ast, &config, epoch);
    assert!(result.is_err());
}

#[test]
fn tier_usable_check() {
    assert!(AutomataTier::Dfa.is_usable());
    assert!(AutomataTier::BoundedNfa.is_usable());
    assert!(AutomataTier::InterpreterFallback.is_usable());
    assert!(!AutomataTier::Declined.is_usable());
}

#[test]
fn tier_all_variants() {
    assert_eq!(AutomataTier::ALL.len(), 4);
}

// ---------------------------------------------------------------------------
// NFA construction
// ---------------------------------------------------------------------------

#[test]
fn nfa_concat_chain() {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let ast = RegExpAstNode::Concat(vec![
        RegExpAstNode::Literal('a'),
        RegExpAstNode::Literal('b'),
        RegExpAstNode::Literal('c'),
    ]);
    let compiled = compile_regexp("abc", &BTreeSet::new(), &ast, &config, epoch).unwrap();
    assert!(compiled.nfa.state_count >= 6);
}

#[test]
fn nfa_alternation_branches() {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let ast = RegExpAstNode::Alternation(vec![
        RegExpAstNode::Literal('a'),
        RegExpAstNode::Literal('b'),
        RegExpAstNode::Literal('c'),
    ]);
    let compiled = compile_regexp("a|b|c", &BTreeSet::new(), &ast, &config, epoch).unwrap();
    assert!(compiled.nfa.state_count >= 8);
}

#[test]
fn nfa_dot_uses_any_transition() {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let ast = RegExpAstNode::Dot;
    let compiled = compile_regexp(".", &BTreeSet::new(), &ast, &config, epoch).unwrap();
    let has_any = compiled
        .nfa
        .states
        .iter()
        .any(|s| s.transitions.iter().any(|(t, _)| *t == NfaTransition::Any));
    assert!(has_any);
}

#[test]
fn nfa_char_class_ranges() {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let ast = RegExpAstNode::CharClass {
        negated: false,
        ranges: vec![CharRange::range('a', 'z'), CharRange::range('0', '9')],
    };
    let compiled = compile_regexp("[a-z0-9]", &BTreeSet::new(), &ast, &config, epoch).unwrap();
    let range_transitions = compiled
        .nfa
        .states
        .iter()
        .flat_map(|s| &s.transitions)
        .filter(|(t, _)| matches!(t, NfaTransition::Range(_)))
        .count();
    assert_eq!(range_transitions, 2);
}

#[test]
fn nfa_epsilon_closure_transitive() {
    let nfa = NfaProgram {
        states: vec![
            NfaState {
                id: 0,
                transitions: vec![(NfaTransition::Epsilon, 1)],
                is_accept: false,
            },
            NfaState {
                id: 1,
                transitions: vec![(NfaTransition::Epsilon, 2)],
                is_accept: false,
            },
            NfaState {
                id: 2,
                transitions: vec![(NfaTransition::Epsilon, 3)],
                is_accept: false,
            },
            NfaState {
                id: 3,
                transitions: vec![],
                is_accept: true,
            },
        ],
        start_state: 0,
        accept_states: {
            let mut s = BTreeSet::new();
            s.insert(3);
            s
        },
        state_count: 4,
    };
    let initial = {
        let mut s = BTreeSet::new();
        s.insert(0);
        s
    };
    let closure = nfa.epsilon_closure(&initial);
    assert_eq!(closure.len(), 4);
}

// ---------------------------------------------------------------------------
// Tail risk
// ---------------------------------------------------------------------------

#[test]
fn tail_risk_safe_default() {
    let safe = TailRiskAssessment::safe();
    assert!(safe.is_safe());
    assert!(!safe.catastrophic_possible);
}

#[test]
fn tail_risk_deep_nesting_catastrophic() {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    // Build deeply nested quantifier
    let mut ast = RegExpAstNode::Literal('a');
    for _ in 0..12 {
        ast = RegExpAstNode::Quantifier {
            child: Box::new(ast),
            min: 0,
            max: None,
            greedy: true,
        };
    }
    let compiled = compile_regexp("(a*)*^12", &BTreeSet::new(), &ast, &config, epoch);
    // Should decline due to catastrophic risk
    assert!(compiled.is_err() || compiled.unwrap().tier == AutomataTier::Declined);
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

#[test]
fn cache_basic_operations() {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let flags = BTreeSet::new();

    let mut cache = AutomataCache::with_default_capacity();
    assert!(cache.is_empty());

    let ast = RegExpAstNode::Literal('a');
    let compiled = compile_regexp("a", &flags, &ast, &config, epoch).unwrap();
    let hash = compiled.content_hash.clone();

    cache.insert(compiled);
    assert_eq!(cache.len(), 1);

    assert!(cache.get(&hash).is_some());
    assert_eq!(cache.hits, 1);
    assert_eq!(cache.misses, 0);

    assert!(cache.get("unknown").is_none());
    assert_eq!(cache.misses, 1);
}

#[test]
fn cache_eviction_fifo() {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let flags = BTreeSet::new();

    let mut cache = AutomataCache::new(3);

    let mut hashes = Vec::new();
    for i in 0u8..5 {
        let ch = (b'a' + i) as char;
        let ast = RegExpAstNode::Literal(ch);
        let compiled = compile_regexp(&format!("{ch}"), &flags, &ast, &config, epoch).unwrap();
        hashes.push(compiled.content_hash.clone());
        cache.insert(compiled);
    }

    assert_eq!(cache.len(), 3);
    assert!(cache.evictions >= 2);
    // First entries should be evicted
    assert!(cache.get(&hashes[0]).is_none());
    assert!(cache.get(&hashes[1]).is_none());
}

#[test]
fn cache_hit_rate_calculation() {
    let mut cache = AutomataCache::new(10);
    assert_eq!(cache.hit_rate_millionths(), 0);
    cache.hits = 7;
    cache.misses = 3;
    assert_eq!(cache.hit_rate_millionths(), 700_000);
}

// ---------------------------------------------------------------------------
// Unicode categories
// ---------------------------------------------------------------------------

#[test]
fn unicode_all_categories_have_names() {
    for cat in UnicodeCategory::ALL {
        assert!(!cat.as_str().is_empty());
        assert!(UnicodeCategory::from_str_name(cat.as_str()).is_some());
    }
}

#[test]
fn unicode_shorthand_aliases() {
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
fn unicode_unknown_returns_none() {
    assert_eq!(UnicodeCategory::from_str_name("XYZ"), None);
}

// ---------------------------------------------------------------------------
// Compilation receipts
// ---------------------------------------------------------------------------

#[test]
fn receipt_has_all_fields() {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let ast = RegExpAstNode::Literal('a');
    let compiled = compile_regexp("a", &BTreeSet::new(), &ast, &config, epoch).unwrap();
    let r = &compiled.receipt;
    assert!(!r.schema_version.is_empty());
    assert_eq!(r.pattern, "a");
    assert!(!r.receipt_hash.is_empty());
    assert!(!r.automata_hash.is_empty());
    assert_eq!(r.tier, AutomataTier::Dfa);
    assert!(r.nfa_state_count > 0);
}

#[test]
fn receipt_deterministic_across_calls() {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let ast = RegExpAstNode::Concat(vec![
        RegExpAstNode::Literal('h'),
        RegExpAstNode::Literal('i'),
    ]);
    let flags = BTreeSet::new();
    let c1 = compile_regexp("hi", &flags, &ast, &config, epoch).unwrap();
    let c2 = compile_regexp("hi", &flags, &ast, &config, epoch).unwrap();
    assert_eq!(c1.receipt.receipt_hash, c2.receipt.receipt_hash);
    assert_eq!(c1.content_hash, c2.content_hash);
}

#[test]
fn receipt_unicode_categories_tracked() {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let ast = RegExpAstNode::UnicodeProperty {
        property: UnicodeCategory::Lu,
        negated: false,
    };
    let mut flags = BTreeSet::new();
    flags.insert(RegExpFlag::Unicode);
    let compiled = compile_regexp("\\p{Lu}", &flags, &ast, &config, epoch).unwrap();
    assert!(
        compiled
            .receipt
            .unicode_categories_used
            .contains(&UnicodeCategory::Lu)
    );
}

#[test]
fn receipt_capture_groups_counted() {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let ast = RegExpAstNode::Concat(vec![
        RegExpAstNode::Group {
            index: 1,
            child: Box::new(RegExpAstNode::Literal('a')),
        },
        RegExpAstNode::Group {
            index: 2,
            child: Box::new(RegExpAstNode::Literal('b')),
        },
    ]);
    let compiled = compile_regexp("(a)(b)", &BTreeSet::new(), &ast, &config, epoch).unwrap();
    assert_eq!(compiled.receipt.capture_group_count, 2);
}

// ---------------------------------------------------------------------------
// CharRange
// ---------------------------------------------------------------------------

#[test]
fn char_range_properties() {
    let r = CharRange::range('A', 'Z');
    assert_eq!(r.len(), 26);
    assert!(r.contains('M'));
    assert!(!r.contains('a'));

    let s = CharRange::single('!');
    assert_eq!(s.len(), 1);
    assert!(s.contains('!'));
    assert!(!s.contains('?'));
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn serde_compiled_regexp_roundtrip() {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let ast = RegExpAstNode::Alternation(vec![
        RegExpAstNode::Literal('a'),
        RegExpAstNode::Literal('b'),
    ]);
    let compiled = compile_regexp("a|b", &BTreeSet::new(), &ast, &config, epoch).unwrap();
    let json = serde_json::to_string(&compiled).unwrap();
    let deser: CompiledRegExp = serde_json::from_str(&json).unwrap();
    assert_eq!(compiled, deser);
}

#[test]
fn serde_receipt_roundtrip() {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let ast = RegExpAstNode::Literal('x');
    let compiled = compile_regexp("x", &BTreeSet::new(), &ast, &config, epoch).unwrap();
    let json = serde_json::to_string(&compiled.receipt).unwrap();
    let deser: CompilationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(compiled.receipt, deser);
}

#[test]
fn serde_cache_roundtrip() {
    let mut cache = AutomataCache::new(50);
    cache.hits = 10;
    cache.misses = 5;
    let json = serde_json::to_string(&cache).unwrap();
    let deser: AutomataCache = serde_json::from_str(&json).unwrap();
    assert_eq!(deser.hits, 10);
    assert_eq!(deser.misses, 5);
}

#[test]
fn serde_inventory_roundtrip() {
    let inv = run_regexp_corpus();
    let json = serde_json::to_string(&inv).unwrap();
    let deser: RegExpEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv.specimen_count, deser.specimen_count);
    assert_eq!(inv.pass_count, deser.pass_count);
}

#[test]
fn serde_tail_risk_roundtrip() {
    let risk = TailRiskAssessment::safe();
    let json = serde_json::to_string(&risk).unwrap();
    let deser: TailRiskAssessment = serde_json::from_str(&json).unwrap();
    assert_eq!(risk, deser);
}

#[test]
fn serde_config_roundtrip() {
    let config = RegExpCompilerConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let deser: RegExpCompilerConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, deser);
}

// ---------------------------------------------------------------------------
// Error display
// ---------------------------------------------------------------------------

#[test]
fn error_display_variants() {
    let errors = vec![
        RegExpCompileError::EmptyPattern,
        RegExpCompileError::InvalidFlagCombination {
            detail: "test".into(),
        },
        RegExpCompileError::NfaBudgetExceeded {
            states: 20000,
            budget: 10000,
        },
        RegExpCompileError::DfaBudgetExceeded {
            states: 100000,
            budget: 50000,
        },
        RegExpCompileError::CatastrophicRisk {
            detail: "nested".into(),
        },
        RegExpCompileError::UnsupportedFeature {
            feature: "atomic".into(),
        },
        RegExpCompileError::CompilationTimeout,
    ];
    for e in &errors {
        assert!(!format!("{e}").is_empty());
    }
}

// ---------------------------------------------------------------------------
// DeclineReason coverage
// ---------------------------------------------------------------------------

#[test]
fn decline_reason_all_have_str() {
    let reasons = [
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
    for r in &reasons {
        assert!(!r.as_str().is_empty());
        assert!(!format!("{r}").is_empty());
    }
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn compilation_is_deterministic() {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(42);
    let flags = BTreeSet::new();
    let ast = RegExpAstNode::Quantifier {
        child: Box::new(RegExpAstNode::Alternation(vec![
            RegExpAstNode::Literal('a'),
            RegExpAstNode::Literal('b'),
        ])),
        min: 1,
        max: None,
        greedy: true,
    };
    let c1 = compile_regexp("(a|b)+", &flags, &ast, &config, epoch).unwrap();
    let c2 = compile_regexp("(a|b)+", &flags, &ast, &config, epoch).unwrap();
    assert_eq!(c1.nfa.state_count, c2.nfa.state_count);
    assert_eq!(c1.content_hash, c2.content_hash);
    assert_eq!(c1.receipt, c2.receipt);
}

#[test]
fn corpus_run_is_deterministic() {
    let inv1 = run_regexp_corpus();
    let inv2 = run_regexp_corpus();
    assert_eq!(inv1.specimen_count, inv2.specimen_count);
    assert_eq!(inv1.pass_count, inv2.pass_count);
    for (e1, e2) in inv1.evidence.iter().zip(inv2.evidence.iter()) {
        assert_eq!(e1.evidence_hash, e2.evidence_hash);
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[test]
fn config_defaults_reasonable() {
    let config = RegExpCompilerConfig::default();
    assert!(config.max_nfa_states > 0);
    assert!(config.max_dfa_states > 0);
    assert!(config.max_dfa_states >= config.max_nfa_states);
    assert!(config.enable_dfa);
}

// ---------------------------------------------------------------------------
// Evidence event serde
// ---------------------------------------------------------------------------

#[test]
fn evidence_event_serde() {
    let event = RegExpEvidenceEvent {
        schema_version: "v1".into(),
        component: REGEXP_ENGINE_COMPONENT.into(),
        event: "test".into(),
        policy_id: REGEXP_ENGINE_POLICY_ID.into(),
        specimen_id: Some("test_id".into()),
        verdict: Some("Pass".into()),
        detail: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let deser: RegExpEvidenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, deser);
}

// ---------------------------------------------------------------------------
// Run manifest serde
// ---------------------------------------------------------------------------

#[test]
fn run_manifest_serde() {
    let manifest = RegExpRunManifest {
        schema_version: "v1".into(),
        component: REGEXP_ENGINE_COMPONENT.into(),
        trace_id: "trace".into(),
        decision_id: "decision".into(),
        policy_id: REGEXP_ENGINE_POLICY_ID.into(),
        inventory_hash: "hash".into(),
        specimen_count: 10,
        pass_count: 10,
        fail_count: 0,
        contract_satisfied: true,
        artifact_paths: RegExpArtifactPaths {
            evidence_inventory: "inv.json".into(),
            run_manifest: "manifest.json".into(),
            events_jsonl: "events.jsonl".into(),
            commands_txt: "commands.txt".into(),
        },
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let deser: RegExpRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, deser);
}

// ---------------------------------------------------------------------------
// Specimen family
// ---------------------------------------------------------------------------

#[test]
fn specimen_family_all_distinct() {
    let mut strs = BTreeSet::new();
    for f in RegExpSpecimenFamily::ALL {
        assert!(strs.insert(f.as_str()));
    }
    assert_eq!(strs.len(), RegExpSpecimenFamily::ALL.len());
}

// ---------------------------------------------------------------------------
// Quantifier variants
// ---------------------------------------------------------------------------

#[test]
fn optional_quantifier_compiles() {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let ast = RegExpAstNode::Quantifier {
        child: Box::new(RegExpAstNode::Literal('a')),
        min: 0,
        max: Some(1),
        greedy: true,
    };
    let compiled = compile_regexp("a?", &BTreeSet::new(), &ast, &config, epoch).unwrap();
    assert_eq!(compiled.tier, AutomataTier::Dfa);
}

#[test]
fn plus_quantifier_compiles() {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let ast = RegExpAstNode::Quantifier {
        child: Box::new(RegExpAstNode::Literal('a')),
        min: 1,
        max: None,
        greedy: true,
    };
    let compiled = compile_regexp("a+", &BTreeSet::new(), &ast, &config, epoch).unwrap();
    assert_eq!(compiled.tier, AutomataTier::Dfa);
}

#[test]
fn star_quantifier_compiles() {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let ast = RegExpAstNode::Quantifier {
        child: Box::new(RegExpAstNode::Literal('a')),
        min: 0,
        max: None,
        greedy: true,
    };
    let compiled = compile_regexp("a*", &BTreeSet::new(), &ast, &config, epoch).unwrap();
    assert_eq!(compiled.tier, AutomataTier::Dfa);
}

// ---------------------------------------------------------------------------
// Anchors and word boundaries
// ---------------------------------------------------------------------------

#[test]
fn anchor_nodes_compile() {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let ast = RegExpAstNode::Concat(vec![
        RegExpAstNode::StartAnchor,
        RegExpAstNode::Literal('a'),
        RegExpAstNode::EndAnchor,
    ]);
    let compiled = compile_regexp("^a$", &BTreeSet::new(), &ast, &config, epoch).unwrap();
    assert!(compiled.tier.is_usable());
}

#[test]
fn word_boundary_node_compiles() {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let ast = RegExpAstNode::Concat(vec![
        RegExpAstNode::WordBoundary { negated: false },
        RegExpAstNode::Literal('a'),
    ]);
    let compiled = compile_regexp("\\ba", &BTreeSet::new(), &ast, &config, epoch).unwrap();
    assert!(compiled.tier.is_usable());
}
