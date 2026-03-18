#![forbid(unsafe_code)]

//! Deep integration tests for `regexp_deterministic_engine`.
//!
//! Focuses on areas not covered by existing integration and enrichment tests:
//! complex AST composition, NFA topology edge cases, epsilon closure with
//! cycles, cache stress and access-count tracking, config boundary values,
//! cross-epoch hash stability, evidence bundle I/O, negated constructs,
//! bounded quantifiers, mixed lookahead/lookbehind, multi-backref patterns,
//! and exhaustive serde for AST node variants.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::regexp_deterministic_engine::{
    AutomataCache, AutomataTier, CharRange, CompiledRegExp, DeclineReason, NfaProgram, NfaState,
    NfaTransition, REGEXP_ENGINE_COMPONENT, REGEXP_ENGINE_EVENT_SCHEMA_VERSION,
    REGEXP_ENGINE_MANIFEST_SCHEMA_VERSION, REGEXP_ENGINE_POLICY_ID, REGEXP_ENGINE_SCHEMA_VERSION,
    RegExpAstNode, RegExpCompileError, RegExpCompilerConfig, RegExpEvidenceEvent,
    RegExpEvidenceInventory, RegExpFlag, RegExpRunManifest, RegExpSpecimenFamily, RegExpVerdict,
    TailRiskAssessment, UnicodeCategory, compile_regexp, run_regexp_corpus,
    write_regexp_evidence_bundle,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn empty_flags() -> BTreeSet<RegExpFlag> {
    BTreeSet::new()
}

fn default_config() -> RegExpCompilerConfig {
    RegExpCompilerConfig::default()
}

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn compile_ok(
    pattern: &str,
    flags: &BTreeSet<RegExpFlag>,
    ast: &RegExpAstNode,
    config: &RegExpCompilerConfig,
    ep: SecurityEpoch,
) -> CompiledRegExp {
    compile_regexp(pattern, flags, ast, config, ep).unwrap()
}

// =========================================================================
// Section 1 — RegExpAstNode exhaustive serde roundtrips
// =========================================================================

#[test]
fn ast_literal_serde_roundtrip() {
    let node = RegExpAstNode::Literal('Z');
    let json = serde_json::to_string(&node).unwrap();
    let back: RegExpAstNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, back);
}

#[test]
fn ast_dot_serde_roundtrip() {
    let node = RegExpAstNode::Dot;
    let json = serde_json::to_string(&node).unwrap();
    let back: RegExpAstNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, back);
}

#[test]
fn ast_start_anchor_serde_roundtrip() {
    let node = RegExpAstNode::StartAnchor;
    let json = serde_json::to_string(&node).unwrap();
    let back: RegExpAstNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, back);
}

#[test]
fn ast_end_anchor_serde_roundtrip() {
    let node = RegExpAstNode::EndAnchor;
    let json = serde_json::to_string(&node).unwrap();
    let back: RegExpAstNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, back);
}

#[test]
fn ast_word_boundary_serde_roundtrip() {
    for negated in [false, true] {
        let node = RegExpAstNode::WordBoundary { negated };
        let json = serde_json::to_string(&node).unwrap();
        let back: RegExpAstNode = serde_json::from_str(&json).unwrap();
        assert_eq!(node, back);
    }
}

#[test]
fn ast_backreference_serde_roundtrip() {
    let node = RegExpAstNode::Backreference(42);
    let json = serde_json::to_string(&node).unwrap();
    let back: RegExpAstNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, back);
}

#[test]
fn ast_char_class_serde_roundtrip() {
    let node = RegExpAstNode::CharClass {
        negated: true,
        ranges: vec![CharRange::range('a', 'z'), CharRange::single('!')],
    };
    let json = serde_json::to_string(&node).unwrap();
    let back: RegExpAstNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, back);
}

#[test]
fn ast_unicode_property_serde_roundtrip() {
    let node = RegExpAstNode::UnicodeProperty {
        property: UnicodeCategory::Zs,
        negated: true,
    };
    let json = serde_json::to_string(&node).unwrap();
    let back: RegExpAstNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, back);
}

#[test]
fn ast_concat_serde_roundtrip() {
    let node = RegExpAstNode::Concat(vec![
        RegExpAstNode::Literal('a'),
        RegExpAstNode::Dot,
        RegExpAstNode::EndAnchor,
    ]);
    let json = serde_json::to_string(&node).unwrap();
    let back: RegExpAstNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, back);
}

#[test]
fn ast_alternation_serde_roundtrip() {
    let node = RegExpAstNode::Alternation(vec![
        RegExpAstNode::Literal('x'),
        RegExpAstNode::Literal('y'),
    ]);
    let json = serde_json::to_string(&node).unwrap();
    let back: RegExpAstNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, back);
}

#[test]
fn ast_quantifier_serde_roundtrip() {
    let node = RegExpAstNode::Quantifier {
        child: Box::new(RegExpAstNode::Literal('q')),
        min: 2,
        max: Some(5),
        greedy: false,
    };
    let json = serde_json::to_string(&node).unwrap();
    let back: RegExpAstNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, back);
}

#[test]
fn ast_group_serde_roundtrip() {
    let node = RegExpAstNode::Group {
        index: 3,
        child: Box::new(RegExpAstNode::Dot),
    };
    let json = serde_json::to_string(&node).unwrap();
    let back: RegExpAstNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, back);
}

#[test]
fn ast_non_capturing_group_serde_roundtrip() {
    let node = RegExpAstNode::NonCapturingGroup(Box::new(RegExpAstNode::Literal('n')));
    let json = serde_json::to_string(&node).unwrap();
    let back: RegExpAstNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, back);
}

#[test]
fn ast_lookahead_serde_roundtrip() {
    for positive in [true, false] {
        let node = RegExpAstNode::Lookahead {
            child: Box::new(RegExpAstNode::Literal('a')),
            positive,
        };
        let json = serde_json::to_string(&node).unwrap();
        let back: RegExpAstNode = serde_json::from_str(&json).unwrap();
        assert_eq!(node, back);
    }
}

#[test]
fn ast_lookbehind_serde_roundtrip() {
    for positive in [true, false] {
        let node = RegExpAstNode::Lookbehind {
            child: Box::new(RegExpAstNode::Literal('b')),
            positive,
        };
        let json = serde_json::to_string(&node).unwrap();
        let back: RegExpAstNode = serde_json::from_str(&json).unwrap();
        assert_eq!(node, back);
    }
}

#[test]
fn ast_deeply_nested_serde_roundtrip() {
    // Group containing quantifier containing alternation containing char-class
    let node = RegExpAstNode::Group {
        index: 1,
        child: Box::new(RegExpAstNode::Quantifier {
            child: Box::new(RegExpAstNode::Alternation(vec![
                RegExpAstNode::CharClass {
                    negated: false,
                    ranges: vec![CharRange::range('0', '9')],
                },
                RegExpAstNode::UnicodeProperty {
                    property: UnicodeCategory::Ll,
                    negated: false,
                },
            ])),
            min: 1,
            max: None,
            greedy: true,
        }),
    };
    let json = serde_json::to_string(&node).unwrap();
    let back: RegExpAstNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, back);
}

// =========================================================================
// Section 2 — NFA topology edge cases
// =========================================================================

#[test]
fn nfa_epsilon_closure_with_cycle() {
    // 0 -eps-> 1 -eps-> 2 -eps-> 0 (cycle), 2 is accept
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
                transitions: vec![(NfaTransition::Epsilon, 0)],
                is_accept: true,
            },
        ],
        start_state: 0,
        accept_states: {
            let mut s = BTreeSet::new();
            s.insert(2);
            s
        },
        state_count: 3,
    };
    let initial = {
        let mut s = BTreeSet::new();
        s.insert(0);
        s
    };
    let closure = nfa.epsilon_closure(&initial);
    // Must terminate despite cycle and include all 3 states
    assert_eq!(closure.len(), 3);
    assert!(closure.contains(&0));
    assert!(closure.contains(&1));
    assert!(closure.contains(&2));
}

#[test]
fn nfa_epsilon_closure_diamond_topology() {
    // 0 -eps-> 1, 0 -eps-> 2, 1 -eps-> 3, 2 -eps-> 3
    let nfa = NfaProgram {
        states: vec![
            NfaState {
                id: 0,
                transitions: vec![(NfaTransition::Epsilon, 1), (NfaTransition::Epsilon, 2)],
                is_accept: false,
            },
            NfaState {
                id: 1,
                transitions: vec![(NfaTransition::Epsilon, 3)],
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

#[test]
fn nfa_has_accepting_path_via_epsilon_chain() {
    // 0 -eps-> 1 -eps-> 2 (accept). No char transitions at all.
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
                transitions: vec![],
                is_accept: true,
            },
        ],
        start_state: 0,
        accept_states: {
            let mut s = BTreeSet::new();
            s.insert(2);
            s
        },
        state_count: 3,
    };
    assert!(nfa.has_accepting_path());
}

#[test]
fn nfa_has_accepting_path_start_is_accept() {
    let nfa = NfaProgram {
        states: vec![NfaState {
            id: 0,
            transitions: vec![],
            is_accept: true,
        }],
        start_state: 0,
        accept_states: {
            let mut s = BTreeSet::new();
            s.insert(0);
            s
        },
        state_count: 1,
    };
    assert!(nfa.has_accepting_path());
}

#[test]
fn nfa_epsilon_closure_empty_input_set() {
    let nfa = NfaProgram {
        states: vec![NfaState {
            id: 0,
            transitions: vec![(NfaTransition::Epsilon, 1)],
            is_accept: false,
        }],
        start_state: 0,
        accept_states: BTreeSet::new(),
        state_count: 1,
    };
    let closure = nfa.epsilon_closure(&BTreeSet::new());
    assert!(closure.is_empty());
}

#[test]
fn nfa_epsilon_closure_multiple_start_states() {
    // Start from both 0 and 2. 0 -eps-> 1, 2 -eps-> 3
    let nfa = NfaProgram {
        states: vec![
            NfaState {
                id: 0,
                transitions: vec![(NfaTransition::Epsilon, 1)],
                is_accept: false,
            },
            NfaState {
                id: 1,
                transitions: vec![],
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
    let mut initial = BTreeSet::new();
    initial.insert(0);
    initial.insert(2);
    let closure = nfa.epsilon_closure(&initial);
    assert_eq!(closure.len(), 4);
}

#[test]
fn nfa_serde_roundtrip() {
    let nfa = NfaProgram {
        states: vec![
            NfaState {
                id: 0,
                transitions: vec![(NfaTransition::Char('x'), 1), (NfaTransition::Epsilon, 2)],
                is_accept: false,
            },
            NfaState {
                id: 1,
                transitions: vec![(NfaTransition::Any, 2)],
                is_accept: false,
            },
            NfaState {
                id: 2,
                transitions: vec![(NfaTransition::Range(CharRange::range('a', 'z')), 0)],
                is_accept: true,
            },
        ],
        start_state: 0,
        accept_states: {
            let mut s = BTreeSet::new();
            s.insert(2);
            s
        },
        state_count: 3,
    };
    let json = serde_json::to_string(&nfa).unwrap();
    let back: NfaProgram = serde_json::from_str(&json).unwrap();
    assert_eq!(nfa, back);
}

// =========================================================================
// Section 3 — CharRange boundary conditions
// =========================================================================

#[test]
fn char_range_max_unicode_char() {
    let r = CharRange::single('\u{10FFFF}');
    assert_eq!(r.len(), 1);
    assert!(r.contains('\u{10FFFF}'));
    assert!(!r.is_empty());
}

#[test]
fn char_range_null_char() {
    let r = CharRange::single('\0');
    assert_eq!(r.len(), 1);
    assert!(r.contains('\0'));
    assert!(!r.contains('\u{0001}'));
}

#[test]
fn char_range_full_ascii() {
    let r = CharRange::range('\0', '\u{007F}');
    assert_eq!(r.len(), 128);
    assert!(r.contains('A'));
    assert!(r.contains('\0'));
    assert!(r.contains('\u{007F}'));
    assert!(!r.contains('\u{0080}'));
}

#[test]
fn char_range_same_start_end() {
    let r = CharRange::range('M', 'M');
    assert_eq!(r.len(), 1);
    assert!(r.contains('M'));
    assert!(!r.contains('N'));
}

#[test]
fn char_range_inverted_is_empty_and_contains_nothing() {
    let r = CharRange {
        start: 'z',
        end: 'a',
    };
    assert!(r.is_empty());
    assert!(!r.contains('a'));
    assert!(!r.contains('m'));
    assert!(!r.contains('z'));
}

#[test]
fn char_range_serde_roundtrip() {
    let r = CharRange::range('\u{0100}', '\u{01FF}');
    let json = serde_json::to_string(&r).unwrap();
    let back: CharRange = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
    assert_eq!(back.len(), 256);
}

#[test]
fn char_range_surrogate_adjacent() {
    // Range right before surrogate range
    let r = CharRange::range('\u{D700}', '\u{D7FF}');
    assert_eq!(r.len(), 256);
    assert!(r.contains('\u{D7FF}'));
}

// =========================================================================
// Section 4 — Compile with config edge values
// =========================================================================

#[test]
fn compile_max_nfa_states_zero_declines_everything() {
    let mut config = default_config();
    config.max_nfa_states = 0;
    let ast = RegExpAstNode::Literal('a');
    // Even a single literal produces 2 NFA states, exceeding budget of 0
    let result = compile_regexp("a", &empty_flags(), &ast, &config, epoch(1));
    if let Ok(c) = result {
        assert_eq!(c.tier, AutomataTier::Declined);
    }
    // Err is also acceptable
}

#[test]
fn compile_max_quantifier_nesting_zero_declines_any_quantifier() {
    let mut config = default_config();
    config.max_quantifier_nesting = 0;
    let ast = RegExpAstNode::Quantifier {
        child: Box::new(RegExpAstNode::Literal('a')),
        min: 0,
        max: None,
        greedy: true,
    };
    let result = compile_regexp("a*", &empty_flags(), &ast, &config, epoch(1));
    if let Ok(c) = result {
        // Nesting of 1 > max of 0, should be catastrophic -> declined
        assert_eq!(c.tier, AutomataTier::Declined);
        assert!(c.receipt.tail_risk.catastrophic_possible);
    }
    // Err is also acceptable
}

#[test]
fn compile_dfa_disabled_uses_bounded_nfa() {
    let mut config = default_config();
    config.enable_dfa = false;
    let ast = RegExpAstNode::Concat(vec![
        RegExpAstNode::Literal('h'),
        RegExpAstNode::Literal('e'),
        RegExpAstNode::Literal('l'),
    ]);
    let compiled = compile_ok("hel", &empty_flags(), &ast, &config, epoch(1));
    assert_eq!(compiled.tier, AutomataTier::BoundedNfa);
    assert_eq!(compiled.receipt.confidence_millionths, 800_000);
    // DFA state count should be 0 when DFA not elected
    assert_eq!(compiled.receipt.dfa_state_count, 0);
}

#[test]
fn compile_dfa_elected_has_nonzero_dfa_state_count() {
    let config = default_config();
    let ast = RegExpAstNode::Literal('x');
    let compiled = compile_ok("x", &empty_flags(), &ast, &config, epoch(1));
    assert_eq!(compiled.tier, AutomataTier::Dfa);
    // DFA state count = nfa_state_count * 2 per source
    assert_eq!(
        compiled.receipt.dfa_state_count,
        compiled.receipt.nfa_state_count * 2
    );
}

// =========================================================================
// Section 5 — Flag combination compilation
// =========================================================================

#[test]
fn compile_with_all_non_conflicting_flags() {
    let mut flags = BTreeSet::new();
    flags.insert(RegExpFlag::Global);
    flags.insert(RegExpFlag::IgnoreCase);
    flags.insert(RegExpFlag::Multiline);
    flags.insert(RegExpFlag::DotAll);
    flags.insert(RegExpFlag::Unicode);
    flags.insert(RegExpFlag::Sticky);
    flags.insert(RegExpFlag::HasIndices);
    let ast = RegExpAstNode::Literal('a');
    let compiled = compile_ok("a", &flags, &ast, &default_config(), epoch(1));
    assert_eq!(compiled.flags.len(), 7);
    assert!(compiled.tier.is_usable());
}

#[test]
fn compile_v_flag_alone_succeeds() {
    let mut flags = BTreeSet::new();
    flags.insert(RegExpFlag::UnicodeSets);
    let ast = RegExpAstNode::Literal('a');
    let compiled = compile_ok("a", &flags, &ast, &default_config(), epoch(1));
    assert!(compiled.tier.is_usable());
    assert!(compiled.flags.contains(&RegExpFlag::UnicodeSets));
}

#[test]
fn compile_u_flag_alone_succeeds() {
    let mut flags = BTreeSet::new();
    flags.insert(RegExpFlag::Unicode);
    let ast = RegExpAstNode::Literal('a');
    let compiled = compile_ok("a", &flags, &ast, &default_config(), epoch(1));
    assert!(compiled.flags.contains(&RegExpFlag::Unicode));
}

// =========================================================================
// Section 6 — Non-capturing group and lookahead compilation
// =========================================================================

#[test]
fn non_capturing_group_compiles_as_child() {
    let ast = RegExpAstNode::NonCapturingGroup(Box::new(RegExpAstNode::Alternation(vec![
        RegExpAstNode::Literal('a'),
        RegExpAstNode::Literal('b'),
    ])));
    let compiled = compile_ok("(?:a|b)", &empty_flags(), &ast, &default_config(), epoch(1));
    assert_eq!(compiled.tier, AutomataTier::Dfa);
    // Non-capturing groups don't count as capture groups
    assert_eq!(compiled.receipt.capture_group_count, 0);
}

#[test]
fn positive_lookahead_compiles() {
    let ast = RegExpAstNode::Concat(vec![
        RegExpAstNode::Lookahead {
            child: Box::new(RegExpAstNode::Literal('x')),
            positive: true,
        },
        RegExpAstNode::Literal('x'),
    ]);
    let compiled = compile_ok("(?=x)x", &empty_flags(), &ast, &default_config(), epoch(1));
    assert!(compiled.tier.is_usable());
}

#[test]
fn negative_lookahead_compiles() {
    let ast = RegExpAstNode::Concat(vec![
        RegExpAstNode::Lookahead {
            child: Box::new(RegExpAstNode::Literal('y')),
            positive: false,
        },
        RegExpAstNode::Literal('x'),
    ]);
    let compiled = compile_ok("(?!y)x", &empty_flags(), &ast, &default_config(), epoch(1));
    assert!(compiled.tier.is_usable());
}

#[test]
fn negative_lookbehind_forces_interpreter() {
    let ast = RegExpAstNode::Lookbehind {
        child: Box::new(RegExpAstNode::Literal('z')),
        positive: false,
    };
    let compiled = compile_ok("(?<!z)", &empty_flags(), &ast, &default_config(), epoch(1));
    assert_eq!(compiled.tier, AutomataTier::InterpreterFallback);
}

// =========================================================================
// Section 7 — Bounded quantifier variants
// =========================================================================

#[test]
fn bounded_quantifier_exact_count() {
    let ast = RegExpAstNode::Quantifier {
        child: Box::new(RegExpAstNode::Literal('a')),
        min: 3,
        max: Some(3),
        greedy: true,
    };
    let compiled = compile_ok("a{3}", &empty_flags(), &ast, &default_config(), epoch(1));
    assert!(compiled.tier.is_usable());
}

#[test]
fn bounded_quantifier_range() {
    let ast = RegExpAstNode::Quantifier {
        child: Box::new(RegExpAstNode::Literal('b')),
        min: 2,
        max: Some(5),
        greedy: true,
    };
    let compiled = compile_ok("b{2,5}", &empty_flags(), &ast, &default_config(), epoch(1));
    assert!(compiled.tier.is_usable());
    assert!(compiled.nfa.state_count > 0);
}

#[test]
fn non_greedy_quantifier_compiles() {
    let ast = RegExpAstNode::Quantifier {
        child: Box::new(RegExpAstNode::Literal('c')),
        min: 0,
        max: None,
        greedy: false,
    };
    let compiled = compile_ok("c*?", &empty_flags(), &ast, &default_config(), epoch(1));
    assert!(compiled.tier.is_usable());
}

// =========================================================================
// Section 8 — Multiple backreferences and capture groups
// =========================================================================

#[test]
fn multiple_backreferences_interpreter_tier() {
    let ast = RegExpAstNode::Concat(vec![
        RegExpAstNode::Group {
            index: 1,
            child: Box::new(RegExpAstNode::Literal('a')),
        },
        RegExpAstNode::Group {
            index: 2,
            child: Box::new(RegExpAstNode::Literal('b')),
        },
        RegExpAstNode::Backreference(1),
        RegExpAstNode::Backreference(2),
    ]);
    let compiled = compile_ok(
        "(a)(b)\\1\\2",
        &empty_flags(),
        &ast,
        &default_config(),
        epoch(1),
    );
    assert_eq!(compiled.tier, AutomataTier::InterpreterFallback);
    assert_eq!(compiled.receipt.capture_group_count, 2);
}

#[test]
fn nested_groups_count_correctly() {
    // ((a)(b))
    let ast = RegExpAstNode::Group {
        index: 1,
        child: Box::new(RegExpAstNode::Concat(vec![
            RegExpAstNode::Group {
                index: 2,
                child: Box::new(RegExpAstNode::Literal('a')),
            },
            RegExpAstNode::Group {
                index: 3,
                child: Box::new(RegExpAstNode::Literal('b')),
            },
        ])),
    };
    let compiled = compile_ok(
        "((a)(b))",
        &empty_flags(),
        &ast,
        &default_config(),
        epoch(1),
    );
    assert_eq!(compiled.receipt.capture_group_count, 3);
}

// =========================================================================
// Section 9 — Negated char class and unicode property compilation
// =========================================================================

#[test]
fn negated_char_class_compiles() {
    let ast = RegExpAstNode::CharClass {
        negated: true,
        ranges: vec![CharRange::range('0', '9')],
    };
    let compiled = compile_ok("[^0-9]", &empty_flags(), &ast, &default_config(), epoch(1));
    assert!(compiled.tier.is_usable());
}

#[test]
fn negated_unicode_property_collects_category() {
    let ast = RegExpAstNode::UnicodeProperty {
        property: UnicodeCategory::Punctuation,
        negated: true,
    };
    let compiled = compile_ok(
        "\\P{Punctuation}",
        &empty_flags(),
        &ast,
        &default_config(),
        epoch(1),
    );
    assert!(
        compiled
            .receipt
            .unicode_categories_used
            .contains(&UnicodeCategory::Punctuation)
    );
}

#[test]
fn all_unicode_categories_collected_from_concat() {
    let nodes: Vec<_> = UnicodeCategory::ALL
        .iter()
        .map(|cat| RegExpAstNode::UnicodeProperty {
            property: *cat,
            negated: false,
        })
        .collect();
    let ast = RegExpAstNode::Concat(nodes);
    let compiled = compile_ok(
        "all_cats",
        &empty_flags(),
        &ast,
        &default_config(),
        epoch(1),
    );
    for cat in UnicodeCategory::ALL {
        assert!(
            compiled.receipt.unicode_categories_used.contains(cat),
            "missing category: {}",
            cat.as_str()
        );
    }
}

// =========================================================================
// Section 10 — Empty concat and alternation
// =========================================================================

#[test]
fn empty_concat_compiles() {
    let ast = RegExpAstNode::Concat(vec![]);
    let compiled = compile_ok("(empty)", &empty_flags(), &ast, &default_config(), epoch(1));
    assert!(compiled.tier.is_usable());
    assert!(compiled.nfa.state_count >= 1);
}

#[test]
fn empty_alternation_compiles() {
    let ast = RegExpAstNode::Alternation(vec![]);
    let compiled = compile_ok(
        "(empty_alt)",
        &empty_flags(),
        &ast,
        &default_config(),
        epoch(1),
    );
    assert!(compiled.tier.is_usable());
}

// =========================================================================
// Section 11 — Cross-epoch hash stability and divergence
// =========================================================================

#[test]
fn same_pattern_same_epoch_same_hash() {
    let ast = RegExpAstNode::Literal('z');
    let c1 = compile_ok("z", &empty_flags(), &ast, &default_config(), epoch(42));
    let c2 = compile_ok("z", &empty_flags(), &ast, &default_config(), epoch(42));
    assert_eq!(c1.content_hash, c2.content_hash);
    assert_eq!(c1.receipt.receipt_hash, c2.receipt.receipt_hash);
    assert_eq!(c1.receipt.automata_hash, c2.receipt.automata_hash);
}

#[test]
fn same_pattern_different_epoch_different_content_hash() {
    let ast = RegExpAstNode::Literal('z');
    let c1 = compile_ok("z", &empty_flags(), &ast, &default_config(), epoch(1));
    let c2 = compile_ok("z", &empty_flags(), &ast, &default_config(), epoch(2));
    // content_hash (automata_hash) incorporates epoch, so should differ
    assert_ne!(c1.content_hash, c2.content_hash);
    // receipt_hash does NOT include epoch (per source), so should be same
    assert_eq!(c1.receipt.receipt_hash, c2.receipt.receipt_hash);
}

#[test]
fn different_patterns_same_epoch_different_hashes() {
    let ast_a = RegExpAstNode::Literal('a');
    let ast_b = RegExpAstNode::Literal('b');
    let c1 = compile_ok("a", &empty_flags(), &ast_a, &default_config(), epoch(1));
    let c2 = compile_ok("b", &empty_flags(), &ast_b, &default_config(), epoch(1));
    assert_ne!(c1.content_hash, c2.content_hash);
    assert_ne!(c1.receipt.receipt_hash, c2.receipt.receipt_hash);
}

// =========================================================================
// Section 12 — Cache stress and access-count tracking
// =========================================================================

#[test]
fn cache_access_count_increments_on_repeated_get() {
    let config = default_config();
    let ast = RegExpAstNode::Literal('a');
    let compiled = compile_ok("a", &empty_flags(), &ast, &config, epoch(1));
    let hash = compiled.content_hash.clone();

    let mut cache = AutomataCache::new(10);
    cache.insert(compiled);

    // Get 5 times
    for i in 0..5 {
        let got = cache.get(&hash);
        assert!(got.is_some(), "get #{i} should succeed");
    }
    assert_eq!(cache.hits, 5);
    assert_eq!(cache.misses, 0);
}

#[test]
fn cache_stress_many_patterns() {
    let config = default_config();
    let mut cache = AutomataCache::new(50);
    let mut hashes = Vec::new();

    // Insert 100 patterns into a cache of capacity 50
    for i in 0u32..100 {
        let ch = char::from_u32('A' as u32 + (i % 26)).unwrap();
        let pattern = format!("p{i}_{ch}");
        let ast = RegExpAstNode::Literal(ch);
        let compiled = compile_ok(&pattern, &empty_flags(), &ast, &config, epoch(1));
        hashes.push(compiled.content_hash.clone());
        cache.insert(compiled);
    }

    assert_eq!(cache.len(), 50);
    assert!(cache.evictions >= 50);

    // Only the last 50 should be present
    let mut present = 0u32;
    for h in &hashes {
        if cache.get(h).is_some() {
            present += 1;
        }
    }
    assert_eq!(present, 50);
}

#[test]
fn cache_reinsertion_replaces_entry() {
    let config = default_config();
    let ast = RegExpAstNode::Literal('r');
    let compiled = compile_ok("r", &empty_flags(), &ast, &config, epoch(1));
    let hash = compiled.content_hash.clone();

    let mut cache = AutomataCache::new(10);
    cache.insert(compiled.clone());
    // Access it to increase count
    cache.get(&hash);
    assert_eq!(cache.hits, 1);

    // Re-insert same hash
    cache.insert(compiled);
    assert_eq!(cache.len(), 1);
}

#[test]
fn cache_hit_rate_with_mixed_lookups() {
    let config = default_config();
    let ast = RegExpAstNode::Literal('a');
    let compiled = compile_ok("a", &empty_flags(), &ast, &config, epoch(1));
    let hash = compiled.content_hash.clone();

    let mut cache = AutomataCache::new(10);
    cache.insert(compiled);

    // 3 hits, 2 misses -> 60% -> 600_000 millionths
    cache.get(&hash);
    cache.get(&hash);
    cache.get(&hash);
    cache.get("miss1");
    cache.get("miss2");

    assert_eq!(cache.hits, 3);
    assert_eq!(cache.misses, 2);
    assert_eq!(cache.hit_rate_millionths(), 600_000);
}

#[test]
fn cache_capacity_one() {
    let config = default_config();
    let mut cache = AutomataCache::new(1);

    let ast_a = RegExpAstNode::Literal('a');
    let ca = compile_ok("a", &empty_flags(), &ast_a, &config, epoch(1));
    let hash_a = ca.content_hash.clone();
    cache.insert(ca);
    assert_eq!(cache.len(), 1);

    let ast_b = RegExpAstNode::Literal('b');
    let cb = compile_ok("b", &empty_flags(), &ast_b, &config, epoch(1));
    cache.insert(cb);
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.evictions, 1);
    // 'a' should be evicted
    assert!(cache.get(&hash_a).is_none());
}

// =========================================================================
// Section 13 — TailRisk boundary and composition
// =========================================================================

#[test]
fn tail_risk_is_safe_at_99999() {
    let mut risk = TailRiskAssessment::safe();
    risk.risk_millionths = 99_999;
    assert!(risk.is_safe());
}

#[test]
fn tail_risk_not_safe_at_100000() {
    let mut risk = TailRiskAssessment::safe();
    risk.risk_millionths = 100_000;
    assert!(!risk.is_safe());
}

#[test]
fn tail_risk_catastrophic_flag_overrides_low_risk() {
    let mut risk = TailRiskAssessment::safe();
    risk.risk_millionths = 0;
    risk.catastrophic_possible = true;
    assert!(!risk.is_safe());
}

#[test]
fn tail_risk_safe_has_correct_defaults() {
    let risk = TailRiskAssessment::safe();
    assert_eq!(risk.risk_millionths, 0);
    assert!(!risk.catastrophic_possible);
    assert_eq!(risk.ambiguous_state_count, 0);
    assert_eq!(risk.max_quantifier_nesting, 0);
    assert!(!risk.has_overlapping_alternatives);
    assert_eq!(risk.summary, "safe");
}

#[test]
fn tail_risk_moderate_nesting_not_catastrophic() {
    // 3 levels of nesting should not be catastrophic with default config
    let mut ast = RegExpAstNode::Literal('a');
    for _ in 0..3 {
        ast = RegExpAstNode::Quantifier {
            child: Box::new(ast),
            min: 0,
            max: None,
            greedy: true,
        };
    }
    let compiled = compile_ok(
        "(a*)*{3}",
        &empty_flags(),
        &ast,
        &default_config(),
        epoch(1),
    );
    // 3 nesting levels <= default max of 8 and NFA size is small
    assert!(compiled.tier.is_usable());
}

// =========================================================================
// Section 14 — Error path and Display tests
// =========================================================================

#[test]
fn error_empty_pattern_display_contains_empty() {
    let err = RegExpCompileError::EmptyPattern;
    let s = err.to_string();
    assert!(s.contains("empty"), "expected 'empty' in: {s}");
}

#[test]
fn error_invalid_flag_display_contains_detail() {
    let err = RegExpCompileError::InvalidFlagCombination {
        detail: "u+v conflict".into(),
    };
    let s = err.to_string();
    assert!(s.contains("u+v conflict"), "expected detail in: {s}");
}

#[test]
fn error_nfa_budget_display_contains_numbers() {
    let err = RegExpCompileError::NfaBudgetExceeded {
        states: 20000,
        budget: 10000,
    };
    let s = err.to_string();
    assert!(s.contains("20000"));
    assert!(s.contains("10000"));
}

#[test]
fn error_dfa_budget_display_contains_numbers() {
    let err = RegExpCompileError::DfaBudgetExceeded {
        states: 60000,
        budget: 50000,
    };
    let s = err.to_string();
    assert!(s.contains("60000"));
    assert!(s.contains("50000"));
}

#[test]
fn error_catastrophic_display_contains_detail() {
    let err = RegExpCompileError::CatastrophicRisk {
        detail: "nested quantifiers".into(),
    };
    let s = err.to_string();
    assert!(s.contains("nested quantifiers"));
}

#[test]
fn error_unsupported_feature_display_contains_feature() {
    let err = RegExpCompileError::UnsupportedFeature {
        feature: "atomic groups".into(),
    };
    let s = err.to_string();
    assert!(s.contains("atomic groups"));
}

#[test]
fn error_timeout_display() {
    let err = RegExpCompileError::CompilationTimeout;
    let s = err.to_string();
    assert!(s.contains("timeout"), "expected 'timeout' in: {s}");
}

// =========================================================================
// Section 15 — AutomataTier Display
// =========================================================================

#[test]
fn automata_tier_display_all_unique() {
    let mut displays = BTreeSet::new();
    for tier in AutomataTier::ALL {
        let s = format!("{tier}");
        assert!(displays.insert(s.clone()), "duplicate display: {s}");
    }
    assert_eq!(displays.len(), 4);
}

#[test]
fn automata_tier_as_str_matches_display() {
    for tier in AutomataTier::ALL {
        assert_eq!(tier.as_str(), format!("{tier}"));
    }
}

// =========================================================================
// Section 16 — DeclineReason Display
// =========================================================================

#[test]
fn decline_reason_as_str_matches_display() {
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
    for r in &all {
        assert_eq!(r.as_str(), format!("{r}"));
    }
}

// =========================================================================
// Section 17 — Compilation receipt consistency
// =========================================================================

#[test]
fn receipt_schema_version_matches_module_constant() {
    let ast = RegExpAstNode::Literal('a');
    let compiled = compile_ok("a", &empty_flags(), &ast, &default_config(), epoch(1));
    assert_eq!(
        compiled.receipt.schema_version,
        REGEXP_ENGINE_SCHEMA_VERSION
    );
}

#[test]
fn receipt_flags_preserved() {
    let mut flags = BTreeSet::new();
    flags.insert(RegExpFlag::Global);
    flags.insert(RegExpFlag::Multiline);
    flags.insert(RegExpFlag::DotAll);
    let ast = RegExpAstNode::Literal('a');
    let compiled = compile_ok("a", &flags, &ast, &default_config(), epoch(1));
    assert_eq!(compiled.receipt.flags, flags);
    assert_eq!(compiled.flags, flags);
}

#[test]
fn receipt_decline_reasons_empty_for_successful_compilation() {
    let ast = RegExpAstNode::Literal('a');
    let compiled = compile_ok("a", &empty_flags(), &ast, &default_config(), epoch(1));
    assert!(compiled.receipt.decline_reasons.is_empty());
}

#[test]
fn receipt_pattern_preserved() {
    let ast = RegExpAstNode::Literal('a');
    let compiled = compile_ok(
        "hello_world",
        &empty_flags(),
        &ast,
        &default_config(),
        epoch(1),
    );
    assert_eq!(compiled.receipt.pattern, "hello_world");
    assert_eq!(compiled.pattern, "hello_world");
}

// =========================================================================
// Section 18 — Evidence inventory edge cases
// =========================================================================

#[test]
fn evidence_inventory_contract_satisfied_requires_nonzero_specimens() {
    let inv = RegExpEvidenceInventory {
        schema_version: "v1".into(),
        component: "test".into(),
        specimen_count: 0,
        pass_count: 0,
        fail_count: 0,
        family_coverage: BTreeMap::new(),
        evidence: vec![],
    };
    // 0 specimens -> contract NOT satisfied
    assert!(!inv.contract_satisfied());
}

#[test]
fn evidence_inventory_contract_fails_with_any_failures() {
    let inv = RegExpEvidenceInventory {
        schema_version: "v1".into(),
        component: "test".into(),
        specimen_count: 10,
        pass_count: 9,
        fail_count: 1,
        family_coverage: BTreeMap::new(),
        evidence: vec![],
    };
    assert!(!inv.contract_satisfied());
}

#[test]
fn evidence_inventory_contract_passes_with_all_pass() {
    let inv = RegExpEvidenceInventory {
        schema_version: "v1".into(),
        component: "test".into(),
        specimen_count: 5,
        pass_count: 5,
        fail_count: 0,
        family_coverage: BTreeMap::new(),
        evidence: vec![],
    };
    assert!(inv.contract_satisfied());
}

// =========================================================================
// Section 19 — write_regexp_evidence_bundle I/O
// =========================================================================

#[test]
fn write_evidence_bundle_creates_all_files() {
    let dir = std::env::temp_dir().join("regexp_deep_test_bundle");
    let _ = std::fs::remove_dir_all(&dir);
    let artifacts = write_regexp_evidence_bundle(&dir).unwrap();

    assert!(artifacts.inventory_path.exists());
    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.events_path.exists());
    assert!(artifacts.commands_path.exists());
    assert!(!artifacts.inventory_hash.is_empty());

    // Verify inventory parses
    let inv_json = std::fs::read_to_string(&artifacts.inventory_path).unwrap();
    let inv: RegExpEvidenceInventory = serde_json::from_str(&inv_json).unwrap();
    assert!(inv.contract_satisfied());

    // Verify manifest parses
    let manifest_json = std::fs::read_to_string(&artifacts.run_manifest_path).unwrap();
    let manifest: RegExpRunManifest = serde_json::from_str(&manifest_json).unwrap();
    assert!(manifest.contract_satisfied);
    assert_eq!(manifest.policy_id, REGEXP_ENGINE_POLICY_ID);

    // Verify events is multi-line JSONL
    let events_text = std::fs::read_to_string(&artifacts.events_path).unwrap();
    let lines: Vec<&str> = events_text.lines().collect();
    assert!(lines.len() >= 3); // start + specimens + end
    for line in &lines {
        let _: RegExpEvidenceEvent = serde_json::from_str(line).unwrap();
    }

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn write_evidence_bundle_deterministic() {
    let dir1 = std::env::temp_dir().join("regexp_deep_test_det1");
    let dir2 = std::env::temp_dir().join("regexp_deep_test_det2");
    let _ = std::fs::remove_dir_all(&dir1);
    let _ = std::fs::remove_dir_all(&dir2);

    let a1 = write_regexp_evidence_bundle(&dir1).unwrap();
    let a2 = write_regexp_evidence_bundle(&dir2).unwrap();

    assert_eq!(a1.inventory_hash, a2.inventory_hash);

    let inv1 = std::fs::read_to_string(&a1.inventory_path).unwrap();
    let inv2 = std::fs::read_to_string(&a2.inventory_path).unwrap();
    assert_eq!(inv1, inv2);

    let _ = std::fs::remove_dir_all(&dir1);
    let _ = std::fs::remove_dir_all(&dir2);
}

// =========================================================================
// Section 20 — Complex AST composition determinism
// =========================================================================

#[test]
fn complex_ast_compilation_deterministic() {
    // ^(?:([a-z]+)|\p{Lu})*\b$
    let ast = RegExpAstNode::Concat(vec![
        RegExpAstNode::StartAnchor,
        RegExpAstNode::Quantifier {
            child: Box::new(RegExpAstNode::NonCapturingGroup(Box::new(
                RegExpAstNode::Alternation(vec![
                    RegExpAstNode::Group {
                        index: 1,
                        child: Box::new(RegExpAstNode::Quantifier {
                            child: Box::new(RegExpAstNode::CharClass {
                                negated: false,
                                ranges: vec![CharRange::range('a', 'z')],
                            }),
                            min: 1,
                            max: None,
                            greedy: true,
                        }),
                    },
                    RegExpAstNode::UnicodeProperty {
                        property: UnicodeCategory::Lu,
                        negated: false,
                    },
                ]),
            ))),
            min: 0,
            max: None,
            greedy: true,
        },
        RegExpAstNode::WordBoundary { negated: false },
        RegExpAstNode::EndAnchor,
    ]);

    let c1 = compile_ok("complex", &empty_flags(), &ast, &default_config(), epoch(1));
    let c2 = compile_ok("complex", &empty_flags(), &ast, &default_config(), epoch(1));

    assert_eq!(c1.content_hash, c2.content_hash);
    assert_eq!(c1.receipt, c2.receipt);
    assert_eq!(c1.nfa.state_count, c2.nfa.state_count);
    assert_eq!(c1.receipt.capture_group_count, 1);
    assert!(
        c1.receipt
            .unicode_categories_used
            .contains(&UnicodeCategory::Lu)
    );
}

#[test]
fn compilation_with_word_boundary_negated() {
    let ast = RegExpAstNode::Concat(vec![
        RegExpAstNode::WordBoundary { negated: true },
        RegExpAstNode::Literal('x'),
    ]);
    let compiled = compile_ok("\\Bx", &empty_flags(), &ast, &default_config(), epoch(1));
    assert!(compiled.tier.is_usable());
}

// =========================================================================
// Section 21 — Constants verification
// =========================================================================

#[test]
fn all_schema_constants_nonempty() {
    assert!(!REGEXP_ENGINE_SCHEMA_VERSION.is_empty());
    assert!(!REGEXP_ENGINE_MANIFEST_SCHEMA_VERSION.is_empty());
    assert!(!REGEXP_ENGINE_EVENT_SCHEMA_VERSION.is_empty());
    assert!(!REGEXP_ENGINE_COMPONENT.is_empty());
    assert!(!REGEXP_ENGINE_POLICY_ID.is_empty());
}

#[test]
fn schema_versions_distinct() {
    let mut set = BTreeSet::new();
    set.insert(REGEXP_ENGINE_SCHEMA_VERSION);
    set.insert(REGEXP_ENGINE_MANIFEST_SCHEMA_VERSION);
    set.insert(REGEXP_ENGINE_EVENT_SCHEMA_VERSION);
    assert_eq!(set.len(), 3, "schema versions should be distinct");
}

#[test]
fn policy_id_is_rgc_312b() {
    assert_eq!(REGEXP_ENGINE_POLICY_ID, "RGC-312B");
}

// =========================================================================
// Section 22 — RegExpFlag ordering
// =========================================================================

#[test]
fn regexp_flag_ord_is_stable() {
    let flags_sorted: Vec<RegExpFlag> = RegExpFlag::ALL.to_vec();
    let mut flags_resorted = flags_sorted.clone();
    flags_resorted.sort();
    assert_eq!(flags_sorted, flags_resorted);
}

#[test]
fn regexp_flag_btreeset_deterministic_iteration() {
    let mut set1 = BTreeSet::new();
    set1.insert(RegExpFlag::Sticky);
    set1.insert(RegExpFlag::Global);
    set1.insert(RegExpFlag::Unicode);

    let mut set2 = BTreeSet::new();
    set2.insert(RegExpFlag::Unicode);
    set2.insert(RegExpFlag::Global);
    set2.insert(RegExpFlag::Sticky);

    let v1: Vec<_> = set1.iter().collect();
    let v2: Vec<_> = set2.iter().collect();
    assert_eq!(v1, v2);
}

// =========================================================================
// Section 23 — UnicodeCategory ordering
// =========================================================================

#[test]
fn unicode_category_ord_stable() {
    let cats: Vec<UnicodeCategory> = UnicodeCategory::ALL.to_vec();
    let mut resorted = cats.clone();
    resorted.sort();
    assert_eq!(cats, resorted);
}

// =========================================================================
// Section 24 — RegExpSpecimenFamily and RegExpExpectedOutcome Display
// =========================================================================

#[test]
fn specimen_family_display_matches_as_str() {
    for fam in RegExpSpecimenFamily::ALL {
        assert_eq!(fam.as_str(), format!("{fam}"));
    }
}

#[test]
fn unicode_category_display_matches_as_str() {
    for cat in UnicodeCategory::ALL {
        assert_eq!(cat.as_str(), format!("{cat}"));
    }
}

#[test]
fn regexp_flag_display_matches_as_str() {
    for flag in RegExpFlag::ALL {
        assert_eq!(flag.as_str(), format!("{flag}"));
    }
}

// =========================================================================
// Section 25 — Corpus run evidence hashes are unique
// =========================================================================

#[test]
fn corpus_evidence_hashes_all_unique() {
    let inv = run_regexp_corpus();
    let mut hashes = BTreeSet::new();
    for ev in &inv.evidence {
        assert!(
            hashes.insert(&ev.evidence_hash),
            "duplicate evidence_hash: {}",
            ev.evidence_hash
        );
    }
}

#[test]
fn corpus_all_evidence_has_specimen_id() {
    let inv = run_regexp_corpus();
    for ev in &inv.evidence {
        assert!(!ev.specimen_id.is_empty());
    }
}

#[test]
fn corpus_family_coverage_sums_to_total() {
    let inv = run_regexp_corpus();
    let coverage_total: u64 = inv.family_coverage.values().sum();
    assert_eq!(coverage_total, inv.specimen_count);
}

#[test]
fn corpus_passing_evidence_has_no_error_detail() {
    let inv = run_regexp_corpus();
    for ev in &inv.evidence {
        if ev.verdict == RegExpVerdict::Pass {
            assert!(
                ev.error_detail.is_none(),
                "passing specimen {} should have no error_detail",
                ev.specimen_id
            );
        }
    }
}
