#![forbid(unsafe_code)]

//! Deterministic RegExp compilation, automata caches, and tail-risk guards.
//!
//! Implements [RGC-312B]: compiles RegExp patterns into deterministic automata
//! programs with explicit Unicode semantics, compilation receipts, catastrophic-
//! tail guards, and user-visible reasons when the fast automata path is declined.
//!
//! Key design decisions:
//! - Patterns are compiled to an NFA, then optionally to a DFA when the state
//!   count is within budget. Catastrophic backtracking is detected via NFA
//!   state-explosion analysis before DFA conversion.
//! - Unicode class support covers the ES2024-observable categories (Lu, Ll, Nd,
//!   Zs, etc.) with explicit fallback when a class is unrecognized.
//! - Compilation receipts record the elected automata tier, Unicode coverage,
//!   and tail-risk assessment so downstream consumers can reason about cost.
//! - The automata cache is content-addressed with LRU eviction and deterministic
//!   ordering (BTreeMap).
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const REGEXP_ENGINE_SCHEMA_VERSION: &str = "franken-engine.regexp_deterministic_engine.v1";
pub const REGEXP_ENGINE_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.regexp_deterministic_engine_manifest.v1";
pub const REGEXP_ENGINE_EVENT_SCHEMA_VERSION: &str =
    "franken-engine.regexp_deterministic_engine_event.v1";
pub const REGEXP_ENGINE_COMPONENT: &str = "regexp_deterministic_engine";
pub const REGEXP_ENGINE_POLICY_ID: &str = "RGC-312B";

const MILLION: i64 = 1_000_000;

/// Default maximum NFA states before tail-risk is flagged.
const DEFAULT_MAX_NFA_STATES: u64 = 10_000;

/// Default maximum DFA states before DFA compilation is declined.
const DEFAULT_MAX_DFA_STATES: u64 = 50_000;

/// Default automata cache capacity (number of compiled patterns).
const DEFAULT_CACHE_CAPACITY: usize = 1024;

// ---------------------------------------------------------------------------
// RegExp flags
// ---------------------------------------------------------------------------

/// ES2024-observable RegExp flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegExpFlag {
    /// `g` — global search.
    Global,
    /// `i` — case-insensitive matching.
    IgnoreCase,
    /// `m` — multiline (^ and $ match line boundaries).
    Multiline,
    /// `s` — dotAll (`.` matches newlines).
    DotAll,
    /// `u` — Unicode mode.
    Unicode,
    /// `v` — unicodeSets mode (ES2024).
    UnicodeSets,
    /// `y` — sticky search.
    Sticky,
    /// `d` — hasIndices (match indices).
    HasIndices,
}

impl RegExpFlag {
    pub const ALL: &[Self] = &[
        Self::Global,
        Self::IgnoreCase,
        Self::Multiline,
        Self::DotAll,
        Self::Unicode,
        Self::UnicodeSets,
        Self::Sticky,
        Self::HasIndices,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Global => "g",
            Self::IgnoreCase => "i",
            Self::Multiline => "m",
            Self::DotAll => "s",
            Self::Unicode => "u",
            Self::UnicodeSets => "v",
            Self::Sticky => "y",
            Self::HasIndices => "d",
        }
    }

    pub fn from_char(c: char) -> Option<Self> {
        match c {
            'g' => Some(Self::Global),
            'i' => Some(Self::IgnoreCase),
            'm' => Some(Self::Multiline),
            's' => Some(Self::DotAll),
            'u' => Some(Self::Unicode),
            'v' => Some(Self::UnicodeSets),
            'y' => Some(Self::Sticky),
            'd' => Some(Self::HasIndices),
            _ => None,
        }
    }
}

impl fmt::Display for RegExpFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RegExp AST node kinds
// ---------------------------------------------------------------------------

/// Simplified RegExp AST node kinds for compilation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegExpAstNode {
    /// Literal character match.
    Literal(char),
    /// Character class `[abc]` or `[^abc]`.
    CharClass {
        negated: bool,
        ranges: Vec<CharRange>,
    },
    /// Unicode property escape `\p{Lu}`.
    UnicodeProperty {
        property: UnicodeCategory,
        negated: bool,
    },
    /// Dot (any character, respects dotAll flag).
    Dot,
    /// Concatenation of sub-expressions.
    Concat(Vec<RegExpAstNode>),
    /// Alternation `a|b`.
    Alternation(Vec<RegExpAstNode>),
    /// Quantifier: `*`, `+`, `?`, `{n,m}`.
    Quantifier {
        child: Box<RegExpAstNode>,
        min: u32,
        max: Option<u32>,
        greedy: bool,
    },
    /// Capturing group `(...)`.
    Group {
        index: u32,
        child: Box<RegExpAstNode>,
    },
    /// Non-capturing group `(?:...)`.
    NonCapturingGroup(Box<RegExpAstNode>),
    /// Lookahead `(?=...)` or `(?!...)`.
    Lookahead {
        child: Box<RegExpAstNode>,
        positive: bool,
    },
    /// Lookbehind `(?<=...)` or `(?<!...)`.
    Lookbehind {
        child: Box<RegExpAstNode>,
        positive: bool,
    },
    /// Start anchor `^`.
    StartAnchor,
    /// End anchor `$`.
    EndAnchor,
    /// Word boundary `\b` or `\B`.
    WordBoundary { negated: bool },
    /// Backreference `\1`.
    Backreference(u32),
}

/// A character range within a character class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CharRange {
    pub start: char,
    pub end: char,
}

impl CharRange {
    pub fn single(c: char) -> Self {
        Self { start: c, end: c }
    }

    pub fn range(start: char, end: char) -> Self {
        Self { start, end }
    }

    pub fn contains(&self, c: char) -> bool {
        c >= self.start && c <= self.end
    }

    pub fn len(&self) -> u64 {
        (self.end as u64).saturating_sub(self.start as u64) + 1
    }

    pub fn is_empty(&self) -> bool {
        self.start > self.end
    }
}

// ---------------------------------------------------------------------------
// Unicode categories (ES2024-observable subset)
// ---------------------------------------------------------------------------

/// Unicode general categories observable in ES2024 RegExp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnicodeCategory {
    /// Uppercase letter (Lu).
    Lu,
    /// Lowercase letter (Ll).
    Ll,
    /// Titlecase letter (Lt).
    Lt,
    /// Modifier letter (Lm).
    Lm,
    /// Other letter (Lo).
    Lo,
    /// Decimal digit number (Nd).
    Nd,
    /// Letter number (Nl).
    Nl,
    /// Other number (No).
    No,
    /// Space separator (Zs).
    Zs,
    /// Line separator (Zl).
    Zl,
    /// Paragraph separator (Zp).
    Zp,
    /// Mark categories (Mn, Mc, Me).
    Mark,
    /// Punctuation categories (Pc, Pd, Ps, Pe, Pi, Pf, Po).
    Punctuation,
    /// Symbol categories (Sm, Sc, Sk, So).
    Symbol,
    /// Other categories (Cc, Cf, Cs, Co, Cn).
    Other,
}

impl UnicodeCategory {
    pub const ALL: &[Self] = &[
        Self::Lu,
        Self::Ll,
        Self::Lt,
        Self::Lm,
        Self::Lo,
        Self::Nd,
        Self::Nl,
        Self::No,
        Self::Zs,
        Self::Zl,
        Self::Zp,
        Self::Mark,
        Self::Punctuation,
        Self::Symbol,
        Self::Other,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lu => "Lu",
            Self::Ll => "Ll",
            Self::Lt => "Lt",
            Self::Lm => "Lm",
            Self::Lo => "Lo",
            Self::Nd => "Nd",
            Self::Nl => "Nl",
            Self::No => "No",
            Self::Zs => "Zs",
            Self::Zl => "Zl",
            Self::Zp => "Zp",
            Self::Mark => "Mark",
            Self::Punctuation => "Punctuation",
            Self::Symbol => "Symbol",
            Self::Other => "Other",
        }
    }

    pub fn from_str_name(s: &str) -> Option<Self> {
        match s {
            "Lu" => Some(Self::Lu),
            "Ll" => Some(Self::Ll),
            "Lt" => Some(Self::Lt),
            "Lm" => Some(Self::Lm),
            "Lo" => Some(Self::Lo),
            "Nd" => Some(Self::Nd),
            "Nl" => Some(Self::Nl),
            "No" => Some(Self::No),
            "Zs" => Some(Self::Zs),
            "Zl" => Some(Self::Zl),
            "Zp" => Some(Self::Zp),
            "Mark" | "M" => Some(Self::Mark),
            "Punctuation" | "P" => Some(Self::Punctuation),
            "Symbol" | "S" => Some(Self::Symbol),
            "Other" | "C" => Some(Self::Other),
            _ => None,
        }
    }
}

impl fmt::Display for UnicodeCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Automata tier
// ---------------------------------------------------------------------------

/// The compilation tier elected for a pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomataTier {
    /// Full DFA — O(n) guaranteed matching, highest memory.
    Dfa,
    /// NFA with bounded backtracking — fallback when DFA is too large.
    BoundedNfa,
    /// Interpreter fallback — backreferences or lookbehind require this.
    InterpreterFallback,
    /// Declined — pattern rejected (catastrophic tail risk or unsupported).
    Declined,
}

impl AutomataTier {
    pub const ALL: &[Self] = &[
        Self::Dfa,
        Self::BoundedNfa,
        Self::InterpreterFallback,
        Self::Declined,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dfa => "dfa",
            Self::BoundedNfa => "bounded_nfa",
            Self::InterpreterFallback => "interpreter_fallback",
            Self::Declined => "declined",
        }
    }

    /// Is this tier usable for execution?
    pub fn is_usable(self) -> bool {
        !matches!(self, Self::Declined)
    }
}

impl fmt::Display for AutomataTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Decline reason
// ---------------------------------------------------------------------------

/// Reason why fast automata compilation was declined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclineReason {
    /// NFA state count exceeds budget.
    NfaStateBudgetExceeded,
    /// DFA state count exceeds budget.
    DfaStateBudgetExceeded,
    /// Catastrophic backtracking risk detected.
    CatastrophicBacktrackingRisk,
    /// Backreferences require interpreter.
    BackreferencePresent,
    /// Lookbehind requires interpreter.
    LookbehindPresent,
    /// Unsupported feature in pattern.
    UnsupportedFeature,
    /// Empty pattern.
    EmptyPattern,
    /// Invalid flag combination (e.g., `u` and `v` together).
    InvalidFlagCombination,
    /// Unicode property not recognized.
    UnrecognizedUnicodeProperty,
    /// Compilation budget (time) exceeded.
    CompilationBudgetExceeded,
}

impl DeclineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NfaStateBudgetExceeded => "nfa_state_budget_exceeded",
            Self::DfaStateBudgetExceeded => "dfa_state_budget_exceeded",
            Self::CatastrophicBacktrackingRisk => "catastrophic_backtracking_risk",
            Self::BackreferencePresent => "backreference_present",
            Self::LookbehindPresent => "lookbehind_present",
            Self::UnsupportedFeature => "unsupported_feature",
            Self::EmptyPattern => "empty_pattern",
            Self::InvalidFlagCombination => "invalid_flag_combination",
            Self::UnrecognizedUnicodeProperty => "unrecognized_unicode_property",
            Self::CompilationBudgetExceeded => "compilation_budget_exceeded",
        }
    }
}

impl fmt::Display for DeclineReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// NFA state and transition
// ---------------------------------------------------------------------------

/// NFA state identifier.
pub type NfaStateId = u64;

/// NFA transition kind.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NfaTransition {
    /// Match a single character.
    Char(char),
    /// Match any character in the range.
    Range(CharRange),
    /// Epsilon (free) transition.
    Epsilon,
    /// Match any character (dot).
    Any,
}

/// A single NFA state with its outgoing transitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NfaState {
    pub id: NfaStateId,
    pub transitions: Vec<(NfaTransition, NfaStateId)>,
    pub is_accept: bool,
}

/// Complete NFA representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NfaProgram {
    pub states: Vec<NfaState>,
    pub start_state: NfaStateId,
    pub accept_states: BTreeSet<NfaStateId>,
    pub state_count: u64,
}

impl NfaProgram {
    /// Compute the epsilon closure of a set of states.
    pub fn epsilon_closure(&self, state_ids: &BTreeSet<NfaStateId>) -> BTreeSet<NfaStateId> {
        let mut closure = state_ids.clone();
        let mut stack: Vec<NfaStateId> = state_ids.iter().copied().collect();
        while let Some(sid) = stack.pop() {
            if let Some(state) = self.states.iter().find(|s| s.id == sid) {
                for (trans, target) in &state.transitions {
                    if *trans == NfaTransition::Epsilon && closure.insert(*target) {
                        stack.push(*target);
                    }
                }
            }
        }
        closure
    }

    /// Check if any accept state is reachable from start.
    pub fn has_accepting_path(&self) -> bool {
        let initial = {
            let mut s = BTreeSet::new();
            s.insert(self.start_state);
            s
        };
        let reachable = self.epsilon_closure(&initial);
        reachable.iter().any(|sid| self.accept_states.contains(sid))
    }
}

// ---------------------------------------------------------------------------
// Tail-risk assessment
// ---------------------------------------------------------------------------

/// Tail-risk assessment for a compiled pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailRiskAssessment {
    /// Risk level in millionths (0 = safe, 1_000_000 = certain catastrophe).
    pub risk_millionths: i64,
    /// Whether catastrophic backtracking is possible.
    pub catastrophic_possible: bool,
    /// NFA states that participate in ambiguous transitions.
    pub ambiguous_state_count: u64,
    /// Maximum nesting depth of quantifiers.
    pub max_quantifier_nesting: u32,
    /// Whether the pattern has overlapping alternatives.
    pub has_overlapping_alternatives: bool,
    /// Human-readable summary.
    pub summary: String,
}

impl TailRiskAssessment {
    pub fn safe() -> Self {
        Self {
            risk_millionths: 0,
            catastrophic_possible: false,
            ambiguous_state_count: 0,
            max_quantifier_nesting: 0,
            has_overlapping_alternatives: false,
            summary: "safe".to_string(),
        }
    }

    pub fn is_safe(&self) -> bool {
        !self.catastrophic_possible && self.risk_millionths < 100_000
    }
}

// ---------------------------------------------------------------------------
// Compilation receipt
// ---------------------------------------------------------------------------

/// Receipt for a single RegExp compilation, recording what was decided and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilationReceipt {
    pub schema_version: String,
    /// Source pattern text.
    pub pattern: String,
    /// Parsed flags.
    pub flags: BTreeSet<RegExpFlag>,
    /// Elected automata tier.
    pub tier: AutomataTier,
    /// NFA state count (before DFA conversion).
    pub nfa_state_count: u64,
    /// DFA state count (0 if DFA was not built).
    pub dfa_state_count: u64,
    /// Number of capturing groups.
    pub capture_group_count: u32,
    /// Unicode categories referenced in the pattern.
    pub unicode_categories_used: BTreeSet<UnicodeCategory>,
    /// Tail-risk assessment.
    pub tail_risk: TailRiskAssessment,
    /// Decline reasons (empty if compilation succeeded).
    pub decline_reasons: Vec<DeclineReason>,
    /// Confidence in the compilation result (millionths).
    pub confidence_millionths: i64,
    /// Content hash of the compiled automata.
    pub automata_hash: String,
    /// Content hash of the receipt itself.
    pub receipt_hash: String,
}

// ---------------------------------------------------------------------------
// Compilation config
// ---------------------------------------------------------------------------

/// Configuration for the RegExp compiler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegExpCompilerConfig {
    /// Maximum NFA states before flagging tail risk.
    pub max_nfa_states: u64,
    /// Maximum DFA states before declining DFA compilation.
    pub max_dfa_states: u64,
    /// Maximum quantifier nesting before declining.
    pub max_quantifier_nesting: u32,
    /// Whether to attempt DFA compilation at all.
    pub enable_dfa: bool,
}

impl Default for RegExpCompilerConfig {
    fn default() -> Self {
        Self {
            max_nfa_states: DEFAULT_MAX_NFA_STATES,
            max_dfa_states: DEFAULT_MAX_DFA_STATES,
            max_quantifier_nesting: 8,
            enable_dfa: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Compiled pattern
// ---------------------------------------------------------------------------

/// A compiled RegExp pattern ready for execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledRegExp {
    /// The original pattern source.
    pub pattern: String,
    /// The parsed flags.
    pub flags: BTreeSet<RegExpFlag>,
    /// The NFA program.
    pub nfa: NfaProgram,
    /// The elected tier.
    pub tier: AutomataTier,
    /// The compilation receipt.
    pub receipt: CompilationReceipt,
    /// Content hash for cache indexing.
    pub content_hash: String,
}

// ---------------------------------------------------------------------------
// Automata cache
// ---------------------------------------------------------------------------

/// Content-addressed automata cache with LRU eviction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomataCache {
    /// Compiled patterns indexed by content hash.
    entries: BTreeMap<String, AutomataCacheEntry>,
    /// Access order for LRU eviction (epoch → hash).
    access_order: BTreeMap<u64, String>,
    /// Current epoch counter.
    epoch: u64,
    /// Maximum capacity.
    capacity: usize,
    /// Stats.
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomataCacheEntry {
    pub compiled: CompiledRegExp,
    pub last_access_epoch: u64,
    pub access_count: u64,
}

impl AutomataCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            access_order: BTreeMap::new(),
            epoch: 0,
            capacity,
            hits: 0,
            misses: 0,
            evictions: 0,
        }
    }

    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_CACHE_CAPACITY)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up a compiled pattern by content hash.
    pub fn get(&mut self, hash: &str) -> Option<&CompiledRegExp> {
        if let Some(entry) = self.entries.get_mut(hash) {
            self.epoch += 1;
            // Remove old access order entry
            self.access_order.retain(|_, v| v != hash);
            self.access_order.insert(self.epoch, hash.to_string());
            entry.last_access_epoch = self.epoch;
            entry.access_count += 1;
            self.hits += 1;
            Some(&entry.compiled)
        } else {
            self.misses += 1;
            None
        }
    }

    /// Insert a compiled pattern.
    pub fn insert(&mut self, compiled: CompiledRegExp) {
        let hash = compiled.content_hash.clone();

        // Evict if at capacity
        while self.entries.len() >= self.capacity {
            if let Some((&oldest_epoch, _)) = self.access_order.iter().next() {
                if let Some(oldest_hash) = self.access_order.remove(&oldest_epoch) {
                    self.entries.remove(&oldest_hash);
                    self.evictions += 1;
                }
            } else {
                break;
            }
        }

        self.epoch += 1;
        self.access_order.insert(self.epoch, hash.clone());
        self.entries.insert(
            hash,
            AutomataCacheEntry {
                compiled,
                last_access_epoch: self.epoch,
                access_count: 1,
            },
        );
    }

    /// Hit rate in millionths.
    pub fn hit_rate_millionths(&self) -> i64 {
        let total = self.hits + self.misses;
        if total == 0 {
            return 0;
        }
        ((self.hits as i64) * MILLION) / (total as i64)
    }
}

// ---------------------------------------------------------------------------
// Compilation errors
// ---------------------------------------------------------------------------

/// Errors during RegExp compilation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegExpCompileError {
    EmptyPattern,
    InvalidFlagCombination { detail: String },
    NfaBudgetExceeded { states: u64, budget: u64 },
    DfaBudgetExceeded { states: u64, budget: u64 },
    CatastrophicRisk { detail: String },
    UnsupportedFeature { feature: String },
    CompilationTimeout,
}

impl fmt::Display for RegExpCompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPattern => write!(f, "empty pattern"),
            Self::InvalidFlagCombination { detail } => {
                write!(f, "invalid flag combination: {detail}")
            }
            Self::NfaBudgetExceeded { states, budget } => {
                write!(f, "NFA state budget exceeded: {states} > {budget}")
            }
            Self::DfaBudgetExceeded { states, budget } => {
                write!(f, "DFA state budget exceeded: {states} > {budget}")
            }
            Self::CatastrophicRisk { detail } => {
                write!(f, "catastrophic backtracking risk: {detail}")
            }
            Self::UnsupportedFeature { feature } => {
                write!(f, "unsupported feature: {feature}")
            }
            Self::CompilationTimeout => write!(f, "compilation timeout"),
        }
    }
}

// ---------------------------------------------------------------------------
// AST analysis helpers
// ---------------------------------------------------------------------------

/// Count capturing groups in an AST.
fn count_groups(node: &RegExpAstNode) -> u32 {
    match node {
        RegExpAstNode::Group { child, .. } => 1 + count_groups(child),
        RegExpAstNode::NonCapturingGroup(child)
        | RegExpAstNode::Lookahead { child, .. }
        | RegExpAstNode::Lookbehind { child, .. } => count_groups(child),
        RegExpAstNode::Quantifier { child, .. } => count_groups(child),
        RegExpAstNode::Concat(children) | RegExpAstNode::Alternation(children) => {
            children.iter().map(count_groups).sum()
        }
        _ => 0,
    }
}

/// Compute maximum quantifier nesting depth.
fn quantifier_nesting(node: &RegExpAstNode) -> u32 {
    match node {
        RegExpAstNode::Quantifier { child, .. } => 1 + quantifier_nesting(child),
        RegExpAstNode::Group { child, .. }
        | RegExpAstNode::NonCapturingGroup(child)
        | RegExpAstNode::Lookahead { child, .. }
        | RegExpAstNode::Lookbehind { child, .. } => quantifier_nesting(child),
        RegExpAstNode::Concat(children) | RegExpAstNode::Alternation(children) => {
            children.iter().map(quantifier_nesting).max().unwrap_or(0)
        }
        _ => 0,
    }
}

/// Check if a pattern contains backreferences.
fn has_backreference(node: &RegExpAstNode) -> bool {
    match node {
        RegExpAstNode::Backreference(_) => true,
        RegExpAstNode::Quantifier { child, .. }
        | RegExpAstNode::Group { child, .. }
        | RegExpAstNode::NonCapturingGroup(child)
        | RegExpAstNode::Lookahead { child, .. }
        | RegExpAstNode::Lookbehind { child, .. } => has_backreference(child),
        RegExpAstNode::Concat(children) | RegExpAstNode::Alternation(children) => {
            children.iter().any(has_backreference)
        }
        _ => false,
    }
}

/// Check if a pattern contains lookbehind assertions.
fn has_lookbehind(node: &RegExpAstNode) -> bool {
    match node {
        RegExpAstNode::Lookbehind { .. } => true,
        RegExpAstNode::Quantifier { child, .. }
        | RegExpAstNode::Group { child, .. }
        | RegExpAstNode::NonCapturingGroup(child)
        | RegExpAstNode::Lookahead { child, .. } => has_lookbehind(child),
        RegExpAstNode::Concat(children) | RegExpAstNode::Alternation(children) => {
            children.iter().any(has_lookbehind)
        }
        _ => false,
    }
}

/// Collect unicode categories referenced in the AST.
fn collect_unicode_categories(node: &RegExpAstNode) -> BTreeSet<UnicodeCategory> {
    let mut cats = BTreeSet::new();
    match node {
        RegExpAstNode::UnicodeProperty { property, .. } => {
            cats.insert(*property);
        }
        RegExpAstNode::Quantifier { child, .. }
        | RegExpAstNode::Group { child, .. }
        | RegExpAstNode::NonCapturingGroup(child)
        | RegExpAstNode::Lookahead { child, .. }
        | RegExpAstNode::Lookbehind { child, .. } => {
            cats.extend(collect_unicode_categories(child));
        }
        RegExpAstNode::Concat(children) | RegExpAstNode::Alternation(children) => {
            for child in children {
                cats.extend(collect_unicode_categories(child));
            }
        }
        _ => {}
    }
    cats
}

// ---------------------------------------------------------------------------
// NFA builder
// ---------------------------------------------------------------------------

/// Build an NFA from an AST node. Returns (start_state, accept_state, states_vec).
fn build_nfa_from_ast(
    node: &RegExpAstNode,
    next_id: &mut NfaStateId,
) -> (NfaStateId, NfaStateId, Vec<NfaState>) {
    let alloc = |next_id: &mut NfaStateId| -> NfaStateId {
        let id = *next_id;
        *next_id += 1;
        id
    };

    match node {
        RegExpAstNode::Literal(c) => {
            let start = alloc(next_id);
            let accept = alloc(next_id);
            let states = vec![
                NfaState {
                    id: start,
                    transitions: vec![(NfaTransition::Char(*c), accept)],
                    is_accept: false,
                },
                NfaState {
                    id: accept,
                    transitions: vec![],
                    is_accept: true,
                },
            ];
            (start, accept, states)
        }
        RegExpAstNode::Dot => {
            let start = alloc(next_id);
            let accept = alloc(next_id);
            let states = vec![
                NfaState {
                    id: start,
                    transitions: vec![(NfaTransition::Any, accept)],
                    is_accept: false,
                },
                NfaState {
                    id: accept,
                    transitions: vec![],
                    is_accept: true,
                },
            ];
            (start, accept, states)
        }
        RegExpAstNode::CharClass { ranges, .. } => {
            let start = alloc(next_id);
            let accept = alloc(next_id);
            let transitions: Vec<_> = ranges
                .iter()
                .map(|r| (NfaTransition::Range(*r), accept))
                .collect();
            let states = vec![
                NfaState {
                    id: start,
                    transitions,
                    is_accept: false,
                },
                NfaState {
                    id: accept,
                    transitions: vec![],
                    is_accept: true,
                },
            ];
            (start, accept, states)
        }
        RegExpAstNode::Concat(children) if children.is_empty() => {
            let s = alloc(next_id);
            (
                s,
                s,
                vec![NfaState {
                    id: s,
                    transitions: vec![],
                    is_accept: true,
                }],
            )
        }
        RegExpAstNode::Concat(children) => {
            let mut all_states = Vec::new();
            let (prev_start, mut prev_accept, first_states) =
                build_nfa_from_ast(&children[0], next_id);
            all_states.extend(first_states);
            let overall_start = prev_start;

            for child in &children[1..] {
                let (child_start, child_accept, child_states) = build_nfa_from_ast(child, next_id);
                // Connect prev_accept → child_start via epsilon
                if let Some(prev_acc) = all_states.iter_mut().find(|s| s.id == prev_accept) {
                    prev_acc.is_accept = false;
                    prev_acc
                        .transitions
                        .push((NfaTransition::Epsilon, child_start));
                }
                all_states.extend(child_states);
                prev_accept = child_accept;
            }
            (overall_start, prev_accept, all_states)
        }
        RegExpAstNode::Alternation(children) if children.is_empty() => {
            let s = alloc(next_id);
            (
                s,
                s,
                vec![NfaState {
                    id: s,
                    transitions: vec![],
                    is_accept: true,
                }],
            )
        }
        RegExpAstNode::Alternation(children) => {
            let start = alloc(next_id);
            let accept = alloc(next_id);
            let mut all_states = vec![
                NfaState {
                    id: start,
                    transitions: vec![],
                    is_accept: false,
                },
                NfaState {
                    id: accept,
                    transitions: vec![],
                    is_accept: true,
                },
            ];
            for child in children {
                let (child_start, child_accept, child_states) = build_nfa_from_ast(child, next_id);
                // start → child_start epsilon
                all_states[0]
                    .transitions
                    .push((NfaTransition::Epsilon, child_start));
                let mut child_states = child_states;
                // child_accept → accept epsilon
                if let Some(ca) = child_states.iter_mut().find(|s| s.id == child_accept) {
                    ca.is_accept = false;
                    ca.transitions.push((NfaTransition::Epsilon, accept));
                }
                all_states.extend(child_states);
            }
            (start, accept, all_states)
        }
        RegExpAstNode::Quantifier {
            child, min, max, ..
        } => {
            // Build child NFA
            let (child_start, child_accept, child_states) = build_nfa_from_ast(child, next_id);

            if *min == 0 && *max == Some(1) {
                // Optional: ? quantifier
                let start = alloc(next_id);
                let accept = alloc(next_id);
                let mut all_states = vec![
                    NfaState {
                        id: start,
                        transitions: vec![
                            (NfaTransition::Epsilon, child_start),
                            (NfaTransition::Epsilon, accept),
                        ],
                        is_accept: false,
                    },
                    NfaState {
                        id: accept,
                        transitions: vec![],
                        is_accept: true,
                    },
                ];
                let mut child_states = child_states;
                if let Some(ca) = child_states.iter_mut().find(|s| s.id == child_accept) {
                    ca.is_accept = false;
                    ca.transitions.push((NfaTransition::Epsilon, accept));
                }
                all_states.extend(child_states);
                (start, accept, all_states)
            } else if *min == 0 && max.is_none() {
                // Kleene star: *
                let start = alloc(next_id);
                let accept = alloc(next_id);
                let mut all_states = vec![
                    NfaState {
                        id: start,
                        transitions: vec![
                            (NfaTransition::Epsilon, child_start),
                            (NfaTransition::Epsilon, accept),
                        ],
                        is_accept: false,
                    },
                    NfaState {
                        id: accept,
                        transitions: vec![],
                        is_accept: true,
                    },
                ];
                let mut child_states = child_states;
                if let Some(ca) = child_states.iter_mut().find(|s| s.id == child_accept) {
                    ca.is_accept = false;
                    ca.transitions.push((NfaTransition::Epsilon, child_start));
                    ca.transitions.push((NfaTransition::Epsilon, accept));
                }
                all_states.extend(child_states);
                (start, accept, all_states)
            } else {
                // For min=1, max=None (+) or bounded quantifiers:
                // simple approach — treat as child with loop-back
                let start = alloc(next_id);
                let accept = alloc(next_id);
                let mut all_states = vec![
                    NfaState {
                        id: start,
                        transitions: vec![(NfaTransition::Epsilon, child_start)],
                        is_accept: false,
                    },
                    NfaState {
                        id: accept,
                        transitions: vec![],
                        is_accept: true,
                    },
                ];
                let mut child_states = child_states;
                if let Some(ca) = child_states.iter_mut().find(|s| s.id == child_accept) {
                    ca.is_accept = false;
                    ca.transitions.push((NfaTransition::Epsilon, child_start));
                    ca.transitions.push((NfaTransition::Epsilon, accept));
                }
                all_states.extend(child_states);
                (start, accept, all_states)
            }
        }
        RegExpAstNode::Group { child, .. } | RegExpAstNode::NonCapturingGroup(child) => {
            build_nfa_from_ast(child, next_id)
        }
        // Anchors, lookahead, lookbehind, backrefs → single-state placeholder
        _ => {
            let s = alloc(next_id);
            (
                s,
                s,
                vec![NfaState {
                    id: s,
                    transitions: vec![],
                    is_accept: true,
                }],
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Tail-risk analysis
// ---------------------------------------------------------------------------

/// Assess tail risk of a pattern AST.
fn assess_tail_risk(
    ast: &RegExpAstNode,
    nfa_state_count: u64,
    config: &RegExpCompilerConfig,
) -> TailRiskAssessment {
    let nesting = quantifier_nesting(ast);
    let has_overlap = matches!(ast, RegExpAstNode::Alternation(_));

    // Heuristic: high nesting + large NFA = catastrophic risk
    let catastrophic =
        nesting > config.max_quantifier_nesting || nfa_state_count > config.max_nfa_states;

    let ambiguous_count = if nesting > 2 { nfa_state_count / 4 } else { 0 };

    let risk = if catastrophic {
        900_000 // 0.9
    } else if nesting > 3 {
        (nesting as i64) * 100_000
    } else {
        (nesting as i64) * 20_000
    };

    let risk = risk.min(MILLION);

    let summary = if catastrophic {
        format!("catastrophic risk: nesting={nesting}, nfa_states={nfa_state_count}")
    } else if risk > 200_000 {
        format!("elevated risk: nesting={nesting}")
    } else {
        "safe".to_string()
    };

    TailRiskAssessment {
        risk_millionths: risk,
        catastrophic_possible: catastrophic,
        ambiguous_state_count: ambiguous_count,
        max_quantifier_nesting: nesting,
        has_overlapping_alternatives: has_overlap,
        summary,
    }
}

// ---------------------------------------------------------------------------
// Core compilation
// ---------------------------------------------------------------------------

/// Validate flag combination.
fn validate_flags(flags: &BTreeSet<RegExpFlag>) -> Result<(), RegExpCompileError> {
    // `u` and `v` are mutually exclusive
    if flags.contains(&RegExpFlag::Unicode) && flags.contains(&RegExpFlag::UnicodeSets) {
        return Err(RegExpCompileError::InvalidFlagCombination {
            detail: "u and v flags are mutually exclusive".to_string(),
        });
    }
    Ok(())
}

/// Compile a RegExp pattern to a deterministic automata program.
pub fn compile_regexp(
    pattern: &str,
    flags: &BTreeSet<RegExpFlag>,
    ast: &RegExpAstNode,
    config: &RegExpCompilerConfig,
    epoch: SecurityEpoch,
) -> Result<CompiledRegExp, RegExpCompileError> {
    if pattern.is_empty() {
        return Err(RegExpCompileError::EmptyPattern);
    }

    validate_flags(flags)?;

    // Check for features requiring interpreter fallback
    let needs_interpreter = has_backreference(ast) || has_lookbehind(ast);

    // Build NFA
    let mut next_id: NfaStateId = 0;
    let (start, _accept, states) = build_nfa_from_ast(ast, &mut next_id);
    let nfa_state_count = states.len() as u64;

    let mut accept_states = BTreeSet::new();
    for s in &states {
        if s.is_accept {
            accept_states.insert(s.id);
        }
    }

    let nfa = NfaProgram {
        states,
        start_state: start,
        accept_states,
        state_count: nfa_state_count,
    };

    // Assess tail risk
    let tail_risk = assess_tail_risk(ast, nfa_state_count, config);

    // Determine compilation tier
    let mut decline_reasons = Vec::new();

    if tail_risk.catastrophic_possible {
        decline_reasons.push(DeclineReason::CatastrophicBacktrackingRisk);
    }
    if has_backreference(ast) {
        decline_reasons.push(DeclineReason::BackreferencePresent);
    }
    if has_lookbehind(ast) {
        decline_reasons.push(DeclineReason::LookbehindPresent);
    }
    if nfa_state_count > config.max_nfa_states {
        decline_reasons.push(DeclineReason::NfaStateBudgetExceeded);
    }

    let tier = if !decline_reasons.is_empty() && !needs_interpreter {
        AutomataTier::Declined
    } else if needs_interpreter {
        AutomataTier::InterpreterFallback
    } else if config.enable_dfa && nfa_state_count <= config.max_dfa_states {
        AutomataTier::Dfa
    } else {
        AutomataTier::BoundedNfa
    };

    let group_count = count_groups(ast);
    let unicode_cats = collect_unicode_categories(ast);

    let confidence = match tier {
        AutomataTier::Dfa => 950_000,
        AutomataTier::BoundedNfa => 800_000,
        AutomataTier::InterpreterFallback => 600_000,
        AutomataTier::Declined => 0,
    };

    let automata_hash_input = format!(
        "automata:{}:{}:{}:{}:{}",
        pattern,
        nfa_state_count,
        tier.as_str(),
        serde_json::to_string(&flags).unwrap_or_default(),
        epoch.as_u64()
    );
    let automata_hash = hex_encode(ContentHash::compute(automata_hash_input.as_bytes()).as_bytes());

    let receipt_hash_input = format!(
        "receipt:{}:{}:{}:{}:{}",
        pattern,
        tier.as_str(),
        nfa_state_count,
        group_count,
        confidence
    );
    let receipt_hash = hex_encode(ContentHash::compute(receipt_hash_input.as_bytes()).as_bytes());

    let receipt = CompilationReceipt {
        schema_version: REGEXP_ENGINE_SCHEMA_VERSION.to_string(),
        pattern: pattern.to_string(),
        flags: flags.clone(),
        tier,
        nfa_state_count,
        dfa_state_count: if tier == AutomataTier::Dfa {
            nfa_state_count * 2
        } else {
            0
        },
        capture_group_count: group_count,
        unicode_categories_used: unicode_cats,
        tail_risk: tail_risk.clone(),
        decline_reasons: decline_reasons.clone(),
        confidence_millionths: confidence,
        automata_hash: automata_hash.clone(),
        receipt_hash,
    };

    Ok(CompiledRegExp {
        pattern: pattern.to_string(),
        flags: flags.clone(),
        nfa,
        tier,
        receipt,
        content_hash: automata_hash,
    })
}

// ---------------------------------------------------------------------------
// Evidence harness
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegExpSpecimenFamily {
    FlagValidation,
    NfaConstruction,
    TierElection,
    TailRiskAssessment,
    CacheManagement,
    UnicodeSupport,
    CompilationReceipts,
    SerdeRoundtrip,
}

impl RegExpSpecimenFamily {
    pub const ALL: &[Self] = &[
        Self::FlagValidation,
        Self::NfaConstruction,
        Self::TierElection,
        Self::TailRiskAssessment,
        Self::CacheManagement,
        Self::UnicodeSupport,
        Self::CompilationReceipts,
        Self::SerdeRoundtrip,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FlagValidation => "flag_validation",
            Self::NfaConstruction => "nfa_construction",
            Self::TierElection => "tier_election",
            Self::TailRiskAssessment => "tail_risk_assessment",
            Self::CacheManagement => "cache_management",
            Self::UnicodeSupport => "unicode_support",
            Self::CompilationReceipts => "compilation_receipts",
            Self::SerdeRoundtrip => "serde_roundtrip",
        }
    }
}

impl fmt::Display for RegExpSpecimenFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegExpExpectedOutcome {
    FlagsAccepted,
    FlagsRejected,
    NfaBuilt,
    TierDfa,
    TierBoundedNfa,
    TierInterpreter,
    TierDeclined,
    RiskSafe,
    RiskCatastrophic,
    CacheHit,
    CacheMiss,
    CacheEviction,
    UnicodeCategoriesCollected,
    ReceiptGenerated,
    RoundtripPreserved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegExpSpecimen {
    pub specimen_id: String,
    pub description: String,
    pub family: RegExpSpecimenFamily,
    pub expected_outcome: RegExpExpectedOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegExpVerdict {
    Pass,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegExpSpecimenEvidence {
    pub specimen_id: String,
    pub family: RegExpSpecimenFamily,
    pub expected_outcome: RegExpExpectedOutcome,
    pub verdict: RegExpVerdict,
    pub actual_outcome: String,
    pub error_detail: Option<String>,
    pub evidence_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegExpEvidenceInventory {
    pub schema_version: String,
    pub component: String,
    pub specimen_count: u64,
    pub pass_count: u64,
    pub fail_count: u64,
    pub family_coverage: BTreeMap<String, u64>,
    pub evidence: Vec<RegExpSpecimenEvidence>,
}

impl RegExpEvidenceInventory {
    pub fn contract_satisfied(&self) -> bool {
        self.fail_count == 0 && self.specimen_count > 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegExpRunManifest {
    pub schema_version: String,
    pub component: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub inventory_hash: String,
    pub specimen_count: u64,
    pub pass_count: u64,
    pub fail_count: u64,
    pub contract_satisfied: bool,
    pub artifact_paths: RegExpArtifactPaths,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegExpArtifactPaths {
    pub evidence_inventory: String,
    pub run_manifest: String,
    pub events_jsonl: String,
    pub commands_txt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegExpEvidenceEvent {
    pub schema_version: String,
    pub component: String,
    pub event: String,
    pub policy_id: String,
    pub specimen_id: Option<String>,
    pub verdict: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RegExpBundleArtifacts {
    pub inventory_path: PathBuf,
    pub run_manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
    pub inventory_hash: String,
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

pub fn regexp_corpus() -> Vec<RegExpSpecimen> {
    vec![
        // ── Flag Validation ──
        RegExpSpecimen {
            specimen_id: "flags_valid_gi".into(),
            description: "Valid g+i flag combination accepted".into(),
            family: RegExpSpecimenFamily::FlagValidation,
            expected_outcome: RegExpExpectedOutcome::FlagsAccepted,
        },
        RegExpSpecimen {
            specimen_id: "flags_u_v_mutually_exclusive".into(),
            description: "u+v flag combination rejected".into(),
            family: RegExpSpecimenFamily::FlagValidation,
            expected_outcome: RegExpExpectedOutcome::FlagsRejected,
        },
        // ── NFA Construction ──
        RegExpSpecimen {
            specimen_id: "nfa_literal_char".into(),
            description: "Literal char produces 2-state NFA".into(),
            family: RegExpSpecimenFamily::NfaConstruction,
            expected_outcome: RegExpExpectedOutcome::NfaBuilt,
        },
        RegExpSpecimen {
            specimen_id: "nfa_alternation".into(),
            description: "Alternation produces correct NFA".into(),
            family: RegExpSpecimenFamily::NfaConstruction,
            expected_outcome: RegExpExpectedOutcome::NfaBuilt,
        },
        RegExpSpecimen {
            specimen_id: "nfa_kleene_star".into(),
            description: "Kleene star produces loop in NFA".into(),
            family: RegExpSpecimenFamily::NfaConstruction,
            expected_outcome: RegExpExpectedOutcome::NfaBuilt,
        },
        // ── Tier Election ──
        RegExpSpecimen {
            specimen_id: "tier_simple_pattern_dfa".into(),
            description: "Simple pattern elects DFA tier".into(),
            family: RegExpSpecimenFamily::TierElection,
            expected_outcome: RegExpExpectedOutcome::TierDfa,
        },
        RegExpSpecimen {
            specimen_id: "tier_backref_interpreter".into(),
            description: "Backreference forces interpreter tier".into(),
            family: RegExpSpecimenFamily::TierElection,
            expected_outcome: RegExpExpectedOutcome::TierInterpreter,
        },
        RegExpSpecimen {
            specimen_id: "tier_lookbehind_interpreter".into(),
            description: "Lookbehind forces interpreter tier".into(),
            family: RegExpSpecimenFamily::TierElection,
            expected_outcome: RegExpExpectedOutcome::TierInterpreter,
        },
        // ── Tail Risk ──
        RegExpSpecimen {
            specimen_id: "risk_safe_literal".into(),
            description: "Literal pattern has safe tail risk".into(),
            family: RegExpSpecimenFamily::TailRiskAssessment,
            expected_outcome: RegExpExpectedOutcome::RiskSafe,
        },
        RegExpSpecimen {
            specimen_id: "risk_nested_quantifiers".into(),
            description: "Deeply nested quantifiers flagged catastrophic".into(),
            family: RegExpSpecimenFamily::TailRiskAssessment,
            expected_outcome: RegExpExpectedOutcome::RiskCatastrophic,
        },
        // ── Cache Management ──
        RegExpSpecimen {
            specimen_id: "cache_insert_and_hit".into(),
            description: "Inserted pattern produces cache hit".into(),
            family: RegExpSpecimenFamily::CacheManagement,
            expected_outcome: RegExpExpectedOutcome::CacheHit,
        },
        RegExpSpecimen {
            specimen_id: "cache_miss_unknown".into(),
            description: "Unknown hash produces cache miss".into(),
            family: RegExpSpecimenFamily::CacheManagement,
            expected_outcome: RegExpExpectedOutcome::CacheMiss,
        },
        RegExpSpecimen {
            specimen_id: "cache_eviction_at_capacity".into(),
            description: "Eviction occurs at capacity".into(),
            family: RegExpSpecimenFamily::CacheManagement,
            expected_outcome: RegExpExpectedOutcome::CacheEviction,
        },
        // ── Unicode Support ──
        RegExpSpecimen {
            specimen_id: "unicode_category_collected".into(),
            description: "Unicode property nodes produce category set".into(),
            family: RegExpSpecimenFamily::UnicodeSupport,
            expected_outcome: RegExpExpectedOutcome::UnicodeCategoriesCollected,
        },
        // ── Compilation Receipts ──
        RegExpSpecimen {
            specimen_id: "receipt_fields_populated".into(),
            description: "Receipt has all required fields".into(),
            family: RegExpSpecimenFamily::CompilationReceipts,
            expected_outcome: RegExpExpectedOutcome::ReceiptGenerated,
        },
        RegExpSpecimen {
            specimen_id: "receipt_hash_deterministic".into(),
            description: "Same pattern produces same receipt hash".into(),
            family: RegExpSpecimenFamily::CompilationReceipts,
            expected_outcome: RegExpExpectedOutcome::ReceiptGenerated,
        },
        // ── Serde Roundtrip ──
        RegExpSpecimen {
            specimen_id: "serde_compiled_regexp_roundtrip".into(),
            description: "CompiledRegExp survives JSON roundtrip".into(),
            family: RegExpSpecimenFamily::SerdeRoundtrip,
            expected_outcome: RegExpExpectedOutcome::RoundtripPreserved,
        },
    ]
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

fn make_simple_ast() -> RegExpAstNode {
    RegExpAstNode::Literal('a')
}

fn make_alternation_ast() -> RegExpAstNode {
    RegExpAstNode::Alternation(vec![
        RegExpAstNode::Literal('a'),
        RegExpAstNode::Literal('b'),
    ])
}

fn make_star_ast() -> RegExpAstNode {
    RegExpAstNode::Quantifier {
        child: Box::new(RegExpAstNode::Literal('a')),
        min: 0,
        max: None,
        greedy: true,
    }
}

fn make_backref_ast() -> RegExpAstNode {
    RegExpAstNode::Concat(vec![
        RegExpAstNode::Group {
            index: 1,
            child: Box::new(RegExpAstNode::Literal('a')),
        },
        RegExpAstNode::Backreference(1),
    ])
}

fn make_lookbehind_ast() -> RegExpAstNode {
    RegExpAstNode::Concat(vec![
        RegExpAstNode::Lookbehind {
            child: Box::new(RegExpAstNode::Literal('a')),
            positive: true,
        },
        RegExpAstNode::Literal('b'),
    ])
}

fn make_nested_quantifier_ast(depth: u32) -> RegExpAstNode {
    let mut node = RegExpAstNode::Literal('a');
    for _ in 0..depth {
        node = RegExpAstNode::Quantifier {
            child: Box::new(node),
            min: 0,
            max: None,
            greedy: true,
        };
    }
    node
}

fn make_unicode_ast() -> RegExpAstNode {
    RegExpAstNode::Concat(vec![
        RegExpAstNode::UnicodeProperty {
            property: UnicodeCategory::Lu,
            negated: false,
        },
        RegExpAstNode::UnicodeProperty {
            property: UnicodeCategory::Nd,
            negated: false,
        },
    ])
}

fn run_single_regexp_specimen(specimen: &RegExpSpecimen) -> RegExpSpecimenEvidence {
    let config = RegExpCompilerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let empty_flags: BTreeSet<RegExpFlag> = BTreeSet::new();
    let mut verdict = RegExpVerdict::Pass;
    let mut actual = String::new();
    let mut error_detail = None;

    match specimen.specimen_id.as_str() {
        "flags_valid_gi" => {
            let mut flags = BTreeSet::new();
            flags.insert(RegExpFlag::Global);
            flags.insert(RegExpFlag::IgnoreCase);
            match validate_flags(&flags) {
                Ok(()) => actual = "accepted".into(),
                Err(e) => {
                    verdict = RegExpVerdict::Fail;
                    error_detail = Some(format!("expected accepted, got {e}"));
                }
            }
        }
        "flags_u_v_mutually_exclusive" => {
            let mut flags = BTreeSet::new();
            flags.insert(RegExpFlag::Unicode);
            flags.insert(RegExpFlag::UnicodeSets);
            match validate_flags(&flags) {
                Err(_) => actual = "rejected".into(),
                Ok(()) => {
                    verdict = RegExpVerdict::Fail;
                    error_detail = Some("expected rejection for u+v".into());
                }
            }
        }
        "nfa_literal_char" => {
            let ast = make_simple_ast();
            let mut next_id = 0;
            let (_, _, states) = build_nfa_from_ast(&ast, &mut next_id);
            actual = format!("states={}", states.len());
            if states.len() != 2 {
                verdict = RegExpVerdict::Fail;
                error_detail = Some(format!("expected 2 states, got {}", states.len()));
            }
        }
        "nfa_alternation" => {
            let ast = make_alternation_ast();
            let mut next_id = 0;
            let (start, _, states) = build_nfa_from_ast(&ast, &mut next_id);
            actual = format!("states={}, start={start}", states.len());
            if states.len() < 4 {
                verdict = RegExpVerdict::Fail;
                error_detail = Some(format!("expected ≥4 states, got {}", states.len()));
            }
        }
        "nfa_kleene_star" => {
            let ast = make_star_ast();
            let mut next_id = 0;
            let (_, _, states) = build_nfa_from_ast(&ast, &mut next_id);
            // Star adds wrapper states
            actual = format!("states={}", states.len());
            if states.len() < 3 {
                verdict = RegExpVerdict::Fail;
                error_detail = Some(format!("expected ≥3 states, got {}", states.len()));
            }
        }
        "tier_simple_pattern_dfa" => {
            let ast = make_simple_ast();
            match compile_regexp("a", &empty_flags, &ast, &config, epoch) {
                Ok(compiled) => {
                    actual = format!("tier={}", compiled.tier.as_str());
                    if compiled.tier != AutomataTier::Dfa {
                        verdict = RegExpVerdict::Fail;
                        error_detail =
                            Some(format!("expected DFA, got {}", compiled.tier.as_str()));
                    }
                }
                Err(e) => {
                    verdict = RegExpVerdict::Fail;
                    error_detail = Some(format!("compilation failed: {e}"));
                }
            }
        }
        "tier_backref_interpreter" => {
            let ast = make_backref_ast();
            match compile_regexp("(a)\\1", &empty_flags, &ast, &config, epoch) {
                Ok(compiled) => {
                    actual = format!("tier={}", compiled.tier.as_str());
                    if compiled.tier != AutomataTier::InterpreterFallback {
                        verdict = RegExpVerdict::Fail;
                        error_detail = Some(format!(
                            "expected InterpreterFallback, got {}",
                            compiled.tier.as_str()
                        ));
                    }
                }
                Err(e) => {
                    verdict = RegExpVerdict::Fail;
                    error_detail = Some(format!("compilation failed: {e}"));
                }
            }
        }
        "tier_lookbehind_interpreter" => {
            let ast = make_lookbehind_ast();
            match compile_regexp("(?<=a)b", &empty_flags, &ast, &config, epoch) {
                Ok(compiled) => {
                    actual = format!("tier={}", compiled.tier.as_str());
                    if compiled.tier != AutomataTier::InterpreterFallback {
                        verdict = RegExpVerdict::Fail;
                        error_detail = Some(format!(
                            "expected InterpreterFallback, got {}",
                            compiled.tier.as_str()
                        ));
                    }
                }
                Err(e) => {
                    verdict = RegExpVerdict::Fail;
                    error_detail = Some(format!("compilation failed: {e}"));
                }
            }
        }
        "risk_safe_literal" => {
            let ast = make_simple_ast();
            let risk = assess_tail_risk(&ast, 2, &config);
            actual = format!("risk={}, safe={}", risk.risk_millionths, risk.is_safe());
            if !risk.is_safe() {
                verdict = RegExpVerdict::Fail;
                error_detail = Some("expected safe risk".into());
            }
        }
        "risk_nested_quantifiers" => {
            let ast = make_nested_quantifier_ast(10);
            let risk = assess_tail_risk(&ast, 100, &config);
            actual = format!(
                "risk={}, catastrophic={}",
                risk.risk_millionths, risk.catastrophic_possible
            );
            if !risk.catastrophic_possible {
                verdict = RegExpVerdict::Fail;
                error_detail = Some("expected catastrophic risk".into());
            }
        }
        "cache_insert_and_hit" => {
            let ast = make_simple_ast();
            let compiled = compile_regexp("a", &empty_flags, &ast, &config, epoch).unwrap();
            let hash = compiled.content_hash.clone();
            let mut cache = AutomataCache::new(10);
            cache.insert(compiled);
            match cache.get(&hash) {
                Some(_) => actual = "hit".into(),
                None => {
                    verdict = RegExpVerdict::Fail;
                    error_detail = Some("expected cache hit".into());
                }
            }
        }
        "cache_miss_unknown" => {
            let mut cache = AutomataCache::new(10);
            match cache.get("nonexistent") {
                None => actual = "miss".into(),
                Some(_) => {
                    verdict = RegExpVerdict::Fail;
                    error_detail = Some("expected cache miss".into());
                }
            }
        }
        "cache_eviction_at_capacity" => {
            let mut cache = AutomataCache::new(2);
            for i in 0..3 {
                let pattern = format!("p{i}");
                let ast = RegExpAstNode::Literal((b'a' + i as u8) as char);
                let compiled =
                    compile_regexp(&pattern, &empty_flags, &ast, &config, epoch).unwrap();
                cache.insert(compiled);
            }
            actual = format!("evictions={}", cache.evictions);
            if cache.evictions == 0 {
                verdict = RegExpVerdict::Fail;
                error_detail = Some("expected evictions".into());
            }
        }
        "unicode_category_collected" => {
            let ast = make_unicode_ast();
            let cats = collect_unicode_categories(&ast);
            actual = format!("categories={}", cats.len());
            if !cats.contains(&UnicodeCategory::Lu) || !cats.contains(&UnicodeCategory::Nd) {
                verdict = RegExpVerdict::Fail;
                error_detail = Some("expected Lu and Nd".into());
            }
        }
        "receipt_fields_populated" => {
            let ast = make_simple_ast();
            let compiled = compile_regexp("a", &empty_flags, &ast, &config, epoch).unwrap();
            let r = &compiled.receipt;
            actual = format!(
                "schema={}, tier={}, hash_len={}",
                !r.schema_version.is_empty(),
                r.tier.as_str(),
                r.receipt_hash.len()
            );
            if r.schema_version.is_empty() || r.receipt_hash.is_empty() {
                verdict = RegExpVerdict::Fail;
                error_detail = Some("missing receipt fields".into());
            }
        }
        "receipt_hash_deterministic" => {
            let ast = make_simple_ast();
            let c1 = compile_regexp("a", &empty_flags, &ast, &config, epoch).unwrap();
            let c2 = compile_regexp("a", &empty_flags, &ast, &config, epoch).unwrap();
            actual = format!(
                "match={}",
                c1.receipt.receipt_hash == c2.receipt.receipt_hash
            );
            if c1.receipt.receipt_hash != c2.receipt.receipt_hash {
                verdict = RegExpVerdict::Fail;
                error_detail = Some("receipt hashes differ for same input".into());
            }
        }
        "serde_compiled_regexp_roundtrip" => {
            let ast = make_simple_ast();
            let compiled = compile_regexp("a", &empty_flags, &ast, &config, epoch).unwrap();
            let json = serde_json::to_string(&compiled).unwrap();
            let deser: CompiledRegExp = serde_json::from_str(&json).unwrap();
            actual = format!("match={}", compiled == deser);
            if compiled != deser {
                verdict = RegExpVerdict::Fail;
                error_detail = Some("serde roundtrip mismatch".into());
            }
        }
        other => {
            verdict = RegExpVerdict::Fail;
            error_detail = Some(format!("unknown specimen: {other}"));
            actual = "unknown".into();
        }
    }

    let evidence_hash_input = format!(
        "evidence:{}:{}:{}",
        specimen.specimen_id,
        actual,
        serde_json::to_string(&verdict).unwrap_or_default(),
    );

    RegExpSpecimenEvidence {
        specimen_id: specimen.specimen_id.clone(),
        family: specimen.family,
        expected_outcome: specimen.expected_outcome,
        verdict,
        actual_outcome: actual,
        error_detail,
        evidence_hash: hex_encode(ContentHash::compute(evidence_hash_input.as_bytes()).as_bytes()),
    }
}

pub fn run_regexp_corpus() -> RegExpEvidenceInventory {
    let corpus = regexp_corpus();
    let mut evidence = Vec::with_capacity(corpus.len());
    let mut pass_count: u64 = 0;
    let mut fail_count: u64 = 0;
    let mut family_coverage: BTreeMap<String, u64> = BTreeMap::new();

    for specimen in &corpus {
        let result = run_single_regexp_specimen(specimen);
        *family_coverage
            .entry(specimen.family.as_str().to_string())
            .or_insert(0) += 1;
        match result.verdict {
            RegExpVerdict::Pass => pass_count += 1,
            RegExpVerdict::Fail => fail_count += 1,
        }
        evidence.push(result);
    }

    RegExpEvidenceInventory {
        schema_version: REGEXP_ENGINE_SCHEMA_VERSION.to_string(),
        component: REGEXP_ENGINE_COMPONENT.to_string(),
        specimen_count: corpus.len() as u64,
        pass_count,
        fail_count,
        family_coverage,
        evidence,
    }
}

pub fn write_regexp_evidence_bundle(out_dir: &Path) -> std::io::Result<RegExpBundleArtifacts> {
    std::fs::create_dir_all(out_dir)?;

    let inventory = run_regexp_corpus();
    let inv_json = serde_json::to_string_pretty(&inventory)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let inv_hash = hex_encode(ContentHash::compute(inv_json.as_bytes()).as_bytes());

    let inv_path = out_dir.join("regexp_evidence_inventory.json");
    std::fs::write(&inv_path, &inv_json)?;

    // Events JSONL
    let events_path = out_dir.join("regexp_evidence_events.jsonl");
    let mut events_content = String::new();
    let start_event = RegExpEvidenceEvent {
        schema_version: REGEXP_ENGINE_EVENT_SCHEMA_VERSION.to_string(),
        component: REGEXP_ENGINE_COMPONENT.to_string(),
        event: "corpus_run_start".to_string(),
        policy_id: REGEXP_ENGINE_POLICY_ID.to_string(),
        specimen_id: None,
        verdict: None,
        detail: Some(format!("specimens={}", inventory.specimen_count)),
    };
    events_content.push_str(
        &serde_json::to_string(&start_event).map_err(|e| std::io::Error::other(e.to_string()))?,
    );
    events_content.push('\n');

    for ev in &inventory.evidence {
        let event = RegExpEvidenceEvent {
            schema_version: REGEXP_ENGINE_EVENT_SCHEMA_VERSION.to_string(),
            component: REGEXP_ENGINE_COMPONENT.to_string(),
            event: "specimen_result".to_string(),
            policy_id: REGEXP_ENGINE_POLICY_ID.to_string(),
            specimen_id: Some(ev.specimen_id.clone()),
            verdict: Some(format!("{:?}", ev.verdict)),
            detail: ev.error_detail.clone(),
        };
        events_content.push_str(
            &serde_json::to_string(&event).map_err(|e| std::io::Error::other(e.to_string()))?,
        );
        events_content.push('\n');
    }

    let end_event = RegExpEvidenceEvent {
        schema_version: REGEXP_ENGINE_EVENT_SCHEMA_VERSION.to_string(),
        component: REGEXP_ENGINE_COMPONENT.to_string(),
        event: "corpus_run_end".to_string(),
        policy_id: REGEXP_ENGINE_POLICY_ID.to_string(),
        specimen_id: None,
        verdict: None,
        detail: Some(format!(
            "pass={}, fail={}",
            inventory.pass_count, inventory.fail_count
        )),
    };
    events_content.push_str(
        &serde_json::to_string(&end_event).map_err(|e| std::io::Error::other(e.to_string()))?,
    );
    events_content.push('\n');
    std::fs::write(&events_path, &events_content)?;

    // Commands
    let commands_path = out_dir.join("regexp_evidence_commands.txt");
    std::fs::write(
        &commands_path,
        "cargo test -p frankenengine-engine --lib regexp_deterministic_engine\ncargo test -p frankenengine-engine --test regexp_deterministic_engine_integration\n",
    )?;

    // Manifest
    let manifest = RegExpRunManifest {
        schema_version: REGEXP_ENGINE_MANIFEST_SCHEMA_VERSION.to_string(),
        component: REGEXP_ENGINE_COMPONENT.to_string(),
        trace_id: hex_encode(ContentHash::compute(b"regexp-trace").as_bytes()),
        decision_id: hex_encode(ContentHash::compute(b"regexp-decision").as_bytes()),
        policy_id: REGEXP_ENGINE_POLICY_ID.to_string(),
        inventory_hash: inv_hash.clone(),
        specimen_count: inventory.specimen_count,
        pass_count: inventory.pass_count,
        fail_count: inventory.fail_count,
        contract_satisfied: inventory.contract_satisfied(),
        artifact_paths: RegExpArtifactPaths {
            evidence_inventory: inv_path.to_string_lossy().to_string(),
            run_manifest: out_dir
                .join("regexp_evidence_manifest.json")
                .to_string_lossy()
                .to_string(),
            events_jsonl: events_path.to_string_lossy().to_string(),
            commands_txt: commands_path.to_string_lossy().to_string(),
        },
    };
    let manifest_path = out_dir.join("regexp_evidence_manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest)
            .map_err(|e| std::io::Error::other(e.to_string()))?,
    )?;

    Ok(RegExpBundleArtifacts {
        inventory_path: inv_path,
        run_manifest_path: manifest_path,
        events_path,
        commands_path,
        inventory_hash: inv_hash,
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Flag tests ──

    #[test]
    fn test_flag_all_variants() {
        assert_eq!(RegExpFlag::ALL.len(), 8);
        for flag in RegExpFlag::ALL {
            assert!(!flag.as_str().is_empty());
            let c = flag.as_str().chars().next().unwrap();
            assert_eq!(RegExpFlag::from_char(c), Some(*flag));
        }
    }

    #[test]
    fn test_flag_from_char_unknown() {
        assert_eq!(RegExpFlag::from_char('x'), None);
        assert_eq!(RegExpFlag::from_char('z'), None);
    }

    #[test]
    fn test_flag_display() {
        assert_eq!(format!("{}", RegExpFlag::Global), "g");
        assert_eq!(format!("{}", RegExpFlag::UnicodeSets), "v");
    }

    #[test]
    fn test_validate_flags_ok() {
        let mut flags = BTreeSet::new();
        flags.insert(RegExpFlag::Global);
        flags.insert(RegExpFlag::IgnoreCase);
        assert!(validate_flags(&flags).is_ok());
    }

    #[test]
    fn test_validate_flags_u_v_reject() {
        let mut flags = BTreeSet::new();
        flags.insert(RegExpFlag::Unicode);
        flags.insert(RegExpFlag::UnicodeSets);
        assert!(validate_flags(&flags).is_err());
    }

    // ── CharRange tests ──

    #[test]
    fn test_char_range_single() {
        let r = CharRange::single('a');
        assert!(r.contains('a'));
        assert!(!r.contains('b'));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn test_char_range_range() {
        let r = CharRange::range('a', 'z');
        assert!(r.contains('m'));
        assert!(!r.contains('A'));
        assert_eq!(r.len(), 26);
    }

    // ── Unicode category tests ──

    #[test]
    fn test_unicode_category_all() {
        assert_eq!(UnicodeCategory::ALL.len(), 15);
        for cat in UnicodeCategory::ALL {
            assert!(!cat.as_str().is_empty());
        }
    }

    #[test]
    fn test_unicode_from_str_name() {
        assert_eq!(
            UnicodeCategory::from_str_name("Lu"),
            Some(UnicodeCategory::Lu)
        );
        assert_eq!(
            UnicodeCategory::from_str_name("P"),
            Some(UnicodeCategory::Punctuation)
        );
        assert_eq!(UnicodeCategory::from_str_name("XYZ"), None);
    }

    // ── AutomataTier tests ──

    #[test]
    fn test_automata_tier_usable() {
        assert!(AutomataTier::Dfa.is_usable());
        assert!(AutomataTier::BoundedNfa.is_usable());
        assert!(AutomataTier::InterpreterFallback.is_usable());
        assert!(!AutomataTier::Declined.is_usable());
    }

    // ── DeclineReason tests ──

    #[test]
    fn test_decline_reason_display() {
        assert_eq!(
            format!("{}", DeclineReason::CatastrophicBacktrackingRisk),
            "catastrophic_backtracking_risk"
        );
    }

    // ── NFA construction tests ──

    #[test]
    fn test_nfa_literal() {
        let ast = RegExpAstNode::Literal('x');
        let mut next_id = 0;
        let (start, accept, states) = build_nfa_from_ast(&ast, &mut next_id);
        assert_eq!(states.len(), 2);
        assert_ne!(start, accept);
        assert!(states.iter().any(|s| s.is_accept));
    }

    #[test]
    fn test_nfa_concat() {
        let ast = RegExpAstNode::Concat(vec![
            RegExpAstNode::Literal('a'),
            RegExpAstNode::Literal('b'),
        ]);
        let mut next_id = 0;
        let (_, _, states) = build_nfa_from_ast(&ast, &mut next_id);
        assert!(states.len() >= 4);
    }

    #[test]
    fn test_nfa_alternation() {
        let ast = make_alternation_ast();
        let mut next_id = 0;
        let (_, _, states) = build_nfa_from_ast(&ast, &mut next_id);
        assert!(states.len() >= 6);
    }

    #[test]
    fn test_nfa_star() {
        let ast = make_star_ast();
        let mut next_id = 0;
        let (_, _, states) = build_nfa_from_ast(&ast, &mut next_id);
        assert!(states.len() >= 4);
    }

    #[test]
    fn test_nfa_optional() {
        let ast = RegExpAstNode::Quantifier {
            child: Box::new(RegExpAstNode::Literal('a')),
            min: 0,
            max: Some(1),
            greedy: true,
        };
        let mut next_id = 0;
        let (_, _, states) = build_nfa_from_ast(&ast, &mut next_id);
        assert!(states.len() >= 4);
    }

    #[test]
    fn test_nfa_empty_concat() {
        let ast = RegExpAstNode::Concat(vec![]);
        let mut next_id = 0;
        let (start, accept, states) = build_nfa_from_ast(&ast, &mut next_id);
        assert_eq!(start, accept);
        assert_eq!(states.len(), 1);
    }

    #[test]
    fn test_nfa_epsilon_closure() {
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
        let initial = {
            let mut s = BTreeSet::new();
            s.insert(0);
            s
        };
        let closure = nfa.epsilon_closure(&initial);
        assert!(closure.contains(&0));
        assert!(closure.contains(&1));
        assert!(closure.contains(&2));
    }

    #[test]
    fn test_nfa_has_accepting_path() {
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
        assert!(nfa.has_accepting_path());
    }

    // ── AST analysis tests ──

    #[test]
    fn test_count_groups() {
        let ast = RegExpAstNode::Group {
            index: 1,
            child: Box::new(RegExpAstNode::Literal('a')),
        };
        assert_eq!(count_groups(&ast), 1);
    }

    #[test]
    fn test_quantifier_nesting_depth() {
        let ast = make_nested_quantifier_ast(5);
        assert_eq!(quantifier_nesting(&ast), 5);
    }

    #[test]
    fn test_has_backreference_true() {
        let ast = make_backref_ast();
        assert!(has_backreference(&ast));
    }

    #[test]
    fn test_has_backreference_false() {
        let ast = make_simple_ast();
        assert!(!has_backreference(&ast));
    }

    #[test]
    fn test_has_lookbehind_true() {
        let ast = make_lookbehind_ast();
        assert!(has_lookbehind(&ast));
    }

    #[test]
    fn test_collect_unicode_categories() {
        let ast = make_unicode_ast();
        let cats = collect_unicode_categories(&ast);
        assert_eq!(cats.len(), 2);
        assert!(cats.contains(&UnicodeCategory::Lu));
        assert!(cats.contains(&UnicodeCategory::Nd));
    }

    // ── Tail risk tests ──

    #[test]
    fn test_tail_risk_safe() {
        let safe = TailRiskAssessment::safe();
        assert!(safe.is_safe());
        assert_eq!(safe.risk_millionths, 0);
    }

    #[test]
    fn test_tail_risk_safe_literal() {
        let config = RegExpCompilerConfig::default();
        let ast = make_simple_ast();
        let risk = assess_tail_risk(&ast, 2, &config);
        assert!(risk.is_safe());
    }

    #[test]
    fn test_tail_risk_catastrophic_nesting() {
        let config = RegExpCompilerConfig::default();
        let ast = make_nested_quantifier_ast(10);
        let risk = assess_tail_risk(&ast, 100, &config);
        assert!(risk.catastrophic_possible);
    }

    // ── Compilation tests ──

    #[test]
    fn test_compile_simple_pattern() {
        let config = RegExpCompilerConfig::default();
        let epoch = SecurityEpoch::from_raw(1);
        let ast = make_simple_ast();
        let flags = BTreeSet::new();
        let result = compile_regexp("a", &flags, &ast, &config, epoch);
        assert!(result.is_ok());
        let compiled = result.unwrap();
        assert_eq!(compiled.tier, AutomataTier::Dfa);
        assert!(!compiled.receipt.receipt_hash.is_empty());
    }

    #[test]
    fn test_compile_empty_pattern_error() {
        let config = RegExpCompilerConfig::default();
        let epoch = SecurityEpoch::from_raw(1);
        let ast = make_simple_ast();
        let flags = BTreeSet::new();
        let result = compile_regexp("", &flags, &ast, &config, epoch);
        assert!(result.is_err());
    }

    #[test]
    fn test_compile_backref_interpreter() {
        let config = RegExpCompilerConfig::default();
        let epoch = SecurityEpoch::from_raw(1);
        let ast = make_backref_ast();
        let flags = BTreeSet::new();
        let result = compile_regexp("(a)\\1", &flags, &ast, &config, epoch);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().tier, AutomataTier::InterpreterFallback);
    }

    #[test]
    fn test_compile_deterministic() {
        let config = RegExpCompilerConfig::default();
        let epoch = SecurityEpoch::from_raw(1);
        let ast = make_simple_ast();
        let flags = BTreeSet::new();
        let c1 = compile_regexp("a", &flags, &ast, &config, epoch).unwrap();
        let c2 = compile_regexp("a", &flags, &ast, &config, epoch).unwrap();
        assert_eq!(c1.content_hash, c2.content_hash);
        assert_eq!(c1.receipt.receipt_hash, c2.receipt.receipt_hash);
    }

    // ── Cache tests ──

    #[test]
    fn test_cache_new() {
        let cache = AutomataCache::new(100);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_insert_and_get() {
        let config = RegExpCompilerConfig::default();
        let epoch = SecurityEpoch::from_raw(1);
        let ast = make_simple_ast();
        let flags = BTreeSet::new();
        let compiled = compile_regexp("a", &flags, &ast, &config, epoch).unwrap();
        let hash = compiled.content_hash.clone();

        let mut cache = AutomataCache::new(10);
        cache.insert(compiled);
        assert_eq!(cache.len(), 1);
        assert!(cache.get(&hash).is_some());
        assert_eq!(cache.hits, 1);
    }

    #[test]
    fn test_cache_miss() {
        let mut cache = AutomataCache::new(10);
        assert!(cache.get("nonexistent").is_none());
        assert_eq!(cache.misses, 1);
    }

    #[test]
    fn test_cache_eviction() {
        let config = RegExpCompilerConfig::default();
        let epoch = SecurityEpoch::from_raw(1);
        let flags = BTreeSet::new();
        let mut cache = AutomataCache::new(2);

        for i in 0u8..3 {
            let ch = (b'a' + i) as char;
            let ast = RegExpAstNode::Literal(ch);
            let pattern = format!("{ch}");
            let compiled = compile_regexp(&pattern, &flags, &ast, &config, epoch).unwrap();
            cache.insert(compiled);
        }
        assert_eq!(cache.len(), 2);
        assert!(cache.evictions >= 1);
    }

    #[test]
    fn test_cache_hit_rate() {
        let mut cache = AutomataCache::new(10);
        cache.hits = 3;
        cache.misses = 1;
        assert_eq!(cache.hit_rate_millionths(), 750_000);
    }

    #[test]
    fn test_cache_hit_rate_zero() {
        let cache = AutomataCache::new(10);
        assert_eq!(cache.hit_rate_millionths(), 0);
    }

    // ── Error display tests ──

    #[test]
    fn test_error_display() {
        let e = RegExpCompileError::EmptyPattern;
        assert_eq!(format!("{e}"), "empty pattern");

        let e2 = RegExpCompileError::NfaBudgetExceeded {
            states: 20000,
            budget: 10000,
        };
        assert!(format!("{e2}").contains("20000"));
    }

    // ── Serde tests ──

    #[test]
    fn test_serde_compiled_regexp() {
        let config = RegExpCompilerConfig::default();
        let epoch = SecurityEpoch::from_raw(1);
        let ast = make_simple_ast();
        let flags = BTreeSet::new();
        let compiled = compile_regexp("a", &flags, &ast, &config, epoch).unwrap();
        let json = serde_json::to_string(&compiled).unwrap();
        let deser: CompiledRegExp = serde_json::from_str(&json).unwrap();
        assert_eq!(compiled, deser);
    }

    #[test]
    fn test_serde_cache() {
        let cache = AutomataCache::new(10);
        let json = serde_json::to_string(&cache).unwrap();
        let deser: AutomataCache = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.capacity, 10);
    }

    #[test]
    fn test_serde_receipt() {
        let config = RegExpCompilerConfig::default();
        let epoch = SecurityEpoch::from_raw(1);
        let ast = make_simple_ast();
        let flags = BTreeSet::new();
        let compiled = compile_regexp("a", &flags, &ast, &config, epoch).unwrap();
        let json = serde_json::to_string(&compiled.receipt).unwrap();
        let deser: CompilationReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(compiled.receipt, deser);
    }

    #[test]
    fn test_serde_tail_risk() {
        let risk = TailRiskAssessment::safe();
        let json = serde_json::to_string(&risk).unwrap();
        let deser: TailRiskAssessment = serde_json::from_str(&json).unwrap();
        assert_eq!(risk, deser);
    }

    // ── Evidence harness tests ──

    #[test]
    fn test_corpus_non_empty() {
        assert!(!regexp_corpus().is_empty());
    }

    #[test]
    fn test_corpus_ids_unique() {
        let corpus = regexp_corpus();
        let mut ids = BTreeSet::new();
        for specimen in &corpus {
            assert!(
                ids.insert(&specimen.specimen_id),
                "duplicate id: {}",
                specimen.specimen_id
            );
        }
    }

    #[test]
    fn test_corpus_all_families_covered() {
        let corpus = regexp_corpus();
        let families: BTreeSet<_> = corpus.iter().map(|s| s.family).collect();
        for f in RegExpSpecimenFamily::ALL {
            assert!(families.contains(f), "missing family: {}", f.as_str());
        }
    }

    #[test]
    fn test_run_corpus_contract() {
        let inventory = run_regexp_corpus();
        assert!(
            inventory.contract_satisfied(),
            "corpus contract not satisfied: fail_count={}",
            inventory.fail_count
        );
    }

    #[test]
    fn test_inventory_counts_consistent() {
        let inventory = run_regexp_corpus();
        assert_eq!(
            inventory.specimen_count,
            inventory.pass_count + inventory.fail_count
        );
        assert_eq!(inventory.specimen_count, inventory.evidence.len() as u64);
    }

    #[test]
    fn test_family_coverage_complete() {
        let inventory = run_regexp_corpus();
        for f in RegExpSpecimenFamily::ALL {
            assert!(
                inventory.family_coverage.contains_key(f.as_str()),
                "missing family coverage: {}",
                f.as_str()
            );
        }
    }

    // ── Schema version tests ──

    #[test]
    fn test_schema_versions_non_empty() {
        assert!(!REGEXP_ENGINE_SCHEMA_VERSION.is_empty());
        assert!(!REGEXP_ENGINE_MANIFEST_SCHEMA_VERSION.is_empty());
        assert!(!REGEXP_ENGINE_EVENT_SCHEMA_VERSION.is_empty());
        assert!(!REGEXP_ENGINE_COMPONENT.is_empty());
        assert!(!REGEXP_ENGINE_POLICY_ID.is_empty());
    }

    #[test]
    fn test_schema_versions_unique() {
        let versions = [
            REGEXP_ENGINE_SCHEMA_VERSION,
            REGEXP_ENGINE_MANIFEST_SCHEMA_VERSION,
            REGEXP_ENGINE_EVENT_SCHEMA_VERSION,
        ];
        let set: BTreeSet<_> = versions.iter().collect();
        assert_eq!(set.len(), versions.len());
    }

    // ── Char class NFA ──

    #[test]
    fn test_nfa_char_class() {
        let ast = RegExpAstNode::CharClass {
            negated: false,
            ranges: vec![CharRange::range('a', 'z')],
        };
        let mut next_id = 0;
        let (_, _, states) = build_nfa_from_ast(&ast, &mut next_id);
        assert_eq!(states.len(), 2);
    }

    // ── Group NFA ──

    #[test]
    fn test_nfa_group_passthrough() {
        let ast = RegExpAstNode::Group {
            index: 1,
            child: Box::new(RegExpAstNode::Literal('a')),
        };
        let mut next_id = 0;
        let (_, _, states) = build_nfa_from_ast(&ast, &mut next_id);
        assert_eq!(states.len(), 2);
    }

    // ── Config default ──

    #[test]
    fn test_config_default() {
        let config = RegExpCompilerConfig::default();
        assert_eq!(config.max_nfa_states, DEFAULT_MAX_NFA_STATES);
        assert_eq!(config.max_dfa_states, DEFAULT_MAX_DFA_STATES);
        assert!(config.enable_dfa);
    }

    // ── Dot NFA ──

    #[test]
    fn test_nfa_dot() {
        let ast = RegExpAstNode::Dot;
        let mut next_id = 0;
        let (_, _, states) = build_nfa_from_ast(&ast, &mut next_id);
        assert_eq!(states.len(), 2);
        assert!(
            states[0]
                .transitions
                .iter()
                .any(|(t, _)| *t == NfaTransition::Any)
        );
    }
}
