//! Backtracking matcher for ECMAScript RegExps (ES2020 21.2.2).
//!
//! The `regex` crate runs most patterns (through `regexp_syntax`), but it
//! has no look-around and no backreferences. This matcher runs the patterns
//! it cannot, with ES2020 semantics for the constructs they need:
//! look-ahead and look-behind (the latter matched right to left), numbered
//! and named backreferences, captures cleared at each repetition, and the
//! rule that an optional iteration may not match the empty string.
//!
//! Matching is over characters (Unicode scalar values), like the `regex`
//! path, so the surrogate rules of `regexp_syntax` apply here too. Every
//! match attempt runs under a step budget that depends only on the pattern
//! and the input length, so a catastrophic pattern ends with
//! [`BacktrackError::StepBudget`] instead of running without bound.

use std::rc::Rc;
use std::sync::OnceLock;

use regex::Regex;

use super::InterpreterError;

/// Steps every search may take, plus [`STEP_BUDGET_PER_CHAR`] per input
/// character.
const STEP_BUDGET_BASE: u64 = 10_000_000;
const STEP_BUDGET_PER_CHAR: u64 = 1_000;
/// Instructions a compiled pattern may hold (counted repetition expands).
const MAX_PROGRAM_LEN: usize = 1 << 16;
const HIGH_SURROGATES: (u32, u32) = (0xD800, 0xDBFF);
const LOW_SURROGATES: (u32, u32) = (0xDC00, 0xDFFF);
const SUPPLEMENTARY: (u32, u32) = (0x1_0000, 0x10_FFFF);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum BacktrackError {
    /// The search took more steps than its budget.
    StepBudget,
}

/// The characters of a haystack and their byte offsets, prepared once per
/// operation so repeated searches (global match, replace, split) stay linear.
pub(super) struct PreparedInput {
    chars: Vec<char>,
    /// `byte_offsets[i]` is the byte offset of `chars[i]`; one extra entry
    /// holds the text length.
    byte_offsets: Vec<usize>,
}

impl PreparedInput {
    pub(super) fn new(text: &str) -> Self {
        let mut chars = Vec::with_capacity(text.len());
        let mut byte_offsets = Vec::with_capacity(text.len() + 1);
        for (offset, c) in text.char_indices() {
            chars.push(c);
            byte_offsets.push(offset);
        }
        byte_offsets.push(text.len());
        Self {
            chars,
            byte_offsets,
        }
    }

    pub(super) fn char_len(&self) -> usize {
        self.chars.len()
    }

    /// The character index at `byte` (the next character boundary).
    pub(super) fn char_index_at_byte(&self, byte: usize) -> usize {
        self.byte_offsets.partition_point(|&offset| offset < byte)
    }

    pub(super) fn byte_offset(&self, char_index: usize) -> usize {
        self.byte_offsets[char_index.min(self.chars.len())]
    }
}

/// A compiled pattern.
pub(super) struct BacktrackRegExp {
    program: Vec<Inst>,
    classes: Vec<CharClass>,
    /// Capture groups including group 0.
    group_count: usize,
    group_names: Vec<Option<String>>,
    registers: usize,
    ignore_case: bool,
    multiline: bool,
    dot_all: bool,
    unicode: bool,
}

/// Capture spans in byte offsets; index 0 is the whole match.
pub(super) type Captures = Vec<Option<(usize, usize)>>;

impl BacktrackRegExp {
    /// Compile `pattern` with `flags`, or return the SyntaxError message.
    pub(super) fn new(pattern: &str, flags: &str) -> Result<Self, String> {
        let unicode = flags.contains('u') || flags.contains('v');
        let mut parser = Parser::new(pattern, unicode);
        let root = parser.pattern()?;
        let mut compiler = Compiler {
            program: Vec::new(),
            registers: 0,
        };
        compiler.push(Inst::Save(0));
        compiler.emit(&root, false)?;
        compiler.push(Inst::Save(1));
        compiler.push(Inst::Match);
        Ok(Self {
            program: compiler.program,
            classes: parser.classes,
            group_count: parser.group_total + 1,
            group_names: parser.names,
            registers: compiler.registers,
            ignore_case: flags.contains('i'),
            multiline: flags.contains('m'),
            dot_all: flags.contains('s'),
            unicode,
        })
    }

    /// Compiled instructions, a measure of the pattern's memory.
    pub(super) fn program_len(&self) -> usize {
        self.program.len()
    }

    /// Group names by group number (index 0 is the whole match).
    pub(super) fn group_names(&self) -> &[Option<String>] {
        &self.group_names
    }

    pub(super) fn is_match(&self, text: &str) -> Result<bool, BacktrackError> {
        Ok(self.exec_at(&PreparedInput::new(text), 0, false)?.is_some())
    }

    /// The first match at or after character index `start` (only at
    /// `start` when `sticky`), as byte spans.
    pub(super) fn exec_at(
        &self,
        input: &PreparedInput,
        start: usize,
        sticky: bool,
    ) -> Result<Option<Captures>, BacktrackError> {
        let length = input.chars.len();
        let mut run = Run {
            regexp: self,
            chars: &input.chars,
            slots: vec![None; self.group_count * 2],
            registers: vec![0; self.registers],
            steps_left: STEP_BUDGET_BASE
                .saturating_add(STEP_BUDGET_PER_CHAR.saturating_mul(length as u64)),
        };
        let mut at = start;
        while at <= length {
            run.slots.fill(None);
            if run.execute(0, at)?.is_some() {
                let captures = run
                    .slots
                    .chunks(2)
                    .map(|pair| match (pair[0], pair[1]) {
                        (Some(from), Some(to)) => {
                            Some((input.byte_offset(from), input.byte_offset(to)))
                        }
                        _ => None,
                    })
                    .collect();
                return Ok(Some(captures));
            }
            if sticky {
                break;
            }
            at += 1;
        }
        Ok(None)
    }

    fn canonicalize(&self, c: char) -> char {
        canonicalize(c, self.unicode)
    }

    fn class_matches(&self, class: &CharClass, c: char) -> bool {
        let found = if self.ignore_case {
            let target = self.canonicalize(c);
            class.contains(c)
                || [single_lower(c), single_upper(c), target]
                    .into_iter()
                    .any(|candidate| {
                        candidate != c
                            && self.canonicalize(candidate) == target
                            && class.contains(candidate)
                    })
        } else {
            class.contains(c)
        };
        found != class.negated
    }
}

/// ES2020 21.2.2.8.2 Canonicalize. Without `u`: the single-character upper
/// case, except that a non-ASCII character never maps to ASCII. With `u`:
/// simple case folding, approximated by lower(upper(c)).
fn canonicalize(c: char, unicode: bool) -> char {
    if unicode {
        single_lower(single_upper(c))
    } else {
        let upper = single_upper(c);
        if !c.is_ascii() && upper.is_ascii() {
            c
        } else {
            upper
        }
    }
}

fn single_upper(c: char) -> char {
    let mut upper = c.to_uppercase();
    match (upper.next(), upper.next()) {
        (Some(single), None) => single,
        _ => c,
    }
}

fn single_lower(c: char) -> char {
    let mut lower = c.to_lowercase();
    match (lower.next(), lower.next()) {
        (Some(single), None) => single,
        _ => c,
    }
}

fn is_line_terminator(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}')
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// `ID_Start` and `ID_Continue` (Unicode derived properties), as one-character
/// `regex` sets built once.
fn identifier_sets() -> &'static (Regex, Regex) {
    static SETS: OnceLock<(Regex, Regex)> = OnceLock::new();
    SETS.get_or_init(|| {
        let set = |property: &str| {
            Regex::new(&format!(r"^\p{{{property}}}$")).expect("Unicode identifier property")
        };
        (set("ID_Start"), set("ID_Continue"))
    })
}

fn is_identifier_start(c: char) -> bool {
    let mut buffer = [0u8; 4];
    c == '$' || c == '_' || identifier_sets().0.is_match(c.encode_utf8(&mut buffer))
}

fn is_identifier_part(c: char) -> bool {
    let mut buffer = [0u8; 4];
    c == '$'
        || c == '\u{200C}'
        || c == '\u{200D}'
        || identifier_sets().1.is_match(c.encode_utf8(&mut buffer))
}

// ---------------------------------------------------------------------------
// Character classes

struct CharClass {
    /// Sorted, merged, inclusive code point ranges.
    ranges: Vec<(u32, u32)>,
    /// `\p{..}`/`\P{..}` sets, each a `regex` class matching one character.
    properties: Vec<Regex>,
    negated: bool,
}

impl CharClass {
    fn contains(&self, c: char) -> bool {
        let value = u32::from(c);
        let index = self.ranges.partition_point(|&(_, last)| last < value);
        if self
            .ranges
            .get(index)
            .is_some_and(|&(first, _)| first <= value)
        {
            return true;
        }
        if self.properties.is_empty() {
            return false;
        }
        let mut buffer = [0u8; 4];
        let text: &str = c.encode_utf8(&mut buffer);
        self.properties.iter().any(|set| set.is_match(text))
    }
}

/// Code point ranges under construction.
#[derive(Default)]
struct RangeSet {
    ranges: Vec<(u32, u32)>,
    properties: Vec<Regex>,
}

impl RangeSet {
    fn push(&mut self, first: u32, last: u32) {
        if first <= last {
            self.ranges.push((first, last));
        }
    }

    /// A code point range without the surrogates no string here holds.
    fn push_scalar(&mut self, first: u32, last: u32) {
        self.push(first, last.min(0xD7FF));
        self.push(first.max(0xE000), last);
    }

    /// A code unit range without `u`: a surrogate half stands for the
    /// supplementary characters whose UTF-16 form contains it.
    fn push_code_units(&mut self, first: u32, last: u32) {
        self.push_scalar(first, last);
        let high = (first.max(HIGH_SURROGATES.0), last.min(HIGH_SURROGATES.1));
        let low = (first.max(LOW_SURROGATES.0), last.min(LOW_SURROGATES.1));
        if high == HIGH_SURROGATES || low == LOW_SURROGATES {
            self.push(SUPPLEMENTARY.0, SUPPLEMENTARY.1);
            return;
        }
        if high.0 <= high.1 {
            self.push(
                combine(high.0, LOW_SURROGATES.0),
                combine(high.1, LOW_SURROGATES.1),
            );
        }
        if low.0 <= low.1 {
            for lead in HIGH_SURROGATES.0..=HIGH_SURROGATES.1 {
                self.push(combine(lead, low.0), combine(lead, low.1));
            }
        }
    }

    fn push_complement(&mut self, ranges: &[(u32, u32)]) {
        let mut next = 0u32;
        for &(first, last) in ranges {
            if first > next {
                self.push(next, first - 1);
            }
            next = last + 1;
        }
        if next <= 0x10_FFFF {
            self.push(next, 0x10_FFFF);
        }
    }

    fn finish(mut self, negated: bool) -> CharClass {
        self.ranges.sort_unstable();
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(self.ranges.len());
        for (first, last) in self.ranges {
            match merged.last_mut() {
                Some(previous) if first <= previous.1.saturating_add(1) => {
                    previous.1 = previous.1.max(last);
                }
                _ => merged.push((first, last)),
            }
        }
        CharClass {
            ranges: merged,
            properties: self.properties,
            negated,
        }
    }
}

const DIGIT_RANGES: [(u32, u32); 1] = [(0x30, 0x39)];
const WORD_RANGES: [(u32, u32); 4] = [(0x30, 0x39), (0x41, 0x5A), (0x5F, 0x5F), (0x61, 0x7A)];
/// ECMAScript WhiteSpace and LineTerminator (ES2020 11.2, 11.3), sorted.
const SPACE_RANGES: [(u32, u32); 10] = [
    (0x09, 0x0D),
    (0x20, 0x20),
    (0xA0, 0xA0),
    (0x1680, 0x1680),
    (0x2000, 0x200A),
    (0x2028, 0x2029),
    (0x202F, 0x202F),
    (0x205F, 0x205F),
    (0x3000, 0x3000),
    (0xFEFF, 0xFEFF),
];

/// Ranges of `\d`, `\w`, `\s`, and whether the escape is negated.
fn class_escape_ranges(escaped: char) -> Option<(&'static [(u32, u32)], bool)> {
    let ranges: &'static [(u32, u32)] = match escaped.to_ascii_lowercase() {
        'd' => &DIGIT_RANGES,
        'w' => &WORD_RANGES,
        's' => &SPACE_RANGES,
        _ => return None,
    };
    Some((ranges, escaped.is_ascii_uppercase()))
}

fn combine(high: u32, low: u32) -> u32 {
    0x1_0000 + ((high - 0xD800) << 10) + (low - 0xDC00)
}

fn split(code_point: u32) -> (u32, u32) {
    let offset = code_point - 0x1_0000;
    (0xD800 + (offset >> 10), 0xDC00 + (offset & 0x3FF))
}

fn is_in(unit: u32, (first, last): (u32, u32)) -> bool {
    (first..=last).contains(&unit)
}

// ---------------------------------------------------------------------------
// Parser

enum Node {
    Empty,
    Char(char),
    Any,
    Class(usize),
    LineStart,
    LineEnd,
    WordBoundary {
        negated: bool,
    },
    /// A group; `index` is the capture number of a capturing group.
    Group {
        index: Option<usize>,
        body: Box<Node>,
    },
    Look {
        ahead: bool,
        negated: bool,
        body: Box<Node>,
    },
    BackRef(usize),
    Concat(Vec<Node>),
    Alt(Vec<Node>),
    /// `groups` are the capture numbers inside `body`, cleared at the start
    /// of every iteration.
    Repeat {
        body: Box<Node>,
        min: u32,
        max: Option<u32>,
        greedy: bool,
        groups: (usize, usize),
    },
}

/// One element of a character class.
enum ClassAtom {
    /// A code unit (without `u`) or code point (with `u`).
    Char(u32),
    Set(RangeSet),
    /// An unescaped `-`, which may form a range.
    Dash,
}

struct Parser {
    chars: Vec<char>,
    index: usize,
    unicode: bool,
    /// Capturing groups in the whole pattern (backreferences may point
    /// forward).
    group_total: usize,
    /// Capturing groups opened so far.
    group_count: usize,
    named_groups: bool,
    names: Vec<Option<String>>,
    classes: Vec<CharClass>,
    /// Named backreferences, resolved once every name is known.
    pending_names: Vec<(usize, String)>,
}

impl Parser {
    fn new(pattern: &str, unicode: bool) -> Self {
        let chars: Vec<char> = pattern.chars().collect();
        let (group_total, named_groups) = count_groups(&chars);
        Self {
            chars,
            index: 0,
            unicode,
            group_total,
            group_count: 0,
            named_groups,
            names: vec![None; group_total + 1],
            classes: Vec::new(),
            pending_names: Vec::new(),
        }
    }

    fn peek(&self, offset: usize) -> Option<char> {
        self.chars.get(self.index + offset).copied()
    }

    fn pattern(&mut self) -> Result<Node, String> {
        let mut root = self.disjunction()?;
        if self.index < self.chars.len() {
            return Err("Unmatched ')'".to_string());
        }
        let pending = std::mem::take(&mut self.pending_names);
        for (placeholder, name) in pending {
            let group = self
                .names
                .iter()
                .position(|candidate| candidate.as_deref() == Some(name.as_str()))
                .ok_or_else(|| "Invalid named capture referenced".to_string())?;
            resolve_named_backref(&mut root, placeholder, group);
        }
        Ok(root)
    }

    fn disjunction(&mut self) -> Result<Node, String> {
        let mut alternatives = vec![self.alternative()?];
        while self.peek(0) == Some('|') {
            self.index += 1;
            alternatives.push(self.alternative()?);
        }
        Ok(if alternatives.len() == 1 {
            alternatives.pop().unwrap_or(Node::Empty)
        } else {
            Node::Alt(alternatives)
        })
    }

    fn alternative(&mut self) -> Result<Node, String> {
        let mut terms = Vec::new();
        while let Some(c) = self.peek(0) {
            if c == '|' || c == ')' {
                break;
            }
            terms.push(self.term()?);
        }
        Ok(match terms.len() {
            0 => Node::Empty,
            1 => terms.pop().unwrap_or(Node::Empty),
            _ => Node::Concat(terms),
        })
    }

    fn term(&mut self) -> Result<Node, String> {
        let groups_before = self.group_count;
        let (atom, quantifiable) = self.atom()?;
        let Some((min, max)) = self.quantifier()? else {
            return Ok(atom);
        };
        if !quantifiable {
            return Err("Nothing to repeat".to_string());
        }
        let greedy = if self.peek(0) == Some('?') {
            self.index += 1;
            false
        } else {
            true
        };
        if max.is_some_and(|max| max < min) {
            return Err("numbers out of order in {} quantifier".to_string());
        }
        Ok(Node::Repeat {
            body: Box::new(atom),
            min,
            max,
            greedy,
            groups: (groups_before + 1, self.group_count + 1),
        })
    }

    /// A quantifier at the cursor; `{` that starts no quantifier is left for
    /// the next atom (Annex B).
    fn quantifier(&mut self) -> Result<Option<(u32, Option<u32>)>, String> {
        let bounds = match self.peek(0) {
            Some('*') => (0, None),
            Some('+') => (1, None),
            Some('?') => (0, Some(1)),
            Some('{') => match self.braced_quantifier() {
                Some((bounds, length)) => {
                    self.index += length;
                    return Ok(Some(bounds));
                }
                None => return Ok(None),
            },
            _ => return Ok(None),
        };
        self.index += 1;
        Ok(Some(bounds))
    }

    /// `{n}`, `{n,}` or `{n,m}` at the cursor, and its length.
    fn braced_quantifier(&self) -> Option<((u32, Option<u32>), usize)> {
        let number = |from: usize| {
            let mut at = from;
            let mut value: u32 = 0;
            while let Some(digit) = self.chars.get(at).and_then(|c| c.to_digit(10)) {
                value = value.saturating_mul(10).saturating_add(digit);
                at += 1;
            }
            (at > from).then_some((value, at))
        };
        let start = self.index + 1;
        let (min, after_min) = number(start)?;
        let (max, end) = if self.chars.get(after_min) == Some(&',') {
            match number(after_min + 1) {
                Some((max, after_max)) => (Some(max), after_max),
                None => (None, after_min + 1),
            }
        } else {
            (Some(min), after_min)
        };
        (self.chars.get(end) == Some(&'}')).then_some(((min, max), end + 1 - self.index))
    }

    /// An atom or assertion, and whether a quantifier may follow it.
    fn atom(&mut self) -> Result<(Node, bool), String> {
        let c = self.peek(0).ok_or("Unexpected end of pattern")?;
        match c {
            '^' => {
                self.index += 1;
                Ok((Node::LineStart, false))
            }
            '$' => {
                self.index += 1;
                Ok((Node::LineEnd, false))
            }
            '.' => {
                self.index += 1;
                Ok((Node::Any, true))
            }
            '(' => self.group(),
            '[' => {
                let node = self.class()?;
                Ok((node, true))
            }
            '*' | '+' | '?' => Err("Nothing to repeat".to_string()),
            '{' if self.braced_quantifier().is_some() => Err("Nothing to repeat".to_string()),
            '\\' => match self.peek(1) {
                Some('b') | Some('B') => {
                    let negated = self.peek(1) == Some('B');
                    self.index += 2;
                    Ok((Node::WordBoundary { negated }, false))
                }
                Some(_) => {
                    let node = self.atom_escape()?;
                    Ok((node, true))
                }
                None => Err("\\ at end of pattern".to_string()),
            },
            _ => {
                self.index += 1;
                Ok((Node::Char(c), true))
            }
        }
    }

    fn group(&mut self) -> Result<(Node, bool), String> {
        let look = match (self.peek(1), self.peek(2), self.peek(3)) {
            (Some('?'), Some('='), _) => Some((true, false, 3)),
            (Some('?'), Some('!'), _) => Some((true, true, 3)),
            (Some('?'), Some('<'), Some('=')) => Some((false, false, 4)),
            (Some('?'), Some('<'), Some('!')) => Some((false, true, 4)),
            _ => None,
        };
        if let Some((ahead, negated, length)) = look {
            self.index += length;
            let body = self.disjunction()?;
            self.close_group()?;
            // Annex B: look-ahead is quantifiable without `u`.
            let quantifiable = ahead && !self.unicode;
            return Ok((
                Node::Look {
                    ahead,
                    negated,
                    body: Box::new(body),
                },
                quantifiable,
            ));
        }
        let index = match (self.peek(1), self.peek(2)) {
            (Some('?'), Some(':')) => {
                self.index += 3;
                None
            }
            (Some('?'), Some('<')) => {
                self.index += 3;
                let name = self.group_name()?;
                self.group_count += 1;
                if self
                    .names
                    .iter()
                    .any(|known| known.as_deref() == Some(&name))
                {
                    return Err("Duplicate capture group name".to_string());
                }
                if let Some(slot) = self.names.get_mut(self.group_count) {
                    *slot = Some(name);
                }
                Some(self.group_count)
            }
            (Some('?'), _) => return Err("Invalid group".to_string()),
            _ => {
                self.index += 1;
                self.group_count += 1;
                Some(self.group_count)
            }
        };
        let body = self.disjunction()?;
        self.close_group()?;
        Ok((
            Node::Group {
                index,
                body: Box::new(body),
            },
            true,
        ))
    }

    fn close_group(&mut self) -> Result<(), String> {
        if self.peek(0) != Some(')') {
            return Err("Unterminated group".to_string());
        }
        self.index += 1;
        Ok(())
    }

    /// A RegExpIdentifierName after `(?<` or `\k<`, through the closing
    /// `>`: ID_Start then ID_Continue characters, `$`, `_`, ZWNJ and ZWJ,
    /// each possibly written as `\uHHHH` (a surrogate pair is one character)
    /// or `\u{H..}`.
    fn group_name(&mut self) -> Result<String, String> {
        let invalid = || "Invalid capture group name".to_string();
        let mut name = String::new();
        loop {
            let value = match self.peek(0).ok_or_else(invalid)? {
                '>' => {
                    self.index += 1;
                    break;
                }
                '\\' if self.peek(1) == Some('u') => {
                    if self.peek(2) == Some('{') {
                        let (value, length) = self.braced_code_point(2).ok_or_else(invalid)?;
                        self.index += 2 + length;
                        value
                    } else {
                        let unit = self.code_unit_escape_at(0).ok_or_else(invalid)?;
                        self.index += 6;
                        match self.code_unit_escape_at(0) {
                            Some(low)
                                if is_in(unit, HIGH_SURROGATES) && is_in(low, LOW_SURROGATES) =>
                            {
                                self.index += 6;
                                combine(unit, low)
                            }
                            _ => unit,
                        }
                    }
                }
                other => {
                    self.index += 1;
                    u32::from(other)
                }
            };
            let c = char::from_u32(value).ok_or_else(invalid)?;
            let valid = if name.is_empty() {
                is_identifier_start(c)
            } else {
                is_identifier_part(c)
            };
            if !valid {
                return Err(invalid());
            }
            name.push(c);
        }
        if name.is_empty() {
            return Err(invalid());
        }
        Ok(name)
    }

    /// An escape outside a class; the cursor is on the backslash.
    fn atom_escape(&mut self) -> Result<Node, String> {
        let escaped = self.chars[self.index + 1];
        if let Some((ranges, negated)) = class_escape_ranges(escaped) {
            self.index += 2;
            let mut set = RangeSet::default();
            if negated {
                set.push_complement(ranges);
            } else {
                set.ranges.extend_from_slice(ranges);
            }
            return Ok(self.add_class(set, false));
        }
        match escaped {
            '1'..='9' => {
                let start = self.index + 1;
                let mut end = start;
                let mut number: usize = 0;
                while let Some(digit) = self.chars.get(end).and_then(|c| c.to_digit(10)) {
                    number = number.saturating_mul(10).saturating_add(digit as usize);
                    end += 1;
                }
                if number <= self.group_total {
                    self.index = end;
                    return Ok(Node::BackRef(number));
                }
                if self.unicode {
                    return Err("Invalid escape".to_string());
                }
                // Annex B: a legacy octal escape, or `\8`/`\9` as themselves.
                self.index += 1;
                if matches!(escaped, '8' | '9') {
                    self.index += 1;
                    return Ok(Node::Char(escaped));
                }
                Ok(Node::Char(char_from(self.legacy_octal())))
            }
            '0' if !self.unicode && self.peek(2).is_some_and(|c| c.is_ascii_digit()) => {
                self.index += 1;
                Ok(Node::Char(char_from(self.legacy_octal())))
            }
            'k' if self.unicode || self.named_groups => {
                if self.peek(2) != Some('<') {
                    return Err("Invalid named reference".to_string());
                }
                self.index += 3;
                let name = self.group_name()?;
                let placeholder = self.pending_names.len();
                self.pending_names.push((placeholder, name));
                Ok(Node::BackRef(usize::MAX - placeholder))
            }
            'c' if !self.peek(2).is_some_and(|c| c.is_ascii_alphabetic()) => {
                // A backslash; the `c` is read as the next atom.
                self.index += 1;
                Ok(Node::Char('\\'))
            }
            'u' => self.atom_unicode_escape(),
            'p' | 'P' if self.unicode => {
                let set = self.property_escape()?;
                Ok(self.add_class(set, false))
            }
            _ => {
                // Shared single-character escapes, then identity escapes.
                self.index += 1;
                let value = self.character_escape();
                Ok(Node::Char(char_from(value)))
            }
        }
    }

    /// `\u` outside a class.
    fn atom_unicode_escape(&mut self) -> Result<Node, String> {
        let Some(unit) = self.code_unit_escape_at(0) else {
            if self.unicode
                && self.peek(2) == Some('{')
                && let Some((value, length)) = self.braced_code_point(2)
            {
                self.index += 2 + length;
                return Ok(Node::Char(char_from(value)));
            }
            self.index += 2;
            return Ok(Node::Char('u'));
        };
        self.index += 6;
        if !is_in(unit, (0xD800, 0xDFFF)) {
            return Ok(Node::Char(char_from(unit)));
        }
        if is_in(unit, HIGH_SURROGATES)
            && let Some(low) = self.code_unit_escape_at(0)
            && is_in(low, LOW_SURROGATES)
        {
            self.index += 6;
            return Ok(Node::Char(char_from(combine(unit, low))));
        }
        let mut set = RangeSet::default();
        if !self.unicode {
            // A high surrogate and a class of low ones are one character.
            if is_in(unit, HIGH_SURROGATES)
                && let Some((first, last, length)) = self.low_surrogate_class()
            {
                self.index += length;
                set.push(combine(unit, first), combine(unit, last));
            } else {
                set.push_code_units(unit, unit);
            }
        }
        Ok(self.add_class(set, false))
    }

    /// `\uHHHH` with the backslash at `self.index + offset`.
    fn code_unit_escape_at(&self, offset: usize) -> Option<u32> {
        if self.peek(offset) != Some('\\') || self.peek(offset + 1) != Some('u') {
            return None;
        }
        hex_value(&self.chars, self.index + offset + 2, 4)
    }

    /// `{H..}` at `self.index + offset`: the code point and the length.
    fn braced_code_point(&self, offset: usize) -> Option<(u32, usize)> {
        let start = self.index + offset + 1;
        let close = self.chars.get(start..)?.iter().position(|&c| c == '}')?;
        let value = hex_value(&self.chars, start, close)?;
        Some((value, close + 2))
    }

    /// A class of low surrogates at the cursor, `[\uDCxx]` or
    /// `[\uDCxx-\uDCyy]`: the range and the class length.
    fn low_surrogate_class(&self) -> Option<(u32, u32, usize)> {
        if self.peek(0) != Some('[') {
            return None;
        }
        let first = self.code_unit_escape_at(1)?;
        if !is_in(first, LOW_SURROGATES) {
            return None;
        }
        if self.peek(7) == Some(']') {
            return Some((first, first, 8));
        }
        let last = self
            .code_unit_escape_at(8)
            .filter(|_| self.peek(7) == Some('-'))?;
        (is_in(last, LOW_SURROGATES) && self.peek(14) == Some(']')).then_some((first, last, 15))
    }

    /// `\p{..}` or `\P{..}` with the cursor on the backslash.
    fn property_escape(&mut self) -> Result<RangeSet, String> {
        if self.peek(2) != Some('{') {
            return Err("Invalid property name".to_string());
        }
        let close = self.chars[self.index..]
            .iter()
            .position(|&c| c == '}')
            .ok_or("Invalid property name")?;
        let text: String = self.chars[self.index..self.index + close + 1]
            .iter()
            .collect();
        self.index += close + 1;
        let set =
            Regex::new(&format!("^[{text}]$")).map_err(|_| "Invalid property name".to_string())?;
        Ok(RangeSet {
            ranges: Vec::new(),
            properties: vec![set],
        })
    }

    /// Annex B LegacyOctalEscapeSequence; the cursor is on the first digit.
    fn legacy_octal(&mut self) -> u32 {
        let digit = |at: usize| self.chars.get(at).and_then(|c| c.to_digit(8));
        let first = digit(self.index).unwrap_or(0);
        self.index += 1;
        let Some(second) = digit(self.index) else {
            return first;
        };
        self.index += 1;
        if first <= 3
            && let Some(third) = digit(self.index)
        {
            self.index += 1;
            return first * 64 + second * 8 + third;
        }
        first * 8 + second
    }

    /// A CharacterEscape (or identity escape) with the cursor on the escaped
    /// character; returns the code unit or code point.
    fn character_escape(&mut self) -> u32 {
        let escaped = self.chars[self.index];
        self.index += 1;
        match escaped {
            't' => 0x09,
            'n' => 0x0A,
            'v' => 0x0B,
            'f' => 0x0C,
            'r' => 0x0D,
            '0' => 0,
            'c' if self.peek(0).is_some_and(|c| c.is_ascii_alphabetic()) => {
                self.index += 1;
                u32::from(self.chars[self.index - 1]) % 32
            }
            'x' => match hex_value(&self.chars, self.index, 2) {
                Some(value) => {
                    self.index += 2;
                    value
                }
                None => u32::from('x'),
            },
            other => u32::from(other),
        }
    }

    fn add_class(&mut self, set: RangeSet, negated: bool) -> Node {
        self.classes.push(set.finish(negated));
        Node::Class(self.classes.len() - 1)
    }

    /// The idiom `[\uD800-\uDBFF][\uDC00-\uDFFF]` at the cursor.
    fn is_surrogate_pair_idiom(&self) -> bool {
        let range_class = |offset: usize, (first, last): (u32, u32)| {
            self.peek(offset) == Some('[')
                && self.code_unit_escape_at(offset + 1) == Some(first)
                && self.peek(offset + 7) == Some('-')
                && self.code_unit_escape_at(offset + 8) == Some(last)
                && self.peek(offset + 14) == Some(']')
        };
        range_class(0, HIGH_SURROGATES) && range_class(15, LOW_SURROGATES)
    }

    /// A character class; the cursor is on the `[`.
    fn class(&mut self) -> Result<Node, String> {
        if !self.unicode && self.is_surrogate_pair_idiom() {
            self.index += 30;
            let mut set = RangeSet::default();
            set.push(SUPPLEMENTARY.0, SUPPLEMENTARY.1);
            return Ok(self.add_class(set, false));
        }
        self.index += 1;
        let negated = self.peek(0) == Some('^');
        if negated {
            self.index += 1;
        }
        let mut atoms = Vec::new();
        loop {
            let c = self.peek(0).ok_or("Unterminated character class")?;
            match c {
                ']' => {
                    self.index += 1;
                    break;
                }
                '-' => {
                    self.index += 1;
                    atoms.push(ClassAtom::Dash);
                }
                '\\' if self.peek(1).is_some() => atoms.push(self.class_escape()?),
                _ => {
                    self.index += 1;
                    let value = u32::from(c);
                    if !self.unicode && value > 0xFFFF {
                        let (high, low) = split(value);
                        atoms.push(ClassAtom::Char(high));
                        atoms.push(ClassAtom::Char(low));
                    } else {
                        atoms.push(ClassAtom::Char(value));
                    }
                }
            }
        }
        // A `-` between two characters makes a range; either end may be a
        // `-` itself (`[+--]`). Next to a set it is a literal (Annex B).
        let as_char = |atom: &ClassAtom| match atom {
            ClassAtom::Char(value) => Some(*value),
            ClassAtom::Dash => Some(u32::from('-')),
            ClassAtom::Set(_) => None,
        };
        let mut set = RangeSet::default();
        let mut position = 0;
        while position < atoms.len() {
            if let (Some(first), Some(ClassAtom::Dash), Some(Some(last))) = (
                as_char(&atoms[position]),
                atoms.get(position + 1),
                atoms.get(position + 2).map(as_char),
            ) {
                if first > last {
                    return Err("Range out of order in character class".to_string());
                }
                self.push_class_range(&mut set, first, last);
                position += 3;
                continue;
            }
            if let ClassAtom::Set(inner) = &mut atoms[position] {
                let inner = std::mem::take(inner);
                set.ranges.extend(inner.ranges);
                set.properties.extend(inner.properties);
            } else if let Some(value) = as_char(&atoms[position]) {
                self.push_class_range(&mut set, value, value);
            }
            position += 1;
        }
        Ok(self.add_class(set, negated))
    }

    fn push_class_range(&self, set: &mut RangeSet, first: u32, last: u32) {
        if self.unicode {
            set.push_scalar(first, last);
        } else {
            set.push_code_units(first, last);
        }
    }

    /// An escape inside a class; the cursor is on the backslash.
    fn class_escape(&mut self) -> Result<ClassAtom, String> {
        let escaped = self.chars[self.index + 1];
        if let Some((ranges, negated)) = class_escape_ranges(escaped) {
            self.index += 2;
            let mut set = RangeSet::default();
            if negated {
                set.push_complement(ranges);
            } else {
                set.ranges.extend_from_slice(ranges);
            }
            return Ok(ClassAtom::Set(set));
        }
        match escaped {
            'b' => {
                self.index += 2;
                Ok(ClassAtom::Char(8))
            }
            '-' => {
                self.index += 2;
                Ok(ClassAtom::Char(u32::from('-')))
            }
            // Annex B ClassControlLetter includes digits and `_`.
            'c' if self
                .peek(2)
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') =>
            {
                self.index += 3;
                Ok(ClassAtom::Char(u32::from(self.chars[self.index - 1]) % 32))
            }
            // `\c` without a control letter is a backslash; `c` follows.
            'c' => {
                self.index += 1;
                Ok(ClassAtom::Char(u32::from('\\')))
            }
            '0'..='7' if !self.unicode || escaped == '0' => {
                self.index += 1;
                Ok(ClassAtom::Char(self.legacy_octal()))
            }
            'u' => {
                if let Some(unit) = self.code_unit_escape_at(0) {
                    self.index += 6;
                    if self.unicode
                        && is_in(unit, HIGH_SURROGATES)
                        && let Some(low) = self.code_unit_escape_at(0)
                        && is_in(low, LOW_SURROGATES)
                    {
                        self.index += 6;
                        return Ok(ClassAtom::Char(combine(unit, low)));
                    }
                    return Ok(ClassAtom::Char(unit));
                }
                if self.unicode
                    && self.peek(2) == Some('{')
                    && let Some((value, length)) = self.braced_code_point(2)
                {
                    self.index += 2 + length;
                    return Ok(ClassAtom::Char(value));
                }
                self.index += 2;
                Ok(ClassAtom::Char(u32::from('u')))
            }
            'p' | 'P' if self.unicode => Ok(ClassAtom::Set(self.property_escape()?)),
            _ => {
                self.index += 1;
                Ok(ClassAtom::Char(self.character_escape()))
            }
        }
    }
}

fn char_from(value: u32) -> char {
    char::from_u32(value).unwrap_or('\u{FFFD}')
}

/// `count` hex digits at `index`.
fn hex_value(chars: &[char], index: usize, count: usize) -> Option<u32> {
    let digits = chars.get(index..index + count)?;
    if count == 0 || count > 6 || !digits.iter().all(char::is_ascii_hexdigit) {
        return None;
    }
    u32::from_str_radix(&digits.iter().collect::<String>(), 16)
        .ok()
        .filter(|&value| value <= 0x10_FFFF)
}

/// Capturing groups in a pattern, and whether any is named.
fn count_groups(chars: &[char]) -> (usize, bool) {
    let (mut count, mut named, mut in_class, mut index) = (0, false, false, 0);
    while index < chars.len() {
        match chars[index] {
            '\\' => index += 1,
            '[' => in_class = true,
            ']' => in_class = false,
            '(' if !in_class => {
                if chars.get(index + 1) != Some(&'?') {
                    count += 1;
                } else if chars.get(index + 2) == Some(&'<')
                    && !matches!(chars.get(index + 3), Some('=') | Some('!'))
                {
                    count += 1;
                    named = true;
                }
            }
            _ => {}
        }
        index += 1;
    }
    (count, named)
}

fn resolve_named_backref(node: &mut Node, placeholder: usize, group: usize) {
    match node {
        Node::BackRef(index) if *index == usize::MAX - placeholder => *index = group,
        Node::Group { body, .. } | Node::Look { body, .. } | Node::Repeat { body, .. } => {
            resolve_named_backref(body, placeholder, group);
        }
        Node::Concat(nodes) | Node::Alt(nodes) => {
            for node in nodes {
                resolve_named_backref(node, placeholder, group);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Compiler

enum Inst {
    /// One character equal to `c` (canonicalized under `i`).
    Char {
        c: char,
        backward: bool,
    },
    Any {
        backward: bool,
    },
    Class {
        class: usize,
        backward: bool,
    },
    LineStart,
    LineEnd,
    WordBoundary {
        negated: bool,
    },
    /// Continue at `first`; on failure, at `second`.
    Split {
        first: usize,
        second: usize,
    },
    Jump(usize),
    Save(usize),
    /// Reset capture slots `from..to`.
    Clear {
        from: usize,
        to: usize,
    },
    /// Record the position at the start of an optional iteration.
    Mark(usize),
    /// Fail when the iteration begun at the marked position was empty.
    CheckProgress(usize),
    BackRef {
        group: usize,
        backward: bool,
    },
    /// Run the assertion at `body` (compiled in its direction) atomically,
    /// then continue at `next`.
    Look {
        negated: bool,
        body: usize,
        next: usize,
    },
    Match,
}

struct Compiler {
    program: Vec<Inst>,
    registers: usize,
}

impl Compiler {
    fn push(&mut self, inst: Inst) -> usize {
        self.program.push(inst);
        self.program.len() - 1
    }

    fn emit(&mut self, node: &Node, backward: bool) -> Result<(), String> {
        if self.program.len() > MAX_PROGRAM_LEN {
            return Err("Regular expression too large".to_string());
        }
        match node {
            Node::Empty => {}
            Node::Char(c) => {
                self.push(Inst::Char { c: *c, backward });
            }
            Node::Any => {
                self.push(Inst::Any { backward });
            }
            Node::Class(class) => {
                self.push(Inst::Class {
                    class: *class,
                    backward,
                });
            }
            Node::LineStart => {
                self.push(Inst::LineStart);
            }
            Node::LineEnd => {
                self.push(Inst::LineEnd);
            }
            Node::WordBoundary { negated } => {
                self.push(Inst::WordBoundary { negated: *negated });
            }
            Node::Group { index, body } => match index {
                Some(index) => {
                    let (open, close) = if backward {
                        (index * 2 + 1, index * 2)
                    } else {
                        (index * 2, index * 2 + 1)
                    };
                    self.push(Inst::Save(open));
                    self.emit(body, backward)?;
                    self.push(Inst::Save(close));
                }
                None => self.emit(body, backward)?,
            },
            Node::Look {
                ahead,
                negated,
                body,
            } => {
                let look = self.push(Inst::Match);
                let body_start = self.program.len();
                self.emit(body, !ahead)?;
                self.push(Inst::Match);
                let next = self.program.len();
                self.program[look] = Inst::Look {
                    negated: *negated,
                    body: body_start,
                    next,
                };
            }
            Node::BackRef(group) => {
                self.push(Inst::BackRef {
                    group: *group,
                    backward,
                });
            }
            Node::Concat(nodes) => {
                if backward {
                    for node in nodes.iter().rev() {
                        self.emit(node, backward)?;
                    }
                } else {
                    for node in nodes {
                        self.emit(node, backward)?;
                    }
                }
            }
            Node::Alt(alternatives) => {
                let mut exits = Vec::new();
                for (position, alternative) in alternatives.iter().enumerate() {
                    if position + 1 == alternatives.len() {
                        self.emit(alternative, backward)?;
                        break;
                    }
                    let split = self.push(Inst::Match);
                    let first = self.program.len();
                    self.emit(alternative, backward)?;
                    exits.push(self.push(Inst::Match));
                    let second = self.program.len();
                    self.program[split] = Inst::Split { first, second };
                }
                let end = self.program.len();
                for exit in exits {
                    self.program[exit] = Inst::Jump(end);
                }
            }
            Node::Repeat {
                body,
                min,
                max,
                greedy,
                groups,
            } => self.repeat(body, *min, *max, *greedy, *groups, backward)?,
        }
        Ok(())
    }

    fn repeat(
        &mut self,
        body: &Node,
        min: u32,
        max: Option<u32>,
        greedy: bool,
        (first_group, end_group): (usize, usize),
        backward: bool,
    ) -> Result<(), String> {
        let clear = (first_group < end_group).then_some(Inst::Clear {
            from: first_group * 2,
            to: end_group * 2,
        });
        let iteration = |compiler: &mut Self| -> Result<(), String> {
            if let Some(Inst::Clear { from, to }) = clear {
                compiler.push(Inst::Clear { from, to });
            }
            compiler.emit(body, backward)
        };
        for _ in 0..min {
            iteration(self)?;
            if self.program.len() > MAX_PROGRAM_LEN {
                return Err("Regular expression too large".to_string());
            }
        }
        let split_to = |first: usize, second: usize| {
            if greedy {
                Inst::Split { first, second }
            } else {
                Inst::Split {
                    first: second,
                    second: first,
                }
            }
        };
        match max {
            None => {
                let register = self.registers;
                self.registers += 1;
                let head = self.push(Inst::Match);
                let body_start = self.program.len();
                self.push(Inst::Mark(register));
                iteration(self)?;
                self.push(Inst::CheckProgress(register));
                self.push(Inst::Jump(head));
                let exit = self.program.len();
                self.program[head] = split_to(body_start, exit);
            }
            Some(max) => {
                let mut splits = Vec::new();
                for _ in min..max {
                    let register = self.registers;
                    self.registers += 1;
                    let split = self.push(Inst::Match);
                    splits.push((split, self.program.len()));
                    self.push(Inst::Mark(register));
                    iteration(self)?;
                    self.push(Inst::CheckProgress(register));
                    if self.program.len() > MAX_PROGRAM_LEN {
                        return Err("Regular expression too large".to_string());
                    }
                }
                let exit = self.program.len();
                for (split, body_start) in splits {
                    self.program[split] = split_to(body_start, exit);
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Execution

enum Frame {
    /// Resume at `pc` and `position`.
    Alternative {
        pc: usize,
        position: usize,
    },
    Slot {
        slot: usize,
        old: Option<usize>,
    },
    Register {
        register: usize,
        old: usize,
    },
}

struct Run<'a> {
    regexp: &'a BacktrackRegExp,
    chars: &'a [char],
    slots: Vec<Option<usize>>,
    registers: Vec<usize>,
    steps_left: u64,
}

impl Run<'_> {
    /// Run from `pc` at `position` until a `Match`; returns its position.
    /// On failure every slot and register change is undone.
    fn execute(
        &mut self,
        start_pc: usize,
        start_position: usize,
    ) -> Result<Option<usize>, BacktrackError> {
        let regexp = self.regexp;
        let chars = self.chars;
        let mut stack: Vec<Frame> = Vec::new();
        let mut pc = start_pc;
        let mut position = start_position;
        loop {
            if self.steps_left == 0 {
                return Err(BacktrackError::StepBudget);
            }
            self.steps_left -= 1;
            let advanced = match &regexp.program[pc] {
                Inst::Char { c, backward } => self.step(position, *backward, |input| {
                    if regexp.ignore_case {
                        regexp.canonicalize(input) == regexp.canonicalize(*c)
                    } else {
                        input == *c
                    }
                }),
                Inst::Any { backward } => self.step(position, *backward, |input| {
                    regexp.dot_all || !is_line_terminator(input)
                }),
                Inst::Class { class, backward } => {
                    let class = &regexp.classes[*class];
                    self.step(position, *backward, |input| {
                        regexp.class_matches(class, input)
                    })
                }
                Inst::LineStart => (position == 0
                    || (regexp.multiline && is_line_terminator(chars[position - 1])))
                .then_some(position),
                Inst::LineEnd => (position == chars.len()
                    || (regexp.multiline && is_line_terminator(chars[position])))
                .then_some(position),
                Inst::WordBoundary { negated } => {
                    let before = position > 0 && is_word_char(chars[position - 1]);
                    let after = position < chars.len() && is_word_char(chars[position]);
                    ((before != after) != *negated).then_some(position)
                }
                Inst::Split { first, second } => {
                    stack.push(Frame::Alternative {
                        pc: *second,
                        position,
                    });
                    pc = *first;
                    continue;
                }
                Inst::Jump(target) => {
                    pc = *target;
                    continue;
                }
                Inst::Save(slot) => {
                    stack.push(Frame::Slot {
                        slot: *slot,
                        old: self.slots[*slot],
                    });
                    self.slots[*slot] = Some(position);
                    Some(position)
                }
                Inst::Clear { from, to } => {
                    for (offset, value) in self.slots[*from..*to].iter_mut().enumerate() {
                        if let Some(old) = value.take() {
                            stack.push(Frame::Slot {
                                slot: from + offset,
                                old: Some(old),
                            });
                        }
                    }
                    Some(position)
                }
                Inst::Mark(register) => {
                    stack.push(Frame::Register {
                        register: *register,
                        old: self.registers[*register],
                    });
                    self.registers[*register] = position;
                    Some(position)
                }
                Inst::CheckProgress(register) => {
                    (self.registers[*register] != position).then_some(position)
                }
                Inst::BackRef { group, backward } => {
                    self.backreference(*group, position, *backward)
                }
                Inst::Look {
                    negated,
                    body,
                    next,
                } => {
                    let before = self.slots.clone();
                    let matched = self.execute(*body, position)?.is_some();
                    if matched == *negated {
                        // Failed: a failed sub-run has undone its changes;
                        // a matching negative one has not.
                        self.slots = before;
                        None
                    } else {
                        if !negated {
                            // Keep the captures, undoably.
                            for (slot, old) in before.into_iter().enumerate() {
                                if self.slots[slot] != old {
                                    stack.push(Frame::Slot { slot, old });
                                }
                            }
                        }
                        pc = *next;
                        continue;
                    }
                }
                Inst::Match => return Ok(Some(position)),
            };
            match advanced {
                Some(next_position) => {
                    position = next_position;
                    pc += 1;
                }
                None => loop {
                    match stack.pop() {
                        None => return Ok(None),
                        Some(Frame::Slot { slot, old }) => self.slots[slot] = old,
                        Some(Frame::Register { register, old }) => {
                            self.registers[register] = old;
                        }
                        Some(Frame::Alternative {
                            pc: resume,
                            position: at,
                        }) => {
                            pc = resume;
                            position = at;
                            break;
                        }
                    }
                },
            }
        }
    }

    /// Consume one character in the given direction if it satisfies `test`.
    fn step(&self, position: usize, backward: bool, test: impl Fn(char) -> bool) -> Option<usize> {
        if backward {
            (position > 0 && test(self.chars[position - 1])).then(|| position - 1)
        } else {
            (position < self.chars.len() && test(self.chars[position])).then(|| position + 1)
        }
    }

    fn backreference(&self, group: usize, position: usize, backward: bool) -> Option<usize> {
        let (Some(from), Some(to)) = (
            self.slots.get(group * 2).copied().flatten(),
            self.slots.get(group * 2 + 1).copied().flatten(),
        ) else {
            // An unset group matches the empty string.
            return Some(position);
        };
        let length = to.saturating_sub(from);
        let start = if backward {
            position.checked_sub(length)?
        } else {
            if position + length > self.chars.len() {
                return None;
            }
            position
        };
        let regexp = self.regexp;
        let same = (0..length).all(|offset| {
            let (expected, actual) = (self.chars[from + offset], self.chars[start + offset]);
            expected == actual
                || (regexp.ignore_case
                    && regexp.canonicalize(expected) == regexp.canonicalize(actual))
        });
        same.then_some(if backward { start } else { position + length })
    }
}

// ---------------------------------------------------------------------------
// Engine selection

/// A compiled RegExp: the `regex` crate's automaton for patterns it can
/// express (rewritten by `regexp_syntax`), this module's matcher otherwise.
#[derive(Clone)]
pub(super) enum CompiledRegExp {
    Automaton(Regex),
    Backtracking(Rc<BacktrackRegExp>),
}

impl CompiledRegExp {
    /// Group names by group number; group 0 (the whole match) has none.
    pub(super) fn group_names(&self) -> Vec<Option<String>> {
        match self {
            Self::Automaton(regex) => regex
                .capture_names()
                .map(|name| name.map(str::to_string))
                .collect(),
            Self::Backtracking(regexp) => regexp.group_names().to_vec(),
        }
    }

    pub(super) fn is_match(&self, text: &str) -> Result<bool, InterpreterError> {
        match self {
            Self::Automaton(regex) => Ok(regex.is_match(text)),
            Self::Backtracking(regexp) => regexp.is_match(text).map_err(budget_error),
        }
    }

    /// The first match at or after byte offset `start` (only at `start` when
    /// `sticky`), as byte spans.
    pub(super) fn captures_at(
        &self,
        text: &str,
        start: usize,
        sticky: bool,
    ) -> Result<Option<Captures>, InterpreterError> {
        match self {
            Self::Automaton(regex) => {
                let Some(captures) = regex.captures_at(text, start) else {
                    return Ok(None);
                };
                let spans: Captures = captures
                    .iter()
                    .map(|group| group.map(|group| (group.start(), group.end())))
                    .collect();
                if sticky && spans[0].is_some_and(|(from, _)| from != start) {
                    return Ok(None);
                }
                Ok(Some(spans))
            }
            Self::Backtracking(regexp) => {
                let input = PreparedInput::new(text);
                regexp
                    .exec_at(&input, input.char_index_at_byte(start), sticky)
                    .map_err(budget_error)
            }
        }
    }

    /// The matches of a global exec loop over `text` (ES2020 21.2.5.8 and
    /// 21.2.5.6 step 8): each search starts where the previous match ended,
    /// or one character further after an empty match (AdvanceStringIndex).
    pub(super) fn all_captures(&self, text: &str) -> Result<Vec<Captures>, InterpreterError> {
        let mut all = Vec::new();
        match self {
            Self::Automaton(regex) => {
                let mut at = 0;
                while at <= text.len() {
                    let Some(captures) = regex.captures_at(text, at) else {
                        break;
                    };
                    let spans: Captures = captures
                        .iter()
                        .map(|group| group.map(|group| (group.start(), group.end())))
                        .collect();
                    let Some((from, to)) = spans[0] else {
                        break;
                    };
                    at = if from == to {
                        to + text[to..].chars().next().map_or(1, char::len_utf8)
                    } else {
                        to
                    };
                    all.push(spans);
                }
            }
            Self::Backtracking(regexp) => {
                let input = PreparedInput::new(text);
                let mut at = 0;
                while at <= input.char_len() {
                    let Some(spans) = regexp.exec_at(&input, at, false).map_err(budget_error)?
                    else {
                        break;
                    };
                    let Some((from, to)) = spans[0] else {
                        break;
                    };
                    let end = input.char_index_at_byte(to);
                    at = if from == to { end + 1 } else { end };
                    all.push(spans);
                }
            }
        }
        Ok(all)
    }
}

/// A search stopped by its step budget is a RangeError in the guest.
fn budget_error(error: BacktrackError) -> InterpreterError {
    match error {
        BacktrackError::StepBudget => InterpreterError::RangeError {
            message: "RegExp matching exceeded its backtracking step budget".to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{BacktrackError, BacktrackRegExp, CompiledRegExp, PreparedInput};

    /// exec at 0 as (match index in bytes, captured strings).
    fn exec(pattern: &str, flags: &str, text: &str) -> Option<(usize, Vec<Option<String>>)> {
        let regexp = BacktrackRegExp::new(pattern, flags)
            .unwrap_or_else(|error| panic!("/{pattern}/{flags}: {error}"));
        let spans = regexp
            .exec_at(&PreparedInput::new(text), 0, flags.contains('y'))
            .expect("within budget")?;
        let groups = spans
            .iter()
            .map(|span| span.map(|(from, to)| text[from..to].to_string()))
            .collect();
        Some((spans[0].map_or(0, |(from, _)| from), groups))
    }

    fn groups(values: &[Option<&str>]) -> Vec<Option<String>> {
        values
            .iter()
            .map(|value| value.map(str::to_string))
            .collect()
    }

    // Expected values are Node v22.2.0's exec results.

    #[test]
    fn look_behind_matches_right_to_left() {
        assert_eq!(
            exec(r"(?<=(\d+)(\d+))$", "", "1053"),
            Some((4, groups(&[Some(""), Some("1"), Some("053")])))
        );
        assert_eq!(
            exec(r"(?<=\1(a))b", "", "aab"),
            Some((2, groups(&[Some("b"), Some("a")])))
        );
    }

    #[test]
    fn look_ahead_keeps_captures_and_is_atomic() {
        assert_eq!(
            exec(r"(?=(a+))a*b\1", "", "baaabac"),
            Some((3, groups(&[Some("aba"), Some("a")])))
        );
        assert_eq!(
            exec(r"(.*?)a(?!(a+)b\2c)\2(.*)", "", "baaabaac"),
            Some((
                0,
                groups(&[Some("baaabaac"), Some("ba"), None, Some("abaac")])
            ))
        );
    }

    #[test]
    fn repetition_clears_captures_and_rejects_empty_iterations() {
        assert_eq!(
            exec(r"(z)((a+)?(b+)?(c))*", "", "zaacbbbcac"),
            Some((
                0,
                groups(&[
                    Some("zaacbbbcac"),
                    Some("z"),
                    Some("ac"),
                    Some("a"),
                    None,
                    Some("c")
                ])
            ))
        );
        assert_eq!(
            exec(r"(a*)*", "", "b"),
            Some((0, groups(&[Some(""), None])))
        );
        assert_eq!(
            exec(r"(?:()|a)*", "", "aaa"),
            Some((0, groups(&[Some("aaa"), None])))
        );
    }

    #[test]
    fn named_and_unset_backreferences() {
        assert_eq!(
            exec(r#"(?<q>["'])(?<body>.*?)\k<q>"#, "", r#"x='a"b' y"#),
            Some((2, groups(&[Some(r#"'a"b'"#), Some("'"), Some(r#"a"b"#)])))
        );
        let regexp = BacktrackRegExp::new(r"(?<q>.)(?<body>.)", "").unwrap();
        assert_eq!(
            regexp.group_names(),
            &[None, Some("q".to_string()), Some("body".to_string())]
        );
        assert_eq!(
            exec(r"(a)|\1b", "", "b"),
            Some((0, groups(&[Some("b"), None])))
        );
        // Names may be escaped and hold ZWJ (Node: _\u200D, the𝟚, $x𝟚).
        let regexp =
            BacktrackRegExp::new(r"(?<_\u200D>a)(?<the\u{1d7da}>b)(?<$x\ud835\udfda>c)", "")
                .unwrap();
        assert_eq!(
            regexp.group_names(),
            &[
                None,
                Some("_\u{200D}".to_string()),
                Some("the\u{1d7da}".to_string()),
                Some("$x\u{1d7da}".to_string())
            ]
        );
        assert!(BacktrackRegExp::new(r"(?<a\u0020>x)", "").is_err());
    }

    #[test]
    fn case_folding_sticky_and_annex_b() {
        // U+212A KELVIN SIGN folds to `k` only under `u`.
        assert_eq!(exec("\u{212A}", "iu", "k"), Some((0, groups(&[Some("k")]))));
        assert_eq!(exec("\u{212A}", "i", "k"), None);
        assert_eq!(exec("ǆ", "i", "ǅ"), Some((0, groups(&[Some("ǅ")]))));
        assert_eq!(exec("a", "y", "ba"), None);
        assert_eq!(exec(r"\01|\8", "", "8"), Some((0, groups(&[Some("8")]))));
    }

    /// lodash's `stringToPath` loop over `rePropName`, with `lastIndex`
    /// stepped past empty matches as `RegExp.prototype.exec` callers do.
    #[test]
    fn lodash_property_path() {
        let regexp = BacktrackRegExp::new(
            r#"[^.[\]]+|\[(?:(-?\d+(?:\.\d+)?)|(["'])((?:(?!\2)[^\\]|\\.)*?)\2)\]|(?=(?:\.|\[\])(?:\.|\[\]|$))"#,
            "g",
        )
        .unwrap();
        let text = "a[0].b['c.d']";
        let input = PreparedInput::new(text);
        let (mut at, mut keys) = (0, Vec::new());
        while let Some(spans) = regexp.exec_at(&input, at, false).unwrap() {
            let piece = |group: usize| spans[group].map(|(from, to)| &text[from..to]);
            let whole = spans[0].unwrap();
            keys.push(
                piece(1)
                    .or(piece(3))
                    .unwrap_or(&text[whole.0..whole.1])
                    .to_string(),
            );
            at = input.char_index_at_byte(whole.1) + usize::from(whole.0 == whole.1);
        }
        assert_eq!(keys, ["a", "0", "b", "c.d"]);
    }

    #[test]
    fn syntax_errors() {
        for pattern in [
            "(",
            "a**",
            "[b-a]",
            "(?<a>x)(?<a>y)",
            r"\k<nope>(?<a>x)",
            "x{2,1}",
            "(?<=a)+",
            "(?=a)*",
        ] {
            assert!(BacktrackRegExp::new(pattern, "u").is_err(), "{pattern}");
        }
        assert!(BacktrackRegExp::new("(?=a)*", "").is_ok(), "Annex B");
    }

    /// Both engines iterate a global search the same way: an empty match
    /// directly after a match counts, then the search moves one character on
    /// (Node: `'abc'.match(/b*/g)` is `["", "b", "", ""]`).
    #[test]
    fn global_iteration_is_the_same_on_both_engines() {
        let automaton = CompiledRegExp::Automaton(regex::Regex::new("b*").unwrap());
        let backtracking =
            CompiledRegExp::Backtracking(std::rc::Rc::new(BacktrackRegExp::new("b*", "").unwrap()));
        for engine in [automaton, backtracking] {
            let spans: Vec<_> = engine
                .all_captures("abc")
                .unwrap()
                .into_iter()
                .map(|captures| captures[0])
                .collect();
            assert_eq!(
                spans,
                [Some((0, 0)), Some((1, 2)), Some((2, 2)), Some((3, 3))]
            );
            let emoji: Vec<_> = engine
                .all_captures("😀")
                .unwrap()
                .into_iter()
                .map(|captures| captures[0])
                .collect();
            assert_eq!(emoji, [Some((0, 0)), Some((4, 4))], "whole characters");
        }
    }

    #[test]
    fn catastrophic_patterns_stop_at_the_step_budget() {
        let regexp = BacktrackRegExp::new("(a+)+b", "").unwrap();
        assert_eq!(
            regexp.exec_at(&PreparedInput::new(&"a".repeat(30)), 0, false),
            Err(BacktrackError::StepBudget)
        );
        assert_eq!(regexp.is_match("aaab"), Ok(true));
    }
}
