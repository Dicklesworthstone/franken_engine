//! ECMAScript RegExp pattern syntax rewritten for the `regex` crate.
//!
//! The interpreter matches RegExps with the `regex` crate, whose syntax
//! differs from ECMAScript's in places where the construct itself is
//! supported. [`js_pattern_to_rust`] rewrites those places so that a pattern
//! valid in JavaScript compiles to the same language:
//!
//! - Character classes are parsed into atoms and ranges and re-emitted with
//!   every atom as `\x{..}`. So `[` inside a class is a literal (a nested
//!   class in `regex`), `&&`, `--` and `~~` are literals (set operators in
//!   `regex`), and `[\d-x]` is `\d`, `-` and `x` (Annex B).
//! - `[]` never matches and `[^]` matches any character.
//! - `\d`, `\w` and `\s` are ASCII digits, ASCII word characters and the
//!   ECMAScript WhiteSpace/LineTerminator set, not their Unicode versions.
//! - `.` excludes `\r`, U+2028 and U+2029 as well as `\n`, unless the `s`
//!   flag is set.
//! - `\cX`, `\0`, `[\b]`, class octal escapes and `\u{..}` (with `u` only).
//! - Annex B literals: a `{` that starts no quantifier, and identity escapes
//!   such as `\a`, `\z` or `\<` (a bell, an end anchor and a word boundary
//!   in `regex`).
//! - Surrogates. The haystack is UTF-8, so only whole characters exist.
//!   A `\uHHHH` high/low pair is the supplementary character it encodes.
//!   Without `u`, a surrogate half matches the characters containing it:
//!   `[\uD800-\uDFFF]` is U+10000..=U+10FFFF, `\uD83C[\uDFFB-\uDFFF]` is
//!   U+1F3FB..=U+1F3FF, and so is the idiom `[\uD800-\uDBFF][\uDC00-\uDFFF]`.
//!   With `u`, a lone surrogate matches nothing.
//!
//! Known differences that remain: without `u`, JavaScript matches UTF-16
//! code units, so `.` or a lone surrogate half consumes half of a
//! supplementary character there and all of it here (`/^.$/` rejects "😀" in
//! JavaScript). Constructs `regex` does not support at all (look-around,
//! backreferences) are left as they are: `regex` rejects such a pattern and
//! `compile_regexp_pattern` runs it on the backtracking matcher
//! (`regexp_backtrack`) instead.

use std::borrow::Cow;

/// ECMAScript WhiteSpace and LineTerminator code points (ES2020 11.2, 11.3),
/// as the body of a character class.
const JS_SPACE_CLASS_BODY: &str = r"\t\n\x0B\x0C\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}";
const DIGIT_CLASS_BODY: &str = "0-9";
const WORD_CLASS_BODY: &str = "0-9A-Za-z_";
/// `.` without the `s` flag: anything but a LineTerminator.
const JS_DOT: &str = r"[^\n\r\x{2028}\x{2029}]";
const NEVER: &str = r"[^\s\S]";
const ANY: &str = r"[\s\S]";
const SUPPLEMENTARY_RANGE: &str = r"\x{10000}-\x{10FFFF}";
const HIGH_SURROGATES: (u32, u32) = (0xD800, 0xDBFF);
const LOW_SURROGATES: (u32, u32) = (0xDC00, 0xDFFF);

/// Rewrite a JavaScript pattern with `flags` into `regex` syntax. Patterns
/// with nothing to rewrite are returned as they are.
pub(super) fn js_pattern_to_rust<'a>(pattern: &'a str, flags: &str) -> Cow<'a, str> {
    let dot_all = flags.contains('s');
    let unicode = flags.contains('u') || flags.contains('v');
    // A 4-byte UTF-8 sequence is a supplementary character, which without
    // `u` is a surrogate pair whose low half a quantifier binds to
    // (bd-9vouw.156): `/^😀?$/` has nothing else to rewrite.
    if !pattern.bytes().any(|byte| {
        matches!(byte, b'\\' | b'[' | b'{')
            || (byte == b'.' && !dot_all)
            || (byte >= 0xF0 && !unicode)
    }) {
        return Cow::Borrowed(pattern);
    }
    let chars: Vec<char> = pattern.chars().collect();
    let named_groups = chars
        .windows(4)
        .any(|w| w[0] == '(' && w[1] == '?' && w[2] == '<' && !matches!(w[3], '=' | '!'));
    let mut translator = Translator {
        chars,
        index: 0,
        out: String::with_capacity(pattern.len() + 16),
        unicode,
        unicode_sets: flags.contains('v'),
        dot_all,
        named_groups,
    };
    translator.pattern();
    Cow::Owned(translator.out)
}

/// One element of a character class.
enum ClassAtom {
    /// A code unit (without `u`) or code point (with `u`).
    Char(u32),
    /// A predefined set, already rendered as class-body text.
    Set(String),
    /// An unescaped `-`, which may form a range.
    Dash,
}

struct Translator {
    chars: Vec<char>,
    index: usize,
    out: String,
    unicode: bool,
    unicode_sets: bool,
    dot_all: bool,
    named_groups: bool,
}

impl Translator {
    fn peek(&self, offset: usize) -> Option<char> {
        self.chars.get(self.index + offset).copied()
    }

    fn pattern(&mut self) {
        while let Some(c) = self.peek(0) {
            match c {
                '\\' if self.peek(1).is_some() => self.atom_escape(),
                '[' => self.class(),
                '{' if !self.is_braced_quantifier() => {
                    self.out.push_str(r"\{");
                    self.index += 1;
                }
                '.' if !self.dot_all => {
                    self.out.push_str(JS_DOT);
                    self.index += 1;
                }
                // Without `u` a literal astral character is a surrogate pair
                // and a quantifier after it applies to its low half, as for
                // the escaped pair (bd-9vouw.156): `/😀?/` matches the pair
                // once, never the empty string.
                _ if !self.unicode && u32::from(c) > 0xFFFF => {
                    self.index += 1;
                    if self.take_low_half_quantifier() {
                        self.out.push(c);
                    } else {
                        self.out.push_str(NEVER);
                    }
                }
                _ => {
                    self.out.push(c);
                    self.index += 1;
                }
            }
        }
    }

    /// Whether the `{` at the cursor begins a `{n}`, `{n,}` or `{n,m}`
    /// quantifier. Any other `{` is a literal (Annex B).
    fn is_braced_quantifier(&self) -> bool {
        let digits_from = |mut at: usize| {
            let start = at;
            while self.chars.get(at).is_some_and(char::is_ascii_digit) {
                at += 1;
            }
            (at > start, at)
        };
        let (has_min, mut cursor) = digits_from(self.index + 1);
        if !has_min {
            return false;
        }
        if self.chars.get(cursor) == Some(&',') {
            cursor = digits_from(cursor + 1).1;
        }
        self.chars.get(cursor) == Some(&'}')
    }

    /// `\uHHHH` at `self.index + offset` (pointing at the backslash).
    fn code_unit_escape_at(&self, offset: usize) -> Option<u32> {
        if self.peek(offset) != Some('\\') || self.peek(offset + 1) != Some('u') {
            return None;
        }
        hex_value(&self.chars, self.index + offset + 2, 4)
    }

    /// An escape outside a class; the cursor is on the backslash.
    fn atom_escape(&mut self) {
        let escaped = self.chars[self.index + 1];
        if let Some((body, negated)) = class_escape_body(escaped) {
            self.out.push_str(if negated { "[^" } else { "[" });
            self.out.push_str(body);
            self.out.push(']');
            self.index += 2;
            return;
        }
        match escaped {
            'u' => self.atom_unicode_escape(),
            'c' if self.peek(2).is_some_and(|c| c.is_ascii_alphabetic()) => {
                push_char(&mut self.out, u32::from(self.chars[self.index + 2]) % 32);
                self.index += 3;
            }
            // `\c` without a control letter is a backslash and `c`.
            'c' => {
                self.out.push_str(r"\\");
                self.index += 1;
            }
            '0' if !self.peek(2).is_some_and(|c| c.is_ascii_digit()) => {
                push_char(&mut self.out, 0);
                self.index += 2;
            }
            'x' => match hex_value(&self.chars, self.index + 2, 2) {
                Some(value) => {
                    push_char(&mut self.out, value);
                    self.index += 4;
                }
                None => {
                    self.out.push('x');
                    self.index += 2;
                }
            },
            'k' if !self.unicode && !self.named_groups => {
                self.out.push('k');
                self.index += 2;
            }
            'p' | 'P' if !self.unicode => {
                self.out.push(escaped);
                self.index += 2;
            }
            // Property names are shared; copy `\p{..}` whole so its brace is
            // not read as a literal.
            'p' | 'P' => {
                let end = self.chars[self.index..]
                    .iter()
                    .position(|&c| c == '}')
                    .map_or(self.index + 2, |close| self.index + close + 1);
                let text: String = self.chars[self.index..end].iter().collect();
                match surrogate_property_class(&text) {
                    Some(class) => self.out.push_str(class),
                    None => self.out.push_str(&text),
                }
                self.index = end;
            }
            // ASCII word boundaries, as `\w` is ASCII.
            'b' | 'B' => {
                self.out.push_str(if escaped == 'b' {
                    r"(?-u:\b)"
                } else {
                    r"(?-u:\B)"
                });
                self.index += 2;
            }
            other => {
                push_identity_escape(&mut self.out, other);
                self.index += 2;
            }
        }
    }

    /// `\u` outside a class.
    fn atom_unicode_escape(&mut self) {
        if let Some(unit) = self.code_unit_escape_at(0) {
            self.index += 6;
            if !is_surrogate(unit) {
                push_char(&mut self.out, unit);
                return;
            }
            if is_in(unit, HIGH_SURROGATES)
                && let Some(low) = self.code_unit_escape_at(0)
                && is_in(low, LOW_SURROGATES)
            {
                self.index += 6;
                if !self.unicode && !self.take_low_half_quantifier() {
                    self.out.push_str(NEVER);
                    return;
                }
                push_char(&mut self.out, combine(unit, low));
                return;
            }
            if self.unicode {
                self.out.push_str(NEVER);
                return;
            }
            // A high surrogate and a class of low ones are one character.
            if is_in(unit, HIGH_SURROGATES)
                && let Some((ranges, length)) = self.low_surrogate_class()
            {
                self.index += length;
                if !self.take_low_half_quantifier() {
                    self.out.push_str(NEVER);
                    return;
                }
                self.out.push('[');
                for (first, last) in ranges {
                    push_range(&mut self.out, combine(unit, first), combine(unit, last));
                }
                self.out.push(']');
                return;
            }
            self.out.push('[');
            push_non_unicode_range(&mut self.out, unit, unit);
            self.out.push(']');
            return;
        }
        if self.unicode
            && self.peek(2) == Some('{')
            && let Some(close) = self.chars[self.index + 3..].iter().position(|&c| c == '}')
            && let Some(value) = hex_value(&self.chars, self.index + 3, close)
        {
            push_char(&mut self.out, value);
            self.index += 4 + close;
            return;
        }
        self.out.push('u');
        self.index += 2;
    }

    /// A class of low surrogates at the cursor: `[`, one or more `\uDCxx`
    /// or `\uDCxx-\uDCyy` items, `]`. regexpu-core writes an astral set
    /// without `u` this way (`\uD835[\uDC00-\uDC19\uDC34-\uDC4D]`), and
    /// translating each half alone multiplied it into tens of thousands of
    /// ranges that took about half a second to compile per use. Returns the
    /// ranges and the class length.
    fn low_surrogate_class(&self) -> Option<(Vec<(u32, u32)>, usize)> {
        if self.peek(0) != Some('[') {
            return None;
        }
        let low = |unit: &u32| is_in(*unit, LOW_SURROGATES);
        let mut ranges = Vec::new();
        let mut offset = 1;
        while self.peek(offset) != Some(']') {
            let first = self.code_unit_escape_at(offset).filter(low)?;
            offset += 6;
            let last = if self.peek(offset) == Some('-') {
                let last = self
                    .code_unit_escape_at(offset + 1)
                    .filter(|unit| low(unit) && *unit >= first)?;
                offset += 7;
                last
            } else {
                first
            };
            ranges.push((first, last));
        }
        (!ranges.is_empty()).then_some((ranges, offset + 1))
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

    /// After a surrogate pair written as two halves and emitted as the one
    /// character it encodes (without `u`), at a quantifier written on the low
    /// half. JavaScript repeats that code unit only; here the character is
    /// one unit, and no low surrogate follows a pair's low half in a
    /// well-formed string, so the pair matches the character once unless the
    /// quantifier demands two or more low halves, when it matches nothing
    /// (bd-9vouw.156). Applying `?` to the whole character instead made
    /// `[\uD800-\uDBFF][\uDC00-\uDFFF]?` match the empty string everywhere.
    /// Where JavaScript would match the high half alone (`??`, `{0}`) the
    /// character is matched, as for any surrogate half (see the module docs).
    /// Consumes the quantifier and a lazy `?`; returns whether the pair can
    /// match.
    fn take_low_half_quantifier(&mut self) -> bool {
        let min_low_halves = match self.peek(0) {
            Some('?' | '*') => {
                self.index += 1;
                0
            }
            Some('+') => {
                self.index += 1;
                1
            }
            Some('{') if self.is_braced_quantifier() => {
                let mut min = 0u32;
                self.index += 1;
                while let Some(digit) = self.peek(0).and_then(|c| c.to_digit(10)) {
                    min = min.saturating_mul(10).saturating_add(digit);
                    self.index += 1;
                }
                while self.peek(0).is_some_and(|c| c != '}') {
                    self.index += 1;
                }
                self.index += 1;
                min
            }
            _ => return true,
        };
        if self.peek(0) == Some('?') {
            self.index += 1;
        }
        min_low_halves <= 1
    }

    /// A character class; the cursor is on the `[`.
    fn class(&mut self) {
        if !self.unicode && self.is_surrogate_pair_idiom() {
            self.index += 30;
            if !self.take_low_half_quantifier() {
                self.out.push_str(NEVER);
                return;
            }
            self.out.push('[');
            self.out.push_str(SUPPLEMENTARY_RANGE);
            self.out.push(']');
            return;
        }
        match (self.peek(1), self.peek(2)) {
            (Some(']'), _) => {
                self.out.push_str(NEVER);
                self.index += 2;
                return;
            }
            (Some('^'), Some(']')) => {
                self.out.push_str(ANY);
                self.index += 3;
                return;
            }
            _ => {}
        }
        if self.unicode_sets {
            self.unicode_sets_class();
            return;
        }
        self.index += 1;
        let negated = self.peek(0) == Some('^');
        if negated {
            self.index += 1;
        }
        let mut atoms = Vec::new();
        loop {
            let Some(c) = self.peek(0) else {
                // Unterminated: keep it unterminated so the build reports it.
                self.out.push('[');
                return;
            };
            match c {
                ']' => {
                    self.index += 1;
                    break;
                }
                '-' => {
                    atoms.push(ClassAtom::Dash);
                    self.index += 1;
                }
                '\\' if self.peek(1).is_some() => atoms.push(self.class_escape()),
                _ => {
                    self.index += 1;
                    let code_point = u32::from(c);
                    if !self.unicode && code_point > 0xFFFF {
                        let (high, low) = split(code_point);
                        atoms.push(ClassAtom::Char(high));
                        atoms.push(ClassAtom::Char(low));
                    } else {
                        atoms.push(ClassAtom::Char(code_point));
                    }
                }
            }
        }
        // A `-` between two characters makes a range; either end may be a
        // `-` itself (`[+--]`). Next to a set it is a literal.
        let as_char = |atom: &ClassAtom| match atom {
            ClassAtom::Char(value) => Some(*value),
            ClassAtom::Dash => Some(u32::from('-')),
            ClassAtom::Set(_) => None,
        };
        let mut body = String::new();
        let mut position = 0;
        while position < atoms.len() {
            let atom = &atoms[position];
            if let (Some(first), Some(ClassAtom::Dash), Some(Some(last))) = (
                as_char(atom),
                atoms.get(position + 1),
                atoms.get(position + 2).map(as_char),
            ) {
                self.push_class_range(&mut body, first, last);
                position += 3;
                continue;
            }
            match (atom, as_char(atom)) {
                (ClassAtom::Set(text), _) => body.push_str(text),
                (_, Some(value)) => self.push_class_range(&mut body, value, value),
                (_, None) => {}
            }
            position += 1;
        }
        self.out.push('[');
        if negated {
            self.out.push('^');
        }
        // Every atom was a surrogate that matches nothing.
        self.out
            .push_str(if body.is_empty() { NEVER } else { &body });
        self.out.push(']');
    }

    fn push_class_range(&self, body: &mut String, first: u32, last: u32) {
        if first > last {
            // A SyntaxError in JavaScript; keep it an error here.
            push_range(body, first, last);
        } else if self.unicode {
            push_scalar_range(body, first, last);
        } else {
            push_non_unicode_range(body, first, last);
        }
    }

    /// An escape inside a class; the cursor is on the backslash.
    fn class_escape(&mut self) -> ClassAtom {
        let escaped = self.chars[self.index + 1];
        self.index += 2;
        if let Some((body, negated)) = class_escape_body(escaped) {
            return ClassAtom::Set(if negated {
                format!("[^{body}]")
            } else {
                body.to_string()
            });
        }
        match escaped {
            'b' => ClassAtom::Char(8),
            'f' => ClassAtom::Char(0x0C),
            'n' => ClassAtom::Char(0x0A),
            'r' => ClassAtom::Char(0x0D),
            't' => ClassAtom::Char(0x09),
            'v' => ClassAtom::Char(0x0B),
            // Annex B ClassControlLetter includes digits and `_`.
            'c' if self
                .peek(0)
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') =>
            {
                self.index += 1;
                ClassAtom::Char(u32::from(self.chars[self.index - 1]) % 32)
            }
            // `\c` without a control letter is a backslash; `c` follows.
            'c' => {
                self.index -= 1;
                ClassAtom::Char(u32::from('\\'))
            }
            '0'..='7' if !self.unicode || escaped == '0' => {
                self.index -= 1;
                ClassAtom::Char(self.legacy_octal())
            }
            'x' => match hex_value(&self.chars, self.index, 2) {
                Some(value) => {
                    self.index += 2;
                    ClassAtom::Char(value)
                }
                None => ClassAtom::Char(u32::from('x')),
            },
            'u' => {
                self.index -= 2;
                if let Some(unit) = self.code_unit_escape_at(0) {
                    self.index += 6;
                    if self.unicode
                        && is_in(unit, HIGH_SURROGATES)
                        && let Some(low) = self.code_unit_escape_at(0)
                        && is_in(low, LOW_SURROGATES)
                    {
                        self.index += 6;
                        return ClassAtom::Char(combine(unit, low));
                    }
                    return ClassAtom::Char(unit);
                }
                if self.unicode
                    && self.peek(2) == Some('{')
                    && let Some(close) = self.chars[self.index + 3..].iter().position(|&c| c == '}')
                    && let Some(value) = hex_value(&self.chars, self.index + 3, close)
                {
                    self.index += 4 + close;
                    return ClassAtom::Char(value);
                }
                self.index += 2;
                ClassAtom::Char(u32::from('u'))
            }
            'p' | 'P' if self.unicode => {
                let close = self.chars[self.index..].iter().position(|&c| c == '}');
                let end = close.map_or(self.index, |close| self.index + close + 1);
                let text: String = self.chars[self.index - 2..end].iter().collect();
                self.index = end;
                ClassAtom::Set(
                    surrogate_property_class(&text).map_or(text, |class| class.to_string()),
                )
            }
            other => ClassAtom::Char(u32::from(other)),
        }
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

    /// A class under the `v` flag, whose nested classes and `&&`/`--`
    /// operators `regex` shares. Only escapes are rewritten.
    fn unicode_sets_class(&mut self) {
        let mut depth = 0usize;
        while let Some(c) = self.peek(0) {
            match c {
                '[' => {
                    depth += 1;
                    self.out.push('[');
                    self.index += 1;
                }
                ']' => {
                    self.out.push(']');
                    self.index += 1;
                    depth -= 1;
                    if depth == 0 {
                        return;
                    }
                }
                '\\' if self.peek(1).is_some() => match self.class_escape() {
                    ClassAtom::Char(value) => push_char(&mut self.out, value),
                    ClassAtom::Set(text) => {
                        let nested = text.starts_with('[') || text.starts_with('\\');
                        if !nested {
                            self.out.push('[');
                        }
                        self.out.push_str(&text);
                        if !nested {
                            self.out.push(']');
                        }
                    }
                    ClassAtom::Dash => self.out.push('-'),
                },
                _ => {
                    self.out.push(c);
                    self.index += 1;
                }
            }
        }
    }
}

/// The class body for `\d`/`\w`/`\s` and their negations.
fn class_escape_body(escaped: char) -> Option<(&'static str, bool)> {
    let body = match escaped.to_ascii_lowercase() {
        'd' => DIGIT_CLASS_BODY,
        'w' => WORD_CLASS_BODY,
        's' => JS_SPACE_CLASS_BODY,
        _ => return None,
    };
    Some((body, escaped.is_ascii_uppercase()))
}

/// An escape outside a class that `regex` shares with JavaScript, or one
/// that stands for the character itself.
fn push_identity_escape(out: &mut String, escaped: char) {
    // Control escapes mean the same in both dialects. Backreferences (a
    // digit or `\k`) stay, and fail to compile as before.
    if "fnrtvk".contains(escaped) || escaped.is_ascii_digit() {
        out.push('\\');
        out.push(escaped);
    } else {
        // Syntax characters, and Annex B identity escapes: `\a` is `a` where
        // `regex` reads a bell, `\z` an end anchor and `\<` a word boundary.
        push_char(out, u32::from(escaped));
    }
}

/// `count` hex digits at `index`.
fn hex_value(chars: &[char], index: usize, count: usize) -> Option<u32> {
    let digits = chars.get(index..index + count)?;
    if count == 0 || count > 6 || !digits.iter().all(char::is_ascii_hexdigit) {
        return None;
    }
    u32::from_str_radix(&digits.iter().collect::<String>(), 16)
        .ok()
        .filter(|&value| value <= 0x10FFFF)
}

fn is_in(unit: u32, (first, last): (u32, u32)) -> bool {
    (first..=last).contains(&unit)
}

fn is_surrogate(unit: u32) -> bool {
    (0xD800..=0xDFFF).contains(&unit)
}

fn combine(high: u32, low: u32) -> u32 {
    0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)
}

fn split(code_point: u32) -> (u32, u32) {
    let offset = code_point - 0x10000;
    (0xD800 + (offset >> 10), 0xDC00 + (offset & 0x3FF))
}

fn push_char(out: &mut String, code_point: u32) {
    out.push_str(&format!(r"\x{{{code_point:X}}}"));
}

fn push_range(out: &mut String, first: u32, last: u32) {
    push_char(out, first);
    if last != first {
        out.push('-');
        push_char(out, last);
    }
}

/// A code point range, leaving out the surrogates no UTF-8 string holds.
fn push_scalar_range(out: &mut String, first: u32, last: u32) {
    if first < 0xD800 {
        push_range(out, first, last.min(0xD7FF));
    }
    if last > 0xDFFF {
        push_range(out, first.max(0xE000), last);
    }
}

/// A code unit range without the `u` flag. A surrogate half stands for the
/// supplementary characters whose UTF-16 form contains it.
fn push_non_unicode_range(out: &mut String, first: u32, last: u32) {
    push_scalar_range(out, first, last);
    let high = (first.max(HIGH_SURROGATES.0), last.min(HIGH_SURROGATES.1));
    let low = (first.max(LOW_SURROGATES.0), last.min(LOW_SURROGATES.1));
    if high == HIGH_SURROGATES || low == LOW_SURROGATES {
        out.push_str(SUPPLEMENTARY_RANGE);
        return;
    }
    if high.0 <= high.1 {
        push_range(
            out,
            combine(high.0, LOW_SURROGATES.0),
            combine(high.1, LOW_SURROGATES.1),
        );
    }
    if low.0 <= low.1 {
        for lead in HIGH_SURROGATES.0..=HIGH_SURROGATES.1 {
            push_range(out, combine(lead, low.0), combine(lead, low.1));
        }
    }
}

// ---------------------------------------------------------------------------
// Unicode property escapes (ES2024 22.2.2.9 UnicodeMatchProperty,
// UnicodeMatchPropertyValue). In a u- or v-mode pattern `\p{..}` and `\P{..}`
// take exactly these spellings: case-sensitive, no spaces, no `Is`/`In`
// prefixes, no other properties. The `regex` crate matches property names
// loosely (UTS #18), so `\p{greek}`, `\p{ Lu }` and `\p{Block=Basic_Latin}`
// were accepted. The tables are the Unicode 16.0 aliases
// (PropertyAliases.txt, PropertyValueAliases.txt) that Node v22.2.0
// (Unicode 15.1) accepts.
// ---------------------------------------------------------------------------
/// Binary properties and General_Category values usable alone (`\p{Alpha}`,
/// `\p{Lu}`).
const LONE_PROPERTY_NAMES: &[&str] = &[
    "AHex",
    "ASCII",
    "ASCII_Hex_Digit",
    "Alpha",
    "Alphabetic",
    "Any",
    "Assigned",
    "Bidi_C",
    "Bidi_Control",
    "Bidi_M",
    "Bidi_Mirrored",
    "C",
    "CI",
    "CWCF",
    "CWCM",
    "CWKCF",
    "CWL",
    "CWT",
    "CWU",
    "Case_Ignorable",
    "Cased",
    "Cased_Letter",
    "Cc",
    "Cf",
    "Changes_When_Casefolded",
    "Changes_When_Casemapped",
    "Changes_When_Lowercased",
    "Changes_When_NFKC_Casefolded",
    "Changes_When_Titlecased",
    "Changes_When_Uppercased",
    "Close_Punctuation",
    "Cn",
    "Co",
    "Combining_Mark",
    "Connector_Punctuation",
    "Control",
    "Cs",
    "Currency_Symbol",
    "DI",
    "Dash",
    "Dash_Punctuation",
    "Decimal_Number",
    "Default_Ignorable_Code_Point",
    "Dep",
    "Deprecated",
    "Dia",
    "Diacritic",
    "EBase",
    "EComp",
    "EMod",
    "EPres",
    "Emoji",
    "Emoji_Component",
    "Emoji_Modifier",
    "Emoji_Modifier_Base",
    "Emoji_Presentation",
    "Enclosing_Mark",
    "Ext",
    "ExtPict",
    "Extended_Pictographic",
    "Extender",
    "Final_Punctuation",
    "Format",
    "Gr_Base",
    "Gr_Ext",
    "Grapheme_Base",
    "Grapheme_Extend",
    "Hex",
    "Hex_Digit",
    "IDC",
    "IDS",
    "IDSB",
    "IDST",
    "IDS_Binary_Operator",
    "IDS_Trinary_Operator",
    "ID_Continue",
    "ID_Start",
    "Ideo",
    "Ideographic",
    "Initial_Punctuation",
    "Join_C",
    "Join_Control",
    "L",
    "LC",
    "LOE",
    "Letter",
    "Letter_Number",
    "Line_Separator",
    "Ll",
    "Lm",
    "Lo",
    "Logical_Order_Exception",
    "Lower",
    "Lowercase",
    "Lowercase_Letter",
    "Lt",
    "Lu",
    "M",
    "Mark",
    "Math",
    "Math_Symbol",
    "Mc",
    "Me",
    "Mn",
    "Modifier_Letter",
    "Modifier_Symbol",
    "N",
    "NChar",
    "Nd",
    "Nl",
    "No",
    "Noncharacter_Code_Point",
    "Nonspacing_Mark",
    "Number",
    "Open_Punctuation",
    "Other",
    "Other_Letter",
    "Other_Number",
    "Other_Punctuation",
    "Other_Symbol",
    "P",
    "Paragraph_Separator",
    "Pat_Syn",
    "Pat_WS",
    "Pattern_Syntax",
    "Pattern_White_Space",
    "Pc",
    "Pd",
    "Pe",
    "Pf",
    "Pi",
    "Po",
    "Private_Use",
    "Ps",
    "Punctuation",
    "QMark",
    "Quotation_Mark",
    "RI",
    "Radical",
    "Regional_Indicator",
    "S",
    "SD",
    "STerm",
    "Sc",
    "Sentence_Terminal",
    "Separator",
    "Sk",
    "Sm",
    "So",
    "Soft_Dotted",
    "Space_Separator",
    "Spacing_Mark",
    "Surrogate",
    "Symbol",
    "Term",
    "Terminal_Punctuation",
    "Titlecase_Letter",
    "UIdeo",
    "Unassigned",
    "Unified_Ideograph",
    "Upper",
    "Uppercase",
    "Uppercase_Letter",
    "VS",
    "Variation_Selector",
    "WSpace",
    "White_Space",
    "XIDC",
    "XIDS",
    "XID_Continue",
    "XID_Start",
    "Z",
    "Zl",
    "Zp",
    "Zs",
    "cntrl",
    "digit",
    "punct",
    "space",
];
/// Properties of strings: `\p{RGI_Emoji}` with the v flag, never negated.
const STRING_PROPERTY_NAMES: &[&str] = &[
    "Basic_Emoji",
    "Emoji_Keycap_Sequence",
    "RGI_Emoji",
    "RGI_Emoji_Flag_Sequence",
    "RGI_Emoji_Modifier_Sequence",
    "RGI_Emoji_Tag_Sequence",
    "RGI_Emoji_ZWJ_Sequence",
];
/// `General_Category=` / `gc=` values.
const GENERAL_CATEGORY_VALUES: &[&str] = &[
    "C",
    "Cased_Letter",
    "Cc",
    "Cf",
    "Close_Punctuation",
    "Cn",
    "Co",
    "Combining_Mark",
    "Connector_Punctuation",
    "Control",
    "Cs",
    "Currency_Symbol",
    "Dash_Punctuation",
    "Decimal_Number",
    "Enclosing_Mark",
    "Final_Punctuation",
    "Format",
    "Initial_Punctuation",
    "L",
    "LC",
    "Letter",
    "Letter_Number",
    "Line_Separator",
    "Ll",
    "Lm",
    "Lo",
    "Lowercase_Letter",
    "Lt",
    "Lu",
    "M",
    "Mark",
    "Math_Symbol",
    "Mc",
    "Me",
    "Mn",
    "Modifier_Letter",
    "Modifier_Symbol",
    "N",
    "Nd",
    "Nl",
    "No",
    "Nonspacing_Mark",
    "Number",
    "Open_Punctuation",
    "Other",
    "Other_Letter",
    "Other_Number",
    "Other_Punctuation",
    "Other_Symbol",
    "P",
    "Paragraph_Separator",
    "Pc",
    "Pd",
    "Pe",
    "Pf",
    "Pi",
    "Po",
    "Private_Use",
    "Ps",
    "Punctuation",
    "S",
    "Sc",
    "Separator",
    "Sk",
    "Sm",
    "So",
    "Space_Separator",
    "Spacing_Mark",
    "Surrogate",
    "Symbol",
    "Titlecase_Letter",
    "Unassigned",
    "Uppercase_Letter",
    "Z",
    "Zl",
    "Zp",
    "Zs",
    "cntrl",
    "digit",
    "punct",
];
/// `Script=` / `sc=` / `Script_Extensions=` / `scx=` values.
const SCRIPT_VALUES: &[&str] = &[
    "Adlam",
    "Adlm",
    "Aghb",
    "Ahom",
    "Anatolian_Hieroglyphs",
    "Arab",
    "Arabic",
    "Armenian",
    "Armi",
    "Armn",
    "Avestan",
    "Avst",
    "Bali",
    "Balinese",
    "Bamu",
    "Bamum",
    "Bass",
    "Bassa_Vah",
    "Batak",
    "Batk",
    "Beng",
    "Bengali",
    "Bhaiksuki",
    "Bhks",
    "Bopo",
    "Bopomofo",
    "Brah",
    "Brahmi",
    "Brai",
    "Braille",
    "Bugi",
    "Buginese",
    "Buhd",
    "Buhid",
    "Cakm",
    "Canadian_Aboriginal",
    "Cans",
    "Cari",
    "Carian",
    "Caucasian_Albanian",
    "Chakma",
    "Cham",
    "Cher",
    "Cherokee",
    "Chorasmian",
    "Chrs",
    "Common",
    "Copt",
    "Coptic",
    "Cpmn",
    "Cprt",
    "Cuneiform",
    "Cypriot",
    "Cypro_Minoan",
    "Cyrillic",
    "Cyrl",
    "Deseret",
    "Deva",
    "Devanagari",
    "Diak",
    "Dives_Akuru",
    "Dogr",
    "Dogra",
    "Dsrt",
    "Dupl",
    "Duployan",
    "Egyp",
    "Egyptian_Hieroglyphs",
    "Elba",
    "Elbasan",
    "Elym",
    "Elymaic",
    "Ethi",
    "Ethiopic",
    "Geor",
    "Georgian",
    "Glag",
    "Glagolitic",
    "Gong",
    "Gonm",
    "Goth",
    "Gothic",
    "Gran",
    "Grantha",
    "Greek",
    "Grek",
    "Gujarati",
    "Gujr",
    "Gunjala_Gondi",
    "Gurmukhi",
    "Guru",
    "Han",
    "Hang",
    "Hangul",
    "Hani",
    "Hanifi_Rohingya",
    "Hano",
    "Hanunoo",
    "Hatr",
    "Hatran",
    "Hebr",
    "Hebrew",
    "Hira",
    "Hiragana",
    "Hluw",
    "Hmng",
    "Hmnp",
    "Hung",
    "Imperial_Aramaic",
    "Inherited",
    "Inscriptional_Pahlavi",
    "Inscriptional_Parthian",
    "Ital",
    "Java",
    "Javanese",
    "Kaithi",
    "Kali",
    "Kana",
    "Kannada",
    "Katakana",
    "Kawi",
    "Kayah_Li",
    "Khar",
    "Kharoshthi",
    "Khitan_Small_Script",
    "Khmer",
    "Khmr",
    "Khoj",
    "Khojki",
    "Khudawadi",
    "Kits",
    "Knda",
    "Kthi",
    "Lana",
    "Lao",
    "Laoo",
    "Latin",
    "Latn",
    "Lepc",
    "Lepcha",
    "Limb",
    "Limbu",
    "Lina",
    "Linb",
    "Linear_A",
    "Linear_B",
    "Lisu",
    "Lyci",
    "Lycian",
    "Lydi",
    "Lydian",
    "Mahajani",
    "Mahj",
    "Maka",
    "Makasar",
    "Malayalam",
    "Mand",
    "Mandaic",
    "Mani",
    "Manichaean",
    "Marc",
    "Marchen",
    "Masaram_Gondi",
    "Medefaidrin",
    "Medf",
    "Meetei_Mayek",
    "Mend",
    "Mende_Kikakui",
    "Merc",
    "Mero",
    "Meroitic_Cursive",
    "Meroitic_Hieroglyphs",
    "Miao",
    "Mlym",
    "Modi",
    "Mong",
    "Mongolian",
    "Mro",
    "Mroo",
    "Mtei",
    "Mult",
    "Multani",
    "Myanmar",
    "Mymr",
    "Nabataean",
    "Nag_Mundari",
    "Nagm",
    "Nand",
    "Nandinagari",
    "Narb",
    "Nbat",
    "New_Tai_Lue",
    "Newa",
    "Nko",
    "Nkoo",
    "Nshu",
    "Nushu",
    "Nyiakeng_Puachue_Hmong",
    "Ogam",
    "Ogham",
    "Ol_Chiki",
    "Olck",
    "Old_Hungarian",
    "Old_Italic",
    "Old_North_Arabian",
    "Old_Permic",
    "Old_Persian",
    "Old_Sogdian",
    "Old_South_Arabian",
    "Old_Turkic",
    "Old_Uyghur",
    "Oriya",
    "Orkh",
    "Orya",
    "Osage",
    "Osge",
    "Osma",
    "Osmanya",
    "Ougr",
    "Pahawh_Hmong",
    "Palm",
    "Palmyrene",
    "Pau_Cin_Hau",
    "Pauc",
    "Perm",
    "Phag",
    "Phags_Pa",
    "Phli",
    "Phlp",
    "Phnx",
    "Phoenician",
    "Plrd",
    "Prti",
    "Psalter_Pahlavi",
    "Qaac",
    "Qaai",
    "Rejang",
    "Rjng",
    "Rohg",
    "Runic",
    "Runr",
    "Samaritan",
    "Samr",
    "Sarb",
    "Saur",
    "Saurashtra",
    "Sgnw",
    "Sharada",
    "Shavian",
    "Shaw",
    "Shrd",
    "Sidd",
    "Siddham",
    "SignWriting",
    "Sind",
    "Sinh",
    "Sinhala",
    "Sogd",
    "Sogdian",
    "Sogo",
    "Sora",
    "Sora_Sompeng",
    "Soyo",
    "Soyombo",
    "Sund",
    "Sundanese",
    "Sylo",
    "Syloti_Nagri",
    "Syrc",
    "Syriac",
    "Tagalog",
    "Tagb",
    "Tagbanwa",
    "Tai_Le",
    "Tai_Tham",
    "Tai_Viet",
    "Takr",
    "Takri",
    "Tale",
    "Talu",
    "Tamil",
    "Taml",
    "Tang",
    "Tangsa",
    "Tangut",
    "Tavt",
    "Telu",
    "Telugu",
    "Tfng",
    "Tglg",
    "Thaa",
    "Thaana",
    "Thai",
    "Tibetan",
    "Tibt",
    "Tifinagh",
    "Tirh",
    "Tirhuta",
    "Tnsa",
    "Toto",
    "Ugar",
    "Ugaritic",
    "Unknown",
    "Vai",
    "Vaii",
    "Vith",
    "Vithkuqi",
    "Wancho",
    "Wara",
    "Warang_Citi",
    "Wcho",
    "Xpeo",
    "Xsux",
    "Yezi",
    "Yezidi",
    "Yi",
    "Yiii",
    "Zanabazar_Square",
    "Zanb",
    "Zinh",
    "Zyyy",
    "Zzzz",
];

/// The SyntaxError message of the first invalid `\p{..}` or `\P{..}` in a u-
/// or v-mode `pattern`, or `None` (also for patterns without either flag,
/// where `\p` is an identity escape).
/// Most Unicode property escapes (`\p{..}`/`\P{..}`) one pattern may hold
/// (franken_engine#2). Each expands to a large code-point set in either
/// RegExp route, so their number, not only the pattern length, bounds the
/// memory a single pattern can claim.
pub(super) const MAX_PROPERTY_ESCAPES: usize = 1024;

/// The SyntaxError message of a pattern over [`MAX_PROPERTY_ESCAPES`].
pub(super) const TOO_MANY_PROPERTY_ESCAPES: &str = "Too many Unicode property escapes";

/// Upper bound on the property escapes in `pattern` (a `\p{`/`\P{` that is
/// itself escaped is counted too, which only errs on the strict side).
pub(super) fn property_escape_count(pattern: &str) -> usize {
    pattern.matches("\\p{").count() + pattern.matches("\\P{").count()
}

pub(super) fn unicode_property_escape_error(pattern: &str, flags: &str) -> Option<&'static str> {
    let unicode_sets = flags.contains('v');
    if !unicode_sets && !flags.contains('u') {
        return None;
    }
    if property_escape_count(pattern) > MAX_PROPERTY_ESCAPES {
        return Some(TOO_MANY_PROPERTY_ESCAPES);
    }
    let chars: Vec<char> = pattern.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] != '\\' {
            index += 1;
            continue;
        }
        let Some(&escaped) = chars.get(index + 1) else {
            break;
        };
        if escaped != 'p' && escaped != 'P' {
            index += 2;
            continue;
        }
        if chars.get(index + 2) != Some(&'{') {
            return Some("Invalid property name");
        }
        let Some(length) = chars[index + 3..].iter().position(|&c| c == '}') else {
            return Some("Invalid property name");
        };
        let body: String = chars[index + 3..index + 3 + length].iter().collect();
        if !valid_property_escape(&body, escaped == 'P', unicode_sets) {
            return Some("Invalid property name");
        }
        index += 4 + length;
    }
    None
}

/// The class for a `\p{..}` or `\P{..}` (whole escape text) that names the
/// surrogate category, which the `regex` crate does not know. Matching runs
/// over strings that hold no lone surrogate (see the module notes), so
/// `\p{Cs}` matches nothing and `\P{Cs}` any character. ohm-js compiles
/// `\p{Cs}` among all General_Category values when it loads.
pub(super) fn surrogate_property_class(text: &str) -> Option<&'static str> {
    let body = text.get(3..text.len().checked_sub(1)?)?;
    let surrogate = matches!(
        body,
        "Cs" | "Surrogate"
            | "gc=Cs"
            | "gc=Surrogate"
            | "General_Category=Cs"
            | "General_Category=Surrogate"
    );
    surrogate.then_some(if text.starts_with(r"\P") { ANY } else { NEVER })
}

fn valid_property_escape(body: &str, negated: bool, unicode_sets: bool) -> bool {
    match body.split_once('=') {
        Some(("General_Category" | "gc", value)) => {
            GENERAL_CATEGORY_VALUES.binary_search(&value).is_ok()
        }
        Some(("Script" | "sc" | "Script_Extensions" | "scx", value)) => {
            SCRIPT_VALUES.binary_search(&value).is_ok()
        }
        Some(_) => false,
        None => {
            LONE_PROPERTY_NAMES.binary_search(&body).is_ok()
                || (unicode_sets && !negated && STRING_PROPERTY_NAMES.binary_search(&body).is_ok())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GENERAL_CATEGORY_VALUES, LONE_PROPERTY_NAMES, SCRIPT_VALUES, STRING_PROPERTY_NAMES,
        js_pattern_to_rust, unicode_property_escape_error,
    };
    use regex::{Regex, RegexBuilder};

    #[test]
    fn property_name_tables_are_sorted_for_binary_search() {
        for table in [
            LONE_PROPERTY_NAMES,
            STRING_PROPERTY_NAMES,
            GENERAL_CATEGORY_VALUES,
            SCRIPT_VALUES,
        ] {
            assert!(table.windows(2).all(|pair| pair[0] < pair[1]));
        }
        assert_eq!(
            unicode_property_escape_error(r"\p{Script=Greek}\P{Lu}", "u"),
            None
        );
        assert!(unicode_property_escape_error(r"\p{Greek}", "u").is_some());
        assert_eq!(unicode_property_escape_error(r"\p{Greek}", ""), None);
    }

    /// Built as the interpreter's `regexp_builder` builds it.
    fn rust_with(pattern: &str, flags: &str) -> Regex {
        RegexBuilder::new(&js_pattern_to_rust(pattern, flags))
            .case_insensitive(flags.contains('i'))
            .multi_line(flags.contains('m'))
            .dot_matches_new_line(flags.contains('s'))
            .unicode(true)
            .build()
            .unwrap_or_else(|error| panic!("`{pattern}` did not translate: {error}"))
    }

    fn rust(pattern: &str) -> Regex {
        rust_with(pattern, "")
    }

    /// A high surrogate before a class of several low ranges (regexpu-core's
    /// astral set without `u`) is one compact class of the characters it
    /// encodes (bd-9vouw.183).
    #[test]
    fn high_surrogate_with_a_multi_range_low_class_is_one_astral_class() {
        let pattern = r"^\uD835[\uDC00-\uDC19\uDC34-\uDC4D\uDC56]$";
        let translated = js_pattern_to_rust(pattern, "");
        assert!(translated.len() < 80, "{translated}");
        let regex = rust(pattern);
        for (text, expected) in [
            ("\u{1D400}", true),
            ("\u{1D419}", true),
            ("\u{1D41A}", false),
            ("\u{1D434}", true),
            ("\u{1D456}", true),
            ("\u{1D457}", false),
            ("a", false),
        ] {
            assert_eq!(regex.is_match(text), expected, "{text:?}");
        }
    }

    #[test]
    fn patterns_without_rewrites_are_borrowed() {
        assert!(matches!(
            js_pattern_to_rust("ab+c|d*", ""),
            std::borrow::Cow::Borrowed("ab+c|d*")
        ));
        assert!(matches!(
            js_pattern_to_rust("a.b", "s"),
            std::borrow::Cow::Borrowed(_)
        ));
    }

    #[test]
    fn brackets_and_set_operators_inside_classes_are_literals() {
        // lodash's reRegExpChar.
        let re = rust(r"[\\^$.*+?()[\]{}|]");
        for c in [
            "\\", "^", "$", ".", "*", "+", "?", "(", ")", "[", "]", "{", "}", "|",
        ] {
            assert!(re.is_match(c), "{c}");
        }
        assert!(!re.is_match("a"));
        assert!(rust("^[a&&b~~c-]+$").is_match("a&b~c-"));
        assert!(rust("^[--]+$").is_match("-"));
        assert!(
            rust("^[+--]+$").is_match("+,-"),
            "`+--` is the range + to -"
        );
    }

    #[test]
    fn empty_and_negated_empty_classes() {
        assert!(!rust("a[]").is_match("a"));
        assert!(rust("a[^]b").is_match("a\nb"));
    }

    #[test]
    fn class_escapes_have_javascript_meaning() {
        assert!(rust(r"^\d$").is_match("7"));
        assert!(
            !rust(r"^\d$").is_match("٣"),
            "Arabic-Indic digit is not \\d"
        );
        assert!(!rust(r"^\w$").is_match("é"), "é is not \\w");
        assert!(rust(r"^\w+$").is_match("a_Z9"));
        assert!(rust(r"^\s$").is_match("\u{FEFF}"));
        assert!(
            !rust(r"^\s$").is_match("\u{85}"),
            "NEL is not \\s in JavaScript"
        );
        assert!(rust(r"^[\d\w]+$").is_match("a1_"));
        assert!(rust(r"^\D\W\S$").is_match("a é"));
        assert!(rust(r"^[\d-z]+$").is_match("1-z"), "\\d- is no range");
        assert!(rust(r"^[\w-.]+$").is_match("a-."));
        assert!(rust(r"^[\w-a]+$").is_match("_-a"));
        assert!(rust(r"^[a-b-c]+$").is_match("ab-c"));
        assert!(rust(r"^[-a]+$").is_match("-a") && rust(r"^[a-]+$").is_match("a-"));
        assert!(rust(r"^[\W\d]+$").is_match("é1"), "é is \\W in JavaScript");
        assert!(!rust(r"^[\S]$").is_match("\u{FEFF}"));
    }

    #[test]
    fn dot_excludes_every_line_terminator() {
        for terminator in ["\n", "\r", "\u{2028}", "\u{2029}"] {
            assert!(!rust("^.$").is_match(terminator));
            assert!(rust_with("^.$", "s").is_match(terminator));
        }
        assert!(rust("^.$").is_match("a"));
    }

    #[test]
    fn control_nul_octal_and_backspace_escapes() {
        assert!(rust(r"^\cJ$").is_match("\n"));
        assert!(rust(r"^\c1$").is_match("\\c1"));
        assert!(rust(r"^\0$").is_match("\0"));
        assert!(rust(r"^[\b]$").is_match("\u{8}"));
        assert!(rust(r"^[\01]$").is_match("\u{1}"));
        assert!(rust(r"^[\c1]$").is_match("\u{11}"));
        assert!(rust(r"^[\c_]$").is_match("\u{1F}"));
        assert!(rust(r"^[\c]+$").is_match("\\c"));
        assert!(rust(r"^[\B]$").is_match("B"));
    }

    #[test]
    fn annex_b_literals() {
        assert!(rust("^a{$").is_match("a{"));
        assert!(rust("^a{b}$").is_match("a{b}"));
        assert!(rust("^x{1,$").is_match("x{1,"));
        assert!(rust("^{}$").is_match("{}"));
        assert!(
            rust("^a{2}b{1,}c{0,1}$").is_match("aabbc"),
            "quantifiers stay"
        );
        assert!(rust(r"^\a\e\z\<\>$").is_match("aez<>"));
        assert!(rust(r"^\xG\u$").is_match("xGu"));
        assert!(rust(r"^\k\p$").is_match("kp"));
        // `\b` is an ASCII boundary: é is no word character.
        assert!(rust(r"a\b").is_match("aé") && !rust(r"a\B").is_match("aé"));
        assert!(rust(r"é\b").is_match("éa"));
        assert!(rust(r"^\u{41}$").is_match(&"u".repeat(41)), "no `u` flag");
    }

    #[test]
    fn unicode_escapes_and_surrogates() {
        assert!(rust(r"^\u00e9$").is_match("é"));
        assert!(rust_with(r"^\u{1F600}$", "u").is_match("😀"));
        assert!(rust_with(r"^\p{L}$", "u").is_match("é"));
        assert!(rust(r"^\uD83D\uDE00$").is_match("😀"));
        assert!(rust(r"^[\uD800-\uDBFF][\uDC00-\uDFFF]$").is_match("😀"));
        assert!(!rust(r"^[\uD800-\uDBFF][\uDC00-\uDFFF]$").is_match("ab"));
        // lodash's reHasUnicode shape and its emoji-modifier range.
        let has_unicode = rust(r"[\u200d\ud800-\udfff\u0300-\u036f\ufe20-\ufe2f]");
        assert!(has_unicode.is_match("x😀"));
        assert!(!has_unicode.is_match("Foo Bar"));
        assert!(rust(r"^\ud83c[\udffb-\udfff]$").is_match("\u{1F3FB}"));
        assert!(!rust(r"^\ud83c[\udffb-\udfff]$").is_match("\u{1F3FA}"));
        assert!(rust(r"^[^\ud800-\udfff]$").is_match("a"));
        assert!(!rust(r"^[^\ud800-\udfff]$").is_match("😀"));
        assert!(rust(r"\ud83d").is_match("😀"));
        assert!(rust(r"\ude00").is_match("😀"));
        assert!(!rust(r"\ude00").is_match("😁"));
        assert!(rust(r"[\u0000-\udfff]").is_match("😀"));
    }

    /// html-entities' `[\uD800-\uDBFF][\uDC00-\uDFFF]?` matched the empty
    /// string everywhere: the `?` on the low half applied to the whole
    /// character the pair was rewritten as (bd-9vouw.156).
    #[test]
    fn quantified_low_half_of_a_pair_matches_the_character_once() {
        let idiom = r"[\uD800-\uDBFF][\uDC00-\uDFFF]";
        for quantifier in ["", "?", "*", "+", "{1}", "{0,3}", "{1,}?", "??", "{0}"] {
            let whole = rust(&format!("^{idiom}{quantifier}$"));
            assert!(whole.is_match("😀"), "{quantifier}");
            assert!(!whole.is_match(""), "{quantifier} matched the empty string");
            assert!(!whole.is_match("é"), "{quantifier}");
            assert!(
                !rust(&format!("{idiom}{quantifier}")).is_match("abc é"),
                "{quantifier}"
            );
        }
        assert!(!rust(&format!("{idiom}{{2}}")).is_match("😀😀"));
        assert!(rust(r"^😀?$").is_match("😀"));
        assert!(!rust(r"^😀?$").is_match(""));
        assert!(rust(r"^\ud83c[\udffb-\udfff]*$").is_match("\u{1F3FC}"));
        assert!(!rust(r"^\ud83c[\udffb-\udfff]*$").is_match(""));
        assert!(!rust(r"\ud83c[\udffb-\udfff]{2}").is_match("\u{1F3FC}\u{1F3FC}"));
        // A group around the pair is quantified as a whole, and with `u` the
        // pair is one code point the quantifier applies to.
        assert!(rust(r"^(?:😀)?$").is_match(""));
        assert!(rust_with(r"^😀?$", "u").is_match(""));
    }

    /// ohm-js compiles `\p{Cs}` for every General_Category value when it
    /// loads, and the `regex` crate has no surrogate category, so ohm failed
    /// with "Invalid property name". Strings here hold no lone surrogate, so
    /// `\p{Cs}` matches nothing and `\P{Cs}` any character, inside and
    /// outside classes. No-claim: Node matches `\p{Cs}` against a lone
    /// surrogate (`/\p{Cs}/u.test("\uD800")` is true); this engine cannot.
    #[test]
    fn surrogate_category_escapes_compile_and_match_no_character() {
        for name in ["Cs", "Surrogate", "gc=Cs", "General_Category=Surrogate"] {
            let escape = format!(r"\p{{{name}}}");
            assert!(!rust_with(&escape, "u").is_match("a😀\u{FFFF}\n"), "{name}");
            assert!(
                rust_with(&format!(r"^\P{{{name}}}+$"), "u").is_match("a😀\n"),
                "{name}"
            );
            assert!(
                rust_with(&format!(r"^[{escape}b]$"), "u").is_match("b"),
                "{name}"
            );
            assert!(
                !rust_with(&format!(r"^[{escape}b]$"), "u").is_match("a"),
                "{name}"
            );
            assert!(
                !rust_with(&format!(r"^[^\P{{{name}}}]$"), "u").is_match("a"),
                "{name}"
            );
        }
        assert_eq!(
            unicode_property_escape_error(r"\p{Cs}\P{Surrogate}", "u"),
            None
        );
        assert!(rust_with(r"^\p{Lu}\p{Cs}?$", "u").is_match("A"));
    }

    #[test]
    fn lone_surrogates_match_nothing_with_the_u_flag() {
        assert!(!rust_with(r"\ud83d", "u").is_match("😀"));
        assert!(!rust_with(r"[\u0000-\udfff]", "u").is_match("😀"));
        assert!(!rust_with(r"^[\u0000-\udfff]$", "u").is_match("\u{FFFF}"));
        assert!(rust_with(r"^[^\ud800-\udfff]$", "u").is_match("😀"));
        assert!(rust_with(r"^[\uD83D\uDE00]$", "u").is_match("😀"));
    }
}
