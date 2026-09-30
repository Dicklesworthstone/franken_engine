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
//! backreferences) are left as they are and fail to compile, as before.

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
    if !pattern
        .bytes()
        .any(|byte| matches!(byte, b'\\' | b'[' | b'{') || (byte == b'.' && !dot_all))
    {
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
        unicode: flags.contains('u') || flags.contains('v'),
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
                self.out.extend(&self.chars[self.index..end]);
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
                push_char(&mut self.out, combine(unit, low));
                self.index += 6;
                return;
            }
            if self.unicode {
                self.out.push_str(NEVER);
                return;
            }
            // A high surrogate and a class of low ones are one character.
            if is_in(unit, HIGH_SURROGATES)
                && let Some((first, last, length)) = self.low_surrogate_class()
            {
                self.out.push('[');
                push_range(&mut self.out, combine(unit, first), combine(unit, last));
                self.out.push(']');
                self.index += length;
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

    /// A class of low surrogates at the cursor, `[\uDCxx]` or
    /// `[\uDCxx-\uDCyy]`. Returns the range and the class length.
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
    fn class(&mut self) {
        if !self.unicode && self.is_surrogate_pair_idiom() {
            self.out.push('[');
            self.out.push_str(SUPPLEMENTARY_RANGE);
            self.out.push(']');
            self.index += 30;
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
                ClassAtom::Set(text)
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

#[cfg(test)]
mod tests {
    use super::js_pattern_to_rust;
    use regex::{Regex, RegexBuilder};

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

    #[test]
    fn lone_surrogates_match_nothing_with_the_u_flag() {
        assert!(!rust_with(r"\ud83d", "u").is_match("😀"));
        assert!(!rust_with(r"[\u0000-\udfff]", "u").is_match("😀"));
        assert!(!rust_with(r"^[\u0000-\udfff]$", "u").is_match("\u{FFFF}"));
        assert!(rust_with(r"^[^\ud800-\udfff]$", "u").is_match("😀"));
        assert!(rust_with(r"^[\uD83D\uDE00]$", "u").is_match("😀"));
    }
}
