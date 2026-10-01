//! `String.prototype.localeCompare` collation: a simplified Unicode
//! Collation Algorithm over the root order ICU uses for English.
//!
//! Each string becomes collation elements with three levels. Primary: the
//! character class (whitespace, then punctuation and symbols in ICU's
//! order, then digits, then letters) and the base letter; secondary: its
//! accents; tertiary: its case (lowercase first). Strings compare level by
//! level, as the `sensitivity` option selects, so
//! `['b', 'A', 'a', 'é', 'e']` sorts as `a A b e é`. `numeric` compares
//! digit runs by value, and `ignorePunctuation` drops whitespace and
//! punctuation. Canonically equivalent strings are equal (NFKD first).
//! Letters outside the few special cases keep code-point order, which
//! matches the root order's script sequence (Latin, Greek, Cyrillic, kana,
//! Han) but not locale-specific tailorings such as Swedish `ä` after `z`.

use std::cmp::Ordering;

use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::is_combining_mark;

/// Which levels decide (Intl.Collator `sensitivity`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Sensitivity {
    /// Base letters only: `a = A = á`.
    Base,
    /// Base letters and accents: `a = A`, `a ≠ á`.
    Accent,
    /// Base letters and case: `a ≠ A`, `a = á`.
    Case,
    /// Every difference (the default).
    Variant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CollationOptions {
    pub(super) sensitivity: Sensitivity,
    pub(super) numeric: bool,
    pub(super) ignore_punctuation: bool,
}

impl Default for CollationOptions {
    fn default() -> Self {
        Self {
            sensitivity: Sensitivity::Variant,
            numeric: false,
            ignore_punctuation: false,
        }
    }
}

/// ICU's root order of the ASCII punctuation and symbols after whitespace.
const PUNCTUATION_ORDER: &str = "_-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Primary {
    Space(u32),
    Punctuation(u32),
    /// A digit, or with `numeric` a whole run: (significant length, digits).
    Digits(usize, Vec<u32>),
    Letter(u32),
    Other(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Element {
    primary: Primary,
    /// Accents (combining marks) and letter variants, in order.
    secondary: Vec<u32>,
    /// 0 lowercase or caseless, 1 uppercase, 2 a compatibility variant.
    tertiary: u8,
    punctuation: bool,
}

/// Letters that sort as other letters (ICU root): expansions, and letters
/// with a secondary difference from their base.
fn special_letter(c: char) -> Option<(&'static str, u32)> {
    Some(match c {
        'ß' => ("ss", 1),
        'æ' => ("ae", 1),
        'Æ' => ("AE", 1),
        'œ' => ("oe", 1),
        'Œ' => ("OE", 1),
        'ø' => ("o", 0x338),
        'Ø' => ("O", 0x338),
        'ł' => ("l", 0x335),
        'Ł' => ("L", 0x335),
        'đ' => ("d", 0x335),
        'Đ' => ("D", 0x335),
        'ı' => ("i", 0x131),
        _ => return None,
    })
}

fn elements(text: &str, options: &CollationOptions) -> Vec<Element> {
    let mut out: Vec<Element> = Vec::new();
    let decomposed: Vec<char> = text.nfkd().collect();
    let compatibility: Vec<char> = text.nfd().collect();
    // A compatibility decomposition (`ﬁ` to `fi`) is a tertiary variant.
    let compatibility_variant = decomposed != compatibility;
    let mut index = 0;
    while index < decomposed.len() {
        let c = decomposed[index];
        index += 1;
        if is_combining_mark(c) {
            if let Some(last) = out.last_mut() {
                last.secondary.push(u32::from(c));
            }
            continue;
        }
        if let Some((expansion, mark)) = special_letter(c) {
            for (position, letter) in expansion.chars().enumerate() {
                let mut element = letter_element(letter);
                if position + 1 == expansion.chars().count() {
                    element.secondary.push(mark);
                }
                out.push(element);
            }
            continue;
        }
        let element = if c.is_whitespace() {
            Element {
                primary: Primary::Space(u32::from(c)),
                secondary: Vec::new(),
                tertiary: 0,
                punctuation: true,
            }
        } else if let Some(digit) = c.to_digit(10) {
            let mut digits = vec![digit];
            if options.numeric {
                while let Some(next) = decomposed.get(index).and_then(|next| next.to_digit(10)) {
                    digits.push(next);
                    index += 1;
                }
                let first_significant = digits.iter().position(|d| *d != 0);
                let significant = first_significant.map_or(Vec::new(), |at| digits[at..].to_vec());
                Element {
                    primary: Primary::Digits(significant.len(), significant),
                    secondary: Vec::new(),
                    tertiary: 0,
                    punctuation: false,
                }
            } else {
                Element {
                    primary: Primary::Digits(1, digits),
                    secondary: Vec::new(),
                    tertiary: 0,
                    punctuation: false,
                }
            }
        } else if c.is_alphabetic() {
            letter_element(c)
        } else if let Some(rank) = PUNCTUATION_ORDER.find(c) {
            Element {
                primary: Primary::Punctuation(rank as u32),
                secondary: Vec::new(),
                tertiary: 0,
                punctuation: true,
            }
        } else if c.is_ascii_punctuation() || (!c.is_alphanumeric() && !c.is_control()) {
            Element {
                primary: Primary::Punctuation(0x100 + u32::from(c)),
                secondary: Vec::new(),
                tertiary: 0,
                punctuation: true,
            }
        } else {
            Element {
                primary: Primary::Other(u32::from(c)),
                secondary: Vec::new(),
                tertiary: 0,
                punctuation: false,
            }
        };
        out.push(element);
    }
    if compatibility_variant {
        for element in &mut out {
            element.tertiary = element.tertiary.max(2);
        }
    }
    if options.ignore_punctuation {
        out.retain(|element| !element.punctuation);
    }
    out
}

fn letter_element(c: char) -> Element {
    let lower = c.to_lowercase().next().unwrap_or(c);
    Element {
        primary: Primary::Letter(u32::from(lower)),
        secondary: Vec::new(),
        tertiary: u8::from(c.is_uppercase()),
        punctuation: false,
    }
}

/// Compare `a` with `b` as `a.localeCompare(b, undefined, options)` does.
pub(super) fn locale_compare(a: &str, b: &str, options: &CollationOptions) -> Ordering {
    let (left, right) = (elements(a, options), elements(b, options));
    let primary = left
        .iter()
        .map(|element| &element.primary)
        .cmp(right.iter().map(|element| &element.primary));
    if primary != Ordering::Equal {
        return primary;
    }
    if matches!(
        options.sensitivity,
        Sensitivity::Accent | Sensitivity::Variant
    ) {
        let secondary = left
            .iter()
            .map(|element| &element.secondary)
            .cmp(right.iter().map(|element| &element.secondary));
        if secondary != Ordering::Equal {
            return secondary;
        }
    }
    if matches!(
        options.sensitivity,
        Sensitivity::Case | Sensitivity::Variant
    ) {
        return left
            .iter()
            .map(|element| element.tertiary)
            .cmp(right.iter().map(|element| element.tertiary));
    }
    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sorted(words: &[&str], options: CollationOptions) -> String {
        let mut words: Vec<&str> = words.to_vec();
        words.sort_by(|a, b| locale_compare(a, b, &options));
        words.join(" ")
    }

    // Expected orders and results are Node v22.2.0's (ICU) localeCompare.

    #[test]
    fn root_order_of_letters_digits_and_punctuation() {
        let ascii: String = (32u8..127).map(char::from).collect();
        let ascii: Vec<String> = ascii.chars().map(String::from).collect();
        let refs: Vec<&str> = ascii.iter().map(String::as_str).collect();
        assert_eq!(
            sorted(&refs, CollationOptions::default()).replace(' ', ""),
            "_-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$0123456789aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ"
        );
        assert_eq!(
            sorted(
                &["b", "A", "a", "B", "é", "e", "Z"],
                CollationOptions::default()
            ),
            "a A b B e é Z"
        );
        assert_eq!(
            sorted(
                &[
                    "a b", "a-b", "ab", "a_b", "a.b", "a1", "a10", "a2", "aB", "Ab", "äb", "ab ",
                    "a"
                ],
                CollationOptions::default()
            ),
            "a a b a_b a-b a.b a1 a10 a2 ab aB Ab äb ab "
        );
        assert_eq!(
            sorted(
                &[
                    "ß", "ss", "st", "sr", "æ", "ae", "af", "ø", "o", "p", "œ", "oe", "ł", "l",
                    "m", "ı", "i", "ﬁ", "fi"
                ],
                CollationOptions::default()
            ),
            "ae æ af fi ﬁ i ı l ł m o ø oe œ p sr ss ß st"
        );
        assert_eq!(
            sorted(
                &[
                    "Ω", "α", "ж", "а", "я", "中", "日", "あ", "ア", "z", "Z", "9"
                ],
                CollationOptions::default()
            ),
            "9 z Z α Ω а ж я あ ア 中 日"
        );
    }

    #[test]
    fn equivalence_and_options() {
        let default = CollationOptions::default();
        assert_eq!(locale_compare("a", "a\u{301}", &default), Ordering::Less);
        assert_eq!(
            locale_compare("\u{e9}", "e\u{301}", &default),
            Ordering::Equal
        );
        assert_eq!(locale_compare("x", "", &default), Ordering::Greater);
        assert_eq!(locale_compare("A", "a", &default), Ordering::Greater);
        let numeric = CollationOptions {
            numeric: true,
            ..default
        };
        assert_eq!(
            sorted(&["10", "9", "1", "item10", "item2"], numeric),
            "1 9 10 item2 item10"
        );
        let base = CollationOptions {
            sensitivity: Sensitivity::Base,
            ..default
        };
        let accent = CollationOptions {
            sensitivity: Sensitivity::Accent,
            ..default
        };
        assert_eq!(locale_compare("a", "A", &accent), Ordering::Equal);
        assert_eq!(locale_compare("é", "e", &base), Ordering::Equal);
        assert_eq!(locale_compare("é", "e", &accent), Ordering::Greater);
        let ignore = CollationOptions {
            ignore_punctuation: true,
            ..default
        };
        assert_eq!(locale_compare("a-b", "ab", &ignore), Ordering::Equal);
        assert_eq!(locale_compare("a", "b", &ignore), Ordering::Less);
    }
}
