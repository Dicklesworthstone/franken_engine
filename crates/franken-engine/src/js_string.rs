//! Engine string value backing with UTF-16 lone-surrogate support (bd-neika).
//!
//! ECMAScript strings are sequences of UTF-16 code units, including unpaired
//! ("lone") surrogates. The interpreter previously stored string values as
//! `Arc<str>` (valid UTF-8 only), which cannot represent a lone surrogate:
//! `"😀".charAt(0)` was forced to the U+FFFD lossy projection,
//! `String.fromCharCode(0xD83D)` degraded to NUL, and JSON round-trips of
//! lone surrogates were impossible.
//!
//! [`JsString`] closes that gap with a dual representation:
//!
//! - `utf8` is always present. For well-formed strings it is the exact
//!   content; for strings containing lone surrogates it is the
//!   `String::from_utf16_lossy` projection (each lone surrogate rendered as
//!   U+FFFD). [`Deref`]`<Target = str>`, [`fmt::Display`], and `AsRef<str>`
//!   expose this projection, so byte-oriented and display-oriented callers
//!   keep the exact pre-existing behaviour for well-formed strings.
//! - `units` carries the exact UTF-16 code units and is populated **iff**
//!   the sequence contains at least one unpaired surrogate (the canonical
//!   invariant). Exact-semantics callers use [`JsString::encode_utf16`] /
//!   [`JsString::code_units_vec`]. Because the inherent `encode_utf16`
//!   shadows `str::encode_utf16` reached through `Deref`, existing
//!   UTF-16-indexing call sites observe exact code units automatically.
//!
//! # Canonical invariant
//!
//! `units.is_some()` ⇔ the logical string contains ≥ 1 lone surrogate, and
//! then `utf8 == String::from_utf16_lossy(units)`. Constructors enforce this
//! ([`JsString::from_code_units`] re-checks well-formedness, which also means
//! an adjacent high+low surrogate pair produced by concatenation *heals* into
//! the supplementary code point, per ES string-concatenation semantics).
//!
//! Under the invariant the derived `PartialEq`/`Eq`/`Ord` are semantically
//! correct and deterministic: a well-formed string can never equal a string
//! holding a lone surrogate (their `units` fields differ), and two
//! lone-surrogate strings compare by projection first with the exact units as
//! tiebreak. For well-formed strings, ordering and equality are exactly the
//! previous `Arc<str>` byte semantics, so no existing content hash, golden,
//! or sort order changes.
//!
//! # Serialization
//!
//! Well-formed strings serialize as plain strings — byte-identical to the
//! previous `Arc<str>` wire format, preserving every existing artifact hash.
//! Lone-surrogate strings serialize as a single-entry map
//! `{"$wtf16": [code units...]}`, which keeps distinct lone-surrogate strings
//! distinct on the wire (hash injectivity) while remaining unambiguous to
//! deserialize in self-describing formats.
//!
//! # Known boundaries (documented, fail-safe)
//!
//! - Object property keys remain `String` (UTF-8): using a lone-surrogate
//!   string as a property key routes through the lossy projection.
//! - Source-literal lone-surrogate escapes (`"\uD800"`) remain fail-closed in
//!   the parser; paired escapes already heal (bd-k9jb0).
//! - Relational ordering for strings remains code-point/byte order (the
//!   pre-existing, documented divergence from ES UTF-16 code-unit order for
//!   astral content is unchanged by this module).

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::ops::Deref;
use std::sync::Arc;

/// Serde map key marking the exact-code-unit payload of a string that
/// contains lone surrogates. Well-formed strings serialize as plain strings.
const WTF16_MAP_KEY: &str = "$wtf16";

/// Interpreter string payload: UTF-8 fast path plus exact UTF-16 code units
/// when (and only when) the content contains a lone surrogate.
///
/// See the module docs for the canonical invariant and the equality /
/// ordering / serialization contracts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct JsString {
    /// UTF-8 projection. Exact when `units` is `None`; the
    /// `String::from_utf16_lossy` projection otherwise.
    utf8: Arc<str>,
    /// Exact UTF-16 code units, present iff the content contains at least
    /// one unpaired surrogate.
    units: Option<Arc<[u16]>>,
}

impl JsString {
    /// The empty string.
    pub fn empty() -> Self {
        Self {
            utf8: Arc::from(""),
            units: None,
        }
    }

    /// Build from exact UTF-16 code units, enforcing the canonical
    /// invariant. Adjacent high+low surrogate units combine into their
    /// supplementary code point (concatenation healing); only genuinely
    /// unpaired surrogates cause the exact-unit backing to be retained.
    pub fn from_code_units(units: &[u16]) -> Self {
        match String::from_utf16(units) {
            Ok(text) => Self {
                utf8: Arc::from(text),
                units: None,
            },
            Err(_) => Self {
                utf8: Arc::from(String::from_utf16_lossy(units)),
                units: Some(Arc::from(units)),
            },
        }
    }

    /// True when the content is well-formed UTF-16 (no lone surrogates), in
    /// which case the UTF-8 projection is exact.
    pub fn is_well_formed(&self) -> bool {
        self.units.is_none()
    }

    /// Exact `&str` view, available only for well-formed content. Callers
    /// that can tolerate the U+FFFD projection should use [`Deref`] /
    /// [`JsString::as_utf8_projection`] instead.
    pub fn as_str(&self) -> Option<&str> {
        match self.units {
            None => Some(&self.utf8),
            Some(_) => None,
        }
    }

    /// The UTF-8 projection: exact for well-formed content, lossy
    /// (lone surrogates → U+FFFD) otherwise.
    pub fn as_utf8_projection(&self) -> &str {
        &self.utf8
    }

    /// Exact UTF-16 code units.
    ///
    /// This inherent method intentionally shadows `str::encode_utf16`
    /// reachable through `Deref`, so UTF-16-indexing call sites observe the
    /// real code units (including lone surrogates) rather than the lossy
    /// projection's units.
    pub fn encode_utf16(&self) -> CodeUnits<'_> {
        CodeUnits {
            inner: match &self.units {
                None => CodeUnitsInner::WellFormed(self.utf8.encode_utf16()),
                Some(units) => CodeUnitsInner::Exact(units.iter().copied()),
            },
        }
    }

    /// Exact UTF-16 code units, collected.
    pub fn code_units_vec(&self) -> Vec<u16> {
        self.encode_utf16().collect()
    }

    /// The ECMAScript `length` of the string: its UTF-16 code-unit count.
    pub fn utf16_len(&self) -> usize {
        match &self.units {
            Some(units) => units.len(),
            None => self.utf8.encode_utf16().count(),
        }
    }

    /// ES string concatenation over exact code units. When both operands are
    /// well-formed this is a plain UTF-8 concatenation (the pre-existing fast
    /// path); otherwise the exact unit sequences are joined and re-normalized,
    /// which heals a trailing high surrogate against a leading low surrogate
    /// into the supplementary code point.
    pub fn concat(&self, other: &JsString) -> JsString {
        if self.units.is_none() && other.units.is_none() {
            let mut text = String::with_capacity(self.utf8.len() + other.utf8.len());
            text.push_str(&self.utf8);
            text.push_str(&other.utf8);
            return Self {
                utf8: Arc::from(text),
                units: None,
            };
        }
        let mut units: Vec<u16> = Vec::with_capacity(self.utf16_len() + other.utf16_len());
        units.extend(self.encode_utf16());
        units.extend(other.encode_utf16());
        Self::from_code_units(&units)
    }
}

impl Default for JsString {
    fn default() -> Self {
        Self::empty()
    }
}

impl Deref for JsString {
    type Target = str;

    fn deref(&self) -> &str {
        &self.utf8
    }
}

impl AsRef<str> for JsString {
    fn as_ref(&self) -> &str {
        &self.utf8
    }
}

impl fmt::Display for JsString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.utf8)
    }
}

impl From<&str> for JsString {
    fn from(value: &str) -> Self {
        Self {
            utf8: Arc::from(value),
            units: None,
        }
    }
}

impl From<String> for JsString {
    fn from(value: String) -> Self {
        Self {
            utf8: Arc::from(value),
            units: None,
        }
    }
}

impl From<Arc<str>> for JsString {
    fn from(value: Arc<str>) -> Self {
        Self {
            utf8: value,
            units: None,
        }
    }
}

impl From<char> for JsString {
    fn from(value: char) -> Self {
        Self {
            utf8: Arc::from(value.to_string()),
            units: None,
        }
    }
}

impl From<&String> for JsString {
    fn from(value: &String) -> Self {
        Self {
            utf8: Arc::from(value.as_str()),
            units: None,
        }
    }
}

impl PartialEq<str> for JsString {
    fn eq(&self, other: &str) -> bool {
        self.units.is_none() && *self.utf8 == *other
    }
}

impl PartialEq<&str> for JsString {
    fn eq(&self, other: &&str) -> bool {
        self.units.is_none() && *self.utf8 == **other
    }
}

/// Iterator over the exact UTF-16 code units of a [`JsString`].
#[derive(Clone)]
pub struct CodeUnits<'a> {
    inner: CodeUnitsInner<'a>,
}

#[derive(Clone)]
enum CodeUnitsInner<'a> {
    WellFormed(std::str::EncodeUtf16<'a>),
    Exact(std::iter::Copied<std::slice::Iter<'a, u16>>),
}

impl Iterator for CodeUnits<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<u16> {
        match &mut self.inner {
            CodeUnitsInner::WellFormed(iter) => iter.next(),
            CodeUnitsInner::Exact(iter) => iter.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.inner {
            CodeUnitsInner::WellFormed(iter) => iter.size_hint(),
            CodeUnitsInner::Exact(iter) => iter.size_hint(),
        }
    }
}

impl fmt::Debug for CodeUnits<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CodeUnits(..)")
    }
}

impl Serialize for JsString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self.units {
            None => serializer.serialize_str(&self.utf8),
            Some(units) => {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry(WTF16_MAP_KEY, units.as_ref())?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for JsString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct JsStringVisitor;

        impl<'de> Visitor<'de> for JsStringVisitor {
            type Value = JsString;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    "a string, or a {\"$wtf16\": [code units]} map for lone-surrogate content",
                )
            }

            fn visit_str<E>(self, value: &str) -> Result<JsString, E>
            where
                E: de::Error,
            {
                Ok(JsString::from(value))
            }

            fn visit_string<E>(self, value: String) -> Result<JsString, E>
            where
                E: de::Error,
            {
                Ok(JsString::from(value))
            }

            fn visit_map<A>(self, mut map: A) -> Result<JsString, A::Error>
            where
                A: MapAccess<'de>,
            {
                let Some(key) = map.next_key::<String>()? else {
                    return Err(de::Error::custom(
                        "expected exactly one \"$wtf16\" entry, found an empty map",
                    ));
                };
                if key != WTF16_MAP_KEY {
                    return Err(de::Error::custom(format!(
                        "unexpected key {key:?}; expected \"$wtf16\""
                    )));
                }
                let units: Vec<u16> = map.next_value()?;
                if map.next_key::<String>()?.is_some() {
                    return Err(de::Error::custom(
                        "expected exactly one \"$wtf16\" entry, found extra keys",
                    ));
                }
                // from_code_units re-normalizes, so a map claiming lone
                // surrogates for well-formed content deserializes to the
                // canonical well-formed representation rather than a
                // non-canonical value.
                Ok(JsString::from_code_units(&units))
            }
        }

        deserializer.deserialize_any(JsStringVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HIGH: u16 = 0xD83D;
    const LOW: u16 = 0xDE00;

    #[test]
    fn well_formed_from_str_has_no_units() {
        let s = JsString::from("hello");
        assert!(s.is_well_formed());
        assert_eq!(s.as_str(), Some("hello"));
        assert_eq!(s.as_utf8_projection(), "hello");
    }

    #[test]
    fn empty_and_default_agree() {
        assert_eq!(JsString::empty(), JsString::default());
        assert!(JsString::empty().is_well_formed());
        assert_eq!(JsString::empty().utf16_len(), 0);
    }

    #[test]
    fn from_code_units_well_formed_normalizes_to_utf8_backing() {
        let s = JsString::from_code_units(&[0x0068, 0x0069]);
        assert!(s.is_well_formed());
        assert_eq!(s.as_str(), Some("hi"));
    }

    #[test]
    fn from_code_units_surrogate_pair_heals_to_supplementary() {
        let s = JsString::from_code_units(&[HIGH, LOW]);
        assert!(s.is_well_formed());
        assert_eq!(s.as_str(), Some("\u{1F600}"));
        assert_eq!(s.code_units_vec(), vec![HIGH, LOW]);
    }

    #[test]
    fn from_code_units_lone_high_surrogate_keeps_exact_units() {
        let s = JsString::from_code_units(&[HIGH]);
        assert!(!s.is_well_formed());
        assert_eq!(s.as_str(), None);
        assert_eq!(s.code_units_vec(), vec![HIGH]);
        assert_eq!(s.as_utf8_projection(), "\u{FFFD}");
    }

    #[test]
    fn from_code_units_lone_low_surrogate_keeps_exact_units() {
        let s = JsString::from_code_units(&[LOW]);
        assert!(!s.is_well_formed());
        assert_eq!(s.code_units_vec(), vec![LOW]);
        assert_eq!(s.as_utf8_projection(), "\u{FFFD}");
    }

    #[test]
    fn from_code_units_mixed_content_projects_each_lone_surrogate() {
        let units = [0x0061, HIGH, 0x0062];
        let s = JsString::from_code_units(&units);
        assert!(!s.is_well_formed());
        assert_eq!(s.as_utf8_projection(), "a\u{FFFD}b");
        assert_eq!(s.code_units_vec(), units.to_vec());
    }

    #[test]
    fn surrogate_block_boundaries_are_not_surrogates() {
        // U+D7FF and U+E000 flank the surrogate block; both are ordinary
        // BMP scalars and must stay on the well-formed fast path.
        let s = JsString::from_code_units(&[0xD7FF, 0xE000]);
        assert!(s.is_well_formed());
        assert_eq!(s.code_units_vec(), vec![0xD7FF, 0xE000]);
    }

    #[test]
    fn inherent_encode_utf16_returns_exact_units_not_projection_units() {
        let s = JsString::from_code_units(&[HIGH]);
        let exact: Vec<u16> = s.encode_utf16().collect();
        assert_eq!(exact, vec![HIGH]);
        // The Deref'd str view projects to U+FFFD instead.
        let projected: Vec<u16> = str::encode_utf16(&s).collect();
        assert_eq!(projected, vec![0xFFFD]);
    }

    #[test]
    fn utf16_len_counts_code_units_for_both_representations() {
        assert_eq!(JsString::from("\u{1F600}").utf16_len(), 2);
        assert_eq!(JsString::from_code_units(&[HIGH]).utf16_len(), 1);
        assert_eq!(JsString::from_code_units(&[0x61, LOW, 0x62]).utf16_len(), 3);
    }

    #[test]
    fn deref_exposes_projection_for_byte_oriented_callers() {
        let s = JsString::from_code_units(&[HIGH]);
        // U+FFFD is three UTF-8 bytes — same width a WTF-8 surrogate
        // encoding would occupy.
        assert_eq!(s.len(), 3);
        assert!(!s.is_empty());
    }

    #[test]
    fn display_uses_projection() {
        let s = JsString::from_code_units(&[0x61, HIGH]);
        assert_eq!(format!("{s}"), "a\u{FFFD}");
        assert_eq!(format!("{}", JsString::from("plain")), "plain");
    }

    #[test]
    fn equality_well_formed_matches_str_semantics() {
        assert_eq!(JsString::from("abc"), JsString::from(String::from("abc")));
        assert_ne!(JsString::from("abc"), JsString::from("abd"));
        assert_eq!(JsString::from("abc"), "abc");
        assert_eq!(JsString::from("abc"), *"abc");
    }

    #[test]
    fn lone_surrogate_never_equals_its_lossy_projection() {
        let lone = JsString::from_code_units(&[HIGH]);
        let projected = JsString::from("\u{FFFD}");
        assert_eq!(lone.as_utf8_projection(), projected.as_utf8_projection());
        assert_ne!(lone, projected);
        assert_ne!(lone, "\u{FFFD}");
    }

    #[test]
    fn distinct_lone_surrogates_are_distinct() {
        let a = JsString::from_code_units(&[0xD800]);
        let b = JsString::from_code_units(&[0xD801]);
        assert_eq!(a.as_utf8_projection(), b.as_utf8_projection());
        assert_ne!(a, b);
        assert_ne!(a.cmp(&b), std::cmp::Ordering::Equal);
    }

    #[test]
    fn ordering_for_well_formed_matches_previous_byte_order() {
        let mut values = [
            JsString::from("b"),
            JsString::from("a"),
            JsString::from("ab"),
        ];
        values.sort();
        let sorted: Vec<&str> = values.iter().map(|v| v.as_utf8_projection()).collect();
        assert_eq!(sorted, vec!["a", "ab", "b"]);
    }

    #[test]
    fn ordering_is_total_and_deterministic_across_representations() {
        let lone = JsString::from_code_units(&[HIGH]);
        let projected = JsString::from("\u{FFFD}");
        // Same projection: the well-formed value sorts first (None < Some),
        // and the order is antisymmetric.
        assert_eq!(projected.cmp(&lone), std::cmp::Ordering::Less);
        assert_eq!(lone.cmp(&projected), std::cmp::Ordering::Greater);
        assert_eq!(lone.cmp(&lone.clone()), std::cmp::Ordering::Equal);
    }

    #[test]
    fn concat_well_formed_fast_path() {
        let joined = JsString::from("foo").concat(&JsString::from("bar"));
        assert!(joined.is_well_formed());
        assert_eq!(joined.as_str(), Some("foobar"));
    }

    #[test]
    fn concat_heals_split_surrogate_pair() {
        let high = JsString::from_code_units(&[HIGH]);
        let low = JsString::from_code_units(&[LOW]);
        let healed = high.concat(&low);
        assert!(healed.is_well_formed());
        assert_eq!(healed.as_str(), Some("\u{1F600}"));
        assert_eq!(healed, JsString::from("\u{1F600}"));
    }

    #[test]
    fn concat_preserves_unhealed_lone_surrogates() {
        let low = JsString::from_code_units(&[LOW]);
        let high = JsString::from_code_units(&[HIGH]);
        // Low followed by high does NOT form a valid pair.
        let joined = low.concat(&high);
        assert!(!joined.is_well_formed());
        assert_eq!(joined.code_units_vec(), vec![LOW, HIGH]);
    }

    #[test]
    fn concat_mixed_wellformed_and_surrogate_operands() {
        let prefix = JsString::from("a");
        let lone = JsString::from_code_units(&[HIGH]);
        let joined = prefix.concat(&lone);
        assert!(!joined.is_well_formed());
        assert_eq!(joined.code_units_vec(), vec![0x61, HIGH]);
        assert_eq!(joined.as_utf8_projection(), "a\u{FFFD}");
    }

    #[test]
    fn concat_heals_across_wellformed_boundary_only_when_pairable() {
        // "a" + high surrogate, then + low surrogate: the second concat
        // heals the trailing high against the leading low.
        let left = JsString::from("a").concat(&JsString::from_code_units(&[HIGH]));
        let healed = left.concat(&JsString::from_code_units(&[LOW]));
        assert!(healed.is_well_formed());
        assert_eq!(healed.as_str(), Some("a\u{1F600}"));
    }

    #[test]
    fn serde_well_formed_wire_format_is_a_plain_string() {
        let s = JsString::from("hello");
        let json = serde_json::to_string(&s).expect("serialize");
        // Byte-identical to the previous Arc<str> wire format.
        assert_eq!(json, "\"hello\"");
        let back: JsString = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, s);
    }

    #[test]
    fn serde_lone_surrogate_round_trips_exactly() {
        let s = JsString::from_code_units(&[0x61, HIGH, 0x62]);
        let json = serde_json::to_string(&s).expect("serialize");
        assert_eq!(json, "{\"$wtf16\":[97,55357,98]}");
        let back: JsString = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, s);
        assert_eq!(back.code_units_vec(), vec![0x61, HIGH, 0x62]);
    }

    #[test]
    fn serde_distinct_lone_surrogates_have_distinct_wire_bytes() {
        let a = serde_json::to_vec(&JsString::from_code_units(&[0xD800])).expect("a");
        let b = serde_json::to_vec(&JsString::from_code_units(&[0xD801])).expect("b");
        assert_ne!(a, b);
    }

    #[test]
    fn serde_map_claiming_well_formed_units_normalizes_canonically() {
        // An adversarial/foreign encoder that wraps well-formed content in
        // the $wtf16 form must not produce a non-canonical value.
        let back: JsString = serde_json::from_str("{\"$wtf16\":[104,105]}").expect("deserialize");
        assert!(back.is_well_formed());
        assert_eq!(back, JsString::from("hi"));
    }

    #[test]
    fn serde_rejects_unknown_map_keys() {
        let err = serde_json::from_str::<JsString>("{\"$other\":[1]}");
        assert!(err.is_err());
        let err = serde_json::from_str::<JsString>("{\"$wtf16\":[1],\"x\":2}");
        assert!(err.is_err());
    }

    #[test]
    fn from_conversions_agree() {
        let owned = String::from("x");
        assert_eq!(JsString::from(owned.clone()), JsString::from("x"));
        assert_eq!(JsString::from(&owned), JsString::from("x"));
        assert_eq!(JsString::from(Arc::<str>::from("x")), JsString::from("x"));
        assert_eq!(JsString::from('x'), JsString::from("x"));
    }

    #[test]
    fn clone_is_cheap_and_equal() {
        let s = JsString::from_code_units(&[0x61, HIGH]);
        let t = s.clone();
        assert_eq!(s, t);
        assert_eq!(t.code_units_vec(), vec![0x61, HIGH]);
    }

    #[test]
    fn code_units_iterator_size_hint_is_exact_for_unit_backing() {
        let s = JsString::from_code_units(&[HIGH, HIGH, LOW]);
        // HIGH followed by HIGH does not pair; HIGH+LOW at the tail heals,
        // so this content still contains a lone surrogate and keeps units.
        assert!(!s.is_well_formed());
        let iter = s.encode_utf16();
        assert_eq!(iter.size_hint(), (3, Some(3)));
        assert_eq!(iter.count(), 3);
    }

    #[test]
    fn interior_pair_and_lone_tail_normalize_correctly() {
        // Pair heals even when followed by a lone surrogate elsewhere.
        let s = JsString::from_code_units(&[HIGH, LOW, HIGH]);
        assert!(!s.is_well_formed());
        assert_eq!(s.code_units_vec(), vec![HIGH, LOW, HIGH]);
        assert_eq!(s.as_utf8_projection(), "\u{1F600}\u{FFFD}");
    }
}
