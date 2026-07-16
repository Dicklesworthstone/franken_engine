//! Runtime string value backing with UTF-16 lone-surrogate support
//! (bd-neika, relocated from `franken-engine` for bd-2vzgi).
//!
//! This module is the single canonical definition of [`JsString`] for both
//! the extracted `franken-core` runtime and the `franken-engine` interpreter
//! (which re-exports it as `frankenengine_engine::js_string`). Keeping one
//! definition below the engine in the dependency graph is what lets the
//! engine ↔ core differential oracle compare lone-surrogate observables
//! exactly instead of through the lossy UTF-8 projection.
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
//! - Runtime heap property maps still use `String` (UTF-8): using a
//!   lone-surrogate string as a property key routes through the lossy
//!   projection. [`ExactPropertyMap`] provides the wire-safe exact-key carrier
//!   for the staged bd-b12xs migration; runtime integration remains a later
//!   child.
//! - `franken-core` quoted source literals now preserve lone-surrogate escapes
//!   exactly through AST/IR lowering (bd-vltnh). The duplicated
//!   `franken-engine` parser/lowering mirror remains a separate landing step;
//!   template-literal quasis are also outside this quoted-literal slice.
//! - Relational ordering: the derived [`Ord`] remains projection-first (with
//!   exact units as tiebreak) for deterministic collections and wire/hash
//!   stability. ES relational semantics — lexicographic over exact UTF-16
//!   code units — are provided separately by [`JsString::utf16_cmp`], which
//!   the engine's relational operators use (bd-rdnhc).

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::Arc;

use crate::deterministic_serde::CanonicalValue;

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

    /// Convert this string to its deterministic canonical representation.
    ///
    /// Well-formed content remains a plain canonical string, preserving the
    /// exact encoding bytes used before [`JsString`] became an AST carrier.
    /// Content with lone surrogates uses the same `$wtf16` tag as serde and
    /// records every exact UTF-16 code unit as an unsigned integer.
    pub fn canonical_value(&self) -> CanonicalValue {
        match &self.units {
            None => CanonicalValue::String(self.utf8.to_string()),
            Some(units) => {
                let mut map = BTreeMap::new();
                map.insert(
                    WTF16_MAP_KEY.to_string(),
                    CanonicalValue::Array(
                        units
                            .iter()
                            .map(|unit| CanonicalValue::U64(u64::from(*unit)))
                            .collect(),
                    ),
                );
                CanonicalValue::Map(map)
            }
        }
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

    /// ES2020 `CodePointAt`: the Unicode code point at UTF-16 code-unit
    /// index `unit_index`. A valid high+low surrogate pair combines into its
    /// supplementary code point; an unpaired surrogate yields its own code
    /// unit value; out of range yields `None`. (bd-rdnhc)
    pub fn code_point_at(&self, unit_index: usize) -> Option<u32> {
        let mut units = self.encode_utf16().skip(unit_index);
        let first = units.next()?;
        if is_high_surrogate(first)
            && let Some(second) = units.next()
            && is_low_surrogate(second)
        {
            let high = u32::from(first) - 0xD800;
            let low = u32::from(second) - 0xDC00;
            return Some(0x10000 + (high << 10) + low);
        }
        Some(u32::from(first))
    }

    /// ES string-iteration elements (the `String.prototype[@@iterator]`
    /// grain used by `for..of`, spread, and `Array.from`): one element per
    /// Unicode code point, with each unpaired surrogate preserved as its own
    /// single-unit element rather than the U+FFFD projection. For well-formed
    /// content this is exactly the per-`char` split. (bd-rdnhc)
    pub fn code_point_elements(&self) -> Vec<JsString> {
        let units = self.code_units_vec();
        let mut elements = Vec::new();
        let mut index = 0;
        while index < units.len() {
            let step = if is_high_surrogate(units[index])
                && index + 1 < units.len()
                && is_low_surrogate(units[index + 1])
            {
                2
            } else {
                1
            };
            elements.push(Self::from_code_units(&units[index..index + step]));
            index += step;
        }
        elements
    }

    /// ES relational order for strings: lexicographic over exact UTF-16 code
    /// units (the string branch of IsLessThan, ES2020 7.2.13). This differs
    /// from the derived [`Ord`] — projection-first with exact units as
    /// tiebreak — which is kept unchanged for deterministic collections and
    /// wire/hash stability. Astral content orders differently under the two:
    /// U+1F600 sorts *below* U+FF5A here (0xD83D < 0xFF5A) but above it under
    /// code-point order. (bd-rdnhc)
    pub fn utf16_cmp(&self, other: &JsString) -> std::cmp::Ordering {
        self.encode_utf16().cmp(other.encode_utf16())
    }

    /// First UTF-16 code-unit index at or after `from` where `needle`'s
    /// exact unit sequence occurs (ES `StringIndexOf`). `from` past the end
    /// clamps to the length; an empty needle matches at the clamped `from`.
    /// A position that splits a surrogate pair is a legal starting offset —
    /// never an error — per ES code-unit semantics. (bd-rdnhc)
    pub fn utf16_index_of(&self, needle: &JsString, from: usize) -> Option<usize> {
        let haystack = self.code_units_vec();
        let needle_units = needle.code_units_vec();
        let from = from.min(haystack.len());
        if needle_units.is_empty() {
            return Some(from);
        }
        if needle_units.len() > haystack.len() {
            return None;
        }
        (from..=haystack.len() - needle_units.len())
            .find(|&index| haystack[index..index + needle_units.len()] == needle_units[..])
    }

    /// Highest UTF-16 code-unit start index at or before `from` where
    /// `needle`'s exact unit sequence occurs (ES `String.prototype.lastIndexOf`
    /// grain). An empty needle matches at `min(from, length)`. (bd-rdnhc)
    pub fn utf16_last_index_of(&self, needle: &JsString, from: usize) -> Option<usize> {
        let haystack = self.code_units_vec();
        let needle_units = needle.code_units_vec();
        if needle_units.is_empty() {
            return Some(from.min(haystack.len()));
        }
        if needle_units.len() > haystack.len() {
            return None;
        }
        let last_start = haystack.len() - needle_units.len();
        let start = from.min(last_start);
        (0..=start)
            .rev()
            .find(|&index| haystack[index..index + needle_units.len()] == needle_units[..])
    }
}

/// UTF-16 high (leading) surrogate range check.
fn is_high_surrogate(unit: u16) -> bool {
    (0xD800..=0xDBFF).contains(&unit)
}

/// UTF-16 low (trailing) surrogate range check.
fn is_low_surrogate(unit: u16) -> bool {
    (0xDC00..=0xDFFF).contains(&unit)
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

/// Deterministic property storage keyed by exact ECMAScript string values.
///
/// JSON object member names cannot carry an unpaired UTF-16 surrogate. This
/// carrier therefore has two self-describing wire shapes:
///
/// - when every key is well formed, it serializes as the historical JSON
///   object map, preserving existing bytes and snapshots;
/// - when any key contains a lone surrogate, it serializes the whole map as a
///   deterministic sequence of `[JsString, value]` pairs, where [`JsString`]
///   uses its exact `$wtf16` representation.
///
/// Deserialization accepts either shape and rejects duplicate exact keys. The
/// dual-shape decoder requires a self-describing serde format, matching the
/// JSON heap/snapshot boundary this type is designed for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactPropertyMap<V> {
    entries: BTreeMap<JsString, V>,
}

impl<V> Default for ExactPropertyMap<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> ExactPropertyMap<V> {
    /// Create an empty exact-key property map.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Return the number of stored entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return whether the map contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return whether `key` is present without projecting its code units.
    pub fn contains_key(&self, key: &JsString) -> bool {
        self.entries.contains_key(key)
    }

    /// Return the value associated with `key` without projecting its code
    /// units.
    pub fn get(&self, key: &JsString) -> Option<&V> {
        self.entries.get(key)
    }

    /// Return a mutable value associated with `key`.
    pub fn get_mut(&mut self, key: &JsString) -> Option<&mut V> {
        self.entries.get_mut(key)
    }

    /// Insert an exact key/value pair, returning the previous value when the
    /// same exact code-unit sequence was already present.
    pub fn insert(&mut self, key: JsString, value: V) -> Option<V> {
        self.entries.insert(key, value)
    }

    /// Remove an exact key/value pair.
    pub fn remove(&mut self, key: &JsString) -> Option<V> {
        self.entries.remove(key)
    }

    /// Iterate entries in deterministic [`JsString`] order.
    pub fn iter(&self) -> std::collections::btree_map::Iter<'_, JsString, V> {
        self.entries.iter()
    }

    /// Iterate keys in deterministic [`JsString`] order.
    pub fn keys(&self) -> std::collections::btree_map::Keys<'_, JsString, V> {
        self.entries.keys()
    }

    /// Iterate values in deterministic key order.
    pub fn values(&self) -> std::collections::btree_map::Values<'_, JsString, V> {
        self.entries.values()
    }

    /// Iterate mutable values in deterministic key order.
    pub fn values_mut(&mut self) -> std::collections::btree_map::ValuesMut<'_, JsString, V> {
        self.entries.values_mut()
    }
}

impl<V> From<BTreeMap<String, V>> for ExactPropertyMap<V> {
    fn from(entries: BTreeMap<String, V>) -> Self {
        Self {
            entries: entries
                .into_iter()
                .map(|(key, value)| (JsString::from(key), value))
                .collect(),
        }
    }
}

impl<V> FromIterator<(JsString, V)> for ExactPropertyMap<V> {
    fn from_iter<T: IntoIterator<Item = (JsString, V)>>(iter: T) -> Self {
        Self {
            entries: iter.into_iter().collect(),
        }
    }
}

impl<'a, V> IntoIterator for &'a ExactPropertyMap<V> {
    type Item = (&'a JsString, &'a V);
    type IntoIter = std::collections::btree_map::Iter<'a, JsString, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

impl<V: Serialize> Serialize for ExactPropertyMap<V> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.entries.keys().all(JsString::is_well_formed) {
            use serde::ser::Error as _;
            use serde::ser::SerializeMap as _;

            let mut map = serializer.serialize_map(Some(self.entries.len()))?;
            for (key, value) in &self.entries {
                let key = key.as_str().ok_or_else(|| {
                    S::Error::custom("well-formed property key has no exact str view")
                })?;
                map.serialize_entry(key, value)?;
            }
            map.end()
        } else {
            use serde::ser::SerializeSeq as _;

            let mut pairs = serializer.serialize_seq(Some(self.entries.len()))?;
            for pair in &self.entries {
                pairs.serialize_element(&pair)?;
            }
            pairs.end()
        }
    }
}

impl<'de, V: Deserialize<'de>> Deserialize<'de> for ExactPropertyMap<V> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ExactPropertyMapVisitor<V>(PhantomData<fn() -> V>);

        impl<'de, V: Deserialize<'de>> Visitor<'de> for ExactPropertyMapVisitor<V> {
            type Value = ExactPropertyMap<V>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string-keyed property map or an exact JsString/value pair sequence")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut entries = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, V>()? {
                    let key = JsString::from(key);
                    match entries.entry(key) {
                        std::collections::btree_map::Entry::Occupied(_) => {
                            return Err(de::Error::custom(
                                "duplicate property key in exact property map",
                            ));
                        }
                        std::collections::btree_map::Entry::Vacant(entry) => {
                            entry.insert(value);
                        }
                    }
                }
                Ok(ExactPropertyMap { entries })
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut entries = BTreeMap::new();
                while let Some((key, value)) = sequence.next_element::<(JsString, V)>()? {
                    match entries.entry(key) {
                        std::collections::btree_map::Entry::Occupied(_) => {
                            return Err(de::Error::custom(
                                "duplicate property key in exact property map",
                            ));
                        }
                        std::collections::btree_map::Entry::Vacant(entry) => {
                            entry.insert(value);
                        }
                    }
                }
                Ok(ExactPropertyMap { entries })
            }
        }

        deserializer.deserialize_any(ExactPropertyMapVisitor::<V>(PhantomData))
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
    fn canonical_well_formed_encoding_preserves_plain_string_bytes() {
        let string = JsString::from("a\u{1F600}b");
        let historical = CanonicalValue::String("a\u{1F600}b".to_string());

        assert_eq!(string.canonical_value(), historical);
        assert_eq!(
            crate::deterministic_serde::encode_value(&string.canonical_value()),
            crate::deterministic_serde::encode_value(&historical)
        );
    }

    #[test]
    fn canonical_encoding_distinguishes_lone_surrogate_units() {
        let high_d800 = JsString::from_code_units(&[0xD800]);
        let high_d801 = JsString::from_code_units(&[0xD801]);

        let canonical_d800 = high_d800.canonical_value();
        let canonical_d801 = high_d801.canonical_value();
        let mut expected_d800 = BTreeMap::new();
        expected_d800.insert(
            "$wtf16".to_string(),
            CanonicalValue::Array(vec![CanonicalValue::U64(0xD800)]),
        );
        assert_eq!(canonical_d800, CanonicalValue::Map(expected_d800));
        assert_eq!(
            crate::deterministic_serde::encode_value(&canonical_d800),
            vec![
                0x07, 0, 0, 0, 1, // map with one entry
                0, 0, 0, 6, b'$', b'w', b't', b'f', b'1', b'6', 0x06, 0, 0, 0,
                1, // array with one entry
                0x01, 0, 0, 0, 0, 0, 0, 0xD8, 0,
            ]
        );
        assert_ne!(canonical_d800, canonical_d801);
        assert_ne!(
            crate::deterministic_serde::encode_value(&canonical_d800),
            crate::deterministic_serde::encode_value(&canonical_d801)
        );
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
    fn exact_property_map_preserves_legacy_well_formed_json_bytes() {
        let legacy = BTreeMap::from([("b".to_string(), 2_u32), ("a".to_string(), 1_u32)]);
        let exact = ExactPropertyMap::from(legacy.clone());

        let legacy_json = serde_json::to_string(&legacy).expect("serialize legacy property map");
        let exact_json = serde_json::to_string(&exact).expect("serialize exact property map");
        assert_eq!(legacy_json, r#"{"a":1,"b":2}"#);
        assert_eq!(exact_json, legacy_json);

        let restored: ExactPropertyMap<u32> =
            serde_json::from_str(&legacy_json).expect("deserialize legacy object shape");
        assert_eq!(restored, exact);
    }

    #[test]
    fn exact_property_map_lone_surrogates_use_deterministic_pair_sequence() {
        let high_d800 = JsString::from_code_units(&[0xD800]);
        let high_d801 = JsString::from_code_units(&[0xD801]);
        let mut properties = ExactPropertyMap::new();
        properties.insert(high_d801.clone(), 2_u32);
        properties.insert(JsString::from("plain"), 3_u32);
        properties.insert(high_d800.clone(), 1_u32);

        let json = serde_json::to_string(&properties).expect("serialize exact property map");
        assert_eq!(
            json,
            r#"[["plain",3],[{"$wtf16":[55296]},1],[{"$wtf16":[55297]},2]]"#
        );

        let restored: ExactPropertyMap<u32> =
            serde_json::from_str(&json).expect("deserialize exact pair sequence");
        assert_eq!(restored, properties);
        assert_eq!(restored.get(&high_d800), Some(&1));
        assert_eq!(restored.get(&high_d801), Some(&2));
    }

    #[test]
    fn exact_property_map_accepts_pair_sequence_with_well_formed_keys() {
        let restored: ExactPropertyMap<u32> =
            serde_json::from_str(r#"[["b",2],["a",1]]"#).expect("deserialize pair sequence");
        assert_eq!(restored.get(&JsString::from("a")), Some(&1));
        assert_eq!(restored.get(&JsString::from("b")), Some(&2));
        assert_eq!(
            serde_json::to_string(&restored).expect("canonicalize well-formed map"),
            r#"{"a":1,"b":2}"#
        );
    }

    #[test]
    fn exact_property_map_rejects_duplicate_keys_in_both_wire_shapes() {
        let duplicate_object = serde_json::from_str::<ExactPropertyMap<u32>>(r#"{"a":1,"a":2}"#)
            .expect_err("duplicate object keys must fail closed");
        assert!(
            duplicate_object
                .to_string()
                .contains("duplicate property key in exact property map")
        );

        let duplicate_sequence = serde_json::from_str::<ExactPropertyMap<u32>>(
            r#"[[{"$wtf16":[55296]},1],[{"$wtf16":[55296]},2]]"#,
        )
        .expect_err("duplicate exact keys must fail closed");
        assert!(
            duplicate_sequence
                .to_string()
                .contains("duplicate property key in exact property map")
        );

        let duplicate_after_normalization =
            serde_json::from_str::<ExactPropertyMap<u32>>(r#"[["a",1],[{"$wtf16":[97]},2]]"#)
                .expect_err("non-canonical exact key aliases must fail closed");
        assert!(
            duplicate_after_normalization
                .to_string()
                .contains("duplicate property key in exact property map")
        );
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

    // --- ES-semantics helpers (bd-rdnhc) ----------------------------------

    #[test]
    fn code_point_at_is_unit_indexed_and_combines_pairs() {
        let s = JsString::from("a\u{1F600}b"); // units [61, D83D, DE00, 62]
        assert_eq!(s.code_point_at(0), Some(0x61));
        assert_eq!(s.code_point_at(1), Some(0x1F600));
        assert_eq!(s.code_point_at(2), Some(u32::from(LOW)));
        assert_eq!(s.code_point_at(3), Some(0x62));
        assert_eq!(s.code_point_at(4), None);
    }

    #[test]
    fn code_point_at_lone_surrogate_yields_its_own_unit_value() {
        let s = JsString::from_code_units(&[0x61, HIGH]);
        assert_eq!(s.code_point_at(1), Some(u32::from(HIGH)));
        let t = JsString::from_code_units(&[LOW, 0x62]);
        assert_eq!(t.code_point_at(0), Some(u32::from(LOW)));
    }

    #[test]
    fn code_point_elements_split_well_formed_content_per_char() {
        let s = JsString::from("a\u{1F600}b");
        let elements = s.code_point_elements();
        assert_eq!(
            elements,
            vec![
                JsString::from("a"),
                JsString::from("\u{1F600}"),
                JsString::from("b")
            ]
        );
    }

    #[test]
    fn code_point_elements_preserve_lone_surrogates_exactly() {
        // [HIGH, HIGH, LOW]: first HIGH is unpaired, second pair heals.
        let s = JsString::from_code_units(&[HIGH, HIGH, LOW]);
        let elements = s.code_point_elements();
        assert_eq!(elements.len(), 2);
        assert_eq!(elements[0].code_units_vec(), vec![HIGH]);
        assert!(!elements[0].is_well_formed());
        assert_eq!(elements[1], JsString::from("\u{1F600}"));
    }

    #[test]
    fn utf16_cmp_orders_astral_below_high_bmp() {
        // ES code-unit order: U+1F600 starts with 0xD83D which sorts below
        // U+FF5A; code-point (derived Ord) order says the opposite.
        let astral = JsString::from("\u{1F600}");
        let high_bmp = JsString::from("\u{FF5A}");
        assert_eq!(astral.utf16_cmp(&high_bmp), std::cmp::Ordering::Less);
        assert_eq!(high_bmp.utf16_cmp(&astral), std::cmp::Ordering::Greater);
        assert!(astral.cmp(&high_bmp) == std::cmp::Ordering::Greater);
    }

    #[test]
    fn utf16_cmp_orders_lone_surrogates_by_exact_unit() {
        // Under the projection both sides render U+FFFD; the exact units
        // must decide. 0xD800 < 0xE000 in code-unit space even though the
        // projection of the lone surrogate (U+FFFD) sorts above U+E000.
        let lone = JsString::from_code_units(&[0xD800]);
        let private_use = JsString::from("\u{E000}");
        assert_eq!(lone.utf16_cmp(&private_use), std::cmp::Ordering::Less);
        assert_eq!(
            JsString::from_code_units(&[0xD800]).utf16_cmp(&JsString::from_code_units(&[0xD801])),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn utf16_index_of_uses_code_unit_offsets() {
        let s = JsString::from("a\u{1F600}b"); // units [61, D83D, DE00, 62]
        assert_eq!(s.utf16_index_of(&JsString::from("b"), 0), Some(3));
        assert_eq!(s.utf16_index_of(&JsString::from("a"), 1), None);
        // A `from` that splits the surrogate pair is a legal offset.
        assert_eq!(s.utf16_index_of(&JsString::from("b"), 2), Some(3));
        // A lone-surrogate needle matches the exact unit, not the projection.
        assert_eq!(
            s.utf16_index_of(&JsString::from_code_units(&[HIGH]), 0),
            Some(1)
        );
    }

    #[test]
    fn utf16_index_of_empty_needle_matches_at_clamped_from() {
        let s = JsString::from("abc");
        assert_eq!(s.utf16_index_of(&JsString::empty(), 0), Some(0));
        assert_eq!(s.utf16_index_of(&JsString::empty(), 99), Some(3));
        assert_eq!(
            JsString::empty().utf16_index_of(&JsString::from("x"), 0),
            None
        );
    }

    #[test]
    fn utf16_last_index_of_finds_highest_start_at_or_before_from() {
        let s = JsString::from("abab");
        let needle = JsString::from("ab");
        assert_eq!(s.utf16_last_index_of(&needle, 99), Some(2));
        assert_eq!(s.utf16_last_index_of(&needle, 1), Some(0));
        assert_eq!(s.utf16_last_index_of(&JsString::from("z"), 99), None);
        assert_eq!(s.utf16_last_index_of(&JsString::empty(), 99), Some(4));
        let astral = JsString::from("\u{1F600}\u{1F600}");
        assert_eq!(
            astral.utf16_last_index_of(&JsString::from_code_units(&[LOW]), 99),
            Some(3)
        );
    }
}
