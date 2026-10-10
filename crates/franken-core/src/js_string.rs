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
//!   keep the exact pre-existing behaviour for well-formed strings. A long
//!   concatenation of well-formed strings keeps its two parts and joins
//!   their bytes on first read (bd-9vouw.468); [`JsString::len`],
//!   [`JsString::utf16_len`] and memory estimates
//!   ([`JsString::retained_bytes`]) do not join it.
//! - `shape` is `Exact(units)`, the exact UTF-16 code units, **iff** the
//!   sequence contains at least one unpaired surrogate (the canonical
//!   invariant), and otherwise `WellFormed { utf16_len }`: the UTF-16 length,
//!   counted once when the string is built, so `length` and indexing do not
//!   rescan the text (bd-9vouw.467). Exact-semantics callers use
//!   [`JsString::encode_utf16`] / [`JsString::code_units_vec`]. Because the
//!   inherent `encode_utf16` shadows `str::encode_utf16` reached through
//!   `Deref`, existing UTF-16-indexing call sites observe exact code units
//!   automatically.
//!
//! # Canonical invariant
//!
//! `shape` is `Exact(units)` ⇔ the logical string contains ≥ 1 lone
//! surrogate, and then `utf8 == String::from_utf16_lossy(units)`; otherwise
//! it is `WellFormed` with `utf8`'s UTF-16 length. Constructors enforce this
//! ([`JsString::from_code_units`] re-checks well-formedness, which also means
//! an adjacent high+low surrogate pair produced by concatenation *heals* into
//! the supplementary code point, per ES string-concatenation semantics).
//!
//! Under the invariant the derived `PartialEq`/`Eq`/`Ord` are semantically
//! correct and deterministic (the UTF-8 bytes compare by content whether
//! they are one buffer or a concatenation): a well-formed string can never
//! equal a string holding a lone surrogate (their `shape` fields differ), and two
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
//! - `franken-core` and `franken-engine` quoted source literals now preserve
//!   lone-surrogate escapes exactly through AST/IR lowering (bd-vltnh).
//!   Template-literal quasis and exact module-specifier metadata remain
//!   separate compatibility boundaries.
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
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use crate::deterministic_serde::CanonicalValue;

/// Serde map key marking the exact-code-unit payload of a string that
/// contains lone surrogates. Well-formed strings serialize as plain strings.
const WTF16_MAP_KEY: &str = "$wtf16";

/// Interpreter string payload: UTF-8 fast path plus exact UTF-16 code units
/// when (and only when) the content contains a lone surrogate.
///
/// See the module docs for the canonical invariant and the equality /
/// ordering / serialization contracts.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct JsString {
    /// UTF-8 projection. Exact when `shape` is `WellFormed`; the
    /// `String::from_utf16_lossy` projection otherwise.
    utf8: Text,
    shape: Shape,
}

// Value stays 40 bytes only while JsString stays 32.
const _: () = assert!(std::mem::size_of::<JsString>() == 32);

/// Concatenations shorter than this many UTF-8 bytes are copied into one
/// buffer; so is an append whose result's last piece stays within it, and a
/// prepend whose first piece does. Copying at most this much per `+` keeps
/// each append constant time while concatenation nodes stay a small fraction
/// of the bytes they join.
const CONCAT_COPY_MAX_BYTES: usize = 1024;

/// Bytes one concatenation node occupies, with its `Arc` counters: the cost
/// per node that [`JsString::retained_bytes`] charges.
pub const CONCAT_NODE_BYTES: usize =
    std::mem::size_of::<Concat>() + 2 * std::mem::size_of::<usize>();

/// A [`JsString`]'s UTF-8 bytes: one shared buffer, or two well-formed
/// strings joined by [`JsString::concat`] whose bytes are copied together the
/// first time something reads them as one `str` (bd-9vouw.468). `s += piece`
/// in a loop then copies each piece about once, where one buffer per result
/// copied the whole accumulated string on every append. 16 bytes, as
/// `Arc<str>` was: the `Concat` pointer sits beside the `Flat` pointer's
/// niche.
#[derive(Clone)]
enum Text {
    Flat(Arc<str>),
    Concat(Arc<Concat>),
}

/// Two well-formed strings joined, with what readers and memory accounting
/// need without joining them.
struct Concat {
    /// The two parts, until the node is joined: from then on the joined bytes
    /// are all it keeps, so a string read between appends does not retain
    /// every earlier joined copy through the chain.
    parts: Mutex<Option<[JsString; 2]>>,
    /// UTF-8 length of the joined bytes.
    byte_len: usize,
    /// The nodes and pieces under this node, fixed when it is built.
    tree: ConcatParts,
    /// The joined bytes, made on first read.
    joined: OnceLock<Arc<str>>,
}

/// The concatenation nodes and flat pieces a string built by
/// [`JsString::concat`] was made of, counted once per occurrence (a subtree
/// shared by both parts counts twice). All zero for a flat string.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConcatParts {
    pub nodes: usize,
    pub pieces: usize,
    pub piece_bytes: usize,
}

impl ConcatParts {
    /// The counts for a node over `left` and `right`.
    fn joining(left: &JsString, right: &JsString) -> Self {
        let [left, right] = [left, right].map(|part| match &part.utf8 {
            Text::Flat(text) => Self {
                nodes: 0,
                pieces: 1,
                piece_bytes: text.len(),
            },
            Text::Concat(node) => node.tree,
        });
        Self {
            nodes: left.nodes.saturating_add(right.nodes).saturating_add(1),
            pieces: left.pieces.saturating_add(right.pieces),
            piece_bytes: left.piece_bytes.saturating_add(right.piece_bytes),
        }
    }
}

impl Text {
    /// The UTF-8 length, without joining.
    fn len(&self) -> usize {
        match self {
            Self::Flat(text) => text.len(),
            Self::Concat(node) => node.byte_len,
        }
    }

    fn as_str(&self) -> &str {
        match self {
            Self::Flat(text) => text,
            Self::Concat(node) => node.joined_text(),
        }
    }

    /// The same bytes, as one buffer when this concatenation was already
    /// joined, so a new node does not keep the old one alive.
    fn settled(&self) -> Self {
        match self {
            Self::Concat(node) => match node.joined.get() {
                Some(joined) => Self::Flat(Arc::clone(joined)),
                None => self.clone(),
            },
            Self::Flat(_) => self.clone(),
        }
    }
}

impl Deref for Text {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl PartialEq for Text {
    fn eq(&self, other: &Self) -> bool {
        if let (Self::Concat(left), Self::Concat(right)) = (self, other)
            && Arc::ptr_eq(left, right)
        {
            return true;
        }
        self.len() == other.len() && self.as_str() == other.as_str()
    }
}

impl Eq for Text {}

impl PartialOrd for Text {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Text {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl fmt::Debug for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl Concat {
    fn new(left: JsString, right: JsString) -> Self {
        Self {
            byte_len: left.utf8.len() + right.utf8.len(),
            tree: ConcatParts::joining(&left, &right),
            parts: Mutex::new(Some([left, right])),
            joined: OnceLock::new(),
        }
    }

    /// The two parts, or `None` once the node is joined.
    fn parts(&self) -> Option<[JsString; 2]> {
        self.parts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn joined_text(&self) -> &str {
        if let Some(joined) = self.joined.get() {
            return joined;
        }
        let joined = self.joined.get_or_init(|| self.join());
        // Released only after `joined` is set: a reader that finds no parts
        // finds the joined bytes. Dropped outside the lock.
        let parts = self
            .parts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        drop(parts);
        joined
    }

    /// The bytes of every piece, left to right, gathered with an explicit
    /// stack: a string appended to many times is a chain that deep.
    fn join(&self) -> Arc<str> {
        let mut text = String::with_capacity(self.byte_len);
        let mut pending: Vec<JsString> = Vec::new();
        if let Some([left, right]) = self.parts() {
            pending.push(right);
            pending.push(left);
        }
        while let Some(part) = pending.pop() {
            match &part.utf8 {
                Text::Flat(flat) => text.push_str(flat),
                Text::Concat(node) => match node.joined.get() {
                    Some(joined) => text.push_str(joined),
                    None => {
                        if let Some([left, right]) = node.parts() {
                            pending.push(right);
                            pending.push(left);
                        }
                    }
                },
            }
        }
        Arc::from(text)
    }
}

impl Drop for Concat {
    /// Releases a chain of uniquely owned nodes one at a time; the recursive
    /// drop glue would overflow the stack on a long append chain.
    fn drop(&mut self) {
        let mut pending: Vec<[JsString; 2]> = Vec::new();
        let mut next = self
            .parts
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        while let Some(parts) = next {
            for part in parts {
                if let Text::Concat(node) = part.utf8
                    && let Some(mut node) = Arc::into_inner(node)
                    && let Some(inner) = node
                        .parts
                        .get_mut()
                        .unwrap_or_else(PoisonError::into_inner)
                        .take()
                {
                    pending.push(inner);
                }
            }
            next = pending.pop();
        }
    }
}

/// What a [`JsString`]'s UTF-8 bytes cannot tell in constant time. It is
/// 16 bytes, as `Option<Arc<[u16]>>` was: the length sits beside the `Arc`
/// pointer's niche. `WellFormed` is declared first so the derived order
/// still puts well-formed content before exact units, as `None` did.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Shape {
    /// No lone surrogate: `utf8` is exact, and has this many UTF-16 code
    /// units. It equals `utf8.len()` exactly when the text is ASCII.
    WellFormed { utf16_len: usize },
    /// The exact code units, at least one of them an unpaired surrogate.
    Exact(Arc<[u16]>),
}

// Preserve the historical Debug shape (`utf8`, `units`): the cached length
// is derived metadata, not an observable.
impl fmt::Debug for JsString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let units = match &self.shape {
            Shape::WellFormed { .. } => None,
            Shape::Exact(units) => Some(units),
        };
        f.debug_struct("JsString")
            .field("utf8", &self.utf8)
            .field("units", &units)
            .finish()
    }
}

impl JsString {
    /// The empty string.
    pub fn empty() -> Self {
        Self::well_formed(Arc::from(""))
    }

    /// A well-formed string, its UTF-16 length counted from the UTF-8 bytes
    /// without decoding: ASCII is one unit per byte, otherwise every byte
    /// that starts a character is one unit and a four-byte lead (a
    /// supplementary character) one more.
    fn well_formed(utf8: Arc<str>) -> Self {
        let utf16_len = if utf8.is_ascii() {
            utf8.len()
        } else {
            utf8.bytes().fold(0, |count, byte| {
                count + usize::from(byte & 0xC0 != 0x80) + usize::from(byte >= 0xF0)
            })
        };
        Self {
            utf8: Text::Flat(utf8),
            shape: Shape::WellFormed { utf16_len },
        }
    }

    /// Build from exact UTF-16 code units, enforcing the canonical
    /// invariant. Adjacent high+low surrogate units combine into their
    /// supplementary code point (concatenation healing); only genuinely
    /// unpaired surrogates cause the exact-unit backing to be retained.
    pub fn from_code_units(units: &[u16]) -> Self {
        match String::from_utf16(units) {
            Ok(text) => Self {
                utf8: Text::Flat(Arc::from(text)),
                shape: Shape::WellFormed {
                    utf16_len: units.len(),
                },
            },
            Err(_) => Self {
                utf8: Text::Flat(Arc::from(String::from_utf16_lossy(units))),
                shape: Shape::Exact(Arc::from(units)),
            },
        }
    }

    /// True when the content is well-formed UTF-16 (no lone surrogates), in
    /// which case the UTF-8 projection is exact.
    pub fn is_well_formed(&self) -> bool {
        matches!(self.shape, Shape::WellFormed { .. })
    }

    /// True when the content is ASCII: one UTF-16 unit per UTF-8 byte.
    fn is_ascii_text(&self) -> bool {
        matches!(self.shape, Shape::WellFormed { utf16_len } if utf16_len == self.utf8.len())
    }

    /// Exact `&str` view, available only for well-formed content. Callers
    /// that can tolerate the U+FFFD projection should use [`Deref`] /
    /// [`JsString::as_utf8_projection`] instead.
    pub fn as_str(&self) -> Option<&str> {
        match self.shape {
            Shape::WellFormed { .. } => Some(self.utf8.as_str()),
            Shape::Exact(_) => None,
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
    #[inline]
    pub fn encode_utf16(&self) -> CodeUnits<'_> {
        CodeUnits {
            inner: match &self.shape {
                Shape::WellFormed { .. } if self.is_ascii_text() => {
                    CodeUnitsInner::Ascii(self.utf8.as_bytes().iter())
                }
                Shape::WellFormed { .. } => CodeUnitsInner::WellFormed(self.utf8.encode_utf16()),
                Shape::Exact(units) => CodeUnitsInner::Exact(units.iter().copied()),
            },
            remaining: self.utf16_len(),
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
        match &self.shape {
            Shape::WellFormed { .. } => CanonicalValue::String(self.utf8.to_string()),
            Shape::Exact(units) => {
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

    /// The ECMAScript `length` of the string: its UTF-16 code-unit count,
    /// kept since the string was built. Counting it on each call made every
    /// `s.length`, `s[i]` and `charCodeAt` on a long string proportional to
    /// its length (bd-9vouw.403, bd-9vouw.467).
    pub fn utf16_len(&self) -> usize {
        match &self.shape {
            Shape::WellFormed { utf16_len } => *utf16_len,
            Shape::Exact(units) => units.len(),
        }
    }

    /// The UTF-8 projection's byte length. This inherent method shadows
    /// `str::len` reached through [`Deref`], so length checks and memory
    /// estimates on a concatenation do not join it (bd-9vouw.468).
    pub fn len(&self) -> usize {
        self.utf8.len()
    }

    /// True for the empty string; shadows `str::is_empty` like
    /// [`JsString::len`].
    pub fn is_empty(&self) -> bool {
        self.utf8.len() == 0
    }

    /// The concatenation nodes and pieces this string was built from; all
    /// zero for a flat string.
    pub fn concat_parts(&self) -> ConcatParts {
        match &self.utf8 {
            Text::Flat(_) => ConcatParts::default(),
            Text::Concat(node) => node.tree,
        }
    }

    /// The bytes this string's UTF-8 storage holds, for memory estimates,
    /// with `buffer_base_bytes` charged per buffer: a flat string is one
    /// buffer of its length. A concatenation holds its nodes and pieces
    /// until it is joined and then only the joined buffer, which is no
    /// longer than its piece bytes, so nodes plus pieces bound it in both
    /// states. Fixed when the string is built, so an estimate does not
    /// change when the string is later joined (bd-9vouw.468). The copy made
    /// while joining is transient, like other temporaries.
    pub fn retained_bytes(&self, buffer_base_bytes: u64) -> u64 {
        let to_u64 = |count: usize| u64::try_from(count).unwrap_or(u64::MAX);
        match &self.utf8 {
            Text::Flat(text) => buffer_base_bytes.saturating_add(to_u64(text.len())),
            Text::Concat(node) => to_u64(node.tree.nodes)
                .saturating_mul(to_u64(CONCAT_NODE_BYTES))
                .saturating_add(to_u64(node.tree.pieces).saturating_mul(buffer_base_bytes))
                .saturating_add(to_u64(node.tree.piece_bytes)),
        }
    }

    /// The UTF-16 code unit at `unit_index`, or `None` out of range. In ASCII
    /// text it is the byte there; otherwise, when the text up to that index
    /// is ASCII, the byte there too, found without decoding the prefix
    /// (bd-9vouw.403).
    pub fn code_unit_at(&self, unit_index: usize) -> Option<u16> {
        match &self.shape {
            Shape::Exact(units) => units.get(unit_index).copied(),
            Shape::WellFormed { .. } => {
                let bytes = self.utf8.as_bytes();
                if self.is_ascii_text() {
                    return bytes.get(unit_index).map(|byte| u16::from(*byte));
                }
                match bytes.get(..=unit_index) {
                    Some(prefix) if prefix.is_ascii() => Some(u16::from(bytes[unit_index])),
                    _ => self.utf8.encode_utf16().nth(unit_index),
                }
            }
        }
    }

    /// The code units from `start` to `end` (UTF-16 offsets, clamped to the
    /// string) as a string; a boundary inside a surrogate pair keeps the lone
    /// half. ASCII text is sliced as bytes and other well-formed text decoded
    /// only up to `end`, so `slice`/`substring`/`substr` no longer copy the
    /// whole string into code units on every call (bd-9vouw.467).
    pub fn utf16_slice(&self, start: usize, end: usize) -> JsString {
        let end = end.min(self.utf16_len());
        let start = start.min(end);
        match &self.shape {
            Shape::WellFormed { .. } if self.is_ascii_text() => Self {
                utf8: Text::Flat(Arc::from(&self.utf8[start..end])),
                shape: Shape::WellFormed {
                    utf16_len: end - start,
                },
            },
            Shape::WellFormed { .. } => {
                let units: Vec<u16> = self
                    .utf8
                    .encode_utf16()
                    .skip(start)
                    .take(end - start)
                    .collect();
                Self::from_code_units(&units)
            }
            Shape::Exact(units) => Self::from_code_units(&units[start..end]),
        }
    }

    /// Whether every exact code unit is ASCII, without scanning the backing.
    /// Every non-ASCII scalar (or projected lone surrogate) uses more UTF-8
    /// bytes than UTF-16 units, so equality of the lengths is sufficient.
    /// This intentionally shadows `str::is_ascii` reached through Deref.
    #[inline]
    pub fn is_ascii(&self) -> bool {
        self.is_ascii_text()
    }

    /// ES string concatenation over exact code units. When both operands are
    /// well-formed this is a UTF-8 concatenation: short results are copied
    /// into one buffer, longer ones become a concatenation node joined on
    /// first read (bd-9vouw.468). Otherwise the exact unit sequences are
    /// joined and re-normalized, which heals a trailing high surrogate
    /// against a leading low surrogate into the supplementary code point.
    pub fn concat(&self, other: &JsString) -> JsString {
        if self.utf16_len() == 0 {
            return other.clone();
        }
        if other.utf16_len() == 0 {
            return self.clone();
        }
        if let (Shape::WellFormed { utf16_len: left }, Shape::WellFormed { utf16_len: right }) =
            (&self.shape, &other.shape)
        {
            let shape = Shape::WellFormed {
                utf16_len: left + right,
            };
            if self.utf8.len() + other.utf8.len() < CONCAT_COPY_MAX_BYTES {
                return Self::copied(self, other, shape);
            }
            let (head, tail) = (self.settled(), other.settled());
            // Appending a short piece to a node whose last piece is short:
            // copy the two into a new last piece instead of adding a node.
            if let Text::Concat(node) = &head.utf8
                && let Text::Flat(_) = &tail.utf8
                && let Some([first, last]) = node.parts()
                && let Text::Flat(_) = &last.utf8
                && last.utf8.len() + tail.utf8.len() <= CONCAT_COPY_MAX_BYTES
            {
                let last = Self::copied(&last, &tail, last.joined_shape(&tail));
                return Self::joined(first, last, shape);
            }
            // The mirror case for prepending.
            if let Text::Concat(node) = &tail.utf8
                && let Text::Flat(_) = &head.utf8
                && let Some([first, last]) = node.parts()
                && let Text::Flat(_) = &first.utf8
                && head.utf8.len() + first.utf8.len() <= CONCAT_COPY_MAX_BYTES
            {
                let first = Self::copied(&head, &first, head.joined_shape(&first));
                return Self::joined(first, last, shape);
            }
            return Self::joined(head, tail, shape);
        }
        let mut units: Vec<u16> = Vec::with_capacity(self.utf16_len() + other.utf16_len());
        units.extend(self.encode_utf16());
        units.extend(other.encode_utf16());
        Self::from_code_units(&units)
    }

    /// The same string, its concatenation node replaced by the joined bytes
    /// when it was already joined.
    fn settled(&self) -> JsString {
        Self {
            utf8: self.utf8.settled(),
            shape: self.shape.clone(),
        }
    }

    /// The shape of two well-formed strings concatenated.
    fn joined_shape(&self, other: &JsString) -> Shape {
        Shape::WellFormed {
            utf16_len: self.utf16_len() + other.utf16_len(),
        }
    }

    /// Two well-formed strings copied into one buffer.
    fn copied(left: &JsString, right: &JsString, shape: Shape) -> JsString {
        let mut text = String::with_capacity(left.utf8.len() + right.utf8.len());
        text.push_str(&left.utf8);
        text.push_str(&right.utf8);
        Self {
            utf8: Text::Flat(Arc::from(text)),
            shape,
        }
    }

    /// Two well-formed strings under a concatenation node.
    fn joined(left: JsString, right: JsString, shape: Shape) -> JsString {
        Self {
            utf8: Text::Concat(Arc::new(Concat::new(left, right))),
            shape,
        }
    }

    /// ES2020 `CodePointAt`: the Unicode code point at UTF-16 code-unit
    /// index `unit_index`. A valid high+low surrogate pair combines into its
    /// supplementary code point; an unpaired surrogate yields its own code
    /// unit value; out of range yields `None`. (bd-rdnhc)
    pub fn code_point_at(&self, unit_index: usize) -> Option<u32> {
        // An ASCII unit is never half of a surrogate pair (bd-9vouw.403).
        if self.is_ascii_text() {
            return self
                .utf8
                .as_bytes()
                .get(unit_index)
                .map(|byte| u32::from(*byte));
        }
        if self.is_well_formed()
            && let Some(prefix) = self.utf8.as_bytes().get(..=unit_index)
            && prefix.is_ascii()
        {
            return Some(u32::from(prefix[unit_index]));
        }
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
        // Stream UTF-8 scalars directly, or borrow the existing exact backing.
        // Neither case needs a temporary UTF-16 copy of the entire string.
        let Shape::Exact(units) = &self.shape else {
            return self.utf8.chars().map(Self::from).collect();
        };
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
        if self.is_ascii() && other.is_ascii() {
            return self.utf8.cmp(&other.utf8);
        }
        self.encode_utf16().cmp(other.encode_utf16())
    }

    /// First UTF-16 code-unit index at or after `from` where `needle`'s
    /// exact unit sequence occurs (ES `StringIndexOf`). `from` past the end
    /// clamps to the length; an empty needle matches at the clamped `from`.
    /// A position that splits a surrogate pair is a legal starting offset —
    /// never an error — per ES code-unit semantics. (bd-rdnhc)
    ///
    /// Matching takes O(n + m) work and O(m) scratch for n haystack units
    /// and m needle units; the haystack is never materialized as a vector.
    /// Well-formed strings use native byte search without UTF-16 or
    /// failure-table allocation. Only lone-surrogate inputs need KMP.
    pub fn utf16_index_of(&self, needle: &JsString, from: usize) -> Option<usize> {
        let haystack_len = self.utf16_len();
        let from = from.min(haystack_len);
        let needle_len = needle.utf16_len();
        if needle_len == 0 {
            return Some(from);
        }
        if needle_len > haystack_len - from {
            return None;
        }
        if self.is_ascii() {
            if !needle.is_ascii() {
                return None;
            }
            // Every byte boundary is a code-unit boundary in ASCII.
            return self.utf8[from..]
                .find(needle.utf8.as_str())
                .map(|index| from + index);
        }
        if self.is_well_formed() && needle.is_well_formed() {
            // A well-formed needle cannot begin at the low half of a pair.
            // Round a split starting position up to the next scalar boundary.
            let (byte_start, unit_start) = utf8_search_boundary(&self.utf8, from, true);
            let suffix = &self.utf8[byte_start..];
            return suffix
                .find(needle.utf8.as_str())
                .map(|index| unit_start + suffix[..index].encode_utf16().count());
        }
        let needle_units = needle.code_units_vec();
        search_utf16_units(self.encode_utf16().skip(from), &needle_units, false)
            .map(|index| from + index)
    }

    /// Highest UTF-16 code-unit start index at or before `from` where
    /// `needle`'s exact unit sequence occurs (ES `String.prototype.lastIndexOf`
    /// grain). An empty needle matches at `min(from, length)`. (bd-rdnhc)
    ///
    /// Uses native reverse byte search for well-formed strings, or the
    /// linear-time, needle-sized-scratch matcher for lone-surrogate inputs.
    /// Both retain overlaps and bound the match's start, not its end, by `from`.
    pub fn utf16_last_index_of(&self, needle: &JsString, from: usize) -> Option<usize> {
        let haystack_len = self.utf16_len();
        let needle_len = needle.utf16_len();
        if needle_len == 0 {
            return Some(from.min(haystack_len));
        }
        if needle_len > haystack_len {
            return None;
        }
        let start = from.min(haystack_len - needle_len);
        // start <= haystack_len - needle_len, so this cannot overflow.
        let end = start + needle_len;
        if self.is_ascii() {
            if !needle.is_ascii() {
                return None;
            }
            return self.utf8[..end].rfind(needle.utf8.as_str());
        }
        if self.is_well_formed() && needle.is_well_formed() {
            if from >= haystack_len - needle_len {
                // The usual unbounded reverse search needs no forward scan
                // to locate `from`. Count from the nearer end of the match.
                return self.utf8.rfind(needle.utf8.as_str()).map(|index| {
                    if index <= self.utf8.len() / 2 {
                        self.utf8[..index].encode_utf16().count()
                    } else {
                        haystack_len - self.utf8[index..].encode_utf16().count()
                    }
                });
            }
            let (byte_start, unit_start) = utf8_search_boundary(&self.utf8, from, false);
            // Include the whole needle for a match starting at byte_start.
            // Clamp without overflow, then round the end DOWN: every actual
            // UTF-8 match already ends at a scalar boundary. This excludes no
            // permitted match, and no match can start later than byte_start.
            let mut byte_end = byte_start + needle.utf8.len().min(self.utf8.len() - byte_start);
            while !self.utf8.is_char_boundary(byte_end) {
                byte_end -= 1;
            }
            return self.utf8[..byte_end]
                .rfind(needle.utf8.as_str())
                .map(|index| unit_start - self.utf8[index..byte_start].encode_utf16().count());
        }
        let needle_units = needle.code_units_vec();
        search_utf16_units(self.encode_utf16().take(end), &needle_units, true)
    }
}

/// Map a UTF-16 position in well-formed UTF-8 to a scalar boundary. An
/// astral scalar straddling `position` rounds up for indexOf and down for
/// lastIndexOf. Return both coordinates so callers do not rescan the prefix.
fn utf8_search_boundary(text: &str, position: usize, round_up: bool) -> (usize, usize) {
    if position == 0 {
        return (0, 0);
    }
    let mut units = 0;
    for (byte, ch) in text.char_indices() {
        if units == position {
            return (byte, units);
        }
        let next = units + ch.len_utf16();
        if next > position {
            return if round_up {
                (byte + ch.len_utf8(), next)
            } else {
                (byte, units)
            };
        }
        units = next;
    }
    (text.len(), units)
}

/// KMP over exact code units. Only the needle and its failure function need
/// random access; streaming avoids an allocation proportional to the haystack.
fn search_utf16_units(
    haystack: impl Iterator<Item = u16>,
    needle: &[u16],
    find_last: bool,
) -> Option<usize> {
    search_utf16_units_with_eq(haystack, needle, find_last, |left, right| left == right)
}

// The comparison seam lets regression tests bound work without wall-clock
// timing. Production specializes this with ordinary u16 equality.
fn search_utf16_units_with_eq(
    haystack: impl Iterator<Item = u16>,
    needle: &[u16],
    find_last: bool,
    mut equal: impl FnMut(u16, u16) -> bool,
) -> Option<usize> {
    if needle.is_empty() {
        return Some(if find_last { haystack.count() } else { 0 });
    }
    let mut failure = vec![0_usize; needle.len()];
    let mut matched = 0;
    for index in 1..needle.len() {
        while matched > 0 && !equal(needle[index], needle[matched]) {
            matched = failure[matched - 1];
        }
        if equal(needle[index], needle[matched]) {
            matched += 1;
        }
        failure[index] = matched;
    }

    matched = 0;
    let mut found = None;
    for (index, unit) in haystack.enumerate() {
        while matched > 0 && !equal(unit, needle[matched]) {
            matched = failure[matched - 1];
        }
        if equal(unit, needle[matched]) {
            matched += 1;
        }
        if matched == needle.len() {
            let start = index + 1 - needle.len();
            if !find_last {
                return Some(start);
            }
            found = Some(start);
            // Keep the proper suffix so overlapping matches are not lost.
            matched = failure[matched - 1];
        }
    }
    found
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
        Self::well_formed(Arc::from(value))
    }
}

impl From<String> for JsString {
    fn from(value: String) -> Self {
        Self::well_formed(Arc::from(value))
    }
}

impl From<Arc<str>> for JsString {
    fn from(value: Arc<str>) -> Self {
        Self::well_formed(value)
    }
}

impl From<char> for JsString {
    fn from(value: char) -> Self {
        // Avoid a temporary heap-allocated String for a single code point.
        let mut buffer = [0_u8; 4];
        let text: &str = value.encode_utf8(&mut buffer);
        Self {
            utf8: Text::Flat(Arc::from(text)),
            shape: Shape::WellFormed {
                utf16_len: value.len_utf16(),
            },
        }
    }
}

impl From<&String> for JsString {
    fn from(value: &String) -> Self {
        Self::well_formed(Arc::from(value.as_str()))
    }
}

impl PartialEq<str> for JsString {
    fn eq(&self, other: &str) -> bool {
        self.is_well_formed() && self.utf8.len() == other.len() && *self.utf8 == *other
    }
}

impl PartialEq<&str> for JsString {
    fn eq(&self, other: &&str) -> bool {
        self.is_well_formed() && self.utf8.len() == other.len() && *self.utf8 == **other
    }
}

/// Iterator over the exact UTF-16 code units of a [`JsString`].
#[derive(Clone)]
pub struct CodeUnits<'a> {
    inner: CodeUnitsInner<'a>,
    remaining: usize,
}

#[derive(Clone)]
enum CodeUnitsInner<'a> {
    Ascii(std::slice::Iter<'a, u8>),
    WellFormed(std::str::EncodeUtf16<'a>),
    Exact(std::iter::Copied<std::slice::Iter<'a, u16>>),
}

impl Iterator for CodeUnits<'_> {
    type Item = u16;

    #[inline]
    fn next(&mut self) -> Option<u16> {
        let unit = match &mut self.inner {
            CodeUnitsInner::Ascii(iter) => iter.next().copied().map(u16::from),
            CodeUnitsInner::WellFormed(iter) => iter.next(),
            CodeUnitsInner::Exact(iter) => iter.next(),
        };
        self.remaining -= usize::from(unit.is_some());
        unit
    }

    #[inline]
    fn nth(&mut self, n: usize) -> Option<u16> {
        if n >= self.remaining {
            // Exhaust without decoding, even for usize::MAX. Replacing the
            // inner iterator also keeps subsequent next/fold/last consistent.
            self.inner = CodeUnitsInner::Ascii(b"".iter());
            self.remaining = 0;
            return None;
        }
        let unit = match &mut self.inner {
            CodeUnitsInner::Ascii(iter) => iter.nth(n).copied().map(u16::from),
            CodeUnitsInner::WellFormed(iter) => iter.nth(n),
            CodeUnitsInner::Exact(iter) => iter.nth(n),
        };
        // n < remaining, so n + 1 cannot overflow.
        self.remaining -= n + 1;
        unit
    }

    #[inline]
    fn count(self) -> usize {
        self.remaining
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }

    fn last(self) -> Option<u16> {
        match self.inner {
            CodeUnitsInner::Ascii(mut iter) => iter.next_back().copied().map(u16::from),
            CodeUnitsInner::WellFormed(iter) => iter.last(),
            CodeUnitsInner::Exact(mut iter) => iter.next_back(),
        }
    }

    fn fold<B, F>(self, init: B, mut f: F) -> B
    where
        F: FnMut(B, u16) -> B,
    {
        // Dispatch once for streaming consumers rather than once per unit.
        match self.inner {
            CodeUnitsInner::Ascii(iter) => iter.fold(init, |acc, &byte| f(acc, u16::from(byte))),
            CodeUnitsInner::WellFormed(iter) => iter.fold(init, f),
            CodeUnitsInner::Exact(iter) => iter.fold(init, f),
        }
    }
}

impl ExactSizeIterator for CodeUnits<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.remaining
    }
}

impl std::iter::FusedIterator for CodeUnits<'_> {}

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
        match &self.shape {
            Shape::WellFormed { .. } => serializer.serialize_str(&self.utf8),
            Shape::Exact(units) => {
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

    /// bd-9vouw.403: the byte-counting `utf16_len` and the ASCII-prefix
    /// `code_unit_at` / `code_point_at` agree with decoding the units, for
    /// ASCII, two- and three-byte, supplementary and lone-surrogate text, at
    /// every index and one past the end.
    #[test]
    fn fast_unit_access_matches_decoding_bd_9vouw_403() {
        let samples = [
            JsString::empty(),
            JsString::from("abc"),
            JsString::from("h\u{e9}llo"),
            JsString::from("\u{65e5}\u{672c}\u{8a9e}"),
            JsString::from("a\u{1f600}b"),
            JsString::from("\u{1f600}"),
            JsString::from("abc\u{e9}xyz"),
            JsString::from_code_units(&[0x61, 0xD800, 0x62]),
            JsString::from_code_units(&[0xDC00]),
        ];
        for sample in samples {
            let units: Vec<u16> = sample.encode_utf16().collect();
            assert_eq!(sample.utf16_len(), units.len(), "{sample:?}");
            for index in 0..=units.len() {
                assert_eq!(
                    sample.code_unit_at(index),
                    units.get(index).copied(),
                    "{sample:?} {index}"
                );
                let decoded = {
                    let mut rest = units.iter().copied().skip(index);
                    rest.next().map(|first| match rest.next() {
                        Some(second)
                            if (0xD800..0xDC00).contains(&first)
                                && (0xDC00..0xE000).contains(&second) =>
                        {
                            0x10000
                                + ((u32::from(first) - 0xD800) << 10)
                                + (u32::from(second) - 0xDC00)
                        }
                        _ => u32::from(first),
                    })
                };
                assert_eq!(sample.code_point_at(index), decoded, "{sample:?} {index}");
            }
        }
    }

    /// bd-9vouw.467: the UTF-16 length a string keeps from construction is
    /// the decoded count however it was built (concatenation adds lengths,
    /// a char, an owned String, serde), `utf16_slice` equals slicing the
    /// decoded units for every range, and the kept length costs no space.
    #[test]
    fn kept_length_and_slices_match_decoding_bd_9vouw_467() {
        let healed = JsString::from_code_units(&[0x61, 0xD83D])
            .concat(&JsString::from_code_units(&[0xDE00, 0x62]));
        assert!(healed.is_well_formed());
        let samples = [
            JsString::from("abc").concat(&JsString::from("defg")),
            JsString::from("h\u{e9}").concat(&JsString::from("\u{1f600}x")),
            JsString::from('\u{1f600}'),
            JsString::from('z'),
            JsString::from(String::from("\u{65e5}a")),
            JsString::from(Arc::<str>::from("ascii only")),
            serde_json::from_str::<JsString>("\"j\\u00e9son\"").expect("string"),
            serde_json::from_str::<JsString>("{\"$wtf16\":[97,55296,98]}").expect("units"),
            healed,
            JsString::from_code_units(&[0xD800]).concat(&JsString::from("tail")),
            JsString::empty(),
        ];
        for sample in samples {
            let units: Vec<u16> = sample.encode_utf16().collect();
            assert_eq!(sample.utf16_len(), units.len(), "{sample:?}");
            for start in 0..=units.len() {
                for end in start..=units.len() {
                    let slice = sample.utf16_slice(start, end);
                    assert_eq!(
                        slice,
                        JsString::from_code_units(&units[start..end]),
                        "{sample:?} {start}..{end}"
                    );
                    assert_eq!(slice.utf16_len(), end - start, "{sample:?} {start}..{end}");
                }
            }
            // Out-of-range bounds clamp instead of panicking.
            assert_eq!(
                sample.utf16_slice(units.len() + 3, units.len() + 9),
                JsString::empty()
            );
        }
        assert_eq!(std::mem::size_of::<JsString>(), 32);
    }

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

    #[test]
    fn utf16_search_matches_exhaustive_code_unit_oracle() {
        fn corpus(max_len: usize) -> Vec<Vec<u16>> {
            let mut all = vec![Vec::new()];
            let mut level = vec![Vec::new()];
            for _ in 0..max_len {
                let mut next = Vec::new();
                for prefix in &level {
                    for unit in [0x61, HIGH, LOW] {
                        let mut value = prefix.clone();
                        value.push(unit);
                        next.push(value);
                    }
                }
                all.extend(next.iter().cloned());
                level = next;
            }
            all
        }

        let needles = corpus(3);
        for haystack in corpus(4) {
            let string = JsString::from_code_units(&haystack);
            for units in &needles {
                let needle = JsString::from_code_units(units);
                let matches: Vec<usize> = (0..=haystack.len())
                    .filter(|&index| {
                        haystack.get(index..index + units.len()) == Some(units.as_slice())
                    })
                    .collect();
                for from in (0..=haystack.len() + 1).chain(std::iter::once(usize::MAX)) {
                    let start = from.min(haystack.len());
                    let first = matches.iter().copied().find(|&index| index >= start);
                    let last = matches.iter().copied().rev().find(|&index| index <= start);
                    assert_eq!(
                        string.utf16_index_of(&needle, from),
                        first,
                        "indexOf: {haystack:?}, {units:?}, {from}"
                    );
                    assert_eq!(
                        string.utf16_last_index_of(&needle, from),
                        last,
                        "lastIndexOf: {haystack:?}, {units:?}, {from}"
                    );
                }
            }
        }
    }

    #[test]
    fn utf16_search_retains_overlapping_matches_and_clamps_extreme_offsets() {
        let string = JsString::from("aaaaa");
        let needle = JsString::from("aaa");
        assert_eq!(string.utf16_index_of(&needle, 1), Some(1));
        assert_eq!(string.utf16_index_of(&needle, usize::MAX), None);
        assert_eq!(string.utf16_last_index_of(&needle, usize::MAX), Some(2));
        assert_eq!(string.utf16_last_index_of(&needle, 1), Some(1));
        assert_eq!(string.utf16_last_index_of(&needle, 0), Some(0));
        assert_eq!(
            string.utf16_index_of(&JsString::empty(), usize::MAX),
            Some(5)
        );
        assert_eq!(
            string.utf16_last_index_of(&JsString::empty(), usize::MAX),
            Some(5)
        );
    }

    #[test]
    fn utf16_search_does_not_confuse_surrogates_with_their_projection() {
        let string = JsString::from_code_units(&[0xFFFD, HIGH, LOW, LOW, HIGH]);
        let high = JsString::from_code_units(&[HIGH]);
        let low_high = JsString::from_code_units(&[LOW, HIGH]);
        assert_eq!(string.utf16_index_of(&high, 0), Some(1));
        assert_eq!(string.utf16_index_of(&high, 2), Some(4));
        assert_eq!(string.utf16_last_index_of(&high, usize::MAX), Some(4));
        assert_eq!(string.utf16_index_of(&low_high, 0), Some(3));
        assert_eq!(
            string.utf16_last_index_of(&JsString::from("\u{FFFD}"), usize::MAX),
            Some(0)
        );
    }

    #[test]
    fn utf16_search_bounds_comparisons_for_adversarial_repeated_prefixes() {
        let haystack = vec![0x61; 65_536];
        let mut needle = vec![0x61; 8_192];
        needle.push(0x62);
        for find_last in [false, true] {
            let mut comparisons = 0_usize;
            let found = search_utf16_units_with_eq(
                haystack.iter().copied(),
                &needle,
                find_last,
                |left, right| {
                    comparisons += 1;
                    left == right
                },
            );
            assert_eq!(found, None);
            assert!(comparisons <= 4 * (haystack.len() + needle.len()));
        }
    }

    #[test]
    fn utf16_search_bounds_work_when_every_match_overlaps() {
        let haystack = vec![0x61; 16_384];
        let needle = vec![0x61; 4_096];
        let mut comparisons = 0_usize;
        let found =
            search_utf16_units_with_eq(haystack.iter().copied(), &needle, true, |left, right| {
                comparisons += 1;
                left == right
            });
        assert_eq!(found, Some(haystack.len() - needle.len()));
        assert!(comparisons <= 4 * (haystack.len() + needle.len()));
    }

    #[test]
    fn utf16_search_first_match_does_not_consume_the_remaining_stream() {
        let haystack = (0..).map(|index| {
            assert!(index < 3, "matcher read beyond the first match");
            [1_u16, 2, 3][index]
        });
        assert_eq!(search_utf16_units(haystack, &[2, 3], false), Some(1));
    }

    /// Every observable of `concat`'s result against the same text in one
    /// buffer, without and then with joining.
    fn assert_same_string(built: &JsString, expected: &str) {
        let flat = JsString::from(expected);
        let units: Vec<u16> = expected.encode_utf16().collect();
        assert_eq!(built.len(), expected.len());
        assert_eq!(built.is_empty(), expected.is_empty());
        assert_eq!(built.utf16_len(), units.len());
        assert!(built.is_well_formed());
        for index in [
            0,
            1,
            units.len() / 3,
            units.len() / 2,
            units.len().saturating_sub(1),
        ] {
            assert_eq!(
                built.code_unit_at(index),
                units.get(index).copied(),
                "{index}"
            );
            assert_eq!(
                built.code_point_at(index),
                flat.code_point_at(index),
                "{index}"
            );
        }
        let (start, end) = (units.len() / 4, units.len() / 2);
        assert_eq!(built.utf16_slice(start, end), flat.utf16_slice(start, end));
        assert_eq!(built, &flat);
        assert_eq!(built.cmp(&flat), std::cmp::Ordering::Equal);
        assert!(*built < JsString::from(format!("{expected}~")));
        assert_eq!(built.as_str(), Some(expected));
        assert_eq!(built, expected);
        assert_eq!(built.to_string(), expected);
        assert_eq!(format!("{built:?}"), format!("{flat:?}"));
        assert_eq!(built.canonical_value(), flat.canonical_value());
        assert_eq!(
            serde_json::to_string(built).expect("serialize"),
            serde_json::to_string(&flat).expect("serialize")
        );
        assert!(built.encode_utf16().eq(units.iter().copied()));
    }

    #[test]
    fn appends_build_concatenations_joined_on_first_read_bd_9vouw_468() {
        let pieces = [
            JsString::from("abcdefg"),
            JsString::from("h\u{e9}\u{1f600}"),
        ];
        let mut built = JsString::empty();
        let mut expected = String::new();
        for round in 0..20_000 {
            let piece = &pieces[round % 2];
            built = built.concat(piece);
            expected.push_str(piece);
        }
        // Short last pieces are merged up to CONCAT_COPY_MAX_BYTES, so the
        // nodes stay a small fraction of the bytes; each byte sits in exactly
        // one piece.
        let parts = built.concat_parts();
        assert!(parts.nodes >= 1, "{parts:?}");
        assert!(
            parts.nodes <= expected.len() / (CONCAT_COPY_MAX_BYTES - 12) + 1,
            "{parts:?}"
        );
        assert_eq!(parts.pieces, parts.nodes + 1);
        assert_eq!(parts.piece_bytes, expected.len());
        let retained = built.retained_bytes(24);
        assert_eq!(
            retained,
            (parts.nodes * CONCAT_NODE_BYTES + parts.pieces * 24 + parts.piece_bytes) as u64
        );
        // Nodes plus pieces bound the joined buffer the string keeps later.
        assert!(retained >= JsString::from(expected.as_str()).retained_bytes(24));
        assert_same_string(&built, &expected);
        // Joining does not change what an estimate charges.
        assert_eq!(built.concat_parts(), parts);
        assert_eq!(built.retained_bytes(24), retained);

        // Prepending merges the first piece the same way.
        let mut built = JsString::empty();
        for round in 0..20_000 {
            built = pieces[round % 2].concat(&built);
        }
        let expected: String = (0..20_000)
            .rev()
            .map(|round| pieces[round % 2].as_utf8_projection())
            .collect();
        let parts = built.concat_parts();
        assert!(
            parts.nodes <= expected.len() / (CONCAT_COPY_MAX_BYTES - 12) + 1,
            "{parts:?}"
        );
        assert_same_string(&built, &expected);

        // Short results stay one buffer.
        let short = JsString::from("ab").concat(&JsString::from("cd"));
        assert_eq!(short.concat_parts(), ConcatParts::default());
        assert_eq!(short.retained_bytes(24), 24 + 4);
        // Concatenating the empty string keeps the other operand.
        assert_eq!(built.concat(&JsString::empty()).concat_parts(), parts);
    }

    #[test]
    fn long_concatenation_chains_join_and_drop_without_recursion_bd_9vouw_468() {
        // Pieces longer than CONCAT_COPY_MAX_BYTES are never merged: one node
        // per append, a chain as deep as the append count.
        let piece = JsString::from("x".repeat(CONCAT_COPY_MAX_BYTES + 1));
        let mut deep = piece.clone();
        for _ in 0..200_000 {
            deep = deep.concat(&piece);
        }
        assert_eq!(
            deep.concat_parts(),
            ConcatParts {
                nodes: 200_000,
                pieces: 200_001,
                piece_bytes: 200_001 * (CONCAT_COPY_MAX_BYTES + 1),
            }
        );
        assert_eq!(deep.len(), 200_001 * (CONCAT_COPY_MAX_BYTES + 1));
        // Dropping a 200,000-node chain recursively overflows a test stack.
        drop(deep);

        let mut joined = piece.clone();
        for _ in 0..20_000 {
            joined = joined.concat(&piece);
        }
        let text = joined.as_str().expect("well-formed");
        assert_eq!(text.len(), 20_001 * (CONCAT_COPY_MAX_BYTES + 1));
        assert!(text.bytes().all(|byte| byte == b'x'));
    }

    #[test]
    fn joining_releases_the_parts_and_later_appends_build_on_the_joined_bytes_bd_9vouw_468() {
        let first = JsString::from("y".repeat(2_000));
        let second = JsString::from("z".repeat(2_000));
        let first_count = |text: &JsString| match &text.utf8 {
            Text::Flat(bytes) => Arc::strong_count(bytes),
            Text::Concat(_) => 0,
        };
        let built = first.concat(&second);
        assert_eq!(built.concat_parts().nodes, 1);
        assert_eq!(first_count(&first), 2);
        assert_eq!(built.as_str().map(str::len), Some(4_000));
        // The node keeps only its joined bytes now.
        assert_eq!(first_count(&first), 1);
        assert_eq!(first_count(&second), 1);
        assert_same_string(
            &built,
            &format!("{}{}", "y".repeat(2_000), "z".repeat(2_000)),
        );

        // An append after a read starts from the joined bytes: one node over
        // two pieces, not a chain that keeps the earlier node and its copy.
        let mut grown = built.clone();
        for _ in 0..50 {
            grown = grown.concat(&second);
            assert!(grown.as_str().is_some());
        }
        let next = grown.concat(&second);
        assert_eq!(
            next.concat_parts(),
            ConcatParts {
                nodes: 1,
                pieces: 2,
                piece_bytes: grown.len() + 2_000,
            }
        );
    }

    #[test]
    fn concatenations_with_lone_surrogates_stay_exact_bd_9vouw_468() {
        let long = "a".repeat(2_000);
        let mut built = JsString::from(long.as_str());
        built = built.concat(&JsString::from("b".repeat(2_000)));
        assert_eq!(built.concat_parts().nodes, 1);
        let lone = built.concat(&JsString::from_code_units(&[HIGH]));
        assert!(!lone.is_well_formed());
        assert_eq!(lone.utf16_len(), 4_001);
        assert_eq!(lone.code_unit_at(4_000), Some(HIGH));
        assert_eq!(lone.concat_parts(), ConcatParts::default());
        // A trailing high surrogate still heals against a leading low one.
        let healed = lone.concat(&JsString::from_code_units(&[LOW]));
        assert_same_string(&healed, &format!("{long}{}\u{1f600}", "b".repeat(2_000)));
    }
}
