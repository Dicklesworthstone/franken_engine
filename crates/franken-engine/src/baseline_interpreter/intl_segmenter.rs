//! ECMA-402 18 `Intl.Segmenter` over UAX #29 (bd-9vouw.247).
//!
//! `Intl.Segmenter` was not defined, so string-width 8.3, which builds one
//! when it loads, threw (npm wave 10's string_width probe).
//! `segment(string)` splits the string into extended grapheme clusters,
//! words or sentences (the `unicode-segmentation` crate's UAX #29 rules, as
//! ICU's root locale does for these). The result is a Segments object:
//! iterable over `{ segment, index, input }` records (word segments add
//! `isWordLike`), with `containing(index)`.
//!
//! A word segmentation of text in a script ICU splits with dictionaries
//! (Han, Hiragana, Katakana, Thai, Lao, Khmer, Myanmar) is refused with a
//! TypeError instead of answering differently from Node. No-claim: no
//! locale tailoring; `isWordLike` is "the segment has a letter or digit";
//! methods remain bound own properties rather than prototype methods;
//! a lone surrogate in the input is read as U+FFFD.
//!
//! Canonical records and iterator cursors are private heap objects reached
//! through builtin bound-object edges, which the collector traces. Neither
//! hidden string properties nor yielded records expose that storage. Every
//! delivery creates a fresh mutable record sharing immutable string backing.

use super::*;

use unicode_segmentation::UnicodeSegmentation;

/// One segment: its text, its UTF-16 index in the input and, for word
/// granularity, whether it is word-like.
type Segment = (JsString, usize, Option<bool>);

/// Preserve the established worst-case admission allowance per UTF-16 code
/// unit even though segmentation no longer stages full slice and tuple
/// buffers. Streaming must not silently relax the input memory limit.
const SEGMENT_NATIVE_BYTES_PER_CODE_UNIT: u64 = 96;

impl InterpreterCore {
    /// ECMA-402 18.1.1 steps 7-13: localeMatcher and granularity.
    pub(super) fn intl_segmenter_options(
        &mut self,
        module: &Ir3Module,
        requested: Option<String>,
        options: &Value,
    ) -> Result<Vec<(&'static str, Value)>, InterpreterError> {
        const SERVICE: &str = "Segmenter";
        self.intl_string_option(
            module,
            options,
            "localeMatcher",
            &["lookup", "best fit"],
            SERVICE,
        )?;
        let granularity = self
            .intl_string_option(
                module,
                options,
                "granularity",
                &["grapheme", "word", "sentence"],
                SERVICE,
            )?
            .unwrap_or_else(|| "grapheme".to_string());
        Ok(vec![
            (
                "locale",
                Value::str(requested.unwrap_or_else(|| "en-US".to_string())),
            ),
            ("granularity", Value::str(granularity)),
        ])
    }

    /// `segmenter.segment(string)` (ECMA-402 18.3.3): a Segments object over
    /// ToString(string).
    pub(super) fn intl_segment(
        &mut self,
        resolved: ObjectId,
        input: String,
    ) -> Result<Value, InterpreterError> {
        let granularity = match self
            .heap
            .get(resolved.0 as usize)
            .and_then(|object| object.properties.get("granularity"))
        {
            Some(Value::Str(granularity)) => granularity.to_string(),
            _ => "grapheme".to_string(),
        };
        // Retain the preflight admission check before segmentation begins.
        // Records are now built and charged as pieces arrive, rather than
        // after staging a slice vector and a vector of owned segment tuples.
        // Removing those buffers must not widen the admitted input sizes.
        let code_units = u64::try_from(input.encode_utf16().count()).unwrap_or(u64::MAX);
        let transient = code_units.saturating_mul(SEGMENT_NATIVE_BYTES_PER_CODE_UNIT);
        let requested = self.estimated_memory_bytes.saturating_add(transient);
        if self.memory_request_exceeds_budget(requested, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested, self.heap_object_count_u32()));
        }
        if granularity == "word"
            && let Some(script) = input.chars().find_map(dictionary_script)
        {
            return Err(Self::intl_segmenter_refusal(script));
        }
        let input = JsString::from(input);
        let text = input
            .as_str()
            .expect("Intl.Segmenter input originates from a Rust String");
        let records = match granularity.as_str() {
            "word" => self.segment_records(text.split_word_bounds(), true)?,
            "sentence" => self.segment_records(text.split_sentence_bounds(), false)?,
            _ => self.segment_records(text.graphemes(true), false)?,
        };
        // Non-enumerable properties on the public object are not internal
        // slots: guests can still read and overwrite them. Only bound native
        // methods retain this private, null-prototype storage object.
        let storage = self.alloc_object_with_prototype(None)?;
        let count = i64::try_from(records.len()).map_err(|_| Self::segment_state_error())?;
        self.set_object_property(storage, "__input".to_string(), Value::Str(input))?;
        self.set_object_property(storage, "__count".to_string(), Value::Int(count))?;
        for (index, record) in records.into_iter().enumerate() {
            self.set_object_property(storage, index.to_string(), record)?;
        }
        let object = self.alloc_object_with_prototype(None)?;
        self.set_object_brand(object, "Intl.Segments")?;
        self.set_object_property(
            object,
            "containing".to_string(),
            Self::segment_builtin("containing", storage),
        )?;
        self.hide_internal_slots(object, &["containing"])?;
        let iterator = RuntimePropertyKey::Symbol(WellKnownSymbol::Iterator.id());
        self.set_object_runtime_property(
            object,
            iterator.clone(),
            Self::segment_builtin("iterator", storage),
        )?;
        self.set_own_property_attributes(object, &iterator, NON_ENUMERABLE_DATA_ATTRIBUTES)?;
        Ok(Value::Object(object))
    }

    fn segment_builtin(method: &str, bound: ObjectId) -> Value {
        Value::BuiltinFunction(BuiltinFunction {
            kind: BuiltinFunctionKind::IntlMethod,
            module_specifier: BuiltinModuleSpecifier::from_nonempty(&format!("Segments.{method}")),
            iterator_handle: None,
            bound_object: Some(bound.0),
        })
    }

    fn segment_state_error() -> InterpreterError {
        InterpreterError::InternalError {
            details: "Intl.Segmenter private state is missing or invalid".to_string(),
        }
    }

    fn segment_storage_info(&self, storage: ObjectId) -> Result<(JsString, usize), InterpreterError> {
        let object = self
            .heap
            .get(storage.0 as usize)
            .ok_or_else(Self::segment_state_error)?;
        match (
            object.properties.get("__input"),
            object.properties.get("__count"),
        ) {
            (Some(Value::Str(input)), Some(Value::Int(count))) => Ok((
                input.clone(),
                usize::try_from(*count).map_err(|_| Self::segment_state_error())?,
            )),
            _ => Err(Self::segment_state_error()),
        }
    }

    /// Borrow only the selected canonical record; never clone the entire
    /// collection. Storage is private, so getters and guest mutations cannot
    /// affect this read or change the ordering of its UTF-16 boundaries.
    fn segment_data_at(&self, storage: ObjectId, index: usize) -> Result<Segment, InterpreterError> {
        let record = self
            .heap
            .get(storage.0 as usize)
            .and_then(|object| object.properties.get(&index.to_string()));
        let Some(Value::Object(record)) = record else {
            return Err(Self::segment_state_error());
        };
        let object = self
            .heap
            .get(record.0 as usize)
            .ok_or_else(Self::segment_state_error)?;
        let (Some(Value::Str(text)), Some(Value::Int(start))) = (
            object.properties.get("segment"),
            object.properties.get("index"),
        ) else {
            return Err(Self::segment_state_error());
        };
        let word_like = match object.properties.get("isWordLike") {
            None => None,
            Some(Value::Bool(flag)) => Some(*flag),
            _ => return Err(Self::segment_state_error()),
        };
        Ok((
            text.clone(),
            usize::try_from(*start).map_err(|_| Self::segment_state_error())?,
            word_like,
        ))
    }

    /// `containing`, iterator creation, and native segment-iterator methods.
    pub(super) fn intl_segments_method(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        method: &str,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let bound = builtin.bound_object.map(ObjectId).ok_or_else(|| {
            InterpreterError::TypeError {
                expected: "an Intl.Segmenter Segments object".to_string(),
                got: "an object without segments".to_string(),
            }
        })?;
        match method {
            "next" => return self.segment_iterator_next(bound),
            "self" => return Ok(Value::Object(bound)),
            "iterator" => return self.segment_iterator(bound),
            "containing" => {}
            _ => return Err(Self::segment_state_error()),
        }
        let (input, count) = self.segment_storage_info(bound)?;
        // ToIntegerOrInfinity may call guest code. Canonical storage is not
        // reachable from any yielded record, even across that reentrant call.
        let index = match self.builtin_arg(args, 0)? {
            None | Some(Value::Undefined) => 0.0,
            Some(value) => {
                let number = self.intl_to_number(module, value)?;
                if number.is_nan() { 0.0 } else { number.trunc() }
            }
        };
        if index < 0.0 || index >= input.utf16_len() as f64 {
            return Ok(Value::Undefined);
        }
        self.segment_containing(bound, &input, count, index as usize)
    }

    fn segment_containing(
        &mut self,
        storage: ObjectId,
        input: &JsString,
        count: usize,
        index: usize,
    ) -> Result<Value, InterpreterError> {
        self.segment_containing_with_probe(storage, input, count, index, || {})
    }

    /// Canonical segments partition the input into nonempty, ordered UTF-16
    /// intervals. Binary search needs at most floor(log2(count)) + 1 record
    /// probes, rather than visiting and cloning every preceding record.
    /// The probe seam measures the actual production path in deterministic
    /// work-bound tests; the empty production closure specializes away.
    fn segment_containing_with_probe(
        &mut self,
        storage: ObjectId,
        input: &JsString,
        count: usize,
        index: usize,
        mut probe: impl FnMut(),
    ) -> Result<Value, InterpreterError> {
        if index >= input.utf16_len() {
            return Ok(Value::Undefined);
        }
        let (mut low, mut high) = (0, count);
        while low < high {
            self.json_charge_work()?;
            probe();
            let middle = low + (high - low) / 2;
            let segment = self.segment_data_at(storage, middle)?;
            if index < segment.1 {
                high = middle;
            } else if index - segment.1 < segment.0.utf16_len() {
                return self.segment_record(&segment, input).map(Value::Object);
            } else {
                low = middle + 1;
            }
        }
        Ok(Value::Undefined)
    }

    /// A private cursor avoids eagerly copying every record into a new array
    /// for each iterator. Advancing allocates only the delivered fresh record
    /// and its IteratorResult, while concurrent iterators keep separate state.
    fn segment_iterator(&mut self, storage: ObjectId) -> Result<Value, InterpreterError> {
        self.segment_storage_info(storage)?;
        let state = self.alloc_object_with_properties(&[
            ("__storage", Value::Object(storage)),
            ("__cursor", Value::Int(0)),
        ])?;
        let iterator = self.alloc_object_with_prototype(None)?;
        self.set_object_property(
            iterator,
            "next".to_string(),
            Self::segment_builtin("next", state),
        )?;
        self.hide_internal_slots(iterator, &["next"])?;
        let key = RuntimePropertyKey::Symbol(WellKnownSymbol::Iterator.id());
        self.set_object_runtime_property(
            iterator,
            key.clone(),
            Self::segment_builtin("self", iterator),
        )?;
        self.set_own_property_attributes(iterator, &key, NON_ENUMERABLE_DATA_ATTRIBUTES)?;
        let tag = RuntimePropertyKey::Symbol(WellKnownSymbol::ToStringTag.id());
        self.set_object_runtime_property(
            iterator,
            tag.clone(),
            Value::str("Segmenter String Iterator"),
        )?;
        self.set_own_property_attributes(
            iterator,
            &tag,
            PropertyAttributes {
                writable: false,
                enumerable: false,
                configurable: true,
            },
        )?;
        Ok(Value::Object(iterator))
    }

    fn segment_iterator_result(&mut self, value: Value, done: bool) -> Result<Value, InterpreterError> {
        self.alloc_object_with_properties(&[("value", value), ("done", Value::Bool(done))])
            .map(Value::Object)
    }

    fn segment_iterator_next(&mut self, state: ObjectId) -> Result<Value, InterpreterError> {
        self.json_charge_work()?;
        let slots = self
            .heap
            .get(state.0 as usize)
            .map(|object| {
                (
                    object.properties.get("__storage").cloned(),
                    object.properties.get("__cursor").cloned(),
                )
            })
            .ok_or_else(Self::segment_state_error)?;
        if matches!(&slots.0, Some(Value::Undefined)) {
            return self.segment_iterator_result(Value::Undefined, true);
        }
        let (Some(Value::Object(storage)), Some(Value::Int(cursor))) = slots else {
            return Err(Self::segment_state_error());
        };
        let cursor = usize::try_from(cursor).map_err(|_| Self::segment_state_error())?;
        let (input, count) = self.segment_storage_info(storage)?;
        if cursor >= count {
            // Exhaustion is sticky and no longer retains the input/records
            // solely for this iterator. Subsequent calls still get fresh results.
            self.set_object_property(state, "__storage".to_string(), Value::Undefined)?;
            return self.segment_iterator_result(Value::Undefined, true);
        }
        let segment = self.segment_data_at(storage, cursor)?;
        let record = self.segment_record(&segment, &input)?;
        let result = self.segment_iterator_result(Value::Object(record), false)?;
        // cursor < count <= i64::MAX, so advancing cannot overflow.
        self.set_object_property(state, "__cursor".to_string(), Value::Int((cursor + 1) as i64))?;
        Ok(result)
    }

    /// A segment data record `{ segment, index, input[, isWordLike] }`.
    fn segment_record(
        &mut self,
        segment: &Segment,
        input: &JsString,
    ) -> Result<ObjectId, InterpreterError> {
        self.segment_record_with_input(segment, Some(input))
    }

    /// Private canonical records need only the segment, start and word flag.
    /// The input lives once in their owning storage object. Including it in
    /// every private record charged its entire length per segment, despite
    /// sharing its immutable backing: ordinary grapheme input hit the memory
    /// budget quadratically before any result was requested. Public records
    /// still receive their own input property, in the specified key order,
    /// through the unchanged ordinary property-accounting path.
    fn segment_record_with_input(
        &mut self,
        (text, index, word_like): &Segment,
        input: Option<&JsString>,
    ) -> Result<ObjectId, InterpreterError> {
        let mut fields = vec![
            ("segment", Value::Str(text.clone())),
            (
                "index",
                Value::Int(i64::try_from(*index).unwrap_or(i64::MAX)),
            ),
        ];
        if let Some(input) = input {
            fields.push(("input", Value::Str(input.clone())));
        }
        if let Some(word_like) = word_like {
            fields.push(("isWordLike", Value::Bool(*word_like)));
        }
        self.alloc_object_with_properties(&fields)
    }

    /// Stream UAX #29 pieces directly into charged record objects. There is
    /// no full-input slice/tuple staging, and each piece gets one immutable
    /// text backing shared by all fresh records referring to that segment.
    fn segment_records<'a>(
        &mut self,
        pieces: impl Iterator<Item = &'a str>,
        word_granularity: bool,
    ) -> Result<Vec<Value>, InterpreterError> {
        let mut records = Vec::new();
        let mut index = 0;
        for piece in pieces {
            let text = JsString::from(piece);
            let end = index + text.utf16_len();
            let word_like = word_granularity.then(|| piece.chars().any(char::is_alphanumeric));
            let record = self.segment_record_with_input(&(text, index, word_like), None)?;
            records.push(Value::Object(record));
            index = end;
        }
        Ok(records)
    }

    fn intl_segmenter_refusal(script: &str) -> InterpreterError {
        InterpreterError::TypeError {
            expected: "text Intl.Segmenter can split into words without ICU dictionaries"
                .to_string(),
            got: format!("{script} text"),
        }
    }
}

/// The script of `c` when ICU splits its words with a dictionary, which
/// UAX #29 does not do.
fn dictionary_script(c: char) -> Option<&'static str> {
    match u32::from(c) {
        0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF | 0x20000..=0x323AF => Some("Han"),
        0x3040..=0x309F => Some("Hiragana"),
        0x30A0..=0x30FF | 0x31F0..=0x31FF | 0xFF66..=0xFF9F => Some("Katakana"),
        0x0E00..=0x0E7F => Some("Thai"),
        0x0E80..=0x0EFF => Some("Lao"),
        0x1780..=0x17FF | 0x19E0..=0x19FF => Some("Khmer"),
        0x1000..=0x109F | 0xA9E0..=0xA9FF | 0xAA60..=0xAA7F => Some("Myanmar"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string_property<'a>(core: &'a InterpreterCore, object: ObjectId, key: &str) -> &'a JsString {
        match core.heap[object.0 as usize].properties.get(key) {
            Some(Value::Str(text)) => text,
            other => panic!("expected string property {key}, got {other:?}"),
        }
    }

    fn object(value: Value) -> ObjectId {
        let Value::Object(id) = value else {
            panic!("expected object, got {value:?}");
        };
        id
    }

    fn bound(core: &InterpreterCore, object: ObjectId, method: &str) -> ObjectId {
        let Some(Value::BuiltinFunction(function)) = core.heap[object.0 as usize].properties.get(method)
        else {
            panic!("expected native {method} method");
        };
        ObjectId(function.bound_object.expect("bound state"))
    }

    fn fixture(core: &mut InterpreterCore, text: &str, granularity: &str) -> (ObjectId, ObjectId) {
        let resolved = core
            .alloc_object_with_properties(&[("granularity", Value::str(granularity))])
            .expect("resolved options");
        let segments = object(core.intl_segment(resolved, text.to_string()).expect("segments"));
        (segments, bound(core, segments, "containing"))
    }

    fn delivered(core: &mut InterpreterCore, state: ObjectId) -> Option<ObjectId> {
        let result = object(core.segment_iterator_next(state).expect("next"));
        let fields = &core.heap[result.0 as usize].properties;
        match (fields.get("value"), fields.get("done")) {
            (Some(Value::Object(record)), Some(Value::Bool(false))) => Some(*record),
            (Some(Value::Undefined), Some(Value::Bool(true))) => None,
            _ => panic!("invalid IteratorResult"),
        }
    }

    #[test]
    fn segmentation_records_share_input_backing_for_every_granularity() {
        for granularity in ["grapheme", "word", "sentence"] {
            let mut core = InterpreterCore::new(InterpreterConfig::default(), "segment-sharing");
            let input = "A\u{1f44d}\u{1f3fd} e\u{301}. Next!\r\n".repeat(32);
            let (segments, storage) = fixture(&mut core, &input, granularity);
            assert_ne!(segments, storage);
            assert!(!core.heap[segments.0 as usize].properties.contains_key("__input"));
            assert!(!core.heap[segments.0 as usize].properties.contains_key("__segments"));
            let (shared, count) = core.segment_storage_info(storage).expect("private storage");
            assert_eq!(shared.as_str(), Some(input.as_str()));
            assert_eq!(shared.utf16_len(), input.encode_utf16().count());
            assert!(count > 1, "fixture must exercise repeated records");
            for index in 0..count {
                let record = object(core.heap[storage.0 as usize].properties.get(&index.to_string()).unwrap().clone());
                assert!(!core.heap[record.0 as usize].properties.contains_key("input"));
                let canonical = core.segment_data_at(storage, index).expect("canonical data");
                let public = core.segment_record(&canonical, &shared).expect("public record");
                let stored = string_property(&core, public, "input");
                assert!(std::ptr::eq(
                    stored.as_str().expect("well-formed input"),
                    shared.as_str().expect("well-formed input"),
                ));
            }
        }
    }

    #[test]
    fn shared_input_does_not_alias_mutable_record_properties() {
        let mut core = InterpreterCore::new(InterpreterConfig::default(), "segment-identity");
        let input = JsString::from("x".repeat(1024));
        let segment = (JsString::from("x".repeat(512)), 0, None);
        let first = core.segment_record(&segment, &input).expect("first record");
        let second = core.segment_record(&segment, &input).expect("second record");
        assert_ne!(first, second);
        for record in [first, second] {
            assert!(std::ptr::eq(
                string_property(&core, record, "input").as_str().expect("well-formed input"),
                input.as_str().expect("well-formed input"),
            ));
            assert!(std::ptr::eq(
                string_property(&core, record, "segment").as_str().expect("well-formed segment"),
                segment.0.as_str().expect("well-formed segment"),
            ));
        }
        core.set_object_property(first, "segment".to_string(), Value::str("changed"))
            .expect("replace first record segment");
        assert_eq!(string_property(&core, second, "segment"), &segment.0);
        core.set_object_property(first, "input".to_string(), Value::str("changed"))
            .expect("replace first record input");
        assert_eq!(string_property(&core, first, "input").as_str(), Some("changed"));
        assert_eq!(string_property(&core, second, "input"), &input);
        assert_eq!(input.utf16_len(), 1024);
    }

    #[test]
    fn streamed_records_preserve_utf16_boundaries_and_word_flags() {
        let input = JsString::from("A\u{1f44d}\u{1f3fd} e\u{301}.\r\n");
        let text = input.as_str().expect("well-formed input");
        let expected = [
            ("A", 0, true),
            ("\u{1f44d}\u{1f3fd}", 1, false),
            (" ", 5, false),
            ("e\u{301}", 6, true),
            (".", 8, false),
            ("\r\n", 9, false),
        ];
        for word_granularity in [false, true] {
            let mut core = InterpreterCore::new(InterpreterConfig::default(), "segment-stream");
            let records = if word_granularity {
                core.segment_records(text.split_word_bounds(), true)
            } else {
                core.segment_records(text.graphemes(true), false)
            }
            .expect("stream records");
            assert_eq!(records.len(), expected.len());
            for (record, (piece, index, word_like)) in records.into_iter().zip(expected) {
                let Value::Object(record) = record else {
                    panic!("expected segment record");
                };
                assert_eq!(string_property(&core, record, "segment").as_str(), Some(piece));
                let properties = &core.heap[record.0 as usize].properties;
                assert_eq!(properties.get("index"), Some(&Value::Int(index)));
                let flag = word_granularity.then_some(Value::Bool(word_like));
                assert_eq!(properties.get("isWordLike"), flag.as_ref());
            }
        }
        let mut core = InterpreterCore::new(InterpreterConfig::default(), "sentence-stream");
        let records = core
            .segment_records(text.split_sentence_bounds(), false)
            .expect("stream sentence");
        assert_eq!(records.len(), 1);
        let Value::Object(record) = records[0].clone() else {
            panic!("expected sentence record");
        };
        assert_eq!(string_property(&core, record, "segment"), &input);
        assert_eq!(core.heap[record.0 as usize].properties.get("index"), Some(&Value::Int(0)));
        assert!(!core.heap[record.0 as usize].properties.contains_key("isWordLike"));
    }

    #[test]
    fn empty_segment_stream_does_not_allocate_records() {
        let mut core = InterpreterCore::new(InterpreterConfig::default(), "empty-segments");
        let before = core.heap.len();
        for word_granularity in [false, true] {
            let records = core
                .segment_records(std::iter::empty::<&str>(), word_granularity)
                .expect("empty stream");
            assert!(records.is_empty());
            assert_eq!(core.heap.len(), before);
        }
    }

    #[test]
    fn native_iterators_are_independent_and_never_deliver_canonical_records() {
        for granularity in ["grapheme", "word", "sentence"] {
            let mut core = InterpreterCore::new(InterpreterConfig::default(), "segment-cursors");
            let (_, storage) = fixture(&mut core, "A\u{1f44d}\u{1f3fd}. Next!", granularity);
            let (input, count) = core.segment_storage_info(storage).expect("storage");
            let first = object(core.segment_iterator(storage).expect("first iterator"));
            let second = object(core.segment_iterator(storage).expect("second iterator"));
            let a = bound(&core, first, "next");
            let b = bound(&core, second, "next");
            assert_ne!(first, second);
            assert_ne!(a, b);
            for slot in 0..count {
                let canonical = core.segment_data_at(storage, slot).expect("canonical segment");
                let left = delivered(&mut core, a).expect("first value");
                let right = delivered(&mut core, b).expect("second value");
                assert_ne!(left, right);
                assert_eq!(string_property(&core, left, "segment"), &canonical.0);
                assert!(std::ptr::eq(
                    string_property(&core, left, "segment").as_str().unwrap(),
                    canonical.0.as_str().unwrap(),
                ));
                core.set_object_property(left, "segment".to_string(), Value::str("changed")).unwrap();
                core.set_object_property(left, "index".to_string(), Value::Int(-1)).unwrap();
                core.set_object_property(left, "input".to_string(), Value::str("changed")).unwrap();
                assert_eq!(string_property(&core, right, "segment"), &canonical.0);
                assert_eq!(core.segment_data_at(storage, slot).unwrap(), canonical);
                let found = object(core.segment_containing(storage, &input, count, canonical.1).unwrap());
                assert_eq!(string_property(&core, found, "segment"), &canonical.0);
                assert_ne!(found, right);
            }
            for state in [a, b] {
                assert_eq!(delivered(&mut core, state), None);
                assert_eq!(delivered(&mut core, state), None);
                assert_eq!(core.heap[state.0 as usize].properties.get("__storage"), Some(&Value::Undefined));
            }
        }
    }

    #[test]
    fn iterator_creation_and_one_step_do_not_copy_the_collection() {
        let mut core = InterpreterCore::new(InterpreterConfig::default(), "segment-lazy-delivery");
        let (_, storage) = fixture(&mut core, &"x".repeat(256), "grapheme");
        let before = core.heap.len();
        let iterator = object(core.segment_iterator(storage).expect("iterator"));
        assert_eq!(core.heap.len() - before, 2, "only iterator and private cursor");
        let state = bound(&core, iterator, "next");
        let before = core.heap.len();
        assert!(delivered(&mut core, state).is_some());
        assert_eq!(core.heap.len() - before, 2, "only data record and IteratorResult");
    }

    #[test]
    fn empty_iterator_results_are_fresh_and_exhaustion_is_sticky() {
        let mut core = InterpreterCore::new(InterpreterConfig::default(), "segment-empty-iterator");
        let (_, storage) = fixture(&mut core, "", "grapheme");
        let iterator = object(core.segment_iterator(storage).unwrap());
        let state = bound(&core, iterator, "next");
        let first = object(core.segment_iterator_next(state).unwrap());
        core.set_object_property(first, "done".to_string(), Value::Bool(false)).unwrap();
        let second = object(core.segment_iterator_next(state).unwrap());
        assert_ne!(first, second);
        assert_eq!(core.heap[second.0 as usize].properties.get("done"), Some(&Value::Bool(true)));
        assert_eq!(core.heap[second.0 as usize].properties.get("value"), Some(&Value::Undefined));
    }

    #[test]
    fn private_segment_state_survives_collection_through_native_methods() {
        let mut core = InterpreterCore::new(InterpreterConfig::default(), "segment-gc");
        let (segments, storage) = fixture(&mut core, "a\u{1f44d}\u{1f3fd}b", "grapheme");
        core.set_reg(0, Value::Object(segments));
        core.collect_garbage().expect("collect with Segments root");
        let (input, count) = core.segment_storage_info(storage).expect("storage retained");
        assert_eq!(count, 3);
        assert_eq!(input.utf16_len(), 6);
        let iterator = object(core.segment_iterator(storage).unwrap());
        let state = bound(&core, iterator, "next");
        core.set_reg(0, Value::Object(iterator));
        core.collect_garbage().expect("collect with only iterator root");
        assert!(core.heap.get(segments.0 as usize).is_none());
        let first = delivered(&mut core, state).expect("first segment");
        assert_eq!(string_property(&core, first, "segment").as_str(), Some("a"));
        assert!(delivered(&mut core, state).is_some());
        assert!(delivered(&mut core, state).is_some());
        assert_eq!(delivered(&mut core, state), None);
        core.collect_garbage().expect("collect exhausted iterator");
        assert!(core.heap.get(storage.0 as usize).is_none());
        assert_eq!(delivered(&mut core, state), None);
    }

    #[test]
    fn exhausted_work_budget_does_not_advance_or_allocate_an_iterator_result() {
        let config = InterpreterConfig {
            instruction_budget: 0,
            ..InterpreterConfig::default()
        };
        let mut core = InterpreterCore::new(config, "segment-budget");
        let (_, storage) = fixture(&mut core, "abc", "grapheme");
        let iterator = object(core.segment_iterator(storage).unwrap());
        let state = bound(&core, iterator, "next");
        let before = core.heap.len();
        assert!(core.segment_iterator_next(state).is_err());
        assert_eq!(core.heap.len(), before);
        assert_eq!(core.heap[state.0 as usize].properties.get("__cursor"), Some(&Value::Int(0)));
        assert_eq!(core.heap[state.0 as usize].properties.get("__storage"), Some(&Value::Object(storage)));
    }

    #[test]
    fn segment_iterator_public_dispatch_matches_node_record_isolation() {
        let source = r#"
const seg = new Intl.Segmenter('en', { granularity: 'word' }).segment('Hi, 42!');
const a = seg[Symbol.iterator]();
const b = seg[Symbol.iterator]();
const x = a.next().value;
const y = b.next().value;
console.log(x === y, a[Symbol.iterator]() === a);
x.segment = 'bad'; x.index = 9000; x.input = 'bad'; x.isWordLike = false;
console.log(JSON.stringify(y), JSON.stringify(seg.containing(1)));
console.log([...seg].map(x => x.segment).join('|'));
console.log(seg.__segments, seg.__input, Object.prototype.toString.call(a));
for (const ignored of a) {}
const exhausted = a.next(); exhausted.done = false;
console.log(a.next().done, a.next().value);
const detached = (() => {
  const s = new Intl.Segmenter().segment('a👍🏽b');
  return s[Symbol.iterator]();
})();
console.log([...detached].map(x => x.index + ':' + x.segment).join('|'));
"#;
        let lines: Vec<String> = crate::HybridRouter::default()
            .eval(source)
            .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
            .console_output
            .into_iter()
            .map(|entry| entry.message)
            .collect();
        assert_eq!(lines, [
            "false true",
            r#"{"segment":"Hi","index":0,"input":"Hi, 42!","isWordLike":true} {"segment":"Hi","index":0,"input":"Hi, 42!","isWordLike":true}"#,
            "Hi|,| |42|!",
            "undefined undefined [object Segmenter String Iterator]",
            "true undefined",
            "0:a|1:👍🏽|5:b",
        ]);
    }

    #[test]
    fn containing_checks_every_utf16_position_with_logarithmic_record_probes() {
        for granularity in ["grapheme", "word", "sentence"] {
            let mut core = InterpreterCore::new(InterpreterConfig::default(), "segment-search");
            let text = "A\u{1f44d}\u{1f3fd} e\u{301}. Next!\r\n".repeat(32);
            let (_, storage) = fixture(&mut core, &text, granularity);
            let (input, count) = core.segment_storage_info(storage).unwrap();
            let canonical: Vec<Segment> = (0..count)
                .map(|slot| core.segment_data_at(storage, slot).unwrap())
                .collect();
            assert!(count > 1);
            let maximum_probes = (usize::BITS - count.leading_zeros()) as usize;
            // Reverse order starts with the former full-scan worst case and
            // includes low surrogates, combining marks and CRLF interiors.
            for index in (0..input.utf16_len()).rev() {
                let expected = canonical.iter().find(|segment| {
                    index >= segment.1 && index - segment.1 < segment.0.utf16_len()
                }).expect("canonical partition covers every code unit");
                let mut probes = 0;
                let before = core.heap.len();
                let found = object(core.segment_containing_with_probe(
                    storage, &input, count, index, || probes += 1,
                ).unwrap());
                assert!(probes > 0 && probes <= maximum_probes, "{granularity} at {index}: {probes}");
                assert_eq!(core.heap.len() - before, 1, "only the delivered record is allocated");
                assert_eq!(string_property(&core, found, "segment"), &expected.0);
                assert_eq!(string_property(&core, found, "input"), &input);
                let fields = &core.heap[found.0 as usize].properties;
                assert_eq!(fields.get("index"), Some(&Value::Int(expected.1 as i64)));
                let word_like = expected.2.map(Value::Bool);
                assert_eq!(fields.get("isWordLike"), word_like.as_ref());
            }
            for index in [input.utf16_len(), usize::MAX] {
                let mut probes = 0;
                let before = core.heap.len();
                let value = core.segment_containing_with_probe(
                    storage, &input, count, index, || probes += 1,
                ).unwrap();
                assert_eq!(value, Value::Undefined);
                assert_eq!(probes, 0);
                assert_eq!(core.heap.len(), before);
            }
        }
    }

    #[test]
    fn containing_empty_and_single_segment_boundaries() {
        for text in ["", "\u{1f44d}\u{1f3fd}"] {
            let mut core = InterpreterCore::new(InterpreterConfig::default(), "segment-search-boundary");
            let (_, storage) = fixture(&mut core, text, "grapheme");
            let (input, count) = core.segment_storage_info(storage).unwrap();
            assert_eq!(count, usize::from(!text.is_empty()));
            for index in 0..=input.utf16_len() {
                let mut probes = 0;
                let found = core.segment_containing_with_probe(
                    storage, &input, count, index, || probes += 1,
                ).unwrap();
                if index == input.utf16_len() {
                    assert_eq!(found, Value::Undefined);
                    assert_eq!(probes, 0);
                } else {
                    assert_eq!(probes, 1);
                    assert_eq!(string_property(&core, object(found), "segment"), &input);
                }
            }
        }
    }

    #[test]
    fn containing_budget_refusal_precedes_record_read_and_allocation() {
        let mut core = InterpreterCore::new(InterpreterConfig::default(), "segment-search-budget");
        let (_, storage) = fixture(&mut core, "abc", "grapheme");
        let (input, count) = core.segment_storage_info(storage).unwrap();
        core.config.instruction_budget = 0;
        let before = core.heap.len();
        let mut probes = 0;
        assert!(core.segment_containing_with_probe(
            storage, &input, count, 2, || probes += 1,
        ).is_err());
        assert_eq!(probes, 0);
        assert_eq!(core.heap.len(), before);
        assert_eq!(core.segment_data_at(storage, 2).unwrap().0.as_str(), Some("c"));
    }

    #[test]
    fn containing_public_dispatch_handles_coercion_and_reentrant_mutation() {
        let source = r#"
const s = new Intl.Segmenter().segment('a👍🏽b');
const inputs = [undefined, NaN, -0, 1.9, 3, 5, 6, -1, Infinity, '3'];
console.log(inputs.map(i => { const v = s.containing(i); return v ? v.index + ':' + v.segment : '-'; }).join('|'));
const index = { valueOf() { const v = s[Symbol.iterator]().next().value; v.index = 999; v.segment = 'bad'; return 3; } };
console.log(JSON.stringify(s.containing(index)));
const old = s.containing(3); old.segment = 'bad';
console.log(s.containing(3).segment, [...s].map(v => v.segment).join('|'));
"#;
        let lines: Vec<String> = crate::HybridRouter::default()
            .eval(source)
            .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
            .console_output
            .into_iter()
            .map(|entry| entry.message)
            .collect();
        assert_eq!(lines, [
            "0:a|0:a|0:a|1:👍🏽|1:👍🏽|5:b|-|-|-|1:👍🏽",
            r#"{"segment":"👍🏽","index":1,"input":"a👍🏽b"}"#,
            "👍🏽 a|👍🏽|b",
        ]);
    }

    #[test]
    fn canonical_segment_memory_grows_linearly_and_long_input_fits_default_budget() {
        let mut charges = Vec::new();
        for length in [4096, 8192] {
            let mut core = InterpreterCore::new(InterpreterConfig::default(), "segment-linear-memory");
            let before = core.estimated_memory_bytes;
            let (_, storage) = fixture(&mut core, &"x".repeat(length), "grapheme");
            let (input, count) = core.segment_storage_info(storage).expect("storage");
            assert_eq!(count, length);
            charges.push(core.estimated_memory_bytes - before);
            let last = object(core.segment_containing(storage, &input, count, length - 1).unwrap());
            assert_eq!(string_property(&core, last, "segment").as_str(), Some("x"));
            assert_eq!(string_property(&core, last, "input"), &input);
            assert_eq!(
                core.heap[last.0 as usize].properties.get("index"),
                Some(&Value::Int((length - 1) as i64)),
            );
        }
        // More keys and digits add linear metadata, not a second copy of
        // the whole input per segment. The old 8K case exhausted 64 MiB.
        assert!(charges[1] > charges[0]);
        assert!(charges[1] < charges[0] * 3, "charges: {charges:?}");
    }

    #[test]
    fn segment_input_preflight_still_refuses_before_allocating_records() {
        let mut core = InterpreterCore::new(InterpreterConfig::default(), "segment-admission");
        let resolved = core.alloc_object_with_properties(&[
            ("granularity", Value::str("grapheme")),
        ]).unwrap();
        let input = "x".repeat(1024);
        let before_heap = core.heap.len();
        let before_bytes = core.estimated_memory_bytes;
        core.config.max_total_memory_bytes = before_bytes
            + input.len() as u64 * SEGMENT_NATIVE_BYTES_PER_CODE_UNIT - 1;
        assert!(core.intl_segment(resolved, input).is_err());
        assert_eq!(core.heap.len(), before_heap);
        assert_eq!(core.estimated_memory_bytes, before_bytes);
    }

    #[test]
    fn long_segment_input_public_results_keep_all_fields_and_property_order() {
        let source = r#"
const input = 'x'.repeat(8192);
const segments = new Intl.Segmenter().segment(input);
const last = segments.containing(8191);
const first = segments[Symbol.iterator]().next().value;
console.log(last.segment, last.index, last.input === input);
console.log(first.segment, first.index, first.input === input);
console.log(Object.keys(last).join(','), segments.containing(8192));
const words = new Intl.Segmenter('en', { granularity: 'word' }).segment('A 12.');
console.log(Object.keys(words.containing(2)).join(','), words.containing(2).isWordLike);
"#;
        let lines: Vec<String> = crate::HybridRouter::default()
            .eval(source)
            .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
            .console_output
            .into_iter()
            .map(|entry| entry.message)
            .collect();
        assert_eq!(lines, [
            "x 8191 true",
            "x 0 true",
            "segment,index,input undefined",
            "segment,index,input,isWordLike true",
        ]);
    }
}
