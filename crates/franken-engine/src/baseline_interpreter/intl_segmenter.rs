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
//! the Segments object holds its methods as own properties (there is no
//! %SegmentsPrototype%); a lone surrogate in the input is read as U+FFFD.

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
        // Records own their properties, but their immutable input text can
        // share one backing. Copying the whole input for each segment made
        // grapheme segmentation allocate quadratically in the input length.
        let input = JsString::from(input);
        let text = input
            .as_str()
            .expect("Intl.Segmenter input originates from a Rust String");
        let records = match granularity.as_str() {
            "word" => self.segment_records(text.split_word_bounds(), &input, true)?,
            "sentence" => self.segment_records(text.split_sentence_bounds(), &input, false)?,
            _ => self.segment_records(text.graphemes(true), &input, false)?,
        };
        let list = self.alloc_array_from_values(&records)?;
        let object = self.alloc_object_with_prototype(None)?;
        self.set_object_brand(object, "Intl.Segments")?;
        self.set_object_property(object, "__segments".to_string(), Value::Object(list))?;
        self.set_object_property(object, "__input".to_string(), Value::Str(input))?;
        let method = |name: &str| {
            Value::BuiltinFunction(BuiltinFunction {
                kind: BuiltinFunctionKind::IntlMethod,
                module_specifier: BuiltinModuleSpecifier::from_nonempty(&format!(
                    "Segments.{name}"
                )),
                iterator_handle: None,
                bound_object: Some(object.0),
            })
        };
        self.set_object_property(object, "containing".to_string(), method("containing"))?;
        self.hide_internal_slots(object, &["__segments", "__input", "containing"])?;
        let iterator = RuntimePropertyKey::Symbol(WellKnownSymbol::Iterator.id());
        self.set_object_runtime_property(object, iterator.clone(), method("iterator"))?;
        self.set_own_property_attributes(object, &iterator, NON_ENUMERABLE_DATA_ATTRIBUTES)?;
        Ok(Value::Object(object))
    }

    /// `segments.containing(index)` and `segments[Symbol.iterator]()`.
    pub(super) fn intl_segments_method(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        method: &str,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let slots = builtin
            .bound_object
            .map(ObjectId)
            .and_then(|object| self.heap.get(object.0 as usize))
            .map(|object| {
                (
                    object.properties.get("__segments").cloned(),
                    object.properties.get("__input").cloned(),
                )
            });
        let Some((Some(Value::Object(list)), Some(Value::Str(input)))) = slots else {
            return Err(InterpreterError::TypeError {
                expected: "an Intl.Segmenter Segments object".to_string(),
                got: "an object without segments".to_string(),
            });
        };
        if method == "iterator" {
            return self.array_prototype_iterator_for_receiver(Value::Object(list), "values");
        }
        // ECMA-402 18.5.2.1: ToIntegerOrInfinity(index); outside the input
        // there is no segment.
        let index = match self.builtin_arg(args, 0)? {
            None | Some(Value::Undefined) => 0.0,
            Some(value) => {
                let number = self.intl_to_number(module, value)?;
                if number.is_nan() { 0.0 } else { number.trunc() }
            }
        };
        let length = input.utf16_len();
        if index < 0.0 || index >= length as f64 {
            return Ok(Value::Undefined);
        }
        let index = index as usize;
        let records = self.array_like_values(list)?;
        for record in records {
            let Value::Object(record) = record else {
                continue;
            };
            let (start, text) = match self.heap.get(record.0 as usize).map(|object| {
                (
                    object.properties.get("index").cloned(),
                    object.properties.get("segment").cloned(),
                )
            }) {
                Some((Some(Value::Int(start)), Some(Value::Str(text)))) => (start as usize, text),
                _ => continue,
            };
            if index >= start && index - start < text.utf16_len() {
                let word_like = self.heap.get(record.0 as usize).and_then(|object| {
                    match object.properties.get("isWordLike") {
                        Some(Value::Bool(flag)) => Some(*flag),
                        _ => None,
                    }
                });
                let fresh = self.segment_record(&(text, start, word_like), &input)?;
                return Ok(Value::Object(fresh));
            }
        }
        Ok(Value::Undefined)
    }

    /// A segment data record `{ segment, index, input[, isWordLike] }`.
    fn segment_record(
        &mut self,
        (text, index, word_like): &Segment,
        input: &JsString,
    ) -> Result<ObjectId, InterpreterError> {
        let mut fields = vec![
            ("segment", Value::Str(text.clone())),
            (
                "index",
                Value::Int(i64::try_from(*index).unwrap_or(i64::MAX)),
            ),
            ("input", Value::Str(input.clone())),
        ];
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
        input: &JsString,
        word_granularity: bool,
    ) -> Result<Vec<Value>, InterpreterError> {
        let mut records = Vec::new();
        let mut index = 0;
        for piece in pieces {
            let text = JsString::from(piece);
            let end = index + text.utf16_len();
            let word_like = word_granularity.then(|| piece.chars().any(char::is_alphanumeric));
            let record = self.segment_record(&(text, index, word_like), input)?;
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

    #[test]
    fn segmentation_records_share_input_backing_for_every_granularity() {
        for granularity in ["grapheme", "word", "sentence"] {
            let mut core = InterpreterCore::new(InterpreterConfig::default(), "segment-sharing");
            let resolved = core
                .alloc_object_with_properties(&[("granularity", Value::str(granularity))])
                .expect("resolved options");
            let input = "A\u{1f44d}\u{1f3fd} e\u{301}. Next!\r\n".repeat(32);
            let Value::Object(segments) = core
                .intl_segment(resolved, input.clone())
                .expect("segment input")
            else {
                panic!("expected Segments object");
            };
            let shared = string_property(&core, segments, "__input").clone();
            assert_eq!(shared.as_str(), Some(input.as_str()));
            assert_eq!(shared.utf16_len(), input.encode_utf16().count());
            let Some(Value::Object(list)) = core.heap[segments.0 as usize]
                .properties
                .get("__segments")
                .cloned()
            else {
                panic!("expected segment list");
            };
            let records = core.array_like_values(list).expect("read segment records");
            assert!(records.len() > 1, "fixture must exercise repeated records");
            for record in records {
                let Value::Object(record) = record else {
                    panic!("expected segment record");
                };
                let stored = string_property(&core, record, "input");
                // Content equality alone passed with the quadratic copies.
                // Every result must retain the very same immutable backing.
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
                string_property(&core, record, "input")
                    .as_str()
                    .expect("well-formed input"),
                input.as_str().expect("well-formed input"),
            ));
        }
        for record in [first, second] {
            assert!(std::ptr::eq(
                string_property(&core, record, "segment")
                    .as_str()
                    .expect("well-formed segment"),
                segment.0.as_str().expect("well-formed segment"),
            ));
        }
        core.set_object_property(first, "segment".to_string(), Value::str("changed"))
            .expect("replace first record segment");
        assert_eq!(string_property(&core, second, "segment"), &segment.0);
        core.set_object_property(first, "input".to_string(), Value::str("changed"))
            .expect("replace first record input");
        assert_eq!(
            string_property(&core, first, "input").as_str(),
            Some("changed")
        );
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
                core.segment_records(text.split_word_bounds(), &input, true)
            } else {
                core.segment_records(text.graphemes(true), &input, false)
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
            .segment_records(text.split_sentence_bounds(), &input, false)
            .expect("stream sentence");
        assert_eq!(records.len(), 1);
        let Value::Object(record) = records[0].clone() else {
            panic!("expected sentence record");
        };
        assert_eq!(string_property(&core, record, "segment"), &input);
        assert_eq!(
            core.heap[record.0 as usize].properties.get("index"),
            Some(&Value::Int(0))
        );
        assert!(
            !core.heap[record.0 as usize]
                .properties
                .contains_key("isWordLike")
        );
    }

    #[test]
    fn empty_segment_stream_does_not_allocate_records() {
        let mut core = InterpreterCore::new(InterpreterConfig::default(), "empty-segments");
        let input = JsString::from("");
        let before = core.heap.len();
        for word_granularity in [false, true] {
            let records = core
                .segment_records(std::iter::empty::<&str>(), &input, word_granularity)
                .expect("empty stream");
            assert!(records.is_empty());
            assert_eq!(core.heap.len(), before);
        }
    }
}
