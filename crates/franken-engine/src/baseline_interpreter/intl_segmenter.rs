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
type Segment = (String, usize, Option<bool>);

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
        let segments = Self::split_segments(&input, &granularity)?;
        let mut records = Vec::with_capacity(segments.len());
        for segment in &segments {
            records.push(Value::Object(self.segment_record(segment, &input)?));
        }
        let list = self.alloc_array_from_values(&records)?;
        let object = self.alloc_object_with_prototype(None)?;
        self.set_object_brand(object, "Intl.Segments")?;
        self.set_object_property(object, "__segments".to_string(), Value::Object(list))?;
        self.set_object_property(object, "__input".to_string(), Value::str(input))?;
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
        let input = input.to_string();
        let length = input.encode_utf16().count();
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
                Some((Some(Value::Int(start)), Some(Value::Str(text)))) => {
                    (start as usize, text.to_string())
                }
                _ => continue,
            };
            if index >= start && index < start + text.encode_utf16().count() {
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
        input: &str,
    ) -> Result<ObjectId, InterpreterError> {
        let mut fields = vec![
            ("segment", Value::str(text.clone())),
            (
                "index",
                Value::Int(i64::try_from(*index).unwrap_or(i64::MAX)),
            ),
            ("input", Value::str(input.to_string())),
        ];
        if let Some(word_like) = word_like {
            fields.push(("isWordLike", Value::Bool(*word_like)));
        }
        self.alloc_object_with_properties(&fields)
    }

    /// The segments of `input` at `granularity`, with UTF-16 indices.
    fn split_segments(input: &str, granularity: &str) -> Result<Vec<Segment>, InterpreterError> {
        let pieces: Vec<&str> = match granularity {
            "word" => {
                if let Some(script) = input.chars().find_map(dictionary_script) {
                    return Err(Self::intl_segmenter_refusal(script));
                }
                input.split_word_bounds().collect()
            }
            "sentence" => input.split_sentence_bounds().collect(),
            _ => input.graphemes(true).collect(),
        };
        let mut index = 0;
        Ok(pieces
            .into_iter()
            .map(|piece| {
                let start = index;
                index += piece.encode_utf16().count();
                let word_like =
                    (granularity == "word").then(|| piece.chars().any(char::is_alphanumeric));
                (piece.to_string(), start, word_like)
            })
            .collect())
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
