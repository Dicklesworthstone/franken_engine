//! Legacy RegExp statics (bd-9vouw.113): `RegExp.$1`-`$9`, `input` (`$_`),
//! `lastMatch` (`$&`), `lastParen` (`$+`), `leftContext` (`` $` ``) and
//! `rightContext` (`$'`), as V8 and the TC39 legacy RegExp features proposal
//! define them. They read the realm's last successful match: exec, test,
//! match, matchAll, replace, split and search all record one, and a failed
//! match leaves the previous values. Before any match every one is "".
//!
//! IFC: the values are copies of a matched string, so they carry that
//! match's label. A match is recorded unlabelled; the innermost builtin call
//! that made it (a HostCall or a builtin function call) labels it with its
//! operands' label. A match nothing labelled reads as TopSecret.

use super::*;

/// The realm's last successful RegExp match.
#[derive(Debug, Clone)]
pub(super) struct LegacyRegExpMatch {
    /// Shared with the matched string when it is one already, so an exec
    /// loop does not copy its whole input per match (bd-9vouw.475).
    input: JsString,
    /// The whole match, then each capture group. Ordinary UTF-8 matches
    /// retain byte spans; code-unit matching records exact UTF-16 spans.
    spans: Vec<Option<(usize, usize)>>,
    utf16_spans: bool,
    label: Option<Label>,
}

/// The property names of the legacy statics.
pub(super) fn is_legacy_regexp_static(key: &str) -> bool {
    matches!(
        key,
        "$1" | "$2"
            | "$3"
            | "$4"
            | "$5"
            | "$6"
            | "$7"
            | "$8"
            | "$9"
            | "input"
            | "$_"
            | "lastMatch"
            | "$&"
            | "lastParen"
            | "$+"
            | "leftContext"
            | "$`"
            | "rightContext"
            | "$'"
    )
}

impl InterpreterCore {
    /// Record a match of `input`, sharing the string instead of copying it;
    /// spans are byte offsets in its UTF-8 projection.
    pub(super) fn record_legacy_regexp_match_shared(
        &mut self,
        input: &JsString,
        spans: &[Option<(usize, usize)>],
    ) {
        if spans.first().is_none_or(Option::is_none) {
            return;
        }
        self.legacy_regexp_match = Some(LegacyRegExpMatch {
            input: input.clone(),
            spans: spans.to_vec(),
            utf16_spans: false,
            label: None,
        });
        self.legacy_regexp_generation = self.legacy_regexp_generation.wrapping_add(1);
    }

    pub(super) fn record_legacy_regexp_input_match(
        &mut self,
        subject: &JsString,
        input: &RegExpInput<'_>,
        spans: &Captures,
    ) {
        if input.retained_bytes() == 0 && subject.is_well_formed() {
            self.record_legacy_regexp_match_shared(subject, spans);
        } else if spans.first().is_some_and(Option::is_some) {
            self.legacy_regexp_match = Some(LegacyRegExpMatch {
                input: subject.clone(),
                spans: input.unit_spans(spans),
                utf16_spans: true,
                label: None,
            });
            self.legacy_regexp_generation = self.legacy_regexp_generation.wrapping_add(1);
        }
    }

    /// After a builtin call that began at `generation`: a match it recorded
    /// and no inner call has labelled takes the call's operand label.
    pub(super) fn label_legacy_regexp_match(&mut self, generation: u64, label: &Label) {
        if self.legacy_regexp_generation == generation {
            return;
        }
        if let Some(record) = self.legacy_regexp_match.as_mut()
            && record.label.is_none()
        {
            record.label = Some(label.clone());
        }
    }

    /// The value of a legacy static. Its label goes to the reading
    /// GetProperty (`legacy_regexp_read_label`) and to an enclosing HostCall
    /// (the pending result label), so no read path drops it.
    pub(super) fn legacy_regexp_static_value(
        &mut self,
        key: &str,
    ) -> Result<Value, InterpreterError> {
        let Some(record) = self.legacy_regexp_match.as_ref() else {
            return Ok(Value::str(""));
        };
        let slice = |from: usize, to: usize| {
            if record.utf16_spans {
                let units: Vec<u16> = record
                    .input
                    .encode_utf16()
                    .skip(from)
                    .take(to - from)
                    .collect();
                JsString::from_code_units(&units)
            } else {
                JsString::from(&record.input[from..to])
            }
        };
        let text = |span: Option<&Option<(usize, usize)>>| {
            span.copied()
                .flatten()
                .map_or_else(|| JsString::from(""), |(from, to)| slice(from, to))
        };
        let (start, end) = record.spans[0].unwrap_or((0, 0));
        let length = if record.utf16_spans {
            record.input.utf16_len()
        } else {
            record.input.len()
        };
        let value = match key {
            "input" | "$_" => record.input.clone(),
            "lastMatch" | "$&" => text(record.spans.first()),
            "lastParen" | "$+" if record.spans.len() > 1 => text(record.spans.last()),
            "lastParen" | "$+" => JsString::from(""),
            "leftContext" | "$`" => slice(0, start),
            "rightContext" | "$'" => slice(end, length),
            group => {
                let index = group
                    .strip_prefix('$')
                    .and_then(|digit| digit.parse::<usize>().ok())
                    .unwrap_or(0);
                text(record.spans.get(index))
            }
        };
        let value = Value::Str(value);
        let label = record.label.clone().unwrap_or(Label::TopSecret);
        let pending = self
            .pending_hostcall_result_label
            .as_ref()
            .map_or_else(|| label.clone(), |pending| pending.join(&label));
        self.replace_pending_hostcall_result_label(Some(pending))?;
        self.legacy_regexp_read_label = Some(
            self.legacy_regexp_read_label
                .take()
                .map_or_else(|| label.clone(), |read| read.join(&label)),
        );
        Ok(value)
    }
}
