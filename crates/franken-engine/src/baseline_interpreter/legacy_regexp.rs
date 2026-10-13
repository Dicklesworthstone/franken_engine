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
    /// Byte spans in `input`'s UTF-8 projection: the whole match, then each
    /// capture group.
    spans: Vec<Option<(usize, usize)>>,
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
    /// Record a successful match of `input` (UpdateLegacyRegExpStaticProperties).
    pub(super) fn record_legacy_regexp_match(
        &mut self,
        input: &str,
        spans: &[Option<(usize, usize)>],
    ) {
        self.record_legacy_regexp_match_shared(&JsString::from(input), spans);
    }

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
            label: None,
        });
        self.legacy_regexp_generation = self.legacy_regexp_generation.wrapping_add(1);
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
        let text = |span: Option<&Option<(usize, usize)>>| {
            span.copied()
                .flatten()
                .map_or("", |(from, to)| &record.input[from..to])
        };
        let (start, end) = record.spans[0].unwrap_or((0, 0));
        let value = match key {
            "input" | "$_" => record.input.as_utf8_projection(),
            "lastMatch" | "$&" => text(record.spans.first()),
            "lastParen" | "$+" if record.spans.len() > 1 => text(record.spans.last()),
            "lastParen" | "$+" => "",
            "leftContext" | "$`" => &record.input[..start],
            "rightContext" | "$'" => &record.input[end..],
            group => {
                let index = group
                    .strip_prefix('$')
                    .and_then(|digit| digit.parse::<usize>().ok())
                    .unwrap_or(0);
                text(record.spans.get(index))
            }
        };
        let value = Value::str(value);
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
