//! Bounded lexical runs over an already-flat, well-formed UTF-8 leaf.
//!
//! Only runs that leave the scanner state unchanged are batched. Their exact
//! UTF-16 length is charged within the current work interval; no cancellation
//! checkpoint, malformed unit or grammar transition may be crossed by a run.

use super::{InterpreterCore, InterpreterError, RawScanner, RawState, ValidationWork};

/// Return a scalar-aligned prefix and its UTF-16 length. UTF-8 has at least
/// one byte per UTF-16 unit, so a byte window bounded by the available unit
/// allowance is conservative. At a short boundary the scalar path takes over.
fn unchanged_prefix(state: RawState, text: &str, allowance: usize) -> (usize, usize) {
    let window = text.len().min(allowance).min(256);
    let bytes = &text.as_bytes()[..window];
    match state {
        RawState::Integer | RawState::Fraction | RawState::Exponent => {
            let end = bytes
                .iter()
                .position(|byte| !byte.is_ascii_digit())
                .unwrap_or(window);
            (end, end)
        }
        RawState::String => {
            // Non-ASCII bytes cannot spell JSON punctuation or controls.
            let mut end = bytes
                .iter()
                .position(|&byte| byte < 0x20 || byte == b'"' || byte == b'\\')
                .unwrap_or(window);
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            // Count without decoding: each scalar lead is one UTF-16 unit,
            // and an astral lead contributes its second surrogate unit.
            let units = bytes[..end].iter().fold(0, |count, &byte| {
                count + usize::from(byte & 0xc0 != 0x80) + usize::from(byte >= 0xf0)
            });
            (end, units)
        }
        _ => (0, 0),
    }
}

impl RawScanner {
    pub(super) fn feed_utf8(
        &mut self,
        core: &mut InterpreterCore,
        mut text: &str,
        work: &mut ValidationWork,
    ) -> Result<bool, InterpreterError> {
        while !text.is_empty() {
            // Admit the first unit before looking ahead. A run uses only the
            // rest of this already-admitted interval and needs no scratch.
            work.tick(core)?;
            let (bytes, units) = unchanged_prefix(self.state, text, work.remaining + 1);
            if bytes != 0 {
                debug_assert!(units != 0 && units <= work.remaining + 1);
                work.remaining -= units - 1;
                text = &text[bytes..];
                continue;
            }
            let scalar = text.chars().next().expect("nonempty UTF-8 leaf");
            let mut pair = [0; 2];
            let units = scalar.encode_utf16(&mut pair);
            if !self.feed(units[0]) {
                return Ok(false);
            }
            for &unit in &units[1..] {
                // An astral scalar may cross the work boundary between its
                // two halves. Preserve that partial scanner state on refusal.
                work.tick(core)?;
                if !self.feed(unit) {
                    return Ok(false);
                }
            }
            text = &text[scalar.len_utf8()..];
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::{
        CancellationToken, InterpreterConfig, JsString, RuntimeCapability,
    };
    use super::*;

    fn core() -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        InterpreterCore::new(config, "raw-json-utf8-runs")
    }

    fn compare(prefix: &str, chunks: &[&str], remaining: usize, budget: u64, cancel: bool) {
        let mut actual = RawScanner::default();
        let mut expected = RawScanner::default();
        for unit in prefix.encode_utf16() {
            assert_eq!(actual.feed(unit), expected.feed(unit));
        }
        let mut actual_core = core();
        let mut expected_core = core();
        for core in [&mut actual_core, &mut expected_core] {
            core.config.instruction_budget = core.instructions_executed + budget;
            core.json_reserve_temporary(77).unwrap();
            core.config.max_total_memory_bytes = core.estimated_memory_bytes();
            if cancel {
                let token = CancellationToken::new();
                token.cancel();
                core.config.cancellation_token = Some(token);
            }
        }
        let mut actual_work = ValidationWork { remaining };
        let mut expected_work = ValidationWork { remaining };
        for chunk in chunks {
            let got = actual.feed_utf8(&mut actual_core, chunk, &mut actual_work);
            let want = (|| {
                for unit in chunk.encode_utf16() {
                    expected_work.tick(&mut expected_core)?;
                    if !expected.feed(unit) {
                        return Ok(false);
                    }
                }
                Ok::<_, InterpreterError>(true)
            })();
            assert_eq!(
                got, want,
                "prefix={prefix:?}, chunk={chunk:?}, budget={budget}"
            );
            assert_eq!(actual.state, expected.state);
            assert_eq!(actual.complete(), expected.complete());
            assert_eq!(actual_work.remaining, expected_work.remaining);
            assert_eq!(
                actual_core.instructions_executed,
                expected_core.instructions_executed
            );
            if got != Ok(true) {
                break;
            }
        }
        for core in [&mut actual_core, &mut expected_core] {
            assert_eq!(core.json_parse_temporary_bytes, 77);
            assert!(core.pending_exception.is_none());
            core.json_release_temporary(77);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }

    #[test]
    fn runs_preserve_every_lexical_transition_and_partial_budget_state() {
        let prefixes = [
            "", "-", "0", "1", "1.", "1.2", "1e", "1e+", "1e1", "\"", "\"\\", "\"\\u",
            "\"\\u0", "\"\\u00", "\"\\u000", "t", "tr", "tru", "true", "f", "fa", "fal", "fals",
            "n", "nu", "nul", "[", "\"done\"",
        ];
        for prefix in prefixes {
            for text in [
                "", "0", "12345.6E-7", "日😀abc\"", "\\uD800\"", "true", "\n",
            ] {
                for remaining in [0, 1, 2, 255] {
                    for budget in [0, 1, 4] {
                        compare(prefix, &[text], remaining, budget, false);
                    }
                }
            }
        }
    }

    #[test]
    fn unicode_and_all_ascii_bytes_keep_window_and_cancellation_boundaries() {
        for position in [0, 1, 63, 252, 253, 254, 255, 256, 511] {
            for scalar in ['é', '日', '😀', '\u{10ffff}'] {
                let text = format!("{}{scalar}\\uD800\"", "a".repeat(position));
                for remaining in [0, 1, 2, 3, 255] {
                    for budget in [0, 1, 8] {
                        compare("\"", &[&text], remaining, budget, false);
                    }
                    compare("\"", &[&text], remaining, 8, true);
                }
            }
        }
        for byte in 0u8..=127 {
            let text = format!("{}{}😀\"", "a".repeat(255), char::from(byte));
            compare("\"", &[&text], 0, 8, false);
        }
    }

    #[test]
    fn lexical_runs_span_leaves_without_resetting_state_or_work() {
        for text in [
            "-123456.789E-12",
            "\"aé日😀\\uD800\\n\\\"z\"",
            "false",
            "\"bad\\u12xz\"",
        ] {
            let boundaries: Vec<_> = (0..=text.len())
                .filter(|&i| text.is_char_boundary(i))
                .collect();
            for &first in &boundaries {
                for &second in boundaries.iter().filter(|&&i| i >= first) {
                    let chunks = [&text[..first], &text[first..second], &text[second..]];
                    for budget in [0, 1, 4] {
                        compare("", &chunks, 1, budget, false);
                    }
                }
            }
        }
    }

    #[test]
    fn run_proofs_are_bounded_and_cannot_hide_numeric_or_escape_transitions() {
        for state in [RawState::Integer, RawState::Fraction, RawState::Exponent] {
            assert_eq!(
                unchanged_prefix(state, &"9".repeat(65_536), usize::MAX),
                (256, 256)
            );
            for tail in [".", "e", "E", "-", "+", "x", "日", "😀"] {
                assert_eq!(unchanged_prefix(state, &format!("123{tail}"), 256), (3, 3));
            }
        }
        for allowance in 0..=256 {
            for text in ["plain ASCII", "é日😀", "😀\"", "日\\", "é\n", "\u{10ffff}"] {
                let (bytes, units) = unchanged_prefix(RawState::String, text, allowance);
                assert!(bytes <= allowance && bytes <= 256 && text.is_char_boundary(bytes));
                assert_eq!(units, text[..bytes].encode_utf16().count());
                assert!(units <= allowance);
                assert!(
                    text[..bytes]
                        .bytes()
                        .all(|b| b >= 0x20 && b != b'"' && b != b'\\')
                );
            }
        }
        for state in [
            RawState::Start,
            RawState::Zero,
            RawState::Escape,
            RawState::Hex(4),
            RawState::Done,
        ] {
            assert_eq!(unchanged_prefix(state, "1234abcd", 256), (0, 0));
        }
    }

    #[test]
    fn production_validation_keeps_flat_exact_and_unjoined_inputs_equivalent() {
        let left = format!("\"{}\\u", "aé日😀".repeat(256));
        let right = "D800\"";
        let rope = JsString::from(left.clone()).concat(&JsString::from(right));
        assert!(rope.unjoined_concat_children().is_some());
        let exact = JsString::from_code_units(&[0x22, 0xd800, 0x61, 0xdc00, 0x22]);
        for input in [JsString::from(format!("{left}{right}")), rope.clone(), exact] {
            let mut expected = RawScanner::default();
            for unit in input.encode_utf16() {
                assert!(expected.feed(unit));
            }
            let mut core = core();
            assert_eq!(
                core.json_raw_text_is_valid(&input).unwrap(),
                expected.complete()
            );
            assert_eq!(core.json_parse_temporary_bytes, 0);
            assert!(core.pending_exception.is_none());
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
        assert!(rope.unjoined_concat_children().is_some());
    }
}
