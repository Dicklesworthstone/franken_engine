//! Bounded literal superinstructions derived from the existing bytecode.
//!
//! Only adjacent Char instructions with the same direction can be combined.
//! Captures, alternatives, assertions and work charges stay in the ordinary
//! executor. The cache belongs to one Run and never changes compiled IR or
//! retains input values. No heap allocation is needed for these four blocks.

use super::{BacktrackError, BacktrackRegExp, Inst};

pub(super) const LITERAL_WIDTH: usize = 32;
const CACHE_SLOTS: usize = 4;

#[derive(Default)]
pub(super) struct LiteralBlocks {
    entries: [Option<LiteralBlock>; CACHE_SLOTS],
    #[cfg(test)]
    pub(super) disabled: bool,
    #[cfg(test)]
    compilations: usize,
}

pub(super) struct LiteralBlock {
    pc: usize,
    pub(super) len: usize,
    backward: bool,
    // Physical input order, reversed from instruction order for lookbehind.
    // Case-insensitive literals are canonicalized once, exactly as Char does.
    text: [char; LITERAL_WIDTH],
}

impl LiteralBlocks {
    pub(super) fn at(&mut self, regexp: &BacktrackRegExp, pc: usize) -> Option<&LiteralBlock> {
        #[cfg(test)]
        if self.disabled {
            return None;
        }
        // Mix block-sized strides as well as low bits. A direct-mapped cache
        // bounds both lookup work and storage even on adversarial bytecode.
        let slot = (pc ^ (pc / LITERAL_WIDTH)) % CACHE_SLOTS;
        if self.entries[slot].as_ref().is_none_or(|entry| entry.pc != pc) {
            let Inst::Char { backward, .. } = regexp.program.get(pc)? else {
                return None;
            };
            let mut block = LiteralBlock {
                pc,
                len: 0,
                backward: *backward,
                text: ['\0'; LITERAL_WIDTH],
            };
            for instruction in regexp.program[pc..].iter().take(LITERAL_WIDTH) {
                let Inst::Char { c, backward } = instruction else {
                    break;
                };
                if *backward != block.backward {
                    break;
                }
                block.text[block.len] = if regexp.ignore_case {
                    regexp.canonicalize(*c)
                } else {
                    *c
                };
                block.len += 1;
            }
            if block.backward {
                block.text[..block.len].reverse();
            }
            #[cfg(test)]
            {
                self.compilations += 1;
            }
            self.entries[slot] = Some(block);
        }
        self.entries[slot].as_ref().filter(|block| block.len >= 2)
    }
}

impl LiteralBlock {
    /// The dispatch loop already paid for the first Char. Examine only the
    /// affordable prefix and debit the remaining instructions in aggregate.
    /// A mismatch pays for that failing Char; EOF also requires an affordable
    /// failing Char. Exhaustion before it is an error, never a false no-match.
    pub(super) fn execute_after_dispatch(
        &self,
        regexp: &BacktrackRegExp,
        chars: &[char],
        position: usize,
        steps_left: &mut u64,
    ) -> Result<Option<usize>, BacktrackError> {
        debug_assert!(position <= chars.len());
        debug_assert!(*steps_left < u64::MAX, "first instruction was charged");
        let affordable = (*steps_left + 1).min(self.len as u64) as usize;
        let available = if self.backward {
            position
        } else {
            chars.len() - position
        };
        let count = affordable.min(available);
        let (actual, expected) = if self.backward {
            (
                &chars[position - count..position],
                &self.text[self.len - count..self.len],
            )
        } else {
            (&chars[position..position + count], &self.text[..count])
        };
        let mismatch = if !regexp.ignore_case && actual == expected {
            None
        } else {
            let differs = |(&actual, &expected): (&char, &char)| {
                if regexp.ignore_case {
                    regexp.canonicalize(actual) != expected
                } else {
                    actual != expected
                }
            };
            if self.backward {
                actual.iter().zip(expected).rev().position(differs)
            } else {
                actual.iter().zip(expected).position(differs)
            }
        };
        if let Some(before_mismatch) = mismatch {
            // N successes + one failure, less the already paid instruction.
            *steps_left -= before_mismatch as u64;
            return Ok(None);
        }
        if count == self.len {
            *steps_left -= (count - 1) as u64;
            return Ok(Some(if self.backward {
                position - count
            } else {
                position + count
            }));
        }
        if count == affordable {
            *steps_left = 0;
            return Err(BacktrackError::StepBudget);
        }
        // All remaining input matched, and the next (EOF) test is affordable.
        *steps_left -= count as u64;
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{PreparedInput, Run};
    use super::*;

    fn compare(
        regexp: &BacktrackRegExp,
        input: &PreparedInput,
        start: usize,
        sticky: bool,
        budget: u64,
    ) {
        let mut actual = Run::new(regexp, input, budget);
        let mut reference = Run::new(regexp, input, budget);
        reference.literal_blocks.disabled = true;
        for at in [start, 0, input.char_len() + 1] {
            assert_eq!(
                actual.search(at, sticky),
                reference.search(at, sticky),
                "start={at} sticky={sticky} budget={budget}"
            );
            assert_eq!(actual.steps_left, reference.steps_left, "exact work charge");
            assert_eq!(actual.slots, reference.slots, "partial capture state");
            assert_eq!(actual.registers, reference.registers, "partial register state");
            assert!(actual.stack.is_empty());
            assert!(actual.capture_seen.iter().all(|seen| !seen));
        }
    }

    #[test]
    fn literal_blocks_match_scalar_dispatch_through_backtracking_and_lookaround() {
        for (pattern, flags) in [
            ("(abcdef)", ""),
            ("(abcde)f|abcdex", ""),
            ("(abcdef)|()", ""),
            ("(?:(abcde)|(abcdf))+x", ""),
            ("(?=(abcdef))abcde\\1", ""),
            ("(?!(abcdef))abcdex", ""),
            ("(?<=abcde)(fx)", ""),
            ("(?<!abcde)(fx)", ""),
            ("(?<=(abcde)|(bcdef))(x)", ""),
            ("(?:abcdef){17,20}x", ""),
            ("(?<=(abcdef){2})(x)", ""),
            ("(kſΣé😀)x", "iu"),
            ("(kſΣé😀)x", "i"),
            ("(?<=kſΣé😀)(x)", "iu"),
        ] {
            let regexp = BacktrackRegExp::new(pattern, flags).expect(pattern);
            for text in ["", "abc", "abcdef", "abcdex", "abcdefx", "abcdefabcdefx", "KsςÉ😀x"] {
                let input = PreparedInput::new(text);
                for start in 0..=input.char_len() + 1 {
                    for sticky in [false, true] {
                        for budget in (0..=96).chain([127, 255, 1024]) {
                            compare(&regexp, &input, start, sticky, budget);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn every_block_mismatch_and_eof_position_has_the_scalar_charge() {
        for length in [2, 3, 7, 31, 32] {
            for backward in [false, true] {
                let mut regexp = BacktrackRegExp::new("", "").unwrap();
                let literals: Vec<_> = (0..length).map(|index| char::from(b'a' + (index % 23) as u8)).collect();
                regexp.program = literals.iter().map(|&c| Inst::Char { c, backward }).collect();
                regexp.program.push(Inst::Match);
                for input_length in 0..=length + 1 {
                    for mismatch in 0..=length {
                        let mut chars: Vec<_> = literals.iter().copied().take(input_length).collect();
                        if input_length > length { chars.push('x'); }
                        if mismatch < chars.len() { chars[mismatch] = '!'; }
                        if backward { chars.reverse(); }
                        let position = if backward { chars.len() } else { 0 };
                        let mut blocks = LiteralBlocks::default();
                        let block = blocks.at(&regexp, 0).unwrap();
                        for budget in (1..=length as u64 + 2).chain([u64::MAX]) {
                            let mut remaining = budget - 1;
                            let actual = block.execute_after_dispatch(&regexp, &chars, position, &mut remaining);
                            let mut expected_remaining = budget;
                            let mut expected = Ok(Some(position));
                            for &literal in &literals {
                                if expected_remaining == 0 {
                                    expected = Err(BacktrackError::StepBudget);
                                    break;
                                }
                                expected_remaining -= 1;
                                let at = expected.as_ref().unwrap().unwrap();
                                let matched = if backward {
                                    at.checked_sub(1).filter(|&index| chars.get(index) == Some(&literal))
                                } else {
                                    (chars.get(at) == Some(&literal)).then_some(at + 1)
                                };
                                expected = Ok(matched);
                                if matched.is_none() { break; }
                            }
                            assert_eq!(actual, expected, "len={length} reverse={backward} input={input_length} mismatch={mismatch} budget={budget}");
                            assert_eq!(remaining, expected_remaining);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn blocks_stop_at_capture_and_direction_boundaries() {
        let mut regexp = BacktrackRegExp::new("ab(cd)ef", "").unwrap();
        let mut blocks = LiteralBlocks::default();
        let block = blocks.at(&regexp, 1).unwrap();
        assert_eq!(block.len, 2);
        regexp.program = vec![
            Inst::Char { c: 'a', backward: false },
            Inst::Char { c: 'b', backward: false },
            Inst::Char { c: 'c', backward: true },
            Inst::Char { c: 'd', backward: true },
            Inst::Match,
        ];
        // Each Run owns its immutable program; a different program gets a
        // different cache, never stale entries from the previous compilation.
        let mut blocks = LiteralBlocks::default();
        assert_eq!(blocks.at(&regexp, 0).unwrap().len, 2);
        let backward = blocks.at(&regexp, 2).unwrap();
        assert!(backward.backward);
        assert_eq!(&backward.text[..backward.len], &['d', 'c']);
    }

    #[test]
    fn matching_long_literals_reduce_actual_dispatches_without_changing_work() {
        for backwards in [false, true] {
            let literal = "abcdefghijklmnop".repeat(128);
            let pattern = if backwards { format!("(?<=({literal}))x") } else { format!("({literal})x") };
            let regexp = BacktrackRegExp::new(&pattern, "").unwrap();
            let text = format!("{literal}x");
            let input = PreparedInput::new(&text);
            let start = if backwards { literal.len() } else { 0 };
            let mut actual = Run::new(&regexp, &input, 100_000);
            let mut reference = Run::new(&regexp, &input, 100_000);
            reference.literal_blocks.disabled = true;
            assert_eq!(actual.search(start, true), reference.search(start, true));
            assert_eq!(actual.slots, reference.slots);
            assert_eq!(actual.steps_left, reference.steps_left);
            assert!(actual.literal_dispatches < 70, "{} literal dispatches", actual.literal_dispatches);
            assert_eq!(reference.literal_dispatches, 2049);
        }
    }

    #[test]
    fn cached_blocks_are_bounded_reused_and_do_not_survive_a_run() {
        let regexp = BacktrackRegExp::new("(?:abcdef)+x", "i").unwrap();
        let input = PreparedInput::new("ABCDEFabcdefx");
        let mut run = Run::new(&regexp, &input, 100_000);
        assert!(run.search(0, true).unwrap().is_some());
        let compilations = run.literal_blocks.compilations;
        assert!(compilations > 0);
        assert!(run.search(0, true).unwrap().is_some());
        // A repeated site is a hit; other sites may legitimately collide in
        // the bounded cache. Do not depend on the compiler's block placement.
        let pc = regexp.program.windows(2).position(|pair| matches!(pair,
            [Inst::Char { .. }, Inst::Char { .. }])).unwrap();
        assert!(run.literal_blocks.at(&regexp, pc).is_some());
        let compiled = run.literal_blocks.compilations;
        assert!(run.literal_blocks.at(&regexp, pc).is_some());
        assert_eq!(run.literal_blocks.compilations, compiled);
        assert!(run.literal_blocks.entries.iter().flatten().count() <= CACHE_SLOTS);
        assert!(run.literal_blocks.entries.iter().flatten().all(|block| block.len <= LITERAL_WIDTH));
        let fresh = Run::new(&regexp, &input, 100_000);
        assert_eq!(fresh.literal_blocks.compilations, 0);
        assert!(fresh.literal_blocks.entries.iter().all(Option::is_none));
    }

    #[test]
    fn fixed_capture_spans_match_live_node_reference_results() {
        // Captured with Node v22.16.0 / V8 12.4.254.21-node.26. Convert its
        // UTF-16 `d` indices to byte offsets, the native Captures contract.
        // These are fixed observables, not another call to the scalar path.
        let cases: &[(&str, &str, &str, &[Option<(usize, usize)>])] = &[
            (
                "(abcdefghijklmnop){2}\\1", "",
                "xxabcdefghijklmnopabcdefghijklmnopabcdefghijklmnop",
                &[Some((2, 50)), Some((18, 34))],
            ),
            (
                "(?<=(abcdefghijklmnop))(x)", "", "abcdefghijklmnopx",
                &[Some((16, 17)), Some((0, 16)), Some((16, 17))],
            ),
            (
                "(?!(abcdefghijklmnop)q)abcdefghijklmnopx", "", "abcdefghijklmnopx",
                &[Some((0, 17)), None],
            ),
            (
                "(abcdefghijklmnop)q|((abcdefghijklmnop)x)", "", "abcdefghijklmnopx",
                &[Some((0, 17)), None, Some((0, 17)), Some((0, 16))],
            ),
            (
                "(?=(abcdefghijklmnop)x)abcdefghijklmnopx", "", "abcdefghijklmnopx",
                &[Some((0, 17)), Some((0, 16))],
            ),
            (
                "(?<=(kſΣé😀))(x)", "iu", "KsςÉ😀x",
                &[Some((12, 13)), Some((0, 12)), Some((12, 13))],
            ),
        ];
        for &(pattern, flags, text, expected) in cases {
            let regexp = BacktrackRegExp::new(pattern, flags).expect(pattern);
            let input = PreparedInput::new(text);
            let mut run = Run::new(&regexp, &input, 1_000_000);
            let actual = run.search(0, false).unwrap().expect("match");
            assert_eq!(actual, expected, "/{pattern}/{flags} on {text:?}");
        }
    }
}
