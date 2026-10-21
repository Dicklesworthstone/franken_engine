//! ISO-2022-JP designation/byte recovery, sharing the existing JIS0208 index.
//!
//! No input queue is retained. Three packed bytes encode phase, output mode,
//! leading byte and the consecutive-designation flag in the existing decoder
//! slot. A two-byte local replay stack handles malformed escapes, including
//! their EOF recovery. Empty streaming input is not EOF.
//!
//! Algorithm: https://encoding.spec.whatwg.org/#iso-2022-jp-decoder
//! Fatal errors retain the surrounding decoder's reset policy, not the
//! standard's unconsumed-input-queue behavior on reuse after a fatal error.

use super::{DecodeState, JsString, index};

const ASCII: u8 = 0;
const ROMAN: u8 = 1;
const KATAKANA: u8 = 2;
const LEAD: u8 = 3;
const TRAIL: u8 = 4;
const ESCAPE_START: u8 = 5;
const ESCAPE: u8 = 6;

#[derive(Default)]
struct State {
    phase: u8,
    output: u8,
    leading: u8,
    designation: bool,
}

enum Action {
    Continue,
    Emit(char),
    Error(Option<u8>, Option<u8>),
    End,
}

impl State {
    fn restore(saved: &DecodeState) -> Option<Self> {
        if !saved.streaming
            || (saved.pending_len == 0 && saved.pending == [0; 3] && !saved.bom_seen)
        {
            return Some(Self::default());
        }
        if saved.pending_len != 3 || saved.bom_seen || saved.pending[1] & 0x7c != 0 {
            return None;
        }
        let state = Self {
            phase: saved.pending[0],
            output: saved.pending[1] & 3,
            leading: saved.pending[2],
            designation: saved.pending[1] & 0x80 != 0,
        };
        // Reject malformed restored slots before arithmetic or table access.
        let valid = match state.phase {
            ASCII..=LEAD => state.phase == state.output && state.leading == 0,
            TRAIL => state.output == LEAD && !state.designation && matches!(state.leading, 0x21..=0x7e),
            ESCAPE_START => state.leading == 0,
            ESCAPE => matches!(state.leading, 0x24 | 0x28),
            _ => false,
        };
        valid.then_some(state)
    }

    fn save(&self) -> DecodeState {
        DecodeState {
            pending: [self.phase, self.output | (u8::from(self.designation) << 7), self.leading],
            pending_len: 3,
            bom_seen: false,
            streaming: true,
        }
    }

    fn step(&mut self, byte: Option<u8>) -> Action {
        match self.phase {
            ASCII..=LEAD => {
                let Some(byte) = byte else { return Action::End };
                if byte == 0x1b {
                    self.phase = ESCAPE_START;
                    return Action::Continue;
                }
                self.designation = false;
                match self.phase {
                    ASCII | ROMAN if byte < 0x80 && !matches!(byte, 0x0e | 0x0f) => {
                        Action::Emit(match (self.phase, byte) {
                            (ROMAN, 0x5c) => '\u{a5}',
                            (ROMAN, 0x7e) => '\u{203e}',
                            _ => char::from(byte),
                        })
                    }
                    KATAKANA if matches!(byte, 0x21..=0x5f) => {
                        Action::Emit(char::from_u32(0xff61 + u32::from(byte - 0x21))
                            .expect("halfwidth katakana is scalar text"))
                    }
                    LEAD if matches!(byte, 0x21..=0x7e) => {
                        self.leading = byte;
                        self.phase = TRAIL;
                        Action::Continue
                    }
                    _ => Action::Error(None, None),
                }
            }
            TRAIL => {
                let lead = std::mem::take(&mut self.leading);
                self.phase = if byte == Some(0x1b) { ESCAPE_START } else { LEAD };
                if let Some(byte @ 0x21..=0x7e) = byte {
                    let pointer = usize::from(lead - 0x21) * 94 + usize::from(byte - 0x21);
                    if let Some(scalar) = index(pointer, false) {
                        return Action::Emit(scalar);
                    }
                }
                // ESC starts a new designation even while a pair is incomplete.
                // Other malformed trailing bytes are consumed, not replayed.
                Action::Error(None, None)
            }
            ESCAPE_START => {
                if let Some(byte @ (0x24 | 0x28)) = byte {
                    self.leading = byte;
                    self.phase = ESCAPE;
                    Action::Continue
                } else {
                    self.phase = self.output;
                    self.designation = false;
                    Action::Error(byte, None)
                }
            }
            ESCAPE => {
                let lead = std::mem::take(&mut self.leading);
                let output = match (lead, byte) {
                    (0x28, Some(0x42)) => Some(ASCII),
                    (0x28, Some(0x4a)) => Some(ROMAN),
                    (0x28, Some(0x49)) => Some(KATAKANA),
                    (0x24, Some(0x40 | 0x42)) => Some(LEAD),
                    _ => None,
                };
                if let Some(output) = output {
                    self.phase = output;
                    self.output = output;
                    let previous = std::mem::replace(&mut self.designation, true);
                    if previous { Action::Error(None, None) } else { Action::Continue }
                } else {
                    self.phase = self.output;
                    self.designation = false;
                    Action::Error(Some(lead), byte)
                }
            }
            _ => unreachable!("only validated phases reach the decoder"),
        }
    }
}

pub(super) fn decode(
    saved: &mut DecodeState,
    bytes: &[u8],
    fatal: bool,
    stream: bool,
) -> Option<JsString> {
    let Some(mut state) = State::restore(saved) else {
        *saved = DecodeState::default();
        return None;
    };
    let mut input = bytes.iter().copied();
    let mut replay = [0u8; 2];
    let mut remaining = 0;
    let mut text = String::new();
    loop {
        let byte = if remaining != 0 {
            remaining -= 1;
            Some(replay[remaining])
        } else {
            input.next()
        };
        if byte.is_none() && stream {
            break;
        }
        match state.step(byte) {
            Action::Continue => {}
            Action::Emit(scalar) => text.push(scalar),
            Action::Error(first, second) => {
                if fatal {
                    *saved = DecodeState::default();
                    return None;
                }
                text.push(char::REPLACEMENT_CHARACTER);
                // Reverse insertion preserves original order on the local stack.
                // Recovery can restore at most two bytes; it cannot recurse.
                for byte in [second, first].into_iter().flatten() {
                    let Some(slot) = replay.get_mut(remaining) else {
                        *saved = DecodeState::default();
                        return None;
                    };
                    *slot = byte;
                    remaining += 1;
                }
            }
            Action::End => break,
        }
    }
    *saved = if stream { state.save() } else { DecodeState::default() };
    Some(JsString::from(text))
}

#[cfg(test)]
mod tests;
