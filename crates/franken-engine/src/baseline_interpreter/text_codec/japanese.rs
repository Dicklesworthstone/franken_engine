//! WHATWG Japanese decoding on the existing TextDecoder state.
//!
//! The byte-pair paths retain only one Shift_JIS lead, or EUC-JP's
//! lead / 0x8F-plus-lead. No input buffer, locale, ICU or runtime index parser.
//! ISO-2022-JP reuses the same packed slot for its bounded designation state.
//! Error recovery preserves ASCII delimiters instead of swallowing them into
//! malformed multibyte sequences. EOF is not inferred from an empty chunk.
//! Fatal streaming errors retain the engine's existing reset policy; retention
//! of the WHATWG unconsumed input queue after such errors is not added here.
//!
//! Tables: https://encoding.spec.whatwg.org/index-jis0208.txt and
//! https://encoding.spec.whatwg.org/index-jis0212.txt (2024-09-18).
//! Exact source pins and reproducible generation live in
//! scripts/build_japanese_decoder_indexes.py. Compact per-index files expand at
//! compile time into 11104 little-endian u16s for jis0208 followed by 7211 for
//! jis0212; 0xFFFF means unmapped. Runtime access is direct indexing.
//!
//! Normative mapping data copyright © WHATWG (Apple, Google, Mozilla, Microsoft).
//! BSD 3-Clause License:
//! Redistribution and use in source and binary forms, with or without
//! modification, are permitted provided that the following conditions are met:
//! 1. Redistributions of source code must retain the above copyright notice,
//!    this list of conditions and the following disclaimer.
//! 2. Redistributions in binary form must reproduce the above copyright notice,
//!    this list of conditions and the following disclaimer in the documentation
//!    and/or other materials provided with the distribution.
//! 3. Neither the name of the copyright holder nor the names of its contributors
//!    may be used to endorse or promote products derived from this software
//!    without specific prior written permission.
//! THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
//! AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//! IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
//! ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
//! LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
//! CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
//! SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
//! INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
//! CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
//! ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//! POSSIBILITY OF SUCH DAMAGE.

use super::{DecodeState, JsString};

mod iso2022;

const JIS0208_LENGTH: usize = 11104;
const JIS0212_LENGTH: usize = 7211;
const INDEXES: &[u8; (JIS0208_LENGTH + JIS0212_LENGTH) * 2] =
    &expand_indexes(
        include_bytes!("jis0208.rle"),
        include_bytes!("jis0212.rle"),
    );

// Only unmapped runs are compressed. Normal words are literal; 0xFFFF is
// followed by a nonzero u16 run length. All decoding and checks are compile
// time: malformed generated data is a build error, not a runtime fallback.
const fn expand_indexes(jis0208: &[u8], jis0212: &[u8]) -> [u8; (JIS0208_LENGTH + JIS0212_LENGTH) * 2] {
    let mut output = [0u8; (JIS0208_LENGTH + JIS0212_LENGTH) * 2];
    let mut target = 0;
    let mut plane = 0;
    while plane < 2 {
        let input = if plane == 0 { jis0208 } else { jis0212 };
        let mut source = 0;
        while source < input.len() {
            let word = u16::from_le_bytes([input[source], input[source + 1]]);
            source += 2;
            let count = if word == 0xffff {
                let count = u16::from_le_bytes([input[source], input[source + 1]]) as usize;
                source += 2;
                assert!(count != 0);
                count
            } else {
                1
            };
            let mut remaining = count;
            while remaining != 0 {
                let bytes = word.to_le_bytes();
                output[target] = bytes[0];
                output[target + 1] = bytes[1];
                target += 2;
                remaining -= 1;
            }
        }
        assert!(target == if plane == 0 { JIS0208_LENGTH * 2 } else { output.len() });
        plane += 1;
    }
    output
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Encoding {
    ShiftJis,
    EucJp,
    Iso2022Jp,
}

impl Encoding {
    pub(super) fn from_name(name: &str) -> Option<Self> {
        match name {
            "shift_jis" => Some(Self::ShiftJis),
            "euc-jp" => Some(Self::EucJp),
            "iso-2022-jp" => Some(Self::Iso2022Jp),
            _ => None,
        }
    }

    fn is_lead(self, byte: u8) -> bool {
        match self {
            Self::ShiftJis => matches!(byte, 0x81..=0x9f | 0xe0..=0xfc),
            Self::EucJp => matches!(byte, 0x8e | 0x8f | 0xa1..=0xfe),
            Self::Iso2022Jp => false, // The separate designation machine owns its lead.
        }
    }
}

/// The caller already performed WHATWG ASCII-whitespace trimming/case folding.
pub(super) fn canonical_encoding(label: &str) -> Option<&'static str> {
    match label {
        "csshiftjis" | "ms932" | "ms_kanji" | "shift-jis" | "shift_jis" | "sjis"
        | "windows-31j" | "x-sjis" => Some("shift_jis"),
        "cseucpkdfmtjapanese" | "euc-jp" | "x-euc-jp" => Some("euc-jp"),
        "csiso2022jp" | "iso-2022-jp" => Some("iso-2022-jp"),
        _ => None,
    }
}

fn index(pointer: usize, jis0212: bool) -> Option<char> {
    let (start, length) = if jis0212 {
        (JIS0208_LENGTH, JIS0212_LENGTH)
    } else {
        (0, JIS0208_LENGTH)
    };
    if pointer >= length {
        return None;
    }
    let offset = (start + pointer) * 2;
    let value = u16::from_le_bytes([INDEXES[offset], INDEXES[offset + 1]]);
    (value != 0xffff)
        .then(|| char::from_u32(u32::from(value)))
        .flatten()
}

fn shift_jis_pair(leading: u8, byte: u8) -> Option<char> {
    if !matches!(byte, 0x40..=0x7e | 0x80..=0xfc) {
        return None;
    }
    let leading_offset = if leading < 0xa0 { 0x81 } else { 0xc1 };
    let trailing_offset = if byte < 0x7f { 0x40 } else { 0x41 };
    let pointer = usize::from(leading - leading_offset) * 188
        + usize::from(byte - trailing_offset);
    if (8836..=10715).contains(&pointer) {
        // Windows EUDC is algorithmic, not an entry in the JIS index.
        char::from_u32(0xe000 + (pointer - 8836) as u32)
    } else {
        index(pointer, false)
    }
}

fn emit(text: &mut String, scalar: Option<char>, byte: u8, fatal: bool) -> Option<()> {
    if let Some(scalar) = scalar {
        text.push(scalar);
    } else {
        if fatal {
            return None;
        }
        text.push(char::REPLACEMENT_CHARACTER);
        // WHATWG restores only ASCII after a failed multibyte sequence. It is
        // an identity mapping in both codecs, so emit it without a replay queue.
        if byte.is_ascii() {
            text.push(char::from(byte));
        }
    }
    Some(())
}

/// Decode under the native backing guard, publishing only a bounded carry.
/// The caller continues to own provenance and the existing heap/state budget.
pub(super) fn decode(
    state: &mut DecodeState,
    encoding: Encoding,
    bytes: &[u8],
    fatal: bool,
    stream: bool,
) -> Option<JsString> {
    if encoding == Encoding::Iso2022Jp {
        return iso2022::decode(state, bytes, fatal, stream);
    }
    if !state.streaming {
        *state = DecodeState::default();
    }
    let mut leading = 0;
    let mut jis0212 = false;
    let decoded = (|| {
        match state.pending_len {
            0 => {}
            1 if encoding.is_lead(state.pending[0]) => leading = state.pending[0],
            2 if encoding == Encoding::EucJp
                && state.pending[0] == 0x8f
                && matches!(state.pending[1], 0xa1..=0xfe) =>
            {
                leading = state.pending[1];
                jis0212 = true;
            }
            // A corrupt restored slot must not reach unchecked lead arithmetic.
            _ => return None,
        }
        if leading == 0 && bytes.is_ascii() {
            return Some(JsString::from(std::str::from_utf8(bytes).ok()?));
        }
        let mut text = String::new();
        for &byte in bytes {
            if leading != 0 {
                if encoding == Encoding::EucJp && leading == 0x8f
                    && matches!(byte, 0xa1..=0xfe)
                {
                    leading = byte;
                    jis0212 = true;
                    continue;
                }
                let previous = std::mem::take(&mut leading);
                let scalar = match encoding {
                    Encoding::ShiftJis => shift_jis_pair(previous, byte),
                    Encoding::EucJp if previous == 0x8e && matches!(byte, 0xa1..=0xdf) => {
                        char::from_u32(0xff61 + u32::from(byte - 0xa1))
                    }
                    Encoding::EucJp if matches!(previous, 0xa1..=0xfe)
                        && matches!(byte, 0xa1..=0xfe) =>
                    {
                        index(usize::from(previous - 0xa1) * 94 + usize::from(byte - 0xa1), jis0212)
                    }
                    Encoding::EucJp => None,
                    Encoding::Iso2022Jp => return None, // Dispatched before this byte-pair path.
                };
                jis0212 = false;
                emit(&mut text, scalar, byte, fatal)?;
            } else if byte.is_ascii() || (encoding == Encoding::ShiftJis && byte == 0x80) {
                text.push(char::from(byte));
            } else if encoding == Encoding::ShiftJis && matches!(byte, 0xa1..=0xdf) {
                text.push(char::from_u32(0xff61 + u32::from(byte - 0xa1))?);
            } else if encoding.is_lead(byte) {
                leading = byte;
            } else {
                emit(&mut text, None, byte, fatal)?;
            }
        }
        if !stream && leading != 0 {
            if fatal {
                return None;
            }
            // An incomplete 0x8F-plus-lead is ONE end-of-queue error.
            text.push(char::REPLACEMENT_CHARACTER);
        }
        Some(JsString::from(text))
    })();
    if decoded.is_none() || !stream {
        // Match the existing decoder's failure/flush ownership: no stale lead
        // or JIS0212 selection can contaminate a subsequent independent call.
        *state = DecodeState::default();
    } else {
        state.pending = if jis0212 { [0x8f, leading, 0] } else { [leading, 0, 0] };
        state.pending_len = if jis0212 { 2 } else { usize::from(leading != 0) };
        state.bom_seen = false;
        state.streaming = true;
    }
    decoded
}

#[cfg(test)]
mod tests;
