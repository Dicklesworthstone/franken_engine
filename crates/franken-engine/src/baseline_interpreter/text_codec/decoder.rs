//! Decode into the runtime's UTF-8 storage, not a temporary UTF-16 vector.
//!
//! Well-formed UTF-8 borrows the input through validation and is copied only
//! into the returned JsString. Legacy encodings build UTF-8 directly. Every
//! result is scalar text: malformed input either fails or becomes U+FFFD.

use super::{DecodeState, JsString, WINDOWS_1252_HIGH, complete_prefix};

impl DecodeState {
    pub(super) fn decode_string(
        &mut self,
        encoding: &str,
        mut bytes: Vec<u8>,
        fatal: bool,
        ignore_bom: bool,
        stream: bool,
    ) -> Option<JsString> {
        if !self.streaming {
            *self = Self::default();
        }
        if self.pending_len != 0 {
            // Reuse the owned input copy. The only added bytes are the bounded
            // carry; nothing points back into an ArrayBuffer supplied by guest.
            bytes.extend_from_slice(&self.pending[..self.pending_len]);
            bytes.rotate_right(self.pending_len);
        }
        let end = if stream {
            complete_prefix(encoding, &bytes)
        } else {
            bytes.len()
        };
        let decoded =
            decode_string(encoding, &bytes[..end], fatal, ignore_bom || self.bom_seen);
        if decoded.is_none() {
            // Node's decoder is reusable after a fatal decoding failure. Do not
            // retain stale bytes or its prior BOM decision after that failure.
            *self = Self::default();
            return None;
        }
        if !stream {
            // No carry or BOM decision may survive a successful final flush.
            *self = Self::default();
            return decoded;
        }
        self.streaming = true;
        self.bom_seen |= end != 0;
        self.pending = [0; 3];
        self.pending_len = bytes.len() - end;
        debug_assert!(self.pending_len <= self.pending.len());
        self.pending[..self.pending_len].copy_from_slice(&bytes[end..]);
        decoded
    }
}


pub(super) fn decode_string(
    encoding: &str,
    bytes: &[u8],
    fatal: bool,
    ignore_bom: bool,
) -> Option<JsString> {
    match encoding {
        "utf-16le" | "utf-16be" => decode_utf16(bytes, encoding == "utf-16be", fatal, ignore_bom),
        "windows-1252" => {
            if bytes.is_ascii() {
                return Some(JsString::from(std::str::from_utf8(bytes).ok()?));
            }
            let text: String = bytes
                .iter()
                .map(|&byte| match byte {
                    0x80..=0x9f => char::from_u32(u32::from(WINDOWS_1252_HIGH[usize::from(byte - 0x80)]))
                        .expect("windows-1252 mappings are Unicode scalars"),
                    other => char::from(other),
                })
                .collect();
            Some(JsString::from(text))
        }
        _ => {
            let bytes = match bytes {
                [0xef, 0xbb, 0xbf, rest @ ..] if !ignore_bom => rest,
                _ => bytes,
            };
            if fatal {
                return Some(JsString::from(std::str::from_utf8(bytes).ok()?));
            }
            // The Cow remains borrowed for valid UTF-8. Malformed subparts
            // use the same replacement decoder as before, without a UTF-16
            // allocation, a second decode, or an intermediate valid String.
            Some(JsString::from(String::from_utf8_lossy(bytes).as_ref()))
        }
    }
}

fn decode_utf16(
    bytes: &[u8],
    big_endian: bool,
    fatal: bool,
    ignore_bom: bool,
) -> Option<JsString> {
    let read = |offset| {
        let pair = [bytes[offset], bytes[offset + 1]];
        if big_endian {
            u16::from_be_bytes(pair)
        } else {
            u16::from_le_bytes(pair)
        }
    };
    let mut text = String::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = bytes.len() - offset;
        if remaining < 2 {
            if fatal {
                return None;
            }
            text.push(char::REPLACEMENT_CHARACTER);
            break;
        }
        let unit = read(offset);
        if offset == 0 && unit == 0xfeff && !ignore_bom {
            offset += 2;
            continue;
        }
        if (0xd800..=0xdbff).contains(&unit) {
            if remaining < 4 {
                if fatal {
                    return None;
                }
                // A high surrogate plus an odd trailing byte is ONE EOF
                // error, not one replacement per pending piece.
                text.push(char::REPLACEMENT_CHARACTER);
                break;
            }
            let low = read(offset + 2);
            if (0xdc00..=0xdfff).contains(&low) {
                let scalar = 0x10000 + ((u32::from(unit) - 0xd800) << 10)
                    + u32::from(low) - 0xdc00;
                text.push(char::from_u32(scalar).expect("surrogate pair is a Unicode scalar"));
                offset += 4;
                continue;
            }
            if fatal {
                return None;
            }
            text.push(char::REPLACEMENT_CHARACTER);
            // The following unit has not been consumed. Reconsider it as
            // another scalar or the beginning of a surrogate pair.
        } else if (0xdc00..=0xdfff).contains(&unit) {
            if fatal {
                return None;
            }
            text.push(char::REPLACEMENT_CHARACTER);
        } else {
            text.push(char::from_u32(u32::from(unit)).expect("non-surrogate BMP scalar"));
        }
        offset += 2;
    }
    Some(JsString::from(text))
}

#[cfg(test)]
mod tests;
