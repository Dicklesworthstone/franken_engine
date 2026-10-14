//! Decode into the runtime's UTF-8 storage, not a temporary UTF-16 vector.
//!
//! Well-formed UTF-8 borrows the input through validation and is copied only
//! into the returned JsString. Legacy encodings build UTF-8 directly. Every
//! result is scalar text: malformed input either fails or becomes U+FFFD.

use super::{DecodeState, JsString, WINDOWS_1252_HIGH, complete_prefix};

impl DecodeState {
    /// Decode under the caller's backing read guard. Only the bounded carry
    /// crosses calls; the input slice and any borrowed UTF-8 view cannot escape.
    pub(super) fn decode_slice(
        &mut self,
        encoding: &str,
        bytes: &[u8],
        fatal: bool,
        ignore_bom: bool,
        stream: bool,
    ) -> Option<JsString> {
        if !self.streaming {
            *self = Self::default();
        }
        let decoded = (|| {
            if self.pending_len == 0 {
                return self.decode_part(encoding, bytes, fatal, ignore_bom, stream);
            }
            // At most three carried bytes plus four fresh bytes suffice to
            // finish the previous scalar and find a new scalar boundary.
            // Never prepend to, resize, or rotate the entire incoming chunk.
            let carried = self.pending_len;
            let take = bytes.len().min(4);
            let mut bridge = [0_u8; 7];
            bridge[..carried].copy_from_slice(&self.pending[..carried]);
            bridge[carried..carried + take].copy_from_slice(&bytes[..take]);
            let bridge = &bridge[..carried + take];
            if take == bytes.len() {
                // All input is here, so EOF/error handling must see it as one
                // sequence (notably a UTF-16 high surrogate plus an odd byte).
                return self.decode_part(encoding, bridge, fatal, ignore_bom, stream);
            }
            let end = complete_prefix(encoding, bridge);
            // A suffix retains at most three bytes. Four fresh bytes guarantee
            // progress beyond the old carry, even for malformed input.
            debug_assert!(end > carried);
            let first = decode_string(
                encoding,
                &bridge[..end],
                fatal,
                ignore_bom || self.bom_seen,
            )?;
            self.bom_seen |= end != 0;
            // Bytes after the selected boundary still belong to the original
            // slice. Revisit them there, not from a copied intermediate tail.
            let rest = self.decode_part(
                encoding,
                &bytes[end - carried..],
                fatal,
                ignore_bom,
                stream,
            )?;
            Some(first.concat(&rest))
        })();
        if decoded.is_none() {
            // Reset on either fragment's fatal error, including a valid
            // prefix followed by an invalid later scalar in the same call.
            *self = Self::default();
        }
        decoded
    }

    /// A complete scalar-boundary segment, possibly with a final carry.
    fn decode_part(
        &mut self,
        encoding: &str,
        bytes: &[u8],
        fatal: bool,
        ignore_bom: bool,
        stream: bool,
    ) -> Option<JsString> {
        let end = if stream {
            complete_prefix(encoding, bytes)
        } else {
            bytes.len()
        };
        let text = decode_string(encoding, &bytes[..end], fatal, ignore_bom || self.bom_seen)?;
        if !stream {
            *self = Self::default();
        } else {
            self.streaming = true;
            self.bom_seen |= end != 0;
            self.pending = [0; 3];
            self.pending_len = bytes.len() - end;
            debug_assert!(self.pending_len <= self.pending.len());
            self.pending[..self.pending_len].copy_from_slice(&bytes[end..]);
        }
        Some(text)
    }

    #[cfg(test)]
    pub(super) fn decode_string(
        &mut self,
        encoding: &str,
        bytes: Vec<u8>,
        fatal: bool,
        ignore_bom: bool,
        stream: bool,
    ) -> Option<JsString> {
        self.decode_slice(encoding, &bytes, fatal, ignore_bom, stream)
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
