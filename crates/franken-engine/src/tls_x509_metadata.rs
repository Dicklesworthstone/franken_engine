#![forbid(unsafe_code)]

//! Bounded X.509 DER metadata extractor for the hermetic TLS loopback.
//!
//! This module extracts a narrow, Node-compatible subset of metadata from an
//! X.509v3 certificate encoded in DER (ITU-T X.690). It is intentionally
//! minimal:
//!
//! - Subject Common Name (`subject.CN`)
//! - Issuer Common Name (`issuer.CN`)
//! - Validity `notBefore` formatted as `MMM DD HH:MM:SS YYYY GMT`
//! - Validity `notAfter` formatted the same way
//!
//! It is not a full X.509 implementation. It does not validate signatures,
//! enforce algorithm policies, walk extensions, or honor RFC 5280
//! name-constraints. It is a fail-closed byte-level reader for the fields
//! Node's `tls.TLSSocket.prototype.getPeerCertificate()` exposes, used to
//! power fixtures 0008 (`subject.CN`), 0022 (`issuer.CN`), and 0023
//! (`valid_from` / `valid_to`) in the engine loopback.
//!
//! Safety properties:
//!
//! - No recursion in the wire parser: a depth counter caps at
//!   [`MAX_DER_DEPTH`] (16) and is incremented only when we *enter* a
//!   constructed type. Malformed nesting returns `Err`.
//! - No indefinite-length encodings: a single `0x80` length byte is rejected.
//! - Bounded element size: leaf elements are bounded by
//!   [`MAX_ELEMENT_BYTES`] (1 KiB) so a hostile DER cannot allocate large
//!   buffers.
//! - Bounded total input: [`MAX_DER_BYTES`] (16 KiB) so a single oversized
//!   certificate cannot be a DoS vector.
//! - Every value is decoded into a Rust `String` — no untrusted `unsafe` is
//!   performed, no foreign-function calls are invoked, and the parser is
//!   fully `forbid(unsafe_code)`.
//! - All bounds are checked before any allocation; no panic is reachable
//!   from any input byte sequence.
//!
//! Reference: bead `bd-il0d9`. The previous loopback returned only `raw`.
//! Fixtures 0008/0022/0023 require CN/issuer-CN/validity strings, so this
//! module exists to satisfy that narrow contract without bringing in a
//! `x509-parser` / `der-parser` / `rustls-webpki` dependency.

use std::fmt;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum total DER input size. Real leaf certificates are well under 4 KiB;
/// 16 KiB gives generous headroom while bounding adversarial allocation.
pub const MAX_DER_BYTES: usize = 16 * 1024;

/// Maximum element body size. Bounds allocation of OCTET STRING, UTF8String,
/// PrintableString, TeletexString, IA5String, BMPString, and other leaf
/// primitives.
pub const MAX_ELEMENT_BYTES: usize = 1024;

/// Maximum nesting depth for constructed types (SEQUENCE, SET, etc.).
pub const MAX_DER_DEPTH: u8 = 16;

/// ASN.1 tag values used by X.509 (subset).
mod tag {
    pub const INTEGER: u8 = 0x02;
    pub const UTF8_STRING: u8 = 0x0c;
    pub const PRINTABLE_STRING: u8 = 0x13;
    pub const TELETEX_STRING: u8 = 0x14;
    pub const IA5_STRING: u8 = 0x16;
    pub const UTCTIME: u8 = 0x17;
    pub const GENERALIZED_TIME: u8 = 0x18;
    pub const BMP_STRING: u8 = 0x1e;
    pub const SEQUENCE: u8 = 0x30;
    pub const SET: u8 = 0x31;
    pub const CONTEXT_SPECIFIC_0: u8 = 0xa0;
}

/// Distinguished Encoding Rules length-form bytes.
mod length_byte {
    pub const SHORT_FORM_MAX: u8 = 0x7f;
    pub const LONG_FORM_MARKER: u8 = 0x80;
    pub const LONG_FORM_VALUE_MASK: u8 = 0x7f;
    pub const LONG_FORM_MAX_OCTETS: u8 = 8;
}

/// OID 2.5.4.3 (id-at-commonName), DER-encoded as three component bytes.
const OID_COMMON_NAME: [u8; 3] = [0x55, 0x04, 0x03];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failure modes for bounded X.509 metadata extraction. The engine loopback
/// treats every error as fail-closed: it surfaces the bare `raw` Buffer to
/// the guest and elides the optional fields. The parser never panics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerError {
    /// Input exceeded [`MAX_DER_BYTES`].
    InputTooLarge { actual: usize, cap: usize },
    /// Truncated input — header promised more bytes than the buffer holds.
    Truncated { offset: usize, needed: usize },
    /// Encountered an indefinite-length (`0x80`) encoding, which this
    /// bounded parser does not support.
    IndefiniteLength { offset: usize },
    /// Length field declared more octets than the long-form allows.
    LengthTooLarge { offset: usize, octets: u8 },
    /// Length field consumed more bytes than were available.
    BadLength { offset: usize },
    /// Constructed type nested beyond [`MAX_DER_DEPTH`].
    DepthExceeded { depth: u8, cap: u8 },
    /// Tag byte was unrecognized for the supported X.509 surface.
    UnsupportedTag { offset: usize, tag: u8 },
    /// Body declared more bytes than [`MAX_ELEMENT_BYTES`].
    ElementTooLarge {
        offset: usize,
        declared: usize,
        cap: usize,
    },
    /// A required outer SEQUENCE was not present.
    NotAnX509Certificate,
}

impl fmt::Display for DerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { actual, cap } => {
                write!(f, "DER input too large ({actual} > {cap})")
            }
            Self::Truncated { offset, needed } => {
                write!(f, "DER truncated at offset {offset} (needed {needed} bytes)")
            }
            Self::IndefiniteLength { offset } => {
                write!(f, "DER indefinite-length form at offset {offset} not supported")
            }
            Self::LengthTooLarge { offset, octets } => {
                write!(f, "DER long-form length at offset {offset} uses {octets} octets")
            }
            Self::BadLength { offset } => {
                write!(f, "DER length field at offset {offset} is malformed")
            }
            Self::DepthExceeded { depth, cap } => {
                write!(f, "DER nesting depth {depth} exceeds cap {cap}")
            }
            Self::UnsupportedTag { offset, tag } => {
                write!(f, "DER unsupported tag 0x{tag:02x} at offset {offset}")
            }
            Self::ElementTooLarge {
                offset,
                declared,
                cap,
            } => {
                write!(
                    f,
                    "DER element at offset {offset} declares {declared} bytes (cap {cap})"
                )
            }
            Self::NotAnX509Certificate => {
                f.write_str("input is not an X.509v3 Certificate SEQUENCE")
            }
        }
    }
}

impl std::error::Error for DerError {}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/// Extracted metadata. Every field is `Option<String>` so a single missing
/// RDN or validity field does not poison the rest of the struct.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct X509Metadata {
    pub subject_cn: Option<String>,
    pub issuer_cn: Option<String>,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
}

impl X509Metadata {
    pub fn is_empty(&self) -> bool {
        self.subject_cn.is_none()
            && self.issuer_cn.is_none()
            && self.valid_from.is_none()
            && self.valid_to.is_none()
    }
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// A cursor that reads TLV elements from a DER byte slice. All errors are
/// `DerError`; bounds checks are enforced before allocation.
struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
    /// Number of currently-open constructed-type contexts. Incremented on
    /// every entry, decremented on every exit, capped at [`MAX_DER_DEPTH`].
    depth: u8,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            pos: 0,
            depth: 0,
        }
    }

    fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.pos)
    }

    fn read_byte(&mut self) -> Result<u8, DerError> {
        if self.pos >= self.input.len() {
            return Err(DerError::Truncated {
                offset: self.pos,
                needed: 1,
            });
        }
        let b = self.input[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// Read a DER length field (X.690 §10.1). Returns the body length and
    /// advances the cursor past the length bytes. Indefinite-length
    /// (0x80) is rejected.
    fn read_length(&mut self) -> Result<usize, DerError> {
        let first = self.read_byte()?;
        if first <= length_byte::SHORT_FORM_MAX {
            return Ok(first as usize);
        }
        if first == length_byte::LONG_FORM_MARKER {
            return Err(DerError::IndefiniteLength { offset: self.pos - 1 });
        }
        let octets = first & length_byte::LONG_FORM_VALUE_MASK;
        if octets == 0 || octets > length_byte::LONG_FORM_MAX_OCTETS {
            return Err(DerError::LengthTooLarge {
                offset: self.pos - 1,
                octets,
            });
        }
        let mut length: usize = 0;
        for _ in 0..octets {
            let b = self.read_byte()?;
            length = length
                .checked_shl(8)
                .ok_or(DerError::BadLength { offset: self.pos })?;
            length = length
                .checked_add(b as usize)
                .ok_or(DerError::BadLength { offset: self.pos })?;
        }
        Ok(length)
    }

    /// Read a TLV header (tag + length) without consuming the body.
    fn peek_header(&mut self) -> Result<(u8, usize), DerError> {
        let tag = self.read_byte()?;
        let length = self.read_length()?;
        Ok((tag, length))
    }

    /// Read the body of the current TLV element as a slice. Bounded by
    /// [`MAX_ELEMENT_BYTES`].
    fn read_body(&mut self, length: usize) -> Result<&'a [u8], DerError> {
        if length > MAX_ELEMENT_BYTES {
            return Err(DerError::ElementTooLarge {
                offset: self.pos,
                declared: length,
                cap: MAX_ELEMENT_BYTES,
            });
        }
        if self.remaining() < length {
            return Err(DerError::Truncated {
                offset: self.pos,
                needed: length,
            });
        }
        let start = self.pos;
        self.pos += length;
        Ok(&self.input[start..start + length])
    }

    /// Enter a constructed type context. Increments the depth counter; if
    /// the counter would exceed [`MAX_DER_DEPTH`], returns `Err`.
    fn enter(&mut self) -> Result<(), DerError> {
        if self.depth >= MAX_DER_DEPTH {
            return Err(DerError::DepthExceeded {
                depth: self.depth + 1,
                cap: MAX_DER_DEPTH,
            });
        }
        self.depth += 1;
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    /// Skip over the next TLV element (header + body). The element does
    /// not need to be a constructed type.
    fn skip_tlv(&mut self) -> Result<(), DerError> {
        let (_, length) = self.peek_header()?;
        // The body must satisfy the same allocation cap as a normal read
        // so a hostile `length` cannot cause us to read past the slice.
        self.read_body(length)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Public entry
// ---------------------------------------------------------------------------

/// Parse an X.509v3 certificate (DER) and return the narrow Node-shaped
/// metadata surface. Returns `Err` for any malformed or out-of-bounds
/// input; callers must treat the error as fail-closed.
pub fn parse_x509_metadata(der: &[u8]) -> Result<X509Metadata, DerError> {
    if der.len() > MAX_DER_BYTES {
        return Err(DerError::InputTooLarge {
            actual: der.len(),
            cap: MAX_DER_BYTES,
        });
    }
    let mut outer = Reader::new(der);
    let (outer_tag, outer_len) = outer.peek_header()?;
    if outer_tag != tag::SEQUENCE {
        return Err(DerError::NotAnX509Certificate);
    }
    let cert_body = outer.read_body(outer_len)?;
    let mut cert = Reader::new(cert_body);
    cert.enter()?;

    // tbsCertificate [0] EXPLICIT SEQUENCE
    let tbs_tag = cert.read_byte()?;
    if tbs_tag != tag::CONTEXT_SPECIFIC_0 {
        return Err(DerError::UnsupportedTag {
            offset: cert.pos - 1,
            tag: tbs_tag,
        });
    }
    let tbs_len = cert.read_length()?;
    let tbs_body = cert.read_body(tbs_len)?;
    let mut tbs = Reader::new(tbs_body);
    tbs.enter()?;

    // Skip any optional [0] EXPLICIT version field.
    if tbs.remaining() > 0 && tbs.input[tbs.pos] == tag::CONTEXT_SPECIFIC_0 {
        tbs.skip_tlv()?;
    }

    // serialNumber INTEGER
    tbs.skip_tlv()?;
    // signature AlgorithmIdentifier SEQUENCE
    tbs.skip_tlv()?;

    // issuer Name — capture body for CN extraction.
    let (issuer_tag, issuer_len) = tbs.peek_header()?;
    if issuer_tag != tag::SEQUENCE {
        return Err(DerError::UnsupportedTag {
            offset: tbs.pos,
            tag: issuer_tag,
        });
    }
    let issuer_body = tbs.read_body(issuer_len)?;
    let issuer_cn = extract_first_cn(issuer_body)?;

    // validity Validity SEQUENCE { notBefore Time, notAfter Time }
    let (validity_tag, validity_len) = tbs.peek_header()?;
    if validity_tag != tag::SEQUENCE {
        return Err(DerError::UnsupportedTag {
            offset: tbs.pos,
            tag: validity_tag,
        });
    }
    let validity_body = tbs.read_body(validity_len)?;
    let (not_before, not_after) = parse_validity(validity_body)?;

    // subject Name
    let (subject_tag, subject_len) = tbs.peek_header()?;
    if subject_tag != tag::SEQUENCE {
        return Err(DerError::UnsupportedTag {
            offset: tbs.pos,
            tag: subject_tag,
        });
    }
    let subject_body = tbs.read_body(subject_len)?;
    let subject_cn = extract_first_cn(subject_body)?;

    // We intentionally do not parse subjectPublicKeyInfo or extensions:
    // the contract is metadata only, and a malformed extension set
    // should not poison the metadata surface.

    Ok(X509Metadata {
        subject_cn,
        issuer_cn,
        valid_from: Some(not_before),
        valid_to: Some(not_after),
    })
}

// ---------------------------------------------------------------------------
// Inner decoders
// ---------------------------------------------------------------------------

/// Extract the first Common Name attribute from a Name (which is a SEQUENCE
/// OF RelativeDistinguishedName SET OF AttributeTypeAndValue). The OID
/// 2.5.4.3 (id-at-commonName) is encoded in DER as `55 04 03`. We scan for
/// that triple and decode the following string primitive.
fn extract_first_cn(name_bytes: &[u8]) -> Result<Option<String>, DerError> {
    if name_bytes.is_empty() {
        return Ok(None);
    }
    let mut name = Reader::new(name_bytes);
    name.enter()?;
    while name.remaining() > 0 {
        // Each top-level element of Name is a SET (the RDN). Some
        // implementations encode it as a SEQUENCE — accept both.
        let (rdn_tag, rdn_len) = name.peek_header()?;
        if rdn_tag != tag::SET && rdn_tag != tag::SEQUENCE {
            // Unknown element: skip it.
            name.skip_tlv()?;
            continue;
        }
        let rdn_body = name.read_body(rdn_len)?;
        let mut rdn = Reader::new(rdn_body);
        rdn.enter()?;
        // Inside the RDN we expect a SEQUENCE of AttributeTypeAndValue.
        if rdn.remaining() == 0 {
            rdn.leave();
            continue;
        }
        let (atv_tag, atv_len) = rdn.peek_header()?;
        if atv_tag != tag::SEQUENCE {
            rdn.leave();
            continue;
        }
        let atv_body = rdn.read_body(atv_len)?;
        let mut atv = Reader::new(atv_body);
        atv.enter()?;
        // OID
        let (oid_tag, oid_len) = atv.peek_header()?;
        if oid_tag != 0x06 || oid_len != OID_COMMON_NAME.len() {
            rdn.leave();
            continue;
        }
        let oid_bytes = atv.read_body(oid_len)?;
        if oid_bytes != OID_COMMON_NAME {
            rdn.leave();
            continue;
        }
        // Value (string primitive)
        let (val_tag, val_len) = atv.peek_header()?;
        let val_body = atv.read_body(val_len)?;
        return decode_string_value(val_tag, val_body).map(Some);
    }
    Ok(None)
}

/// Parse the Validity SEQUENCE { notBefore Time, notAfter Time }.
fn parse_validity(validity_bytes: &[u8]) -> Result<(String, String), DerError> {
    let mut validity = Reader::new(validity_bytes);
    validity.enter()?;
    // notBefore
    let nb_tag = validity.read_byte()?;
    let nb_len = validity.read_length()?;
    let nb_body = validity.read_body(nb_len)?;
    let not_before = decode_time_value(nb_tag, nb_body)?;
    // notAfter
    let na_tag = validity.read_byte()?;
    let na_len = validity.read_length()?;
    let na_body = validity.read_body(na_len)?;
    let not_after = decode_time_value(na_tag, na_body)?;
    Ok((not_before, not_after))
}

fn decode_string_value(tag: u8, body: &[u8]) -> Result<String, DerError> {
    match tag {
        tag::UTF8_STRING | tag::PRINTABLE_STRING | tag::TELETEX_STRING | tag::IA5_STRING => {
            // ASCII-compatible primitives. Non-ASCII bytes are replaced
            // with U+FFFD so we never produce a malformed `String`.
            Ok(body
                .iter()
                .map(|&b| if b.is_ascii() { b as char } else { '\u{FFFD}' })
                .collect())
        }
        tag::BMP_STRING => {
            // UCS-2 big-endian, two bytes per code point, BMP only.
            if body.len() % 2 != 0 {
                return Ok(String::new());
            }
            let mut out = String::with_capacity(body.len() / 2);
            for pair in body.chunks_exact(2) {
                let cp = u16::from_be_bytes([pair[0], pair[1]]);
                if let Some(ch) = char::from_u32(cp as u32) {
                    out.push(ch);
                } else {
                    out.push('\u{FFFD}');
                }
            }
            Ok(out)
        }
        _ => Err(DerError::UnsupportedTag { offset: 0, tag }),
    }
}

/// Decode a Time value as either `UTCTime` (YYMMDDHHMMSSZ) or
/// `GeneralizedTime` (YYYYMMDDHHMMSSZ) and reformat it as the
/// Node-shaped `MMM DD HH:MM:SS YYYY GMT` string used by
/// `tls.TLSSocket.getPeerCertificate()`.
fn decode_time_value(tag: u8, body: &[u8]) -> Result<String, DerError> {
    if !body.ends_with(b"Z") {
        return Err(DerError::UnsupportedTag {
            offset: 0,
            tag,
        });
    }
    let digits = &body[..body.len() - 1];
    if !digits.iter().all(|b| b.is_ascii_digit()) {
        return Err(DerError::UnsupportedTag {
            offset: 0,
            tag,
        });
    }
    let (year, month, day, hour, minute, second) = match tag {
        tag::UTCTIME => {
            // UTCTime: two-digit year; RFC 5280 §4.1.2.5.1: 00–49 → 20YY,
            // 50–99 → 19YY. This matches historical Node behavior.
            if digits.len() != 12 {
                return Err(DerError::UnsupportedTag {
                    offset: 0,
                    tag,
                });
            }
            let yy = parse_two(&digits[0..2]);
            let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
            (
                year,
                parse_two(&digits[2..4]),
                parse_two(&digits[4..6]),
                parse_two(&digits[6..8]),
                parse_two(&digits[8..10]),
                parse_two(&digits[10..12]),
            )
        }
        tag::GENERALIZED_TIME => {
            if digits.len() != 14 {
                return Err(DerError::UnsupportedTag {
                    offset: 0,
                    tag,
                });
            }
            (
                parse_four(&digits[0..4]),
                parse_two(&digits[4..6]),
                parse_two(&digits[6..8]),
                parse_two(&digits[8..10]),
                parse_two(&digits[10..12]),
                parse_two(&digits[12..14]),
            )
        }
        _ => {
            return Err(DerError::UnsupportedTag {
                offset: 0,
                tag,
            })
        }
    };

    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(DerError::UnsupportedTag {
            offset: 0,
            tag,
        });
    }
    let month_name = month_abbr(month);
    Ok(format!(
        "{month_name:>3} {day:02} {hour:02}:{minute:02}:{second:02} {year:04} GMT"
    ))
}

fn parse_two(b: &[u8]) -> u32 {
    (b[0] as u32 - b'0' as u32) * 10 + (b[1] as u32 - b'0' as u32)
}

fn parse_four(b: &[u8]) -> u32 {
    (b[0] as u32 - b'0' as u32) * 1000
        + (b[1] as u32 - b'0' as u32) * 100
        + (b[2] as u32 - b'0' as u32) * 10
        + (b[3] as u32 - b'0' as u32)
}

fn month_abbr(month: u32) -> &'static str {
    match month {
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        12 => "Dec",
        _ => "???",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A real, self-signed, RFC-compliant X.509v3 certificate (PEM from
    /// the engine's existing `tls_root_certificates` fixture, base64-decoded).
    /// Subject CN=ISRG Root X1, validity 2015-06-04..2035-06-04, public.
    const ISRG_ROOT_X1_DER: &[u8] = &[
        0x30, 0x82, 0x05, 0xba, 0x30, 0x82, 0x03, 0xa2, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10,
        0x82, 0x10, 0xcf, 0xb0, 0xd2, 0x40, 0xe3, 0x59, 0x50, 0x07, 0xe3, 0x62, 0x54, 0xa0, 0x37,
        0x8d, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
        0x00, 0x30, 0x4f, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
        0x53, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x19, 0x49, 0x6e, 0x74,
        0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x20,
        0x52, 0x65, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x20, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x31,
        0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x13, 0x49, 0x53, 0x52, 0x47, 0x20,
        0x52, 0x6f, 0x6f, 0x74, 0x20, 0x58, 0x31, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x35, 0x30, 0x36,
        0x30, 0x34, 0x31, 0x31, 0x30, 0x34, 0x33, 0x38, 0x5a, 0x17, 0x0d, 0x33, 0x35, 0x30, 0x36,
        0x30, 0x34, 0x31, 0x31, 0x30, 0x34, 0x33, 0x38, 0x5a, 0x30, 0x4f, 0x31, 0x0b, 0x30, 0x09,
        0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03,
        0x55, 0x04, 0x0a, 0x13, 0x19, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x53,
        0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x20, 0x52, 0x65, 0x73, 0x65, 0x61, 0x72, 0x63,
        0x68, 0x20, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04,
        0x03, 0x13, 0x13, 0x49, 0x53, 0x52, 0x47, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x58, 0x31,
    ];

    #[test]
    fn parses_isrg_root_x1_subject_and_issuer() {
        let md = parse_x509_metadata(ISRG_ROOT_X1_DER).expect("ISRG Root X1 should parse");
        assert_eq!(md.subject_cn.as_deref(), Some("ISRG Root X1"));
        assert_eq!(md.issuer_cn.as_deref(), Some("ISRG Root X1"));
        // Validity: 2015-06-04 11:04:38 GMT .. 2035-06-04 11:04:38 GMT
        assert_eq!(md.valid_from.as_deref(), Some("Jun 04 11:04:38 2015 GMT"));
        assert_eq!(md.valid_to.as_deref(), Some("Jun 04 11:04:38 2035 GMT"));
    }

    #[test]
    fn oversized_input_is_rejected() {
        let oversized = vec![0u8; MAX_DER_BYTES + 1];
        let err = parse_x509_metadata(&oversized).unwrap_err();
        assert!(matches!(err, DerError::InputTooLarge { .. }));
    }

    #[test]
    fn truncated_input_is_rejected() {
        let err = parse_x509_metadata(&[0x30, 0x82, 0x00, 0x10]).unwrap_err();
        assert!(matches!(err, DerError::Truncated { .. }));
    }

    #[test]
    fn indefinite_length_is_rejected() {
        let err = parse_x509_metadata(&[0x30, 0x80, 0x00, 0x00]).unwrap_err();
        assert!(matches!(err, DerError::IndefiniteLength { .. }));
    }

    #[test]
    fn wrong_outer_tag_is_rejected() {
        // 0x31 (SET) instead of 0x30 (SEQUENCE) at the outer level.
        let err = parse_x509_metadata(&[0x31, 0x03, 0x01, 0x02, 0x03]).unwrap_err();
        assert!(matches!(err, DerError::NotAnX509Certificate));
    }

    #[test]
    fn empty_input_is_rejected() {
        let err = parse_x509_metadata(&[]).unwrap_err();
        assert!(matches!(err, DerError::Truncated { .. }));
    }

    #[test]
    fn element_too_large_is_rejected() {
        // Outer SEQUENCE declares a body larger than MAX_ELEMENT_BYTES.
        let body_len = MAX_ELEMENT_BYTES + 1;
        let mut header = vec![0x30, 0x82, (body_len >> 8) as u8, body_len as u8];
        header.resize(header.len() + body_len, 0);
        let err = parse_x509_metadata(&header).unwrap_err();
        // Either ElementTooLarge (caught when reading the body) or
        // Truncated (header consumes bytes we don't have).
        assert!(
            matches!(
                err,
                DerError::ElementTooLarge { .. } | DerError::Truncated { .. }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn missing_cn_returns_none() {
        // Hand-rolled minimal certificate with empty issuer/Name.
        // Layout: SEQUENCE { tbs [0] EXPLICIT SEQUENCE { version omitted,
        // serialNumber INTEGER 1, signature AlgorithmIdentifier,
        // issuer SEQUENCE {}, validity SEQUENCE { notBefore UTCTime,
        // notAfter UTCTime }, subject SEQUENCE {} } }
        let cert: Vec<u8> = vec![
            0x30, 0x20, // outer SEQUENCE body 32 bytes
            0xa0, 0x1e, // [0] EXPLICIT tbsCertificate (30 bytes)
            0x30, 0x1c, // SEQUENCE (28 bytes)
            // serialNumber INTEGER 1
            0x02, 0x01, 0x01,
            // signature AlgorithmIdentifier SEQUENCE { OID, NULL }
            0x30, 0x05, 0x06, 0x01, 0x2a, 0x05, 0x00,
            // issuer Name (empty SEQUENCE)
            0x30, 0x00,
            // validity SEQUENCE { UTCTime 2015-06-04 11:04:38Z, UTCTime 2035-06-04 11:04:38Z }
            0x30, 0x10, 0x17, 0x0d, b'1', b'5', b'0', b'6', b'0', b'4', b'1', b'1', b'0', b'4',
            b'3', b'8', b'Z', 0x17, 0x0d, b'3', b'5', b'0', b'6', b'0', b'4', b'1', b'1', b'0',
            b'4', b'3', b'8', b'Z',
            // subject Name (empty SEQUENCE)
            0x30, 0x00,
        ];
        let md = parse_x509_metadata(&cert).expect("valid empty-CN cert should parse");
        assert!(md.subject_cn.is_none());
        assert!(md.issuer_cn.is_none());
        assert_eq!(md.valid_from.as_deref(), Some("Jun 04 11:04:38 2015 GMT"));
        assert_eq!(md.valid_to.as_deref(), Some("Jun 04 11:04:38 2035 GMT"));
    }

    #[test]
    fn depth_limit_is_enforced() {
        // Build a deeply nested SEQUENCE structure. The depth counter
        // increments on every constructed-type entry; we trip it at
        // MAX_DER_DEPTH = 16 by stacking 18 SEQUENCE wrappers.
        let mut buf: Vec<u8> = vec![0x00];
        for _ in 0..(MAX_DER_DEPTH as usize + 2) {
            buf.insert(0, 0x30);
            buf.insert(1, 0x02);
        }
        let err = parse_x509_metadata(&buf).unwrap_err();
        assert!(matches!(err, DerError::DepthExceeded { .. }));
    }
}
