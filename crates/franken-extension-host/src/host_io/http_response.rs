//! Bounded HTTP/1.x response framing for the one-shot network provider.
//!
//! A socket closing is not proof that a length-delimited HTTP message is
//! complete. Conversely, a complete self-delimited message does not require
//! socket closure. The same state machine handles plaintext and rustls reads;
//! an unclean TLS EOF is never converted into a successful close-delimited body.
//! Framing follows RFC 9112 sections 6.3, 7.1 and 8. Raw bytes, including chunk
//! framing and informational responses, are retained for the effect journal.

use std::borrow::Cow;
use std::io::{self, Read};

const MAX_HEAD_BYTES: usize = 64 * 1024;
const MAX_LINE_BYTES: usize = 8192;
const MAX_FIELDS: usize = 1024;
const MAX_INFORMATIONAL_RESPONSES: usize = 16;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn capacity_error() -> io::Error {
    invalid("HTTP response exceeds its wire-byte limit")
}

/// A validated final HTTP response borrowed from a completed host outcome.
/// Headers exclude informational responses and trailers. The raw host outcome
/// remains unchanged; only `body_bytes` removes chunk framing for the consumer.
#[derive(Debug)]
pub struct ParsedHttpResponse<'a> {
    pub status: u16,
    pub status_text: &'a [u8],
    header_bytes: &'a [u8],
    header_count: usize,
    wire_body: &'a [u8],
    chunked: bool,
    body_len: usize,
}

impl<'a> ParsedHttpResponse<'a> {
    /// Original final-response fields, without merging or rewriting duplicates.
    pub fn headers(&self) -> impl Iterator<Item = (&'a [u8], &'a [u8])> + 'a {
        self.header_bytes
            .split_inclusive(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| {
                field(&line[..line.len() - 2]).expect("immutable response fields were validated")
            })
    }

    pub fn header_count(&self) -> usize {
        self.header_count
    }

    /// Exact decoded size, available before a caller admits a body allocation.
    pub fn body_len(&self) -> usize {
        self.body_len
    }

    /// Transfer-decode chunked payloads; fixed/close-delimited bodies borrow the
    /// input. Content-Encoding (for example gzip) is deliberately not decoded.
    /// This allocates at most the already validated decoded body length.
    pub fn body_bytes(&self) -> io::Result<Cow<'a, [u8]>> {
        if !self.chunked {
            return Ok(Cow::Borrowed(self.wire_body));
        }
        let mut body = Vec::new();
        body.try_reserve_exact(self.body_len)
            .map_err(|_| invalid("decoded HTTP body allocation failed"))?;
        let mut start = 0;
        loop {
            let mut scan = start;
            let end = delimiter(self.wire_body, &mut scan, b"\r\n")
                .ok_or_else(|| invalid("incomplete HTTP chunk-size line"))?;
            let size = chunk_size(&self.wire_body[start..end - 2])?;
            if size == 0 {
                debug_assert_eq!(body.len(), self.body_len);
                return Ok(Cow::Owned(body));
            }
            let data_end = end.checked_add(size).ok_or_else(capacity_error)?;
            let chunk = self
                .wire_body
                .get(end..data_end)
                .ok_or_else(|| invalid("incomplete HTTP chunk data"))?;
            body.extend_from_slice(chunk);
            start = data_end.checked_add(2).ok_or_else(capacity_error)?;
        }
    }
}

/// Validate an entire recorded response using the live transport's framing
/// rules. Unlike the one-shot socket reader, a persisted outcome must contain
/// exactly one response exchange, with no unsolicited trailing bytes.
///
/// This parser allocates nothing on success. A close-delimited outcome relies
/// on the producer's successful EOF observation; parsing alone authenticates
/// neither the peer nor a caller-supplied replay transcript.
pub fn parse_http_response<'a>(raw: &'a [u8], method: &str) -> io::Result<ParsedHttpResponse<'a>> {
    let mut framer = Framer::new(method.as_bytes(), raw.len());
    let end = match framer.advance(raw)? {
        Some(end) => end,
        None if matches!(framer.phase, Phase::CloseDelimited) => raw.len(),
        None => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete HTTP response",
            ));
        }
    };
    if end != raw.len() {
        return Err(invalid("recorded HTTP response contains trailing bytes"));
    }
    let final_head = framer
        .final_head
        .ok_or_else(|| invalid("HTTP response has no final status"))?;
    let body_len = if matches!(framer.phase, Phase::CloseDelimited) {
        end - final_head.end
    } else {
        framer.body_len
    };
    Ok(ParsedHttpResponse {
        status: final_head.head.status,
        status_text: &raw[final_head.start + 13..final_head.start + final_head.head.status_end],
        header_bytes: &raw[final_head.start + final_head.head.status_end + 2..final_head.end - 2],
        header_count: final_head.head.fields,
        wire_body: &raw[final_head.end..end],
        chunked: framer.chunked,
        body_len,
    })
}

/// Read one final response, retaining any preceding informational responses.
///
/// `request` is the exact request already sent. Its method determines HEAD and
/// CONNECT response semantics. Upgrades/tunnels and transfer codings other than
/// `chunked` require a different provider and are explicitly rejected here.
/// No payload is decoded or normalized. A server's unsolicited suffix after a
/// complete response is not part of this one-shot exchange and is discarded.
///
/// At most `cap + 1` bytes are read, with the extra byte used only to detect an
/// oversized incomplete message. This bounds wire bytes, not allocator/RSS use.
/// The caller must configure transport timeouts; a byte bound is not a deadline.
pub(super) fn read_response<R: Read>(
    reader: &mut R,
    request: &[u8],
    cap: u64,
) -> io::Result<Vec<u8>> {
    let cap = usize::try_from(cap)
        .map_err(|_| invalid("HTTP response limit exceeds addressable memory"))?;
    let method = request
        .split(|byte| *byte == b' ')
        .next()
        .unwrap_or_default();
    let mut framer = Framer::new(method, cap);
    let mut wire = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        if let Some(end) = framer.advance(&wire)? {
            wire.truncate(end);
            return Ok(wire);
        }
        if wire.len() > cap {
            return Err(capacity_error());
        }
        let read_limit = buffer.len().min((cap - wire.len()).saturating_add(1));
        let count = match reader.read(&mut buffer[..read_limit]) {
            Ok(0) if matches!(framer.phase, Phase::CloseDelimited) => return Ok(wire),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete HTTP response",
                ));
            }
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        wire.try_reserve(count)
            .map_err(|_| invalid("HTTP response allocation failed"))?;
        wire.extend_from_slice(&buffer[..count]);
    }
}

#[derive(Clone, Copy)]
enum Phase {
    Head {
        start: usize,
        scan: usize,
    },
    Fixed {
        end: usize,
    },
    ChunkSize {
        start: usize,
        scan: usize,
    },
    ChunkData {
        end: usize,
    },
    Trailers {
        section: usize,
        start: usize,
        scan: usize,
        fields: usize,
    },
    CloseDelimited,
    Complete {
        end: usize,
    },
}

struct Framer {
    phase: Phase,
    head_request: bool,
    connect_request: bool,
    cap: usize,
    informational: usize,
    final_head: Option<FinalHead>,
    chunked: bool,
    body_len: usize,
}

struct FinalHead {
    start: usize,
    end: usize,
    head: Head,
}

impl Framer {
    fn new(method: &[u8], cap: usize) -> Self {
        Self {
            phase: Phase::Head { start: 0, scan: 0 },
            head_request: method == b"HEAD",
            connect_request: method == b"CONNECT",
            cap,
            informational: 0,
            final_head: None,
            chunked: false,
            body_len: 0,
        }
    }

    fn bounded_end(&self, start: usize, length: usize) -> io::Result<usize> {
        start
            .checked_add(length)
            .filter(|end| *end <= self.cap)
            .ok_or_else(capacity_error)
    }

    fn advance(&mut self, wire: &[u8]) -> io::Result<Option<usize>> {
        loop {
            match self.phase {
                Phase::Head { start, mut scan } => {
                    let Some(end) = delimiter(wire, &mut scan, b"\r\n\r\n") else {
                        if wire.len() - start > MAX_HEAD_BYTES {
                            return Err(invalid("HTTP response header section is too large"));
                        }
                        self.phase = Phase::Head { start, scan };
                        return Ok(None);
                    };
                    if end - start > MAX_HEAD_BYTES {
                        return Err(invalid("HTTP response header section is too large"));
                    }
                    self.bounded_end(0, end)?;
                    let head = parse_head(&wire[start..end])?;
                    if head.status == 101
                        || (self.connect_request && (200..300).contains(&head.status))
                    {
                        return Err(invalid("HTTP upgrade/tunnel requires a streaming provider"));
                    }
                    if head.status < 200 {
                        self.informational += 1;
                        if self.informational > MAX_INFORMATIONAL_RESPONSES {
                            return Err(invalid("too many informational HTTP responses"));
                        }
                        self.phase = Phase::Head {
                            start: end,
                            scan: end,
                        };
                    } else {
                        self.phase = if self.head_request || matches!(head.status, 204 | 304) {
                            Phase::Complete { end }
                        } else if head.chunked {
                            self.chunked = true;
                            Phase::ChunkSize {
                                start: end,
                                scan: end,
                            }
                        } else if let Some(length) = head.content_length {
                            self.body_len = length;
                            Phase::Fixed {
                                end: self.bounded_end(end, length)?,
                            }
                        } else {
                            Phase::CloseDelimited
                        };
                        self.final_head = Some(FinalHead { start, end, head });
                    }
                }
                Phase::Fixed { end } => {
                    if wire.len() < end {
                        return Ok(None);
                    }
                    self.phase = Phase::Complete { end };
                }
                Phase::ChunkSize { start, mut scan } => {
                    let Some(end) = delimiter(wire, &mut scan, b"\r\n") else {
                        if wire.len() - start > MAX_LINE_BYTES {
                            return Err(invalid("HTTP chunk-size line is too large"));
                        }
                        self.phase = Phase::ChunkSize { start, scan };
                        return Ok(None);
                    };
                    if end - start > MAX_LINE_BYTES {
                        return Err(invalid("HTTP chunk-size line is too large"));
                    }
                    self.bounded_end(0, end)?;
                    let size = chunk_size(&wire[start..end - 2])?;
                    self.body_len = self.body_len.checked_add(size).ok_or_else(capacity_error)?;
                    self.phase = if size == 0 {
                        Phase::Trailers {
                            section: end,
                            start: end,
                            scan: end,
                            fields: 0,
                        }
                    } else {
                        let data_end = self.bounded_end(end, size)?;
                        Phase::ChunkData {
                            end: self.bounded_end(data_end, 2)?,
                        }
                    };
                }
                Phase::ChunkData { end } => {
                    if wire.len() < end {
                        return Ok(None);
                    }
                    if &wire[end - 2..end] != b"\r\n" {
                        return Err(invalid("HTTP chunk data lacks its CRLF terminator"));
                    }
                    self.phase = Phase::ChunkSize {
                        start: end,
                        scan: end,
                    };
                }
                Phase::Trailers {
                    section,
                    start,
                    mut scan,
                    fields,
                } => {
                    let Some(end) = delimiter(wire, &mut scan, b"\r\n") else {
                        if wire.len() - start > MAX_LINE_BYTES
                            || wire.len() - section > MAX_HEAD_BYTES
                        {
                            return Err(invalid("HTTP trailer section is too large"));
                        }
                        self.phase = Phase::Trailers {
                            section,
                            start,
                            scan,
                            fields,
                        };
                        return Ok(None);
                    };
                    if end - start > MAX_LINE_BYTES || end - section > MAX_HEAD_BYTES {
                        return Err(invalid("HTTP trailer section is too large"));
                    }
                    self.bounded_end(0, end)?;
                    if end == start + 2 {
                        self.phase = Phase::Complete { end };
                    } else {
                        if fields == MAX_FIELDS {
                            return Err(invalid("too many HTTP trailer fields"));
                        }
                        let (name, _) = field(&wire[start..end - 2])?;
                        if name.eq_ignore_ascii_case(b"content-length")
                            || name.eq_ignore_ascii_case(b"transfer-encoding")
                        {
                            return Err(invalid("HTTP trailer cannot redefine message framing"));
                        }
                        self.phase = Phase::Trailers {
                            section,
                            start: end,
                            scan: end,
                            fields: fields + 1,
                        };
                    }
                }
                Phase::CloseDelimited => return Ok(None),
                Phase::Complete { end } => return Ok(Some(end)),
            }
        }
    }
}

// Resume scanning where the previous fragment ended, retaining only the
// delimiter-width overlap. Even byte-at-a-time peers do not cause rescanning
// of the entire retained prefix.
fn delimiter(wire: &[u8], scan: &mut usize, needle: &[u8]) -> Option<usize> {
    while wire.len().saturating_sub(*scan) >= needle.len() {
        if wire[*scan..].starts_with(needle) {
            *scan += needle.len();
            return Some(*scan);
        }
        *scan += 1;
    }
    None
}

struct Head {
    status: u16,
    status_end: usize,
    fields: usize,
    content_length: Option<usize>,
    chunked: bool,
}

fn parse_head(block: &[u8]) -> io::Result<Head> {
    // The final empty line is excluded. Every remaining line must end in CRLF;
    // bare LF, obsolete folding and whitespace before ':' are not normalized.
    let mut lines = block[..block.len() - 2]
        .split_inclusive(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty());
    let status_line = lines.next().unwrap_or_default();
    let status_line = status_line
        .strip_suffix(b"\r\n")
        .ok_or_else(|| invalid("invalid HTTP status line"))?;
    if status_line.len() < 13
        || status_line.len() > MAX_LINE_BYTES
        || !matches!(&status_line[..8], b"HTTP/1.0" | b"HTTP/1.1")
        || status_line[8] != b' '
        || status_line[12] != b' '
        || !status_line[9..12].iter().all(u8::is_ascii_digit)
        || !status_line[13..].iter().copied().all(field_value_byte)
    {
        return Err(invalid("invalid HTTP status line"));
    }
    let status = u16::from(status_line[9] - b'0') * 100
        + u16::from(status_line[10] - b'0') * 10
        + u16::from(status_line[11] - b'0');
    if !(100..600).contains(&status) {
        return Err(invalid("invalid HTTP status code"));
    }
    let mut head = Head {
        status,
        status_end: status_line.len(),
        fields: 0,
        content_length: None,
        chunked: false,
    };
    let mut count = 0;
    for line in lines {
        count += 1;
        if count > MAX_FIELDS || line.len() > MAX_LINE_BYTES {
            return Err(invalid(
                "HTTP response has too many or oversized header fields",
            ));
        }
        let line = line
            .strip_suffix(b"\r\n")
            .ok_or_else(|| invalid("HTTP header requires CRLF"))?;
        let (name, value) = field(line)?;
        if name.eq_ignore_ascii_case(b"content-length") {
            for item in value.split(|byte| *byte == b',') {
                let length = decimal(trim_ows(item))?;
                if head.content_length.is_some_and(|old| old != length) {
                    return Err(invalid("conflicting HTTP Content-Length fields"));
                }
                head.content_length = Some(length);
            }
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            // Additional transfer codings require actual decoding, not merely
            // treating their encoded bytes as the application representation.
            if head.chunked || !value.eq_ignore_ascii_case(b"chunked") {
                return Err(invalid("unsupported or repeated HTTP transfer coding"));
            }
            if &status_line[..8] != b"HTTP/1.1" {
                return Err(invalid("HTTP/1.0 cannot use Transfer-Encoding"));
            }
            head.chunked = true;
        }
    }
    if head.chunked && head.content_length.is_some() {
        return Err(invalid(
            "HTTP response has both Transfer-Encoding and Content-Length",
        ));
    }
    head.fields = count;
    Ok(head)
}

fn field(line: &[u8]) -> io::Result<(&[u8], &[u8])> {
    let colon = line
        .iter()
        .position(|byte| *byte == b':')
        .ok_or_else(|| invalid("HTTP field lacks ':'"))?;
    let name = &line[..colon];
    let value = trim_ows(&line[colon + 1..]);
    if name.is_empty()
        || !name.iter().copied().all(token_byte)
        || !value.iter().copied().all(field_value_byte)
    {
        return Err(invalid("invalid HTTP field syntax"));
    }
    Ok((name, value))
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn field_value_byte(byte: u8) -> bool {
    byte == b'\t' || (byte >= b' ' && byte != 0x7f)
}

fn decimal(value: &[u8]) -> io::Result<usize> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return Err(invalid("invalid HTTP Content-Length"));
    }
    value.iter().try_fold(0_usize, |length, byte| {
        length
            .checked_mul(10)
            .and_then(|length| length.checked_add(usize::from(*byte - b'0')))
            .ok_or_else(|| invalid("HTTP Content-Length overflow"))
    })
}

fn chunk_size(line: &[u8]) -> io::Result<usize> {
    let mut index = 0;
    let mut size = 0_usize;
    while let Some(&byte) = line.get(index) {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => break,
        };
        size = size
            .checked_mul(16)
            .and_then(|size| size.checked_add(usize::from(digit)))
            .ok_or_else(|| invalid("HTTP chunk-size overflow"))?;
        index += 1;
    }
    if index == 0 {
        return Err(invalid("invalid HTTP chunk size"));
    }
    // Extensions do not affect the payload, but still need syntactically valid
    // token/quoted-string boundaries (including escaped quotes and semicolons).
    while index < line.len() {
        skip_ows(line, &mut index);
        if index == line.len() {
            break;
        }
        if line[index] != b';' {
            return Err(invalid("invalid HTTP chunk extension"));
        }
        index += 1;
        skip_ows(line, &mut index);
        consume_token(line, &mut index)?;
        skip_ows(line, &mut index);
        if line.get(index) == Some(&b'=') {
            index += 1;
            skip_ows(line, &mut index);
            if line.get(index) == Some(&b'"') {
                index += 1;
                loop {
                    match line.get(index).copied() {
                        Some(b'"') => {
                            index += 1;
                            break;
                        }
                        Some(b'\\') => {
                            index += 1;
                            if !line.get(index).copied().is_some_and(field_value_byte) {
                                return Err(invalid("invalid quoted HTTP chunk extension"));
                            }
                            index += 1;
                        }
                        Some(byte) if field_value_byte(byte) => index += 1,
                        _ => return Err(invalid("unterminated HTTP chunk extension")),
                    }
                }
            } else {
                consume_token(line, &mut index)?;
            }
        }
    }
    Ok(size)
}

fn skip_ows(bytes: &[u8], index: &mut usize) {
    while bytes
        .get(*index)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        *index += 1;
    }
}

fn consume_token(bytes: &[u8], index: &mut usize) -> io::Result<()> {
    let start = *index;
    while bytes.get(*index).copied().is_some_and(token_byte) {
        *index += 1;
    }
    if *index == start {
        return Err(invalid("missing HTTP chunk extension token"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
    const FIXED: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody";
    const CHUNKED: &[u8] =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n";

    struct Fragmented<'a> {
        remaining: &'a [u8],
        width: usize,
        interrupt: bool,
        end_error: Option<io::ErrorKind>,
    }

    impl Read for Fragmented<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.interrupt {
                self.interrupt = false;
                return Err(io::ErrorKind::Interrupted.into());
            }
            if self.remaining.is_empty() {
                return self.end_error.map_or(Ok(0), |kind| Err(kind.into()));
            }
            let count = self.remaining.len().min(buffer.len()).min(self.width);
            buffer[..count].copy_from_slice(&self.remaining[..count]);
            self.remaining = &self.remaining[count..];
            Ok(count)
        }
    }

    fn assert_self_delimited(message: &[u8], request: &[u8]) {
        for width in 1..=message.len() {
            let mut reader = Fragmented {
                remaining: message,
                width,
                interrupt: true,
                end_error: Some(io::ErrorKind::WouldBlock),
            };
            assert_eq!(
                read_response(&mut reader, request, message.len() as u64).unwrap(),
                message,
                "message must finish without asking for EOF, fragment width {width}",
            );
        }
    }

    #[test]
    fn fixed_length_response_finishes_without_eof_at_every_fragment_width() {
        assert_self_delimited(FIXED, GET);
    }

    #[test]
    fn chunked_response_finishes_without_eof_at_every_fragment_width() {
        assert_self_delimited(CHUNKED, GET);
        assert_self_delimited(
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: CHUNKED\r\n\r\n2; x=token\r\n\x00\xff\r\n2; q=\"semi;\\\"quote\"\r\nok\r\n0\r\nX-Checksum: abc\r\n\r\n",
            GET,
        );
    }

    #[test]
    fn informational_responses_are_retained_but_do_not_finish_the_exchange() {
        let mut message =
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n".to_vec();
        message.extend_from_slice(FIXED);
        assert_self_delimited(&message, GET);
        assert!(
            read_response(
                &mut io::Cursor::new(b"HTTP/1.1 100 Continue\r\n\r\n"),
                GET,
                4096,
            )
            .is_err()
        );
    }

    #[test]
    fn head_and_status_without_body_ignore_representation_length() {
        assert_self_delimited(
            b"HTTP/1.1 200 OK\r\nContent-Length: 9999999\r\n\r\n",
            b"HEAD / HTTP/1.1\r\n\r\n",
        );
        assert_self_delimited(b"HTTP/1.1 204 No Content\r\n\r\n", GET);
        assert_self_delimited(
            b"HTTP/1.1 304 Not Modified\r\nContent-Length: 9999999\r\n\r\n",
            GET,
        );
        assert_self_delimited(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", GET);
    }

    #[test]
    fn identical_content_lengths_are_valid_but_conflicts_are_rejected() {
        assert_self_delimited(
            b"HTTP/1.1 200 OK\r\nContent-Length: 4, 04\r\ncontent-length: 4\r\n\r\nbody",
            GET,
        );
        for fields in [
            "Content-Length: 4, 5\r\n",
            "Content-Length: 4\r\nContent-Length: 5\r\n",
            "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n",
            "Content-Length: -1\r\n",
            "Content-Length: +4\r\n",
            "Content-Length: 4,\r\n",
            "Content-Length: \r\n",
            "Content-Length: 9999999999999999999999999999\r\n",
        ] {
            let bytes = format!("HTTP/1.1 200 OK\r\n{fields}\r\nbody");
            assert!(
                read_response(&mut io::Cursor::new(bytes), GET, 4096).is_err(),
                "{fields}"
            );
        }
    }

    #[test]
    fn every_truncated_fixed_or_chunked_prefix_is_an_error() {
        for message in [FIXED, CHUNKED] {
            for end in 0..message.len() {
                assert!(
                    read_response(&mut io::Cursor::new(&message[..end]), GET, 4096,).is_err(),
                    "accepted truncated message prefix {end}"
                );
            }
        }
    }

    #[test]
    fn clean_eof_is_required_for_close_delimited_responses() {
        let message = b"HTTP/1.0 200 OK\r\n\r\nclose-delimited body";
        assert_eq!(
            read_response(&mut io::Cursor::new(message), GET, 4096).unwrap(),
            message
        );
        let mut unclean = Fragmented {
            remaining: message,
            width: 3,
            interrupt: false,
            end_error: Some(io::ErrorKind::UnexpectedEof),
        };
        assert_eq!(
            read_response(&mut unclean, GET, 4096).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn self_delimited_messages_need_no_tls_close_notification() {
        for message in [FIXED, CHUNKED] {
            let mut unclean = Fragmented {
                remaining: message,
                width: 1,
                interrupt: false,
                end_error: Some(io::ErrorKind::UnexpectedEof),
            };
            assert_eq!(read_response(&mut unclean, GET, 4096).unwrap(), message);
        }
    }

    #[test]
    fn wire_limit_is_exact_and_includes_headers_and_chunk_framing() {
        for message in [FIXED, CHUNKED] {
            assert_eq!(
                read_response(&mut io::Cursor::new(message), GET, message.len() as u64).unwrap(),
                message
            );
            assert!(
                read_response(&mut io::Cursor::new(message), GET, message.len() as u64 - 1)
                    .is_err()
            );
        }
        for limit in [0, 1, 17, 8192] {
            let mut reader = io::Cursor::new(vec![b'x'; 20_000]);
            assert!(read_response(&mut reader, GET, limit).is_err());
            assert_eq!(reader.position(), limit + 1);
        }
    }

    #[test]
    fn impossible_body_lengths_fail_before_waiting_for_more_bytes() {
        let message = b"HTTP/1.1 200 OK\r\nContent-Length: 99999\r\n\r\n";
        let mut reader = Fragmented {
            remaining: message,
            width: message.len(),
            interrupt: false,
            end_error: Some(io::ErrorKind::WouldBlock),
        };
        assert_eq!(
            read_response(&mut reader, GET, 4096).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let message =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffffff\r\n";
        assert!(read_response(&mut io::Cursor::new(message), GET, 4096).is_err());
    }

    #[test]
    fn malformed_heads_and_unsupported_protocols_are_not_successes() {
        for message in [
            &b"garbage\r\n\r\n"[..],
            b"HTTP/1.1 20 OK\r\n\r\n",
            b"HTTP/1.1 600 Invalid\r\n\r\n",
            b"HTTP/2.0 200 OK\r\n\r\n",
            b"HTTP/1.1 200 O\x00K\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n\nX: y\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX: one\r\n two\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length : 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX: one\rtwo\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
        ] {
            assert!(
                read_response(&mut io::Cursor::new(message), GET, 4096).is_err(),
                "{message:?}"
            );
        }
        assert!(
            read_response(
                &mut io::Cursor::new(FIXED),
                b"CONNECT x:443 HTTP/1.1\r\n\r\n",
                4096
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_chunk_boundaries_extensions_and_trailers_are_rejected() {
        for suffix in [
            "x\r\n",
            "-1\r\n",
            "1\r\nxXX0\r\n\r\n",
            "1;=x\r\nx\r\n0\r\n\r\n",
            "1;x=\"unterminated\r\nx\r\n0\r\n\r\n",
            "1;x=\r\nx\r\n0\r\n\r\n",
            "1;x=\"ok\"bad\r\nx\r\n0\r\n\r\n",
            "0\r\nContent-Length: 9\r\n\r\n",
            "0\r\nTransfer-Encoding: chunked\r\n\r\n",
            "0\r\nX: value\r\n folded\r\n\r\n",
            "0\r\nX: value\n\r\n",
        ] {
            let message = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{suffix}");
            assert!(
                read_response(&mut io::Cursor::new(message), GET, 4096).is_err(),
                "{suffix:?}"
            );
        }
    }

    #[test]
    fn metadata_counts_and_sizes_have_independent_bounds() {
        let too_many_fields = format!(
            "HTTP/1.1 200 OK\r\n{}\r\n",
            "X: y\r\n".repeat(MAX_FIELDS + 1)
        );
        assert!(read_response(&mut io::Cursor::new(too_many_fields), GET, 100_000).is_err());
        let too_long = format!(
            "HTTP/1.1 200 OK\r\nX: {}\r\n\r\n",
            "x".repeat(MAX_LINE_BYTES + 1)
        );
        assert!(read_response(&mut io::Cursor::new(too_long), GET, 100_000).is_err());
        let mut informational =
            b"HTTP/1.1 100 Continue\r\n\r\n".repeat(MAX_INFORMATIONAL_RESPONSES + 1);
        informational.extend_from_slice(FIXED);
        assert!(read_response(&mut io::Cursor::new(informational), GET, 100_000).is_err());
    }

    #[test]
    fn an_unsolicited_suffix_is_not_part_of_the_one_shot_response() {
        let mut input = FIXED.to_vec();
        input.extend_from_slice(b"unsolicited bytes");
        for width in 1..=input.len() {
            let mut reader = Fragmented {
                remaining: &input,
                width,
                interrupt: false,
                end_error: None,
            };
            assert_eq!(
                read_response(&mut reader, GET, FIXED.len() as u64).unwrap(),
                FIXED
            );
        }
    }

    #[test]
    fn decoded_view_selects_final_headers_and_preserves_wire_input() {
        let mut raw = b"HTTP/1.1 103 Early Hints\r\nX-Source: interim\r\n\r\n".to_vec();
        raw.extend_from_slice(b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\nX-Source: final\r\n\r\n2\r\n\x00\xff\r\n2\r\nok\r\n0\r\nX-Source: trailer\r\n\r\n");
        let before = raw.clone();
        let parsed = parse_http_response(&raw, "GET").unwrap();
        assert_eq!(parsed.status, 201);
        assert_eq!(parsed.status_text, b"Created");
        assert_eq!(parsed.header_count(), 2);
        assert_eq!(
            parsed.headers().collect::<Vec<_>>(),
            vec![
                (&b"Transfer-Encoding"[..], &b"chunked"[..]),
                (&b"X-Source"[..], &b"final"[..]),
            ]
        );
        assert_eq!(parsed.body_len(), 4);
        assert_eq!(parsed.body_bytes().unwrap().as_ref(), b"\x00\xffok");
        assert_eq!(raw, before, "decoding must not change replay bytes");
    }

    #[test]
    fn chunk_decoding_joins_split_utf8_before_character_decoding() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n\xc3\r\n1\r\n\xa9\r\n0\r\n\r\n";
        let parsed = parse_http_response(raw, "GET").unwrap();
        let body = parsed.body_bytes().unwrap();
        assert_eq!(body.len(), 2);
        assert_eq!(String::from_utf8_lossy(&body), "é");
    }

    #[test]
    fn non_chunked_views_borrow_body_and_empty_headers_are_safe() {
        let parsed = parse_http_response(FIXED, "GET").unwrap();
        assert!(matches!(parsed.body_bytes().unwrap(), Cow::Borrowed(_)));
        assert_eq!(parsed.body_len(), 4);
        let raw = b"HTTP/1.0 200 OK\r\n\r\nbody";
        let parsed = parse_http_response(raw, "GET").unwrap();
        assert_eq!(parsed.headers().count(), 0);
        assert_eq!(parsed.body_len(), 4);
        assert_eq!(parsed.body_bytes().unwrap().as_ref(), b"body");
    }

    #[test]
    fn head_view_has_no_body_despite_nonzero_representation_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n";
        let parsed = parse_http_response(raw, "HEAD").unwrap();
        assert_eq!(parsed.body_len(), 0);
        assert!(parsed.body_bytes().unwrap().is_empty());
        assert!(parse_http_response(raw, "GET").is_err());
    }

    #[test]
    fn recorded_view_rejects_truncation_and_unrecordable_suffix() {
        for message in [FIXED, CHUNKED] {
            for end in 0..message.len() {
                assert!(parse_http_response(&message[..end], "GET").is_err());
            }
            let mut extra = message.to_vec();
            extra.extend_from_slice(b"unrelated bytes");
            assert!(parse_http_response(&extra, "GET").is_err());
        }
    }
}
