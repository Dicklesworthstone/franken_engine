//! Differential checks against the previous whole-input UTF-8 partitioner.

use super::{DecodeState, complete_prefix, decode_bytes};

fn full_scan(bytes: &[u8]) -> usize {
    let mut offset = 0;
    while let Err(error) = std::str::from_utf8(&bytes[offset..]) {
        offset += error.valid_up_to();
        match error.error_len() {
            Some(length) => offset += length,
            None => return offset,
        }
    }
    bytes.len()
}

#[test]
fn every_two_byte_input_has_the_same_complete_prefix() {
    assert_eq!(complete_prefix("utf-8", &[]), 0);
    for a in 0..=u8::MAX {
        assert_eq!(complete_prefix("utf-8", &[a]), full_scan(&[a]));
        for b in 0..=u8::MAX {
            let bytes = [a, b];
            assert_eq!(
                complete_prefix("utf-8", &bytes),
                full_scan(&bytes),
                "{bytes:x?}"
            );
        }
    }
}

#[test]
fn structural_utf8_boundaries_reject_malformed_but_keep_incomplete_tails() {
    let alphabet = [
        0, 0x7f, 0x80, 0x8f, 0x90, 0x9f, 0xa0, 0xbf, 0xc0, 0xc1, 0xc2, 0xdf, 0xe0, 0xed, 0xef,
        0xf0, 0xf4, 0xf5, 0xff,
    ];
    for a in alphabet {
        for b in alphabet {
            for c in alphabet {
                for d in alphabet {
                    let bytes = [a, b, c, d];
                    assert_eq!(
                        complete_prefix("utf-8", &bytes),
                        full_scan(&bytes),
                        "{bytes:x?}"
                    );
                }
            }
        }
    }
}

#[test]
fn long_valid_and_malformed_prefixes_do_not_change_the_tail_partition() {
    let prefixes = [
        "abcdef".repeat(8192).into_bytes(),
        "é€😀".repeat(8192).into_bytes(),
        vec![0xff; 32768],
    ];
    let tails: &[&[u8]] = &[
        &[],
        &[0xc2],
        &[0xc0],
        &[0xe0, 0xa0],
        &[0xe0, 0x80],
        &[0xed, 0x9f],
        &[0xed, 0xa0],
        &[0xf0, 0x90, 0x80],
        &[0xf0, 0x80, 0x80],
        &[0xf4, 0x8f, 0xbf],
        &[0xf4, 0x90, 0x80],
        &[0xef, 0xbb, 0xbf],
        &[0xff, 0xe2, 0x82],
        &[0x80, 0x80, 0x80, 0x80],
        &[0xf0, 0x90, 0x80, 0x80],
    ];
    for prefix in &prefixes {
        for tail in tails {
            let mut bytes = prefix.clone();
            bytes.extend_from_slice(tail);
            assert_eq!(complete_prefix("utf-8", &bytes), full_scan(&bytes));
            assert_eq!(
                complete_prefix("utf-8", &bytes),
                prefix.len() + full_scan(tail)
            );
        }
    }
}

// The previous state transition, with the independent full scan above. Keep
// output, carry bytes, BOM state, flushes and fatal reset behavior comparable
// after EVERY call, not only after concatenating the eventual output.
fn reference_decode(
    state: &mut DecodeState,
    mut bytes: Vec<u8>,
    fatal: bool,
    ignore_bom: bool,
    stream: bool,
) -> Option<Vec<u16>> {
    if !state.streaming {
        *state = DecodeState::default();
    }
    if state.pending_len != 0 {
        bytes.extend_from_slice(&state.pending[..state.pending_len]);
        bytes.rotate_right(state.pending_len);
    }
    let end = if stream {
        full_scan(&bytes)
    } else {
        bytes.len()
    };
    let decoded = decode_bytes("utf-8", &bytes[..end], fatal, ignore_bom || state.bom_seen);
    if decoded.is_none() || !stream {
        *state = DecodeState::default();
        return decoded;
    }
    state.streaming = true;
    state.bom_seen |= end != 0;
    state.pending = [0; 3];
    state.pending_len = bytes.len() - end;
    state.pending[..state.pending_len].copy_from_slice(&bytes[end..]);
    decoded
}

fn compare_calls(chunks: &[Vec<u8>], fatal: bool, ignore_bom: bool) {
    let mut actual = DecodeState::default();
    let mut expected = DecodeState::default();
    for (index, chunk) in chunks.iter().enumerate() {
        // Periodic final flushes also exercise successful resets in the
        // middle of a sequence, after which a later BOM must be stripped again.
        let stream = index % 5 != 4;
        assert_eq!(
            actual.decode("utf-8", chunk.clone(), fatal, ignore_bom, stream),
            reference_decode(&mut expected, chunk.clone(), fatal, ignore_bom, stream),
            "call={index}, fatal={fatal}, ignore_bom={ignore_bom}"
        );
        assert_eq!(actual, expected, "state after call {index}");
        assert!(actual.pending_len <= 3);
    }
    assert_eq!(
        actual.decode("utf-8", Vec::new(), fatal, ignore_bom, false),
        reference_decode(&mut expected, Vec::new(), fatal, ignore_bom, false)
    );
    assert_eq!(actual, expected);
    assert_eq!(actual, DecodeState::default());
}

#[test]
fn streaming_transitions_match_across_bom_fatal_flush_and_recovery() {
    let examples = [
        vec![0xef, 0xbb, 0xbf, b'a', 0xf0, 0x9f, 0x98, 0x80, 0xe2, 0x82],
        vec![0xff, 0xe0, 0xa0, 0x80, 0xed, 0xa0, 0x80, 0xef, 0xbb, 0xbf],
        vec![0xc0, 0x80, 0xf4, 0x8f, 0xbf, 0xbf, 0xf4, 0x90, 0x80],
    ];
    for bytes in &examples {
        for split in 0..=bytes.len() {
            let chunks = vec![
                bytes[..split].to_vec(),
                bytes[split..].to_vec(),
                Vec::new(),
                vec![0xef],
                vec![0xbb],
                vec![0xbf, b'z'],
                Vec::new(),
                vec![0xff, 0xe2],
                vec![0xef, 0xbb, 0xbf, b'q'],
            ];
            for fatal in [false, true] {
                for ignore_bom in [false, true] {
                    compare_calls(&chunks, fatal, ignore_bom);
                }
            }
        }
    }
}

#[test]
fn seeded_streams_preserve_each_output_and_packed_state() {
    let mut seed = 0x6e57_01ab_u32;
    for _ in 0..128 {
        let mut chunks = Vec::new();
        for length in 0..24 {
            let bytes = (0..length)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    seed as u8
                })
                .collect();
            chunks.push(bytes);
        }
        for fatal in [false, true] {
            for ignore_bom in [false, true] {
                compare_calls(&chunks, fatal, ignore_bom);
            }
        }
    }
}

#[test]
fn incomplete_tail_does_not_defer_fatal_errors_in_the_complete_prefix() {
    for bytes in [
        vec![0xff, 0xe2, 0x82],
        vec![0xe0, 0x80, 0xf0, 0x90, 0x80],
        vec![0xed, 0xa0, 0x80, 0xc2],
    ] {
        let mut state = DecodeState::default();
        assert_eq!(state.decode("utf-8", bytes, true, false, true), None);
        assert_eq!(state, DecodeState::default());
        assert_eq!(
            state.decode("utf-8", vec![0xef, 0xbb, 0xbf, b'x'], true, false, true),
            Some(vec![u16::from(b'x')])
        );
    }
}
