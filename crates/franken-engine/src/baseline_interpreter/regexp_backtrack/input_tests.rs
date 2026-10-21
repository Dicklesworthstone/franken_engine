//! The old dense representation is an oracle for the production matcher,
//! not a second matcher. Both inputs run through the same real bytecode.

use super::*;

fn dense_input(text: &str) -> PreparedInput {
    let mut chars = Vec::with_capacity(text.len());
    let mut byte_offsets = Vec::with_capacity(text.len() + 1);
    for (offset, c) in text.char_indices() {
        chars.push(c);
        byte_offsets.push(offset);
    }
    byte_offsets.push(text.len());
    PreparedInput {
        chars,
        byte_offsets: ByteOffsets::Usize(byte_offsets),
    }
}

fn check_offsets(text: &str) {
    let actual = PreparedInput::new(text);
    let reference = dense_input(text);
    assert_eq!(actual.chars, reference.chars);
    assert_eq!(actual.char_len(), reference.char_len());
    for byte in (0..=text.len() + 1).chain([usize::MAX]) {
        assert_eq!(
            actual.char_index_at_byte(byte),
            reference.char_index_at_byte(byte),
            "text={text:?}, byte={byte}"
        );
    }
    for character in (0..=actual.char_len() + 1).chain([usize::MAX]) {
        assert_eq!(
            actual.byte_offset(character),
            reference.byte_offset(character),
            "text={text:?}, character={character}"
        );
    }
    assert_eq!(
        matches!(actual.byte_offsets, ByteOffsets::Identity),
        text.is_ascii()
    );
}

#[test]
fn ascii_has_identity_offsets_including_nul_del_and_empty_input() {
    let all_ascii: String = (0..=127_u8).map(char::from).collect();
    for text in ["", "a", "\0\r\n\t\x7f", all_ascii.as_str()] {
        check_offsets(text);
    }
}

#[test]
fn unicode_and_interior_byte_offsets_keep_next_boundary_semantics() {
    for text in [
        "é",
        "日",
        "😀",
        "aé日😀z",
        "\u{7f}\u{80}\u{7ff}\u{800}\u{d7ff}\u{e000}\u{ffff}\u{10000}\u{10ffff}",
        "\0😀\0é日\r\n",
    ] {
        check_offsets(text);
    }
    let input = PreparedInput::new("a😀é");
    assert_eq!(input.char_index_at_byte(2), 2);
    assert_eq!(input.char_index_at_byte(4), 2);
    assert_eq!(input.char_index_at_byte(5), 2);
    assert_eq!(input.char_index_at_byte(6), 3);
    assert_eq!(input.char_index_at_byte(7), 3);
    assert_eq!(input.char_index_at_byte(8), 4);
}

#[test]
fn generated_mixed_inputs_agree_with_dense_offsets() {
    let alphabet = ['\0', 'a', '\n', 'é', '日', '😀', '\u{e000}'];
    for length in 0..=4_u32 {
        for mut encoded in 0..alphabet.len().pow(length) {
            let mut text = String::new();
            for _ in 0..length {
                text.push(alphabet[encoded % alphabet.len()]);
                encoded /= alphabet.len();
            }
            check_offsets(&text);
        }
    }
}

#[test]
fn preparation_retains_no_ascii_table_and_no_byte_sized_unicode_slack() {
    let text = "a".repeat(65_536);
    let ascii = PreparedInput::new(&text);
    let reference = dense_input(&text);
    assert!(matches!(ascii.byte_offsets, ByteOffsets::Identity));
    assert_eq!(ascii.chars.capacity(), text.len());
    assert_eq!(ascii.chars, reference.chars);
    let ByteOffsets::Usize(reference_offsets) = &reference.byte_offsets else {
        panic!("dense oracle keeps usize offsets");
    };
    assert_eq!(reference_offsets.capacity(), text.len() + 1);
    for scalar in ["é", "日", "😀"] {
        let text = scalar.repeat(4096);
        let input = PreparedInput::new(&text);
        assert_eq!(input.chars.capacity(), 4096);
        let ByteOffsets::U32(offsets) = &input.byte_offsets else {
            panic!("ordinary Unicode input should use compact offsets");
        };
        assert_eq!(offsets.capacity(), 4097);
        assert_eq!(
            offsets.capacity() * std::mem::size_of::<u32>(),
            4097 * std::mem::size_of::<u32>()
        );
        assert_eq!(input.byte_offset(4096), text.len());
    }
}

#[test]
fn empty_patterns_distinguish_eof_from_starts_beyond_it() {
    let regexp = BacktrackRegExp::new("(?=)", "u").unwrap();
    for text in ["", "a", "abc", "é😀"] {
        let input = PreparedInput::new(text);
        for sticky in [false, true] {
            let eof = input.char_index_at_byte(text.len());
            assert_eq!(
                regexp.exec_at(&input, eof, sticky).unwrap(),
                Some(vec![Some((text.len(), text.len()))])
            );
            for byte in [text.len() + 1, usize::MAX] {
                assert_eq!(
                    regexp
                        .exec_at(&input, input.char_index_at_byte(byte), sticky)
                        .unwrap(),
                    None
                );
            }
        }
    }
}

#[test]
fn native_captures_and_remaining_work_match_dense_inputs_at_every_budget() {
    for (pattern, flags) in [
        ("(?=)", ""),
        ("(a*?)b", ""),
        ("(a{0,32}?)b", ""),
        ("(?<=(a+))b", ""),
        ("(?=(a+))a*b\\1", ""),
        ("(?:(a)|b)+", ""),
        ("^([a-z]*)(.*?)$", "m"),
        ("(?<q>é|😀)\\k<q>", "u"),
        ("(k*)(?=!)", "iu"),
        ("(?<=日)(😀*)", "u"),
    ] {
        let regexp = BacktrackRegExp::new(pattern, flags).unwrap();
        for text in ["", "a", "aaab", "baabac", "a\nb", "\0ab", "éé", "日😀😀", "Kk!"] {
            let actual = PreparedInput::new(text);
            let reference = dense_input(text);
            for byte in (0..=text.len() + 1).chain([usize::MAX]) {
                for sticky in [false, true] {
                    for budget in (0..=32).chain([63, 127, 4096]) {
                        let mut left = budget;
                        let mut right = budget;
                        assert_eq!(
                            regexp.exec_at_with_budget(
                                &actual, actual.char_index_at_byte(byte), sticky, &mut left
                            ),
                            regexp.exec_at_with_budget(
                                &reference, reference.char_index_at_byte(byte), sticky, &mut right
                            ),
                            "/{pattern}/{flags} text={text:?} byte={byte} sticky={sticky} budget={budget}"
                        );
                        assert_eq!(left, right, "offset storage cannot renew work");
                    }
                }
            }
        }
    }
}

#[test]
fn global_matches_keep_byte_spans_when_inputs_change_encoding() {
    let regexp = Rc::new(BacktrackRegExp::new("(?=)(a*)", "u").unwrap());
    let compiled = CompiledRegExp::Backtracking(Rc::clone(&regexp));
    for text in ["aaa", "😀aé", "", "\0aa", "a"].repeat(2) {
        let reference = dense_input(text);
        let mut expected = Vec::new();
        let mut at = 0;
        let mut steps = BacktrackRegExp::step_budget(&reference);
        while at <= reference.char_len() {
            let Some(spans) = regexp
                .exec_at_with_budget(&reference, at, false, &mut steps)
                .unwrap()
            else {
                break;
            };
            let (from, to) = spans[0].unwrap();
            at = reference.char_index_at_byte(to) + usize::from(from == to);
            expected.push(spans);
        }
        assert_eq!(
            compiled
                .all_captures(text, CaptureRetention::AllGroups, &mut RetentionBudget::new(u64::MAX))
                .unwrap(),
            expected
        );
    }
}


#[test]
fn compact_offsets_match_wide_oracle_at_u32_boundaries() {
    // Construct the representations directly so the wide fallback receives
    // coverage without materializing a multi-gigabyte guest string.
    let compact = PreparedInput {
        chars: vec!['a', 'é', '日', '😀'],
        byte_offsets: ByteOffsets::U32(vec![0, 1, 3, 6, 10]),
    };
    let wide = PreparedInput {
        chars: compact.chars.clone(),
        byte_offsets: ByteOffsets::Usize(vec![0, 1, 3, 6, 10]),
    };
    for byte in (0..=12).chain([usize::MAX]) {
        assert_eq!(compact.char_index_at_byte(byte), wide.char_index_at_byte(byte));
    }
    for character in (0..=6).chain([usize::MAX]) {
        assert_eq!(compact.byte_offset(character), wide.byte_offset(character));
    }
    assert_eq!(
        std::mem::size_of::<u32>() * 5,
        20,
        "compact table is four bytes per boundary"
    );
}
