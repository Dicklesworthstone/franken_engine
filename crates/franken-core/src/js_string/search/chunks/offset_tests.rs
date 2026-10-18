use super::*;

#[test]
fn uniform_three_byte_offsets_cover_every_scalar_boundary() {
    for repetitions in [0, 1, 7, 64, 4096] {
        let text = "\u{800}\u{65e5}\u{ffff}".repeat(repetitions);
        let units = text.encode_utf16().count();
        for byte in (0..=text.len()).step_by(3) {
            assert_eq!(units_before(&text, byte, units), byte / 3);
        }
    }
}

#[test]
fn variable_width_and_astral_offsets_cannot_use_an_average_width() {
    for text in [
        "",
        "ascii",
        "\u{e9}\u{e9}\u{e9}",
        "\u{1f600}\u{1f600}",
        "a\u{65e5}",
        "\u{65e5}a",
        "a\u{1f600}\u{65e5}\u{e9}",
        "\u{10ffff}\u{800}a\u{ffff}",
    ] {
        let units = text.encode_utf16().count();
        for byte in text.char_indices().map(|(byte, _)| byte).chain([text.len()]) {
            assert_eq!(units_before(text, byte, units), text[..byte].encode_utf16().count());
        }
    }
}

#[test]
fn successful_unicode_searches_keep_utf16_offsets_and_unjoined_backing() {
    fn rope(left: JsString, right: JsString) -> JsString {
        let shape = left.joined_shape(&right);
        JsString::joined(left, right, shape)
    }
    let value = rope(
        JsString::from(format!("{}\u{8a9e}", "\u{65e5}".repeat(8192))),
        JsString::from(format!("{}\u{8a9e}", "\u{672c}".repeat(4096))),
    );
    let needle = JsString::from("\u{8a9e}");
    for from in [0, 1, 4096, 8192] {
        assert_eq!(value.utf16_index_of(&needle, from), Some(8192));
    }
    for from in [8193, 10_000, 12_289] {
        assert_eq!(value.utf16_index_of(&needle, from), Some(12_289));
    }
    assert_eq!(value.utf16_last_index_of(&needle, usize::MAX), Some(12_289));
    assert_eq!(value.utf16_last_index_of(&needle, 12_288), Some(8192));
    assert_eq!(value.utf16_last_index_of(&needle, 8191), None);
    let Text::Concat(node) = &value.utf8 else { panic!("expected rope") };
    assert!(node.joined.get().is_none());
}

#[test]
fn offset_conversion_is_inverse_to_non_split_unit_boundaries() {
    for text in [
        "\u{65e5}\u{672c}\u{8a9e}".repeat(64),
        "a\u{65e5}\u{1f600}\u{e9}".repeat(64),
    ] {
        let units = text.encode_utf16().count();
        for index in 0..=units {
            let (byte, split) = access::utf16_boundary(&text, units, index);
            if !split {
                assert_eq!(units_before(&text, byte, units), index);
            }
        }
    }
}
