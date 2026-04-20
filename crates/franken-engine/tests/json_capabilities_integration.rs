//! Integration coverage for canonical JSON builtin capability aliases and ABI.

#![forbid(unsafe_code)]

use frankenengine_engine::json_capabilities::{
    JSON_PARSE_CAPABILITY, JSON_STRINGIFY_CAPABILITY, JsonBuiltinAbi, JsonBuiltinKind,
    canonical_json_capability_for_function_index, canonical_json_capability_name,
    json_builtin_abi_for_capability, json_builtin_kind_for_capability,
    json_builtin_kind_for_function_index,
};

#[test]
fn json_capability_aliases_normalize_to_canonical_names() {
    for (alias, expected_kind, expected_capability) in [
        (
            "builtin:JsonParse",
            JsonBuiltinKind::Parse,
            JSON_PARSE_CAPABILITY,
        ),
        (
            "builtin:JSONParse",
            JsonBuiltinKind::Parse,
            JSON_PARSE_CAPABILITY,
        ),
        (
            "builtin:JsonStringify",
            JsonBuiltinKind::Stringify,
            JSON_STRINGIFY_CAPABILITY,
        ),
        (
            "builtin:JSONStringify",
            JsonBuiltinKind::Stringify,
            JSON_STRINGIFY_CAPABILITY,
        ),
    ] {
        assert_eq!(json_builtin_kind_for_capability(alias), Some(expected_kind));
        assert_eq!(
            canonical_json_capability_name(alias),
            Some(expected_capability)
        );
    }
}

#[test]
fn json_capability_function_indices_share_canonical_abi() {
    let expected_abi = JsonBuiltinAbi {
        first_value_arg_offset: 0,
        receiver_arg_offset: None,
    };

    for (function_index, expected_kind, expected_capability) in [
        (70, JsonBuiltinKind::Parse, JSON_PARSE_CAPABILITY),
        (366, JsonBuiltinKind::Parse, JSON_PARSE_CAPABILITY),
        (71, JsonBuiltinKind::Stringify, JSON_STRINGIFY_CAPABILITY),
        (365, JsonBuiltinKind::Stringify, JSON_STRINGIFY_CAPABILITY),
    ] {
        assert_eq!(
            json_builtin_kind_for_function_index(function_index),
            Some(expected_kind)
        );
        assert_eq!(
            canonical_json_capability_for_function_index(function_index),
            Some(expected_capability)
        );
        assert_eq!(
            json_builtin_abi_for_capability(expected_capability),
            Some(expected_abi)
        );
    }
}

#[test]
fn json_capability_resolution_fails_closed_for_unknown_inputs() {
    for capability in [
        "",
        "builtin:Json",
        "builtin:JSON",
        "builtin:JsonParseReviver",
        "builtin:ConsoleLog",
    ] {
        assert_eq!(json_builtin_kind_for_capability(capability), None);
        assert_eq!(canonical_json_capability_name(capability), None);
        assert_eq!(json_builtin_abi_for_capability(capability), None);
    }

    for function_index in [0, 69, 72, 364, 367, u32::MAX] {
        assert_eq!(json_builtin_kind_for_function_index(function_index), None);
        assert_eq!(
            canonical_json_capability_for_function_index(function_index),
            None
        );
    }
}
