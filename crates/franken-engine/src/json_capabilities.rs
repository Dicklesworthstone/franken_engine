#![forbid(unsafe_code)]

//! Canonical JSON builtin capability names and argument ABI.

/// Canonical capability name for `JSON.parse`.
pub const JSON_PARSE_CAPABILITY: &str = "builtin:JsonParse";
/// Canonical capability name for `JSON.stringify`.
pub const JSON_STRINGIFY_CAPABILITY: &str = "builtin:JsonStringify";

const BATCH_36_JSON_PARSE_CAPABILITY: &str = "builtin:JSONParse";
const BATCH_36_JSON_STRINGIFY_CAPABILITY: &str = "builtin:JSONStringify";

/// The canonical ABI for static JSON builtins.
///
/// `JSON.parse(value)` and `JSON.stringify(value)` consume their first semantic
/// value from `args.start`. They do not reserve `args.start` for a receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonBuiltinAbi {
    pub first_value_arg_offset: u32,
    pub receiver_arg_offset: Option<u32>,
}

impl JsonBuiltinAbi {
    pub const STATIC_FUNCTION: Self = Self {
        first_value_arg_offset: 0,
        receiver_arg_offset: None,
    };
}

/// JSON builtin family after canonical name normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JsonBuiltinKind {
    Parse,
    Stringify,
}

impl JsonBuiltinKind {
    pub fn canonical_capability(self) -> &'static str {
        match self {
            Self::Parse => JSON_PARSE_CAPABILITY,
            Self::Stringify => JSON_STRINGIFY_CAPABILITY,
        }
    }

    pub fn abi(self) -> JsonBuiltinAbi {
        JsonBuiltinAbi::STATIC_FUNCTION
    }

    pub fn function_indices(self) -> &'static [u32] {
        match self {
            Self::Parse => &[70, 366],
            Self::Stringify => &[71, 365],
        }
    }
}

/// Normalize all known JSON builtin capability spellings to one canonical name.
pub fn canonical_json_capability_name(capability: &str) -> Option<&'static str> {
    json_builtin_kind_for_capability(capability).map(JsonBuiltinKind::canonical_capability)
}

/// Resolve all known JSON builtin capability spellings to the canonical kind.
pub fn json_builtin_kind_for_capability(capability: &str) -> Option<JsonBuiltinKind> {
    match capability {
        JSON_PARSE_CAPABILITY | BATCH_36_JSON_PARSE_CAPABILITY => Some(JsonBuiltinKind::Parse),
        JSON_STRINGIFY_CAPABILITY | BATCH_36_JSON_STRINGIFY_CAPABILITY => {
            Some(JsonBuiltinKind::Stringify)
        }
        _ => None,
    }
}

/// Resolve the known baseline function-index aliases to the canonical JSON kind.
pub fn json_builtin_kind_for_function_index(function_index: u32) -> Option<JsonBuiltinKind> {
    match function_index {
        70 | 366 => Some(JsonBuiltinKind::Parse),
        71 | 365 => Some(JsonBuiltinKind::Stringify),
        _ => None,
    }
}

/// Resolve baseline function-index aliases directly to canonical capability names.
pub fn canonical_json_capability_for_function_index(function_index: u32) -> Option<&'static str> {
    json_builtin_kind_for_function_index(function_index).map(JsonBuiltinKind::canonical_capability)
}

/// Return the canonical JSON ABI for any accepted JSON capability alias.
pub fn json_builtin_abi_for_capability(capability: &str) -> Option<JsonBuiltinAbi> {
    json_builtin_kind_for_capability(capability).map(JsonBuiltinKind::abi)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_capabilities_normalize_duplicate_parse_names() {
        assert_eq!(
            canonical_json_capability_name("builtin:JsonParse"),
            Some(JSON_PARSE_CAPABILITY)
        );
        assert_eq!(
            canonical_json_capability_name("builtin:JSONParse"),
            Some(JSON_PARSE_CAPABILITY)
        );
    }

    #[test]
    fn json_capabilities_normalize_duplicate_stringify_names() {
        assert_eq!(
            canonical_json_capability_name("builtin:JsonStringify"),
            Some(JSON_STRINGIFY_CAPABILITY)
        );
        assert_eq!(
            canonical_json_capability_name("builtin:JSONStringify"),
            Some(JSON_STRINGIFY_CAPABILITY)
        );
    }

    #[test]
    fn json_capabilities_unify_duplicate_function_indices() {
        assert_eq!(
            canonical_json_capability_for_function_index(70),
            canonical_json_capability_for_function_index(366)
        );
        assert_eq!(
            canonical_json_capability_for_function_index(71),
            canonical_json_capability_for_function_index(365)
        );
        assert_eq!(
            canonical_json_capability_for_function_index(70),
            Some(JSON_PARSE_CAPABILITY)
        );
        assert_eq!(
            canonical_json_capability_for_function_index(365),
            Some(JSON_STRINGIFY_CAPABILITY)
        );
    }

    #[test]
    fn json_capabilities_pin_static_function_abi_for_all_aliases() {
        let expected = JsonBuiltinAbi {
            first_value_arg_offset: 0,
            receiver_arg_offset: None,
        };

        for capability in [
            "builtin:JsonParse",
            "builtin:JSONParse",
            "builtin:JsonStringify",
            "builtin:JSONStringify",
        ] {
            assert_eq!(json_builtin_abi_for_capability(capability), Some(expected));
        }
    }

    #[test]
    fn json_capabilities_reject_non_json_capabilities() {
        assert_eq!(canonical_json_capability_name("builtin:ConsoleLog"), None);
        assert_eq!(json_builtin_kind_for_function_index(100), None);
    }
}
