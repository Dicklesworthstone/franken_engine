//! Node's `util.inspect` rendering for console output.
//!
//! Console arguments used to go through ToString: `console.log({ a: 1 })`
//! printed `[object Object]`, `console.log([1, [2]])` printed `1,2` and
//! `console.log(-0)` printed `0`. Node renders every non-string argument
//! with `util.inspect` and applies `printf`-style directives when the first
//! argument is a string (`util.formatWithOptions`). This follows
//! lib/internal/util/inspect.js at its default options (depth 2,
//! breakLength 80, compact 3, at most 100 entries per array or collection
//! and 10000 characters per string) for the value kinds the engine has.
//!
//! Rendering is read-only and runs no guest code. Accessors print as
//! `[Getter]`/`[Setter]`. A Proxy prints its target, as Node does without
//! `showProxy`. `constructor` names are read off the prototype chain
//! without `Symbol.hasInstance`. `check_console_confidentiality` has already
//! walked every value reachable from the arguments, so nothing printed here
//! escapes the sink check. Every rendered value is charged as native work.
//!
//! Known differences from Node:
//! - class constructors print as functions (`[Function: A]`, not
//!   `[class A]`);
//! - the engine unboxes `new Number(1)`;
//! - `Symbol.toStringTag` getters are not run;
//! - `%o` renders like `%O` at depth 4, without hidden properties;
//! - `%d`/`%i`/`%f` convert objects to `NaN` instead of calling `valueOf`;
//! - `%j` serializes plain data (objects, arrays, primitives, Dates)
//!   without calling user `toJSON` methods;
//! - error stacks carry the engine's own frames.

use super::*;

const INSPECT_DEPTH: i64 = 2;
const INSPECT_PERCENT_O_DEPTH: i64 = 4;
const INSPECT_BREAK_LENGTH: usize = 80;
const INSPECT_COMPACT: i64 = 3;
const INSPECT_MAX_ARRAY_LENGTH: usize = 100;
const INSPECT_MAX_STRING_LENGTH: usize = 10_000;
/// Strings up to this many code units are never split at line breaks.
const INSPECT_MIN_LINE_WIDTH: usize = 16;
/// Output produced at one indentation level after which Node stops
/// descending into containers.
const INSPECT_LEVEL_BUDGET: usize = 1 << 27;
/// Buffers print at most this many bytes.
const INSPECT_MAX_BUFFER_BYTES: usize = 50;

/// Whether a container's entries are array elements (grouped into columns,
/// printed without keys) or keyed properties.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EntryKind {
    Object,
    Array,
}

/// Identity of a value that can be on the current formatting path.
#[derive(Clone, Copy, PartialEq, Eq)]
enum InspectIdentity {
    Object(u32),
    Function(u32),
    Closure(u32),
}

struct InspectState<'m> {
    module: Option<&'m Ir3Module>,
    depth: i64,
    /// `maxArrayLength`: array, typed array, Map and Set entries shown.
    max_array_length: usize,
    /// `breakLength`: the width past which entries go on separate lines
    /// (`usize::MAX` for Infinity).
    break_length: usize,
    seen: Vec<InspectIdentity>,
    /// Targets of `[Circular *n]` references; reference `n` is index `n - 1`.
    circular: Vec<InspectIdentity>,
    indentation: usize,
    current_depth: i64,
    level_budget: BTreeMap<usize, usize>,
}

impl<'m> InspectState<'m> {
    fn new(module: Option<&'m Ir3Module>, depth: i64) -> Self {
        Self {
            module,
            depth,
            max_array_length: INSPECT_MAX_ARRAY_LENGTH,
            break_length: INSPECT_BREAK_LENGTH,
            seen: Vec::new(),
            circular: Vec::new(),
            indentation: 0,
            current_depth: 0,
            level_budget: BTreeMap::new(),
        }
    }

    fn circular_index(&mut self, identity: InspectIdentity) -> usize {
        match self.circular.iter().position(|seen| *seen == identity) {
            Some(index) => index + 1,
            None => {
                self.circular.push(identity);
                self.circular.len()
            }
        }
    }
}

/// An own property key: string keys print as names, symbol keys as their
/// rendered `[Symbol(description)]`.
enum InspectKey {
    String(JsString),
    Symbol(String),
}

impl InspectKey {
    fn text(&self) -> Option<&str> {
        match self {
            Self::String(key) => key.as_str(),
            Self::Symbol(_) => None,
        }
    }
}

/// A heap object's own property, as far as rendering is concerned.
enum InspectProperty {
    Data(Value),
    Getter,
    Setter,
    GetterSetter,
}

/// JavaScript `.length` of rendered text (UTF-16 code units).
fn js_length(text: &str) -> usize {
    text.chars().map(char::len_utf16).sum()
}

/// Display width used for column alignment (Node's `getStringWidth`,
/// without its East Asian wide-character table).
fn display_width(text: &str) -> usize {
    text.chars().count()
}

/// Node's internal/cli_table (bd-9vouw.158): a box table of `head` over
/// `columns`, rows as long as the longest column, a missing cell empty, every
/// cell left-justified to its column's display width.
pub(super) fn console_table_text(head: &[String], columns: &[Vec<Option<String>>]) -> String {
    let rows = columns.iter().map(Vec::len).max().unwrap_or(0);
    let cell = |column: usize, row: usize| -> &str {
        columns
            .get(column)
            .and_then(|cells| cells.get(row))
            .and_then(|cell| cell.as_deref())
            .unwrap_or("")
    };
    let mut widths: Vec<usize> = head.iter().map(|text| display_width(text)).collect();
    for (column, width) in widths.iter_mut().enumerate() {
        for row in 0..rows {
            *width = (*width).max(display_width(cell(column, row)));
        }
    }
    let render = |cells: &[&str]| {
        let mut out = String::from("\u{2502} ");
        for (index, text) in cells.iter().enumerate() {
            out.push_str(text);
            out.push_str(&" ".repeat(widths[index].saturating_sub(display_width(text))));
            if index + 1 != cells.len() {
                out.push_str(" \u{2502} ");
            }
        }
        out.push_str(" \u{2502}");
        out
    };
    let divider: Vec<String> = widths
        .iter()
        .map(|width| "\u{2500}".repeat(width + 2))
        .collect();
    let head: Vec<&str> = head.iter().map(String::as_str).collect();
    let mut out = format!("\u{250c}{}\u{2510}\n", divider.join("\u{252c}"));
    out.push_str(&render(&head));
    out.push_str(&format!("\n\u{251c}{}\u{2524}\n", divider.join("\u{253c}")));
    for row in 0..rows {
        let cells: Vec<&str> = (0..head.len()).map(|column| cell(column, row)).collect();
        out.push_str(&render(&cells));
        out.push('\n');
    }
    out.push_str(&format!("\u{2514}{}\u{2518}", divider.join("\u{2534}")));
    out
}

fn pad_start(text: &str, width: usize) -> String {
    let current = display_width(text);
    if current >= width {
        return text.to_string();
    }
    format!("{}{text}", " ".repeat(width - current))
}

fn pad_end(text: &str, width: usize) -> String {
    let current = display_width(text);
    if current >= width {
        return text.to_string();
    }
    format!("{text}{}", " ".repeat(width - current))
}

/// Node's `strEscape`: quote with `'`, or `"` when the text contains `'`
/// but no `"`, or a backtick when it also contains `"` but no backtick or
/// `${`. Control characters, the chosen quote, backslashes and lone
/// surrogates are escaped.
pub(super) fn inspect_quote(units: &[u16]) -> String {
    let contains = |needle: u16| units.contains(&needle);
    let has_template_open = units.windows(2).any(|pair| pair == [0x24, 0x7b]);
    let (quote, escape_single) = if contains(0x27) {
        if !contains(0x22) {
            ('"', false)
        } else if !contains(0x60) && !has_template_open {
            ('`', false)
        } else {
            ('\'', true)
        }
    } else {
        ('\'', true)
    };
    let mut out = String::with_capacity(units.len() + 2);
    out.push(quote);
    let mut index = 0;
    while index < units.len() {
        let unit = units[index];
        match unit {
            0x27 if escape_single => out.push_str("\\'"),
            0x5c => out.push_str("\\\\"),
            0x08 => out.push_str("\\b"),
            0x09 => out.push_str("\\t"),
            0x0a => out.push_str("\\n"),
            0x0c => out.push_str("\\f"),
            0x0d => out.push_str("\\r"),
            0x00..=0x1f | 0x7f..=0x9f => out.push_str(&format!("\\x{unit:02X}")),
            0xd800..=0xdbff => {
                if let Some(&low) = units.get(index + 1)
                    && (0xdc00..=0xdfff).contains(&low)
                {
                    let code =
                        0x10000 + ((u32::from(unit) - 0xd800) << 10) + (u32::from(low) - 0xdc00);
                    out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                    index += 1;
                } else {
                    out.push_str(&format!("\\u{unit:x}"));
                }
            }
            0xdc00..=0xdfff => out.push_str(&format!("\\u{unit:x}")),
            _ => out.push(char::from_u32(u32::from(unit)).unwrap_or('\u{fffd}')),
        }
        index += 1;
    }
    out.push(quote);
    out
}

/// Node's `formatNumber`: `-0` keeps its sign.
fn inspect_number(value: f64) -> String {
    if value == 0.0 && value.is_sign_negative() {
        "-0".to_string()
    } else {
        Float64::new(value).to_string()
    }
}

/// Property names print bare when they look like identifiers, else quoted.
fn inspect_key_name(key: &JsString) -> String {
    let text = key.as_str();
    if let Some(text) = text {
        if text == "__proto__" {
            return "['__proto__']".to_string();
        }
        let mut chars = text.chars();
        if chars
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
            && chars.all(|rest| rest.is_ascii_alphanumeric() || rest == '_')
        {
            return text.to_string();
        }
    }
    inspect_quote(&key.code_units_vec())
}

/// Node's `groupArrayElements`: lay out more than six short array entries
/// in aligned columns.
fn group_array_elements(
    output: Vec<String>,
    has_more: bool,
    numeric: &[bool],
    break_length: usize,
) -> Vec<String> {
    let mut total_length = 0usize;
    let mut max_length = 0usize;
    let output_length = if has_more {
        output.len() - 1
    } else {
        output.len()
    };
    const SEPARATOR_SPACE: usize = 2;
    let data_len: Vec<usize> = output[..output_length]
        .iter()
        .map(|entry| display_width(entry))
        .collect();
    for &len in &data_len {
        total_length += len + SEPARATOR_SPACE;
        max_length = max_length.max(len);
    }
    let actual_max = max_length + SEPARATOR_SPACE;
    if actual_max * 3 < break_length
        && (total_length as f64 / actual_max as f64 > 5.0 || max_length <= 6)
    {
        let approx_char_heights = 2.5_f64;
        let average_bias = (actual_max as f64 - total_length as f64 / output.len() as f64).sqrt();
        let biased_max = (actual_max as f64 - 3.0 - average_bias).max(1.0);
        let columns = ((approx_char_heights * biased_max * output_length as f64).sqrt()
            / biased_max)
            .round()
            .min((break_length / actual_max) as f64)
            .min((INSPECT_COMPACT * 4) as f64)
            .min(15.0) as usize;
        if columns <= 1 {
            return output;
        }
        let mut max_line_length = Vec::with_capacity(columns);
        for column in 0..columns {
            let mut line_length = 0;
            let mut index = column;
            while index < output_length {
                line_length = line_length.max(data_len[index]);
                index += columns;
            }
            max_line_length.push(line_length + SEPARATOR_SPACE);
        }
        let pad_numbers = numeric
            .iter()
            .take(output.len())
            .all(|is_number| *is_number)
            && numeric.len() >= output.len();
        let mut grouped = Vec::new();
        let mut row_start = 0;
        while row_start < output_length {
            let row_end = (row_start + columns).min(output_length);
            let mut line = String::new();
            for index in row_start..row_end - 1 {
                let cell = format!("{}, ", output[index]);
                let width = max_line_length[index - row_start];
                line.push_str(&if pad_numbers {
                    pad_start(&cell, width)
                } else {
                    pad_end(&cell, width)
                });
            }
            let last = row_end - 1;
            if pad_numbers {
                let width = max_line_length[last - row_start] - SEPARATOR_SPACE;
                line.push_str(&pad_start(&output[last], width));
            } else {
                line.push_str(&output[last]);
            }
            grouped.push(line);
            row_start += columns;
        }
        if has_more && let Some(more) = output.last() {
            grouped.push(more.clone());
        }
        return grouped;
    }
    output
}

fn more_items(remaining: usize) -> String {
    format!(
        "... {remaining} more item{}",
        if remaining > 1 { "s" } else { "" }
    )
}

fn empty_items(count: usize) -> String {
    format!("<{count} empty item{}>", if count > 1 { "s" } else { "" })
}

/// Node's `getPrefix`.
fn inspect_prefix(constructor: Option<&str>, tag: &str, fallback: &str, size: &str) -> String {
    match constructor {
        None if !tag.is_empty() && tag != fallback => {
            format!("[{fallback}{size}: null prototype] [{tag}] ")
        }
        None => format!("[{fallback}{size}: null prototype] "),
        Some(constructor) if !tag.is_empty() && tag != constructor => {
            format!("{constructor}{size} [{tag}] ")
        }
        Some(constructor) => format!("{constructor}{size} "),
    }
}

impl InterpreterCore {
    /// `util.formatWithOptions` for one console call.
    pub(super) fn console_format_arguments(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
    ) -> Result<String, InterpreterError> {
        let mut values = Vec::with_capacity(args.count as usize);
        for offset in 0..args.count {
            values.push(self.builtin_arg(args, offset)?.unwrap_or(Value::Undefined));
        }
        self.format_values(module, &values)
    }

    /// `console.table`'s cell: `util.inspect(value, { depth, maxArrayLength:
    /// 3, breakLength: Infinity })` (bd-9vouw.158).
    pub(super) fn inspect_table_cell(
        &mut self,
        module: Option<&Ir3Module>,
        value: &Value,
        depth: i64,
    ) -> Result<String, InterpreterError> {
        let mut state = InspectState::new(module, depth);
        state.max_array_length = 3;
        state.break_length = usize::MAX;
        self.inspect_value(&mut state, value, 0)
    }

    /// `util.inspect(value)` at the default depth (console.dir).
    pub(super) fn console_inspect(
        &mut self,
        module: Option<&Ir3Module>,
        value: &Value,
    ) -> Result<String, InterpreterError> {
        self.inspect_with_depth(module, value, INSPECT_DEPTH)
    }

    /// `util.format(...values)`.
    pub(super) fn format_values(
        &mut self,
        module: Option<&Ir3Module>,
        values: &[Value],
    ) -> Result<String, InterpreterError> {
        let mut out = String::new();
        let mut next = 0;
        let mut join = "";
        if let Some(Value::Str(first)) = values.first() {
            if values.len() == 1 {
                return Ok(first.to_string());
            }
            let text: Vec<char> = first.to_string().chars().collect();
            let mut last = 0;
            let mut index = 0;
            while index + 1 < text.len() {
                if text[index] != '%' {
                    index += 1;
                    continue;
                }
                index += 1;
                let directive = text[index];
                if next + 1 == values.len() {
                    if directive == '%' {
                        out.extend(&text[last..index]);
                        last = index + 1;
                    }
                    index += 1;
                    continue;
                }
                let rendered = match directive {
                    's' => {
                        next += 1;
                        Some(self.console_format_percent_s(module, &values[next])?)
                    }
                    'd' | 'i' | 'f' => {
                        next += 1;
                        Some(Self::console_format_numeric(directive, &values[next]))
                    }
                    'j' => {
                        next += 1;
                        Some(self.console_format_json(&values[next])?)
                    }
                    'O' => {
                        next += 1;
                        Some(self.inspect_with_depth(module, &values[next], INSPECT_DEPTH)?)
                    }
                    'o' => {
                        next += 1;
                        Some(self.inspect_with_depth(
                            module,
                            &values[next],
                            INSPECT_PERCENT_O_DEPTH,
                        )?)
                    }
                    'c' => {
                        next += 1;
                        Some(String::new())
                    }
                    '%' => {
                        out.extend(&text[last..index]);
                        last = index + 1;
                        None
                    }
                    _ => None,
                };
                if let Some(rendered) = rendered {
                    if last != index - 1 {
                        out.extend(&text[last..index - 1]);
                    }
                    out.push_str(&rendered);
                    last = index + 1;
                }
                index += 1;
            }
            if last != 0 {
                next += 1;
                join = " ";
                if last < text.len() {
                    out.extend(&text[last..]);
                }
            }
        }
        while next < values.len() {
            out.push_str(join);
            match &values[next] {
                Value::Str(text) => out.push_str(text.as_ref()),
                value => {
                    let rendered = self.inspect_with_depth(module, value, INSPECT_DEPTH)?;
                    out.push_str(&rendered);
                }
            }
            join = " ";
            next += 1;
        }
        Ok(out)
    }

    /// `util.inspect(value)` at the given depth.
    pub(super) fn inspect_with_depth(
        &mut self,
        module: Option<&Ir3Module>,
        value: &Value,
        depth: i64,
    ) -> Result<String, InterpreterError> {
        let mut state = InspectState::new(module, depth);
        self.inspect_value(&mut state, value, 0)
    }

    /// Node's `determineSpecificType` (lib/internal/errors.js), the
    /// "Received ..." of an ERR_INVALID_ARG_TYPE message: `null` or
    /// `undefined`, `function <name>`, `an instance of <constructor>`, else
    /// `type <typeof> (<inspected>)` with an inspection longer than 28
    /// characters cut to 25 and `...` (bd-9vouw.181).
    pub(super) fn node_received_description(&mut self, value: &Value) -> String {
        match value {
            Value::Undefined => "undefined".to_string(),
            Value::Null => "null".to_string(),
            _ if value.is_callable() && !self.inspect_function_name(None, value).is_empty() => {
                format!("function {}", self.inspect_function_name(None, value))
            }
            Value::Object(id) if !value.is_callable() => {
                match self.inspect_constructor_name(None, *id) {
                    Some(name) => format!("an instance of {name}"),
                    None => self
                        .inspect_with_depth(None, value, -1)
                        .unwrap_or_else(|_| "an object".to_string()),
                }
            }
            _ => {
                let inspected = self
                    .inspect_with_depth(None, value, INSPECT_DEPTH)
                    .unwrap_or_default();
                let inspected = if inspected.chars().count() > 28 {
                    format!("{}...", inspected.chars().take(25).collect::<String>())
                } else {
                    inspected
                };
                let kind = if value.is_callable() {
                    "function"
                } else {
                    value.type_name()
                };
                format!("type {kind} ({inspected})")
            }
        }
    }

    /// `util.inspect(value, { depth })` for `require('util')`
    /// (bd-9vouw.109). args = (value, depth); `Infinity` has no limit.
    pub(super) fn util_inspect_builtin(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let depth = match self.builtin_arg(args, 1)? {
            Some(Value::Int(depth)) => depth,
            Some(Value::Float(depth)) if depth.inner() == f64::INFINITY => i64::MAX,
            Some(Value::Float(depth)) if depth.inner().is_finite() => depth.inner() as i64,
            _ => INSPECT_DEPTH,
        };
        self.util_format_labelled(args, std::slice::from_ref(&value), |core| {
            core.inspect_with_depth(module, &value, depth)
        })
    }

    /// `util.format(...values)` for `require('util')`: args = (values array).
    pub(super) fn util_format_builtin(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let values = match self.builtin_arg(args, 0)? {
            Some(Value::Object(array)) => self.array_like_values(array)?,
            _ => Vec::new(),
        };
        self.util_format_labelled(args, &values, |core| core.format_values(module, &values))
    }

    /// Runs a formatter whose text shows `values`. The text carries the
    /// labels of everything console output of `values` could show: the
    /// arguments' labels and the console sink's reachable walk, joined into
    /// the HostCall's result label as JSON.stringify does.
    fn util_format_labelled(
        &mut self,
        args: RegRange,
        values: &[Value],
        format: impl FnOnce(&mut Self) -> Result<String, InterpreterError>,
    ) -> Result<Value, InterpreterError> {
        let context = self.join_arg_range_label(args)?;
        let context_bytes = Self::estimate_label_bytes(&context);
        let previous_bytes = self
            .active_inline_callback_context_label
            .as_ref()
            .map(Self::estimate_label_bytes)
            .unwrap_or(0);
        self.json_reserve_temporary(previous_bytes)?;
        if let Err(error) = self.apply_memory_component_delta(previous_bytes, context_bytes) {
            self.json_release_temporary(previous_bytes);
            return Err(error);
        }
        let previous = self.active_inline_callback_context_label.replace(context);
        let mut outcome = (|| {
            for value in values {
                self.console_observe_reachable_value(value)?;
            }
            let text = format(self)?;
            self.check_string_limit(text.len())?;
            Ok(text)
        })();
        let context = self
            .active_inline_callback_context_label
            .take()
            .expect("the formatter restores the operation context");
        if outcome.is_ok() {
            let joined = self.clone_dominant_label_with_temporary_budget(
                &context,
                self.pending_hostcall_result_label
                    .as_ref()
                    .unwrap_or(&Label::Public),
                0,
            );
            if let Err(error) =
                joined.and_then(|label| self.replace_pending_hostcall_result_label(Some(label)))
            {
                outcome = Err(error);
            }
        }
        self.active_inline_callback_context_label = previous;
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(Self::estimate_label_bytes(&context))
            .saturating_add(previous_bytes);
        self.json_release_temporary(previous_bytes);
        outcome.map(Value::str)
    }

    /// The internal type `util.types` tests: the engine's tag of a native
    /// object (Map, Date, Uint8Array, ...), `Proxy`, `DataView`, `Error` for
    /// an object on Error.prototype's chain, `Boxed<Type>` for a primitive
    /// wrapper, the kind of a function, promise or generator value, and
    /// otherwise `Array`, `Object` or `primitive`.
    pub(super) fn util_type_tag(&mut self, value: &Value) -> Result<String, InterpreterError> {
        let id = match value {
            Value::Object(id) => *id,
            Value::Promise(_) | Value::AsyncFunctionObject(_) => return Ok("Promise".into()),
            Value::Generator(_) => return Ok("Generator".into()),
            Value::AsyncGeneratorObject(_) => return Ok("AsyncGenerator".into()),
            Value::GeneratorFunction(_) => return Ok("GeneratorFunction".into()),
            Value::AsyncFunction(_) => return Ok("AsyncFunction".into()),
            Value::AsyncGeneratorFunction(_) => return Ok("AsyncGeneratorFunction".into()),
            Value::Function(_) | Value::Closure(_) | Value::BuiltinFunction(_) => {
                return Ok("Function".into());
            }
            _ => return Ok("primitive".into()),
        };
        if self.proxy_record(id)?.is_some() {
            return Ok(PROXY_TYPE_TAG.into());
        }
        let object = self
            .heap
            .get(id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: id.0 })?;
        let boxed = match &object.primitive_value {
            Some(Value::Int(_) | Value::Float(_)) => Some("BoxedNumber"),
            Some(Value::Str(_)) => Some("BoxedString"),
            Some(Value::Bool(_)) => Some("BoxedBoolean"),
            Some(Value::BigInt(_)) => Some("BoxedBigInt"),
            Some(Value::Symbol(_)) => Some("BoxedSymbol"),
            _ => None,
        };
        if let Some(boxed) = boxed {
            return Ok(boxed.into());
        }
        if object.data_view.is_some() {
            return Ok("DataView".into());
        }
        let is_array = object.is_array;
        if let Some(kind) = self.inspect_internal_type(id) {
            return Ok(kind);
        }
        Ok(if self.inspect_is_error(id) {
            "Error".into()
        } else if is_array {
            "Array".into()
        } else {
            "Object".into()
        })
    }

    fn console_format_percent_s(
        &mut self,
        module: Option<&Ir3Module>,
        value: &Value,
    ) -> Result<String, InterpreterError> {
        Ok(match value {
            Value::Int(number) => inspect_number(*number as f64),
            Value::Float(number) => inspect_number(number.inner()),
            Value::BigInt(digits) => format!("{digits}n"),
            Value::Object(_) | Value::Promise(_) => self.inspect_with_depth(module, value, 0)?,
            Value::Symbol(symbol) => self.symbol_display_string(*symbol),
            other => self.value_to_string(other),
        })
    }

    fn console_format_numeric(directive: char, value: &Value) -> String {
        let number = match value {
            Value::BigInt(digits) => return format!("{digits}n"),
            Value::Int(number) => *number as f64,
            Value::Float(number) => number.inner(),
            Value::Bool(value) => f64::from(u8::from(*value)),
            Value::Null => 0.0,
            Value::Str(text) => match directive {
                'd' => super::primitive_conversion::string_number(text),
                _ => {
                    let text = text.to_string();
                    let trimmed = text.trim_start();
                    let prefix: String = trimmed
                        .chars()
                        .enumerate()
                        .take_while(|(index, ch)| {
                            ch.is_ascii_digit()
                                || (*index == 0 && (*ch == '-' || *ch == '+'))
                                || (directive == 'f' && (*ch == '.' || *ch == 'e' || *ch == 'E'))
                        })
                        .map(|(_, ch)| ch)
                        .collect();
                    let parsed = prefix.parse::<f64>().unwrap_or(f64::NAN);
                    if directive == 'i' {
                        parsed.trunc()
                    } else {
                        parsed
                    }
                }
            },
            _ => f64::NAN,
        };
        let number = if directive == 'i' && number.is_finite() {
            number.trunc()
        } else {
            number
        };
        inspect_number(number)
    }

    /// `%j`: JSON of plain data, `[Circular]` for a cycle.
    fn console_format_json(&mut self, value: &Value) -> Result<String, InterpreterError> {
        let mut path = Vec::new();
        match self.inspect_json(value, &mut path) {
            Ok(rendered) => Ok(rendered.unwrap_or_else(|| "undefined".to_string())),
            // Node's `%j` prints `[Circular]` instead of throwing.
            Err(InterpreterError::TypeError { got, .. }) if got == "[Circular]" => {
                Ok("[Circular]".to_string())
            }
            Err(error) => Err(error),
        }
    }

    fn inspect_json(
        &mut self,
        value: &Value,
        path: &mut Vec<u32>,
    ) -> Result<Option<String>, InterpreterError> {
        if matches!(value, Value::Object(_)) {
            self.json_charge_work()?;
        }
        Ok(Some(match value {
            Value::Null => "null".to_string(),
            Value::Bool(value) => value.to_string(),
            Value::Int(number) => number.to_string(),
            // JSON writes `-0` as `0`.
            Value::Float(number) if number.inner() == 0.0 => "0".to_string(),
            Value::Float(number) if number.inner().is_finite() => number.to_string(),
            Value::Float(_) => "null".to_string(),
            Value::Str(text) => {
                serde_json::to_string(&text.to_string()).unwrap_or_else(|_| "\"\"".to_string())
            }
            Value::Object(id) => {
                if path.contains(&id.0) {
                    return Err(InterpreterError::TypeError {
                        expected: "acyclic value".to_string(),
                        got: "[Circular]".to_string(),
                    });
                }
                if let Some(time) = self.inspect_date_time(*id) {
                    return Ok(Some(if time.is_finite() {
                        format!("\"{}\"", Self::inspect_iso_date(time))
                    } else {
                        "null".to_string()
                    }));
                }
                path.push(id.0);
                let is_array = self.heap.get(id.0 as usize).is_some_and(|o| o.is_array);
                let rendered = if is_array {
                    let length = self.inspect_array_length(*id);
                    let mut items = Vec::new();
                    for index in 0..length {
                        let element = self
                            .array_index_value(*id, index)?
                            .unwrap_or(Value::Undefined);
                        items.push(
                            self.inspect_json(&element, path)?
                                .unwrap_or_else(|| "null".to_string()),
                        );
                    }
                    format!("[{}]", items.join(","))
                } else {
                    let mut items = Vec::new();
                    for (key, property) in self.inspect_own_string_properties(*id) {
                        let InspectProperty::Data(property) = property else {
                            continue;
                        };
                        if let Some(rendered) = self.inspect_json(&property, path)? {
                            let key = serde_json::to_string(&key.to_string())
                                .unwrap_or_else(|_| "\"\"".to_string());
                            items.push(format!("{key}:{rendered}"));
                        }
                    }
                    format!("{{{}}}", items.join(","))
                };
                path.pop();
                rendered
            }
            _ => return Ok(None),
        }))
    }

    fn inspect_value(
        &mut self,
        state: &mut InspectState<'_>,
        value: &Value,
        recurse_times: i64,
    ) -> Result<String, InterpreterError> {
        // Containers are charged as native work (their cost grows with their
        // size); primitives are O(1) and were already charged by the
        // confidentiality walk, so logging them keeps instruction counts
        // unchanged.
        if matches!(value, Value::Object(_) | Value::Promise(_)) {
            self.json_charge_work()?;
        }
        match value {
            Value::Undefined => Ok("undefined".to_string()),
            Value::Null => Ok("null".to_string()),
            Value::Bool(value) => Ok(value.to_string()),
            Value::Int(number) => Ok(number.to_string()),
            Value::Float(number) => Ok(inspect_number(number.inner())),
            Value::BigInt(digits) => Ok(format!("{digits}n")),
            Value::Symbol(symbol) => Ok(self.symbol_display_string(*symbol)),
            Value::Str(text) => Ok(Self::inspect_string(state, text)),
            Value::Accessor { get, set } => Ok(match (get.is_some(), set.is_some()) {
                (true, true) => "[Getter/Setter]",
                (true, false) => "[Getter]",
                (false, true) => "[Setter]",
                (false, false) => "undefined",
            }
            .to_string()),
            Value::Promise(handle) => self.inspect_promise(state, *handle, recurse_times),
            Value::Generator(_) => Ok("Object [Generator] {}".to_string()),
            Value::AsyncGeneratorObject(_) => Ok("Object [AsyncGenerator] {}".to_string()),
            Value::Iterator(_) => Ok("Object [Array Iterator] {}".to_string()),
            Value::AsyncFunctionObject(_) => Ok("Promise { <pending> }".to_string()),
            Value::Object(id) => self.inspect_object(state, *id, recurse_times),
            Value::Function(_)
            | Value::Closure(_)
            | Value::GeneratorFunction(_)
            | Value::AsyncFunction(_)
            | Value::AsyncGeneratorFunction(_)
            | Value::BuiltinFunction(_) => self.inspect_function(state, value, recurse_times),
        }
    }

    fn inspect_string(state: &InspectState<'_>, text: &JsString) -> String {
        let mut units = text.code_units_vec();
        let mut trailer = String::new();
        if units.len() > INSPECT_MAX_STRING_LENGTH {
            let remaining = units.len() - INSPECT_MAX_STRING_LENGTH;
            units.truncate(INSPECT_MAX_STRING_LENGTH);
            trailer = format!(
                "... {remaining} more character{}",
                if remaining > 1 { "s" } else { "" }
            );
        }
        if units.len() > INSPECT_MIN_LINE_WIDTH
            && units.len() + state.indentation + 4 > state.break_length
        {
            // Split after each line break.
            let mut lines = Vec::new();
            let mut start = 0;
            for (index, unit) in units.iter().enumerate() {
                if *unit == 0x0a {
                    lines.push(inspect_quote(&units[start..=index]));
                    start = index + 1;
                }
            }
            if start < units.len() {
                lines.push(inspect_quote(&units[start..]));
            }
            if lines.len() > 1 {
                let separator = format!(" +\n{}", " ".repeat(state.indentation + 2));
                return lines.join(&separator) + &trailer;
            }
        }
        inspect_quote(&units) + &trailer
    }

    fn inspect_promise(
        &mut self,
        state: &mut InspectState<'_>,
        handle: u32,
        recurse_times: i64,
    ) -> Result<String, InterpreterError> {
        if recurse_times > state.depth {
            return Ok("[Promise]".to_string());
        }
        let recurse_times = recurse_times + 1;
        state.current_depth = recurse_times;
        let settled = self
            .promise_store
            .get(crate::promise_model::PromiseHandle(handle))
            .ok()
            .map(|record| record.state.clone());
        let entry = match settled {
            Some(crate::promise_model::PromiseState::Fulfilled(value)) => {
                let value = self.js_value_to_value(&value);
                state.indentation += 2;
                let rendered = self.inspect_value(state, &value, recurse_times);
                state.indentation -= 2;
                rendered?
            }
            Some(crate::promise_model::PromiseState::Rejected(reason)) => {
                let reason = self.js_value_to_value(&reason);
                state.indentation += 2;
                let rendered = self.inspect_value(state, &reason, recurse_times);
                state.indentation -= 2;
                format!("<rejected> {}", rendered?)
            }
            _ => "<pending>".to_string(),
        };
        Ok(Self::reduce_to_single_string(
            state,
            vec![entry],
            "",
            ("Promise {".to_string(), "}"),
            EntryKind::Object,
            recurse_times,
            &[],
        ))
    }

    /// Node's `getFunctionBase` plus the function's own enumerable
    /// properties.
    fn inspect_function(
        &mut self,
        state: &mut InspectState<'_>,
        value: &Value,
        recurse_times: i64,
    ) -> Result<String, InterpreterError> {
        // Node formats a proxy as its target (showProxy is off), a revoked
        // one as <Revoked Proxy> (bd-9vouw.132).
        if let Value::BuiltinFunction(builtin) = value
            && builtin.kind == BuiltinFunctionKind::CallableProxy
        {
            let proxy = Self::callable_proxy_record_id(builtin)?;
            if matches!(self.proxy_record(proxy)?, Some((_, _, true))) {
                return Ok("<Revoked Proxy>".to_string());
            }
            if let Some(target) = self.proxy_call_target(proxy) {
                return self.inspect_function(state, &target, recurse_times);
            }
        }
        let kind = match value {
            Value::GeneratorFunction(_) => "GeneratorFunction",
            Value::AsyncFunction(_) => "AsyncFunction",
            Value::AsyncGeneratorFunction(_) => "AsyncGeneratorFunction",
            _ => "Function",
        };
        let name = self.inspect_function_name(state.module, value);
        let base = if name.is_empty() {
            format!("[{kind} (anonymous)]")
        } else {
            format!("[{kind}: {name}]")
        };
        let identity = match value {
            Value::Function(index) => InspectIdentity::Function(*index),
            Value::Closure(id)
            | Value::GeneratorFunction(id)
            | Value::AsyncFunction(id)
            | Value::AsyncGeneratorFunction(id) => InspectIdentity::Closure(*id),
            _ => return Ok(base),
        };
        let Some(module) = state.module else {
            return Ok(base);
        };
        let backing = self
            .function_own_property_key(module, value)?
            .and_then(|key| self.function_prototypes.get(&key).copied());
        let Some(backing) = backing else {
            return Ok(base);
        };
        let properties: Vec<_> = self
            .inspect_own_properties(backing)
            .into_iter()
            .filter(|(key, _)| key.text() != Some("prototype"))
            .collect();
        if properties.is_empty() {
            return Ok(base);
        }
        if state.seen.contains(&identity) {
            let index = state.circular_index(identity);
            return Ok(format!("[Circular *{index}]"));
        }
        if recurse_times > state.depth {
            return Ok("[Function]".to_string());
        }
        let recurse_times = recurse_times + 1;
        state.seen.push(identity);
        state.current_depth = recurse_times;
        let mut output = Vec::with_capacity(properties.len());
        for (key, property) in properties {
            output.push(self.inspect_property(state, &key, property, recurse_times)?);
        }
        state.seen.pop();
        let base = match state.circular.iter().position(|seen| *seen == identity) {
            Some(index) => format!("<ref *{}> {base}", index + 1),
            None => base,
        };
        Ok(Self::reduce_to_single_string(
            state,
            output,
            &base,
            ("{".to_string(), "}"),
            EntryKind::Object,
            recurse_times,
            &[],
        ))
    }

    /// `Function.prototype.toString` (ES2024 20.2.3.5): a user function,
    /// arrow, method or class answers its source text as written
    /// (bd-9vouw.184); built-ins, bound functions and a function whose text
    /// was not recorded answer the NativeFunction form
    /// (`function name() { [native code] }`).
    pub(super) fn function_native_source_text(
        &self,
        module: Option<&Ir3Module>,
        value: &Value,
    ) -> String {
        if let Some(text) = self.function_source_text(module, value) {
            return text;
        }
        if let Value::BuiltinFunction(builtin) = value
            && builtin.kind == BuiltinFunctionKind::BoundFunction
        {
            return "function () { [native code] }".to_string();
        }
        let name = self.inspect_function_name(module, value);
        if name.is_empty() {
            "function () { [native code] }".to_string()
        } else {
            format!("function {name}() {{ [native code] }}")
        }
    }

    /// The source text the module that compiled `value` recorded for it
    /// (Ir3Module::function_sources), if `value` is a user function.
    fn function_source_text(&self, module: Option<&Ir3Module>, value: &Value) -> Option<String> {
        let module = module?;
        let (index, owner) = match value {
            Value::Function(index) => (*index, None),
            Value::Closure(id)
            | Value::GeneratorFunction(id)
            | Value::AsyncFunction(id)
            | Value::AsyncGeneratorFunction(id) => (
                self.closure_function_index(*id).ok()?,
                self.foreign_closure_module(value, module).ok().flatten(),
            ),
            _ => return None,
        };
        owner
            .as_deref()
            .unwrap_or(module)
            .function_sources
            .get(&index)
            .map(|text| text.as_str().to_string())
    }

    /// `fn.name` without running guest code.
    fn inspect_function_name(&self, module: Option<&Ir3Module>, value: &Value) -> String {
        match value {
            Value::BuiltinFunction(builtin) => match builtin.kind {
                BuiltinFunctionKind::BoundFunction => {
                    let target = self
                        .bound_function_parts(builtin)
                        .map(|parts| parts.0)
                        .unwrap_or(Value::Undefined);
                    format!("bound {}", self.inspect_function_name(module, &target))
                }
                BuiltinFunctionKind::StandardConstructor => {
                    Self::standard_constructor_name(builtin)
                        .unwrap_or_default()
                        .to_string()
                }
                // The built-in's `name` (bd-9vouw.177): symbol-keyed methods
                // read `[Symbol.match]`, a promise's resolving functions are
                // anonymous.
                _ => builtin.spec_name().to_string(),
            },
            Value::Function(index) => module
                .and_then(|module| Self::function_name_or_length(module, *index, "name"))
                .map(|name| self.value_to_string(&name))
                .unwrap_or_default(),
            Value::Closure(id)
            | Value::GeneratorFunction(id)
            | Value::AsyncFunction(id)
            | Value::AsyncGeneratorFunction(id) => {
                if let Some(metadata) = self.closure_method_metadata.get(id) {
                    return metadata.name.to_string();
                }
                let Some(module) = module else {
                    return String::new();
                };
                let owner = self.foreign_closure_module(value, module).ok().flatten();
                self.closure_function_index(*id)
                    .ok()
                    .and_then(|index| {
                        Self::function_name_or_length(
                            owner.as_deref().unwrap_or(module),
                            index,
                            "name",
                        )
                    })
                    .map(|name| self.value_to_string(&name))
                    .unwrap_or_default()
            }
            _ => String::new(),
        }
    }

    /// Own enumerable properties in `[[OwnPropertyKeys]]` order, without the
    /// engine's internal slots.
    fn inspect_own_properties(&self, id: ObjectId) -> Vec<(InspectKey, InspectProperty)> {
        let mut properties: Vec<_> = self
            .inspect_own_string_properties(id)
            .into_iter()
            .map(|(key, property)| (InspectKey::String(key), property))
            .collect();
        let Some(object) = self.heap.get(id.0 as usize) else {
            return properties;
        };
        for symbol in object
            .properties
            .baseline_symbol_key_order()
            .iter()
            .copied()
        {
            let key = RuntimePropertyKey::Symbol(engine_symbol_id(symbol));
            if object
                .property_attributes
                .get(&key)
                .is_some_and(|attributes| !attributes.enumerable)
            {
                continue;
            }
            let property = match object.properties.baseline_symbol_property(symbol) {
                Some(BaselineSymbolProperty::Data(value)) => InspectProperty::Data(value.clone()),
                Some(BaselineSymbolProperty::Accessor { get, set }) => {
                    match (get.is_some(), set.is_some()) {
                        (true, true) => InspectProperty::GetterSetter,
                        (false, true) => InspectProperty::Setter,
                        _ => InspectProperty::Getter,
                    }
                }
                None => continue,
            };
            let name = format!("[{}]", self.symbol_display_string(engine_symbol_id(symbol)));
            properties.push((InspectKey::Symbol(name), property));
        }
        properties
    }

    fn inspect_own_string_properties(&self, id: ObjectId) -> Vec<(JsString, InspectProperty)> {
        let Some(object) = self.heap.get(id.0 as usize) else {
            return Vec::new();
        };
        let internal = self.inspect_internal_type(id);
        let hidden: &[&str] = match internal.as_deref() {
            _ if object.typed_array.is_some() => &[
                "length",
                "byteLength",
                "byteOffset",
                "buffer",
                "BYTES_PER_ELEMENT",
            ],
            Some("RegExp") => &["lastIndex"],
            _ => &[],
        };
        object
            .properties
            .exact_keys()
            .into_iter()
            .filter(|key| {
                !(internal.is_some()
                    && key
                        .as_str()
                        .is_some_and(|text| text.starts_with("__") || hidden.contains(&text)))
            })
            .filter(|key| self.ordinary_own_string_key_is_enumerable(id, key))
            .filter_map(|key| {
                let property = match object.properties.get_exact(&key)? {
                    Value::Accessor { get, set } => match (get.is_some(), set.is_some()) {
                        (true, true) => InspectProperty::GetterSetter,
                        (false, true) => InspectProperty::Setter,
                        _ => InspectProperty::Getter,
                    },
                    value => InspectProperty::Data(value.clone()),
                };
                Some((key, property))
            })
            .collect()
    }

    /// The engine's brand of a native object (Map, Set, Date, ...). Guest
    /// data can carry a `__type` field (a common JSON discriminator); it is
    /// ordinary data, never the brand (bd-9vouw.150). Map, Set and Date must
    /// also have their storage slot.
    pub(super) fn inspect_internal_type(&self, id: ObjectId) -> Option<String> {
        let object = self.heap.get(id.0 as usize)?;
        let kind = object.brand()?.to_string();
        let native = match kind.as_str() {
            "Map" => self.collection_storage_id(id, "Map", "__entries").is_some(),
            "Set" => self.collection_storage_id(id, "Set", "__values").is_some(),
            "Date" => matches!(
                object.properties.get("__timestamp"),
                Some(Value::Int(_) | Value::Float(_))
            ),
            "RegExp"
            | "WeakMap"
            | "WeakSet"
            | PROXY_TYPE_TAG
            | TIMER_HANDLE_TIMEOUT_TYPE
            | TIMER_HANDLE_IMMEDIATE_TYPE
            | TIMERS_PROMISES_INTERVAL_TYPE => true,
            _ => object.typed_array.is_some() || object.array_buffer.is_some(),
        };
        native.then_some(kind)
    }

    fn inspect_array_length(&self, id: ObjectId) -> usize {
        match self
            .heap
            .get(id.0 as usize)
            .and_then(|object| object.properties.get("length"))
        {
            Some(Value::Int(length)) => usize::try_from(*length).unwrap_or(0),
            Some(Value::Float(length)) => length.inner().max(0.0) as usize,
            _ => 0,
        }
    }

    fn inspect_date_time(&self, id: ObjectId) -> Option<f64> {
        if self.inspect_internal_type(id).as_deref() != Some("Date") {
            return None;
        }
        Some(
            match self
                .heap
                .get(id.0 as usize)
                .and_then(|object| object.properties.get("__timestamp"))
            {
                Some(Value::Int(time)) => *time as f64,
                Some(Value::Float(time)) => time.inner(),
                _ => f64::NAN,
            },
        )
    }

    fn inspect_iso_date(time: f64) -> String {
        use super::date_math::*;
        let year = year_from_time(time);
        let year_text = if (0.0..=9999.0).contains(&year) {
            format!("{:04}", year as i64)
        } else {
            format!(
                "{}{:06}",
                if year < 0.0 { '-' } else { '+' },
                year.abs() as i64
            )
        };
        format!(
            "{year_text}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            month_from_time(time) as i64 + 1,
            date_from_time(time) as i64,
            hour(time) as i64,
            minute(time) as i64,
            second(time) as i64,
            millisecond(time) as i64
        )
    }

    /// Node's `getConstructorName` without `instanceof`: the name of the
    /// first named `constructor` function on the prototype chain above the
    /// object itself; `None` when the chain ends without one.
    fn inspect_constructor_name(&self, module: Option<&Ir3Module>, id: ObjectId) -> Option<String> {
        let reverse_builtin = |candidate: ObjectId| {
            self.builtin_prototypes
                .iter()
                .find(|(_, prototype)| **prototype == candidate)
                .map(|(name, _)| name.clone())
        };
        let object = self.heap.get(id.0 as usize)?;
        let mut current = if object.prototype.is_some() || object.is_null_prototype {
            object.prototype
        } else if object.is_array {
            return Some("Array".to_string());
        } else {
            return Some("Object".to_string());
        };
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            let prototype_id = current?;
            if let Some(name) = reverse_builtin(prototype_id) {
                return Some(name);
            }
            let prototype = self.heap.get(prototype_id.0 as usize)?;
            if let Some(constructor) = prototype.properties.get("constructor") {
                let name = self.inspect_function_name(module, constructor);
                if !name.is_empty() {
                    return Some(name);
                }
            }
            current = if prototype.prototype.is_some() || prototype.is_null_prototype {
                prototype.prototype
            } else {
                return Some("Object".to_string());
            };
        }
        None
    }

    pub(super) fn inspect_is_error(&self, id: ObjectId) -> bool {
        self.builtin_prototypes
            .get("Error")
            .is_some_and(|prototype| {
                self.prototype_chain_contains(id, *prototype)
                    .unwrap_or(false)
            })
    }

    fn inspect_object(
        &mut self,
        state: &mut InspectState<'_>,
        id: ObjectId,
        recurse_times: i64,
    ) -> Result<String, InterpreterError> {
        let mut id = id;
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            match self.proxy_record(id) {
                Ok(Some((_, _, true))) => return Ok("<Revoked Proxy>".to_string()),
                Ok(Some((target, _, false))) => id = target,
                _ => break,
            }
        }
        let identity = InspectIdentity::Object(id.0);
        if state.seen.contains(&identity) {
            let index = state.circular_index(identity);
            return Ok(format!("[Circular *{index}]"));
        }
        let Some(object) = self.heap.get(id.0 as usize) else {
            return Ok("[Object]".to_string());
        };
        let is_array = object.is_array;
        let typed_array = object.typed_array.clone();
        let array_buffer = object.array_buffer.is_some();
        let constructor = self.inspect_constructor_name(state.module, id);
        let internal = self.inspect_internal_type(id);
        let mut properties = self.inspect_own_properties(id);

        let mut base = String::new();
        let mut entries: Vec<String> = Vec::new();
        let mut entry_kind = EntryKind::Object;
        let mut numeric: Vec<bool> = Vec::new();
        let braces: (String, &str);

        enum Body {
            Array(usize),
            Typed(TypedArrayView),
            Map,
            Set,
            Weak,
            Plain,
        }
        let body;

        if is_array {
            let length = self.inspect_array_length(id);
            properties.retain(|(key, _)| {
                !key.text()
                    .and_then(|text| {
                        text.parse::<usize>()
                            .ok()
                            .filter(|index| index.to_string() == text)
                    })
                    .is_some_and(|index| index < length)
            });
            let prefix = if constructor.as_deref() != Some("Array") {
                inspect_prefix(constructor.as_deref(), "", "Array", &format!("({length})"))
            } else {
                String::new()
            };
            if length == 0 && properties.is_empty() {
                return Ok(format!("{prefix}[]"));
            }
            braces = (format!("{prefix}["), "]");
            entry_kind = EntryKind::Array;
            body = Body::Array(length);
        } else if let Some(view) = typed_array {
            if view.is_buffer {
                return self.inspect_buffer(&view);
            }
            let length = view.length;
            properties.retain(|(key, _)| {
                !key.text()
                    .and_then(|text| text.parse::<usize>().ok())
                    .is_some_and(|index| index < length)
            });
            // The engine does not link typed arrays to their constructor's
            // prototype, so the chain only reaches Object.prototype.
            let name = view.kind.type_name();
            let constructor = match constructor.as_deref() {
                None | Some("Object") => name,
                Some(other) => other,
            };
            let prefix = inspect_prefix(Some(constructor), "", name, &format!("({length})"));
            if length == 0 && properties.is_empty() {
                return Ok(format!("{prefix}[]"));
            }
            braces = (format!("{prefix}["), "]");
            entry_kind = EntryKind::Array;
            body = Body::Typed(view);
        } else if array_buffer {
            return self.inspect_array_buffer(state, id, recurse_times);
        } else if matches!(internal.as_deref(), Some("Map" | "Set")) {
            let is_map = internal.as_deref() == Some("Map");
            let size = if is_map {
                self.collection_storage_id(id, "Map", "__entries")
            } else {
                self.collection_storage_id(id, "Set", "__values")
            }
            .and_then(|storage| self.heap.get(storage.0 as usize))
            .map_or(0, |storage| storage.properties.len());
            let fallback = if is_map { "Map" } else { "Set" };
            let prefix = inspect_prefix(constructor.as_deref(), "", fallback, &format!("({size})"));
            if size == 0 && properties.is_empty() {
                return Ok(format!("{prefix}{{}}"));
            }
            braces = (format!("{prefix}{{"), "}");
            body = if is_map { Body::Map } else { Body::Set };
        } else if matches!(internal.as_deref(), Some("WeakMap" | "WeakSet")) {
            let fallback = internal.as_deref().unwrap_or("WeakMap");
            braces = (
                format!(
                    "{}{{",
                    inspect_prefix(constructor.as_deref(), "", fallback, "")
                ),
                "}",
            );
            body = Body::Weak;
        } else if let Some(time) = self.inspect_date_time(id) {
            let text = if time.is_finite() {
                Self::inspect_iso_date(time)
            } else {
                "Invalid Date".to_string()
            };
            if properties.is_empty() {
                return Ok(text);
            }
            base = text;
            braces = ("{".to_string(), "}");
            body = Body::Plain;
        } else if let Some(primitive) = self.primitive_wrapper_value(id).cloned() {
            // Node: `[Number: 3]`, `[String: 'ab']`, `[Boolean: false]`,
            // `[BigInt: 1n]`, `[Symbol: Symbol(q)]` (bd-9vouw.73).
            let type_name = match &primitive {
                Value::Bool(_) => "Boolean",
                Value::Int(_) | Value::Float(_) => "Number",
                Value::Str(_) => "String",
                Value::BigInt(_) => "BigInt",
                _ => "Symbol",
            };
            let shown = match &primitive {
                Value::Str(text) => Self::inspect_string(state, text),
                Value::BigInt(digits) => format!("{digits}n"),
                other => self.value_to_string(other),
            };
            let text = format!("[{type_name}: {shown}]");
            if properties.is_empty() {
                return Ok(text);
            }
            base = text;
            braces = ("{".to_string(), "}");
            body = Body::Plain;
        } else if internal.as_deref() == Some("RegExp") {
            let text = self.inspect_regexp_source(id);
            if properties.is_empty() || recurse_times > state.depth {
                return Ok(text);
            }
            base = text;
            braces = ("{".to_string(), "}");
            body = Body::Plain;
        } else if self.inspect_is_error(id) {
            let text = self.inspect_error(state, id, constructor.as_deref(), &mut properties);
            if properties.is_empty() {
                return Ok(text);
            }
            base = text;
            braces = ("{".to_string(), "}");
            body = Body::Plain;
        } else {
            let prefix = match constructor.as_deref() {
                Some("Object") => String::new(),
                other => inspect_prefix(other, "", "Object", ""),
            };
            if properties.is_empty() {
                return Ok(format!("{prefix}{{}}"));
            }
            braces = (format!("{prefix}{{"), "}");
            body = Body::Plain;
        }

        if recurse_times > state.depth {
            let name = match (constructor.as_deref(), &body) {
                (_, Body::Array(_)) if constructor.as_deref() == Some("Array") => {
                    "Array".to_string()
                }
                (Some(name), _) => name.to_string(),
                (None, _) => "Object: null prototype".to_string(),
            };
            return Ok(format!("[{name}]"));
        }
        let recurse_times = recurse_times + 1;
        state.seen.push(identity);
        state.current_depth = recurse_times;

        match body {
            Body::Array(length) => {
                // Node's formatArray / formatSpecialArray: walk the present
                // indices, one `<n empty items>` entry per run of holes, at
                // most 100 entries.
                let indices: Vec<usize> = self
                    .heap
                    .get(id.0 as usize)
                    .map(|object| {
                        object
                            .properties
                            .exact_keys()
                            .into_iter()
                            .filter_map(|key| {
                                let text = key.as_str()?;
                                let index = text.parse::<usize>().ok()?;
                                (index < length && index.to_string() == text).then_some(index)
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let mut index = 0;
                for present in indices {
                    if entries.len() >= state.max_array_length {
                        break;
                    }
                    if present != index {
                        entries.push(empty_items(present - index));
                        index = present;
                        if entries.len() == state.max_array_length {
                            break;
                        }
                    }
                    let element = self
                        .array_index_value(id, present)?
                        .unwrap_or(Value::Undefined);
                    state.indentation += 2;
                    let rendered = self.inspect_value(state, &element, recurse_times);
                    state.indentation -= 2;
                    entries.push(rendered?);
                    index += 1;
                }
                let remaining = length - index.min(length);
                if entries.len() != state.max_array_length {
                    if remaining > 0 {
                        entries.push(empty_items(remaining));
                    }
                } else if remaining > 0 {
                    entries.push(more_items(remaining));
                }
                // Columns are right-aligned only when every slot up to the
                // entry count holds a number (Node checks `value[i]`).
                for slot in 0..entries.len() {
                    let element = if slot < length {
                        self.array_index_value(id, slot)?
                    } else {
                        None
                    };
                    numeric.push(matches!(
                        element,
                        Some(Value::Int(_) | Value::Float(_) | Value::BigInt(_))
                    ));
                }
            }
            Body::Typed(view) => {
                let length = view.length;
                let shown = length.min(state.max_array_length);
                for index in 0..shown {
                    let element = self
                        .array_index_value(id, index)?
                        .unwrap_or(Value::Undefined);
                    entries.push(self.inspect_value(state, &element, recurse_times)?);
                    numeric.push(true);
                }
                if shown < length {
                    entries.push(more_items(length - shown));
                    numeric.push(true);
                }
            }
            Body::Map => {
                let storage = self.collection_storage_id(id, "Map", "__entries");
                let pairs: Vec<(Value, Value)> = storage
                    .and_then(|storage| self.heap.get(storage.0 as usize))
                    .map(|storage| {
                        storage
                            .properties
                            .iter()
                            .map(|(repr, value)| {
                                (Self::collection_key_from_repr(repr), value.clone())
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let total = pairs.len();
                state.indentation += 2;
                for (key, value) in pairs.into_iter().take(state.max_array_length) {
                    let key = self.inspect_value(state, &key, recurse_times);
                    let value = key.and_then(|key| {
                        self.inspect_value(state, &value, recurse_times)
                            .map(|value| format!("{key} => {value}"))
                    });
                    match value {
                        Ok(entry) => entries.push(entry),
                        Err(error) => {
                            state.indentation -= 2;
                            return Err(error);
                        }
                    }
                }
                state.indentation -= 2;
                if total > state.max_array_length {
                    entries.push(more_items(total - state.max_array_length));
                }
            }
            Body::Set => {
                let storage = self.collection_storage_id(id, "Set", "__values");
                let values: Vec<Value> = storage
                    .and_then(|storage| self.heap.get(storage.0 as usize))
                    .map(|storage| storage.properties.values().cloned().collect())
                    .unwrap_or_default();
                let total = values.len();
                state.indentation += 2;
                for value in values.into_iter().take(state.max_array_length) {
                    match self.inspect_value(state, &value, recurse_times) {
                        Ok(entry) => entries.push(entry),
                        Err(error) => {
                            state.indentation -= 2;
                            return Err(error);
                        }
                    }
                }
                state.indentation -= 2;
                if total > state.max_array_length {
                    entries.push(more_items(total - state.max_array_length));
                }
            }
            Body::Weak => entries.push("<items unknown>".to_string()),
            Body::Plain => {}
        }
        for (key, property) in properties {
            let entry = self.inspect_property(state, &key, property, recurse_times)?;
            entries.push(entry);
        }
        state.seen.pop();
        if let Some(index) = state.circular.iter().position(|seen| *seen == identity) {
            let reference = format!("<ref *{}>", index + 1);
            base = if base.is_empty() {
                reference
            } else {
                format!("{reference} {base}")
            };
        }
        let rendered = Self::reduce_to_single_string(
            state,
            entries,
            &base,
            braces,
            entry_kind,
            recurse_times,
            &numeric,
        );
        let spent = state.level_budget.entry(state.indentation).or_insert(0);
        *spent += rendered.len();
        if *spent > INSPECT_LEVEL_BUDGET {
            state.depth = -1;
        }
        Ok(rendered)
    }

    fn inspect_property(
        &mut self,
        state: &mut InspectState<'_>,
        key: &InspectKey,
        property: InspectProperty,
        recurse_times: i64,
    ) -> Result<String, InterpreterError> {
        let rendered = match property {
            InspectProperty::Data(value) => {
                state.indentation += 2;
                let rendered = self.inspect_value(state, &value, recurse_times);
                state.indentation -= 2;
                rendered?
            }
            InspectProperty::Getter => "[Getter]".to_string(),
            InspectProperty::Setter => "[Setter]".to_string(),
            InspectProperty::GetterSetter => "[Getter/Setter]".to_string(),
        };
        let name = match key {
            InspectKey::Symbol(name) => name.clone(),
            InspectKey::String(key) => inspect_key_name(key),
        };
        Ok(format!("{name}: {rendered}"))
    }

    fn inspect_regexp_source(&self, id: ObjectId) -> String {
        let (source, flags) = self.regexp_source_flags_from_object(id).unwrap_or_default();
        format!("/{source}/{flags}")
    }

    /// Node's `formatError`: the stack (or `Name: message`), with the
    /// constructor name worked in and continuation lines indented.
    fn inspect_error(
        &self,
        state: &InspectState<'_>,
        id: ObjectId,
        constructor: Option<&str>,
        properties: &mut Vec<(InspectKey, InspectProperty)>,
    ) -> String {
        // Own or inherited data properties; accessors are not run.
        let read = |key: &str| self.chain_data_property(id, key).cloned();
        let name = match read("name") {
            None | Some(Value::Undefined | Value::Null) => "Error".to_string(),
            Some(value) => self.value_to_string(&value),
        };
        let message = match read("message") {
            None | Some(Value::Undefined) => String::new(),
            Some(value) => self.value_to_string(&value),
        };
        let mut stack = match read("stack") {
            Some(Value::Str(stack)) if !stack.is_empty() => stack.to_string(),
            _ if message.is_empty() => name.clone(),
            _ => format!("{name}: {message}"),
        };
        // Keys whose value the stack already shows are not repeated.
        properties.retain(|(key, property)| {
            let Some(text) = key.text() else {
                return true;
            };
            if !matches!(text, "name" | "message" | "stack") {
                return true;
            }
            match property {
                InspectProperty::Data(value) => !stack.contains(&self.value_to_string(value)),
                _ => true,
            }
        });
        // `improveStack`: name the constructor when a normal-looking stack
        // does not (`class MyError extends Error {}` prints `MyError: ...`).
        let name_len = name.len();
        let looks_normal = name.ends_with("Error")
            && stack.starts_with(&name)
            && (stack.len() == name_len
                || stack[name_len..].starts_with(':')
                || stack[name_len..].starts_with('\n'));
        if looks_normal {
            let prefix = inspect_prefix(constructor, "", "Error", "");
            let prefix = prefix.trim_end();
            if name != prefix {
                stack = if prefix.contains(name.as_str()) {
                    format!("{prefix}{}", &stack[name_len..])
                } else {
                    format!("{prefix} [{name}]{}", &stack[name_len..])
                };
            }
        }
        let message_end = if message.is_empty() {
            None
        } else {
            stack
                .find(&message)
                .map(|position| position + message.len())
        };
        let search_from = message_end.unwrap_or(0);
        if !stack[search_from..].contains("\n    at") {
            stack = format!("[{stack}]");
        }
        if state.indentation != 0 {
            let indentation = " ".repeat(state.indentation);
            stack = stack.replace('\n', &format!("\n{indentation}"));
        }
        stack
    }

    fn inspect_buffer(&self, view: &TypedArrayView) -> Result<String, InterpreterError> {
        let bytes = self.typed_array_view_bytes(view)?;
        let mut out = String::from("<Buffer");
        for byte in bytes.iter().take(INSPECT_MAX_BUFFER_BYTES) {
            out.push_str(&format!(" {byte:02x}"));
        }
        if bytes.len() > INSPECT_MAX_BUFFER_BYTES {
            let remaining = bytes.len() - INSPECT_MAX_BUFFER_BYTES;
            out.push_str(&format!(
                " ... {remaining} more byte{}",
                if remaining > 1 { "s" } else { "" }
            ));
        }
        out.push('>');
        Ok(out)
    }

    fn inspect_array_buffer(
        &mut self,
        state: &mut InspectState<'_>,
        id: ObjectId,
        recurse_times: i64,
    ) -> Result<String, InterpreterError> {
        let bytes = self
            .heap
            .get(id.0 as usize)
            .and_then(|object| object.array_buffer.as_ref())
            .map(|backing| backing.bytes.clone())
            .unwrap_or_default();
        // A SharedArrayBuffer prints under its own name (bd-9vouw.244).
        let name = match self.heap.get(id.0 as usize).and_then(HeapObject::brand) {
            Some("SharedArrayBuffer") => "SharedArrayBuffer",
            _ => "ArrayBuffer",
        };
        if recurse_times > state.depth {
            return Ok(format!("[{name}]"));
        }
        let mut contents = String::from("<");
        for (index, byte) in bytes.iter().take(INSPECT_MAX_BUFFER_BYTES).enumerate() {
            if index > 0 {
                contents.push(' ');
            }
            contents.push_str(&format!("{byte:02x}"));
        }
        if bytes.len() > INSPECT_MAX_BUFFER_BYTES {
            let remaining = bytes.len() - INSPECT_MAX_BUFFER_BYTES;
            contents.push_str(&format!(
                " ... {remaining} more byte{}",
                if remaining > 1 { "s" } else { "" }
            ));
        }
        contents.push('>');
        let entries = vec![
            format!("[Uint8Contents]: {contents}"),
            format!("byteLength: {}", bytes.len()),
        ];
        Ok(Self::reduce_to_single_string(
            state,
            entries,
            "",
            (format!("{name} {{"), "}"),
            EntryKind::Object,
            recurse_times + 1,
            &[],
        ))
    }

    /// Node's `reduceToSingleString` for `compact: 3`.
    fn reduce_to_single_string(
        state: &InspectState<'_>,
        output: Vec<String>,
        base: &str,
        braces: (String, &str),
        entry_kind: EntryKind,
        recurse_times: i64,
        numeric: &[bool],
    ) -> String {
        let entries = output.len();
        let has_more = output
            .last()
            .is_some_and(|last| last.starts_with("... ") && last.contains(" more item"));
        let output = if entry_kind == EntryKind::Array && entries > 6 {
            group_array_elements(output, has_more, numeric, state.break_length)
        } else {
            output
        };
        let base_prefix = if base.is_empty() {
            String::new()
        } else {
            format!("{base} ")
        };
        if state.current_depth - recurse_times < INSPECT_COMPACT && entries == output.len() {
            let start =
                output.len() + state.indentation + js_length(&braces.0) + js_length(base) + 10;
            let mut total = output.len() + start;
            let mut fits = total + output.len() <= state.break_length;
            if fits {
                for entry in &output {
                    total += js_length(entry);
                    if total > state.break_length {
                        fits = false;
                        break;
                    }
                }
            }
            if fits && !base.contains('\n') {
                let joined = output.join(", ");
                if !joined.contains('\n') {
                    return format!("{base_prefix}{} {joined} {}", braces.0, braces.1);
                }
            }
        }
        let indentation = format!("\n{}", " ".repeat(state.indentation));
        format!(
            "{base_prefix}{}{indentation}  {}{indentation}{}",
            braces.0,
            output.join(&format!(",{indentation}  ")),
            braces.1
        )
    }
}
