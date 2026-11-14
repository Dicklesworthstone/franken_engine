//! Token-directed runtime enum declarations, shared by both TS ingestion paths.
//!
//! Enum objects remain mutable, merge at their declaration sites, and publish
//! numeric reverse mappings. Initializers use the namespace binding resolver,
//! so a member reference is distinguished from a parameter or property name.

use std::collections::{BTreeMap, BTreeSet};

use super::namespaces::{self, Edit, Lexed, TokenKind};

const INVALID: &str = "unsupported or malformed enum declaration";
const MAX_CONSTANT_STRING_BYTES: usize = 65_536;
const MAX_RETAINED_CONSTANT_BYTES: usize = 1_048_576;
const MAX_EMITTED_ENUM_BYTES: usize = 8_388_608;

#[derive(Default)]
pub(super) struct Budget {
    retained: usize,
    emitted: usize,
}

impl Budget {
    fn replace(
        &mut self,
        constants: &mut Constants,
        name: &str,
        value: Option<Constant>,
    ) -> Result<(), &'static str> {
        let old = constants.0.get(name).map_or(0, Constant::retained_bytes);
        let next = self
            .retained
            .saturating_sub(old)
            .saturating_add(value.as_ref().map_or(0, Constant::retained_bytes));
        if next > MAX_RETAINED_CONSTANT_BYTES {
            return Err("enum retained constant budget");
        }
        if let Some(value) = value {
            constants.0.insert(name.to_owned(), value);
        } else {
            constants.0.remove(name);
        }
        self.retained = next;
        Ok(())
    }

    fn reserve_output(&mut self, bytes: usize) -> Result<(), &'static str> {
        let next = self.emitted.saturating_add(bytes);
        if next > MAX_EMITTED_ENUM_BYTES {
            return Err("enum emitted output budget");
        }
        self.emitted = next;
        Ok(())
    }

    fn append(&mut self, output: &mut String, text: &str) -> Result<(), &'static str> {
        self.reserve_output(text.len())?;
        output.push_str(text);
        Ok(())
    }
}

#[derive(Clone, Debug)]
enum Constant {
    Number(f64),
    String(String),
}

#[derive(Default, Debug)]
pub(super) struct Constants(BTreeMap<String, Constant>);

impl Constant {
    fn retained_bytes(&self) -> usize {
        match self {
            Self::String(value) => value.len(),
            _ => 0,
        }
    }
    fn source(&self) -> String {
        match self {
            Self::String(value) => quoted_key(value),
            Self::Number(value) if value.is_nan() => "NaN".to_owned(),
            Self::Number(value) if *value == f64::INFINITY => "Infinity".to_owned(),
            Self::Number(value) if *value == f64::NEG_INFINITY => "-Infinity".to_owned(),
            Self::Number(value) if *value == 0.0 => "0".to_owned(),
            Self::Number(value) => value.to_string(),
        }
    }
}

fn numeric_literal(raw: &str) -> Option<f64> {
    let raw = raw.replace('_', "");
    for (prefixes, radix) in [(["0x", "0X"], 16), (["0b", "0B"], 2), (["0o", "0O"], 8)] {
        if let Some(digits) = prefixes.iter().find_map(|prefix| raw.strip_prefix(prefix)) {
            return u128::from_str_radix(digits, radix)
                .ok()
                .map(|value| value as f64);
        }
    }
    raw.parse().ok()
}

fn uint32(value: f64) -> u32 {
    if !value.is_finite() || value == 0.0 {
        0
    } else {
        value.trunc().rem_euclid(4_294_967_296.0) as u32
    }
}

struct ConstantExpression<'a> {
    source: &'a str,
    lexed: &'a Lexed,
    cursor: usize,
    enum_name: &'a str,
    constants: &'a Constants,
    depth: usize,
    limit_exceeded: bool,
}

impl ConstantExpression<'_> {
    fn expression(&mut self, minimum: u8) -> Option<Constant> {
        if self.depth >= 256 {
            return None;
        }
        self.depth += 1;
        let result = self.expression_inner(minimum);
        self.depth -= 1;
        result
    }

    fn expression_inner(&mut self, minimum: u8) -> Option<Constant> {
        let token = self.lexed.tokens.get(self.cursor)?;
        self.cursor += 1;
        let unary = matches!(token.text.as_str(), "+" | "-" | "~");
        let mut value = if matches!(token.text.as_str(), "+" | "-" | "~") {
            let Constant::Number(value) = self.expression(8)? else {
                return None;
            };
            Constant::Number(match token.text.as_str() {
                "+" => value,
                "-" => -value,
                _ => f64::from(!(uint32(value) as i32)),
            })
        } else if token.text == "(" {
            let value = self.expression(0)?;
            if text(self.lexed, self.cursor) != ")" {
                return None;
            }
            self.cursor += 1;
            value
        } else if token.kind == TokenKind::Literal {
            let raw = &self.source[token.start..token.end];
            if raw.starts_with(['\'', '"']) {
                Constant::String(string_member_name(raw)?)
            } else {
                Constant::Number(numeric_literal(raw)?)
            }
        } else if token.kind == TokenKind::Word {
            let mut name = token.text.clone();
            if name == self.enum_name {
                if text(self.lexed, self.cursor) == "." {
                    self.cursor += 1;
                    name = self.lexed.tokens.get(self.cursor)?.text.clone();
                    self.cursor += 1;
                } else if text(self.lexed, self.cursor) == "[" {
                    self.cursor += 1;
                    let key = self.lexed.tokens.get(self.cursor)?;
                    name = string_member_name(&self.source[key.start..key.end])?;
                    self.cursor += 1;
                    if text(self.lexed, self.cursor) != "]" {
                        return None;
                    }
                    self.cursor += 1;
                }
            }
            self.constants.0.get(&name)?.clone()
        } else {
            return None;
        };
        if matches!(&value, Constant::String(text) if text.len() > MAX_CONSTANT_STRING_BYTES) {
            self.limit_exceeded = true;
            return None;
        }
        loop {
            let op = text(self.lexed, self.cursor);
            let precedence = match op {
                "|" => 1,
                "^" => 2,
                "&" => 3,
                "<<" | ">>" | ">>>" => 4,
                "+" | "-" => 5,
                "*" | "/" | "%" => 6,
                "**" => 7,
                _ => break,
            };
            if precedence < minimum {
                break;
            }
            if unary && op == "**" {
                return None;
            }
            self.cursor += 1;
            let right = self.expression(precedence + u8::from(op != "**"))?;
            value = match (value, right) {
                (Constant::String(left), Constant::String(right)) if op == "+" => {
                    if left.len().saturating_add(right.len()) > MAX_CONSTANT_STRING_BYTES {
                        self.limit_exceeded = true;
                        return None;
                    }
                    Constant::String(left + &right)
                }
                (Constant::Number(left), Constant::Number(right)) => Constant::Number(match op {
                    "+" => left + right,
                    "-" => left - right,
                    "*" => left * right,
                    "/" => left / right,
                    "%" => left % right,
                    "**" => left.powf(right),
                    "|" => f64::from((uint32(left) | uint32(right)) as i32),
                    "^" => f64::from((uint32(left) ^ uint32(right)) as i32),
                    "&" => f64::from((uint32(left) & uint32(right)) as i32),
                    "<<" => f64::from((uint32(left) as i32).wrapping_shl(uint32(right) & 31)),
                    ">>" => f64::from((uint32(left) as i32) >> (uint32(right) & 31)),
                    ">>>" => f64::from(uint32(left) >> (uint32(right) & 31)),
                    _ => return None,
                }),
                _ => return None,
            };
        }
        Some(value)
    }
}

fn constant_expression(
    source: &str,
    name: &str,
    constants: &Constants,
) -> Result<Option<Constant>, &'static str> {
    let lexed = namespaces::lex(source)?;
    let mut parser = ConstantExpression {
        source,
        lexed: &lexed,
        cursor: 0,
        enum_name: name,
        constants,
        depth: 0,
        limit_exceeded: false,
    };
    let value = parser.expression(0);
    if parser.limit_exceeded {
        return Err("enum constant string expansion limit");
    }
    Ok(value.filter(|_| parser.cursor == lexed.tokens.len()))
}

#[derive(Debug)]
pub(super) struct Member {
    pub(super) name: String,
    key: String,
    initializer: Option<String>,
}

#[derive(Debug)]
pub(super) struct Site {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) name: String,
    pub(super) exported: bool,
    pub(super) ambient: bool,
    pub(super) members: Vec<Member>,
}

fn text(lexed: &Lexed, index: usize) -> &str {
    lexed
        .tokens
        .get(index)
        .map_or("", |token| token.text.as_str())
}

fn quoted_key(name: &str) -> String {
    let mut quoted = String::from("\"");
    for ch in name.chars() {
        match ch {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            ch if ch.is_control() || matches!(ch, '\u{2028}' | '\u{2029}') => {
                quoted.push_str(&format!("\\u{{{:x}}}", u32::from(ch)));
            }
            ch => quoted.push(ch),
        }
    }
    quoted.push('"');
    quoted
}

// Only decoded identifier names enter the binding map. Keep the original key
// literal for emission, including escapes and non-identifier string members.
fn string_member_name(raw: &str) -> Option<String> {
    let quote = raw.chars().next()?;
    if !matches!(quote, '\'' | '"') || !raw.ends_with(quote) {
        return None;
    }
    let mut chars = raw[1..raw.len() - 1].chars();
    let mut result = String::new();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            result.push(ch);
            continue;
        }
        let escaped = chars.next()?;
        let decoded = match escaped {
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'b' => '\u{8}',
            'f' => '\u{c}',
            'v' => '\u{b}',
            '0' => '\0',
            '\n' => continue,
            '\r' => {
                if chars.clone().next() == Some('\n') {
                    chars.next();
                }
                continue;
            }
            'x' | 'u' => {
                let mut digits = String::new();
                if escaped == 'u' && chars.clone().next() == Some('{') {
                    chars.next();
                    loop {
                        let ch = chars.next()?;
                        if ch == '}' {
                            break;
                        }
                        if digits.len() >= 6 || !ch.is_ascii_hexdigit() {
                            return None;
                        }
                        digits.push(ch);
                    }
                } else {
                    for _ in 0..if escaped == 'x' { 2 } else { 4 } {
                        digits.push(chars.next()?);
                    }
                }
                char::from_u32(u32::from_str_radix(&digits, 16).ok()?)?
            }
            other => other,
        };
        result.push(decoded);
    }
    Some(result)
}

/// Read a complete declaration at a token boundary. Property names and method
/// names called `enum` are not declarations; a declaration-looking malformed
/// head is refused rather than silently passed to an unrelated JS path.
pub(super) fn site(
    source: &str,
    lexed: &Lexed,
    cursor: usize,
) -> Result<Option<(Site, usize)>, &'static str> {
    if cursor > 0 && matches!(text(lexed, cursor - 1), "." | "?.") {
        return Ok(None);
    }
    let exported = text(lexed, cursor) == "export";
    let mut keyword = cursor + usize::from(exported);
    let ambient = text(lexed, keyword) == "declare";
    keyword += usize::from(ambient);
    keyword += usize::from(text(lexed, keyword) == "const");
    if text(lexed, keyword) != "enum" {
        return Ok(None);
    }
    if keyword == cursor && matches!(text(lexed, keyword + 1), ":" | "(" | "=" | "," | "}") {
        return Ok(None);
    }
    let name = lexed
        .tokens
        .get(keyword + 1)
        .filter(|token| token.kind == TokenKind::Word)
        .ok_or(INVALID)?
        .text
        .clone();
    let open = keyword + 2;
    if text(lexed, open) != "{" {
        return Err(INVALID);
    }
    let close = lexed.pairs[open].ok_or(INVALID)?;
    let mut at = open + 1;
    let mut members = Vec::new();
    let mut names = BTreeSet::new();
    while at < close {
        let token = &lexed.tokens[at];
        let raw = &source[token.start..token.end];
        let (name, key) = if token.kind == TokenKind::Word {
            (token.text.clone(), quoted_key(&token.text))
        } else if token.kind == TokenKind::Literal && raw.starts_with(['\'', '"']) {
            (string_member_name(raw).ok_or(INVALID)?, raw.to_owned())
        } else {
            return Err(INVALID);
        };
        if !names.insert(name.clone()) {
            return Err("duplicate enum member");
        }
        at += 1;
        let initializer = if text(lexed, at) == "=" {
            at += 1;
            let first = at;
            while at < close && text(lexed, at) != "," {
                if matches!(text(lexed, at), "(" | "[" | "{" | "\x24{") {
                    at = lexed.pairs[at].ok_or(INVALID)? + 1;
                } else {
                    at += 1;
                }
            }
            if at == first {
                return Err(INVALID);
            }
            Some(source[lexed.tokens[first].start..lexed.tokens[at - 1].end].to_owned())
        } else {
            None
        };
        members.push(Member {
            name,
            key,
            initializer,
        });
        if at < close {
            if text(lexed, at) != "," {
                return Err(INVALID);
            }
            at += 1;
        }
    }
    let finish = close + 1 + usize::from(text(lexed, close + 1) == ";");
    Ok(Some((
        Site {
            start: lexed.tokens[cursor].start,
            end: lexed.tokens[finish - 1].end,
            name,
            exported,
            ambient,
            members,
        },
        finish,
    )))
}

pub(super) fn fresh(identifiers: &mut BTreeSet<String>, serial: &mut usize) -> String {
    loop {
        let name = format!("__franken_enum_{}", *serial);
        *serial += 1;
        if identifiers.insert(name.clone()) {
            return name;
        }
    }
}

fn helper(name: &str, identifiers: &mut BTreeSet<String>, serial: &mut usize) -> String {
    // Separate enum activations may reuse a local helper. Only source names
    // can be captured; collisions receive a globally reserved fresh spelling.
    if identifiers.contains(name) {
        fresh(identifiers, serial)
    } else {
        name.to_owned()
    }
}

/// Emit a single activation. A namespace supplies its existing object path;
/// the local enum binding is initialized before any initializer runs.
pub(super) struct Emission<'a> {
    pub(super) members: &'a BTreeSet<String>,
    pub(super) constants: &'a mut Constants,
    pub(super) parent: Option<&'a str>,
    pub(super) declaration: &'a str,
    pub(super) export: bool,
    pub(super) identifiers: &'a mut BTreeSet<String>,
    pub(super) serial: &'a mut usize,
    pub(super) namespace_scope: bool,
    pub(super) budget: &'a mut Budget,
}

pub(super) fn render(
    source: &str,
    site: &Site,
    Emission {
        members,
        constants,
        parent,
        declaration,
        export,
        identifiers,
        serial,
        namespace_scope,
        budget,
    }: Emission<'_>,
) -> Result<String, &'static str> {
    if site.ambient {
        return Ok("\n".repeat(source[site.start..site.end].matches('\n').count()));
    }
    let alias = helper("__enum", identifiers, serial);
    let next = helper("__enum_next", identifiers, serial);
    let value_alias = helper("__value", identifiers, serial);
    let mut references = BTreeMap::from([(site.name.clone(), alias.clone())]);
    references.extend(
        members
            .iter()
            .map(|name| (name.clone(), format!("{alias}[{}]", quoted_key(name)))),
    );
    let mut output = String::new();
    if !declaration.is_empty() {
        if export {
            budget.append(&mut output, "export ")?;
        }
        budget.append(&mut output, &format!("{declaration} {}; ", site.name))?;
    } else if export {
        budget.append(&mut output, &format!("export {{ {} }};", site.name))?;
    }
    budget.append(
        &mut output,
        &format!("(function ({alias}) {{ let {next} = 0;"),
    )?;
    let mut known_next = Some(0.0);
    for member in &site.members {
        let value = if let Some(initializer) = &member.initializer {
            if let Some(value) = constant_expression(initializer, &site.name, constants)? {
                known_next = match &value {
                    Constant::Number(value) => Some(value + 1.0),
                    _ => None,
                };
                let rendered = value.source();
                budget.replace(constants, &member.name, Some(value))?;
                rendered
            } else {
                known_next = None;
                budget.replace(constants, &member.name, None)?;
                let expression = format!("({initializer});");
                let lexed = namespaces::lex(&expression)?;
                let edits = namespaces::bindings::rewrite_enum(
                    &expression,
                    &lexed,
                    &references,
                    namespace_scope,
                )?;
                let rewritten = namespaces::apply(&expression, &edits, 0, expression.len())?;
                rewritten[1..rewritten.len() - 2].to_owned()
            }
        } else if let Some(value) = known_next {
            known_next = Some(value + 1.0);
            let constant = Constant::Number(value);
            let rendered = constant.source();
            budget.replace(constants, &member.name, Some(constant))?;
            rendered
        } else {
            budget.replace(constants, &member.name, None)?;
            next.clone()
        };
        budget.append(&mut output, &format!(" {{ const {value_alias} = ({value}); {alias}[{}] = {value_alias}; if (typeof {value_alias} === \"number\") {{ {alias}[{value_alias}] = {}; {next} = {value_alias} + 1; }} }}", member.key, member.key))?;
    }
    let name = &site.name;
    let target = parent.map_or_else(
        || name.clone(),
        |parent| format!("{parent}[{}]", quoted_key(name)),
    );
    let argument = if parent.is_some() {
        format!("{name} = {target} || ({target} = {{}})")
    } else {
        format!("{name} || ({name} = {{}})")
    };
    budget.append(&mut output, &format!("}})({argument});"))?;
    let original_lines = source[site.start..site.end].matches('\n').count();
    let padding = original_lines.saturating_sub(output.matches('\n').count());
    budget.reserve_output(padding)?;
    output.extend(std::iter::repeat_n('\n', padding));
    Ok(output)
}

/// Lower enums wherever declarations can occur. Braced lexical scopes own
/// their own enum bindings; merged declarations in one scope share one object.
pub fn lower(source: &str) -> Result<String, &'static str> {
    if !source.contains("enum") {
        return Ok(source.to_owned());
    }
    let lexed = namespaces::lex(source)?;
    let mut identifiers = lexed
        .tokens
        .iter()
        .filter(|token| token.kind == TokenKind::Word)
        .map(|token| token.text.clone())
        .collect::<BTreeSet<_>>();
    let mut groups: BTreeMap<(usize, String), BTreeSet<String>> = BTreeMap::new();
    let mut sites = Vec::new();
    let mut scopes = vec![0usize];
    let mut next_scope = 1;
    let mut cursor = 0;
    while cursor < lexed.tokens.len() {
        if let Some((site, end)) = site(source, &lexed, cursor)? {
            let scope = *scopes.last().unwrap();
            if !site.ambient {
                groups
                    .entry((scope, site.name.clone()))
                    .or_default()
                    .extend(site.members.iter().map(|member| member.name.clone()));
            }
            sites.push((scope, site));
            cursor = end;
            continue;
        }
        if matches!(text(&lexed, cursor), "{" | "\x24{") {
            scopes.push(next_scope);
            next_scope += 1;
        } else if text(&lexed, cursor) == "}" {
            scopes.pop();
        }
        cursor += 1;
    }
    let mut edits = Vec::new();
    let mut declared = BTreeSet::new();
    let mut exported = BTreeSet::new();
    let mut serial = 0;
    let mut constants: BTreeMap<(usize, String), Constants> = BTreeMap::new();
    let mut budget = Budget::default();
    for (scope, site) in sites {
        let key = (scope, site.name.clone());
        let declaration = if site.ambient || !declared.insert(key.clone()) {
            ""
        } else if scope == 0 {
            "var"
        } else {
            "let"
        };
        let export = site.exported && !site.ambient && exported.insert(key.clone());
        let empty = BTreeSet::new();
        let replacement = render(
            source,
            &site,
            Emission {
                members: groups.get(&key).unwrap_or(&empty),
                constants: constants.entry(key).or_default(),
                parent: None,
                declaration,
                export,
                identifiers: &mut identifiers,
                serial: &mut serial,
                namespace_scope: false,
                budget: &mut budget,
            },
        )?;
        edits.push(Edit {
            start: site.start,
            end: site.end,
            replacement,
        });
    }
    namespaces::apply(source, &edits, 0, source.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_and_block_enums_have_scoped_bindings() {
        let output = lower(
            "call(); enum A{X} function f(){enum A{Y=4} enum A{Z=Y+1} return A;} enum A{W=9}",
        )
        .unwrap();
        assert_eq!(output.matches("var A;").count(), 1);
        assert_eq!(output.matches("let A;").count(), 1);
        assert!(!output.contains("enum A"));
        assert!(output.contains("const __value = (5); __enum[\"Z\"]"));
    }

    #[test]
    fn literals_property_names_and_shadowed_parameters_are_preserved() {
        let source = "const object={enum(){return /enum X{}/;}}; const s='enum X{A}'; enum E{A=1,B=((A)=>A+1)(3),C=({A}).A}";
        let output = lower(source).unwrap();
        assert!(output.contains("const object={enum(){return /enum X{}/;}}; const s='enum X{A}';"));
        assert!(output.contains("((A)=>A+1)(3)"));
        assert!(output.contains("({A}).A"));
    }

    #[test]
    fn aliases_are_hygienic_and_ambient_members_do_not_emit() {
        let output = lower(
            "const __franken_enum_0=8, __enum=9; declare enum D{A} enum E{A=__franken_enum_0}",
        )
        .unwrap();
        assert!(output.contains("(function (__franken_enum_1)"));
        assert!(!output.contains("var D"));
        assert!(output.contains("(__franken_enum_0)"));
    }

    #[test]
    fn malformed_declarations_are_refused() {
        for source in [
            "enum E",
            "enum E { A = }",
            "enum E{A B}",
            "enum E{[f()]=2}",
            "enum E{A,A}",
        ] {
            assert!(lower(source).is_err(), "{source}");
        }
    }

    #[test]
    fn constant_folding_is_separate_from_computed_closure_references() {
        let output = lower(
            "enum E{A=1,B=1<<4,C=(E.A=7),D=A+2,F=E.A+3,G=(()=>A)(),S='s',T=S+'!'} enum E{H=D+2}",
        )
        .unwrap();
        for expected in [
            "(16); __enum[\"B\"]",
            "(3); __enum[\"D\"]",
            "(4); __enum[\"F\"]",
            "(5); __enum[\"H\"]",
            "(\"s!\"); __enum[\"T\"]",
            "(()=>__enum[\"A\"])()",
        ] {
            assert!(output.contains(expected), "missing {expected}: {output}");
        }
    }

    #[test]
    fn merged_module_exports_are_emitted_once() {
        let output = lower("export enum E { A=1 } export enum E { B=A+1 }").unwrap();
        assert_eq!(output.matches("export var E;").count(), 1);
        assert!(output.contains("(2); __enum[\"B\"]"));
        let output = lower("enum E { A=1 } export enum E { B=A+1 }").unwrap();
        assert_eq!(output.matches("var E;").count(), 1);
        assert_eq!(output.matches("export { E };").count(), 1);
    }

    #[test]
    fn exponential_constant_strings_have_a_bounded_refusal() {
        let mut source = String::from("enum E{A0='a'");
        for index in 1..=17 {
            source.push_str(&format!(",A{index}=A{}+A{}", index - 1, index - 1));
        }
        source.push('}');
        assert_eq!(lower(&source), Err("enum constant string expansion limit"));
    }

    #[test]
    fn a_single_constant_string_must_fit_the_constant_limit() {
        let source = format!(
            "enum E{{A='{}'}}",
            "a".repeat(MAX_CONSTANT_STRING_BYTES + 1)
        );
        assert_eq!(lower(&source), Err("enum constant string expansion limit"));
    }

    #[test]
    fn constant_retention_is_bounded_across_merged_declarations_and_namespaces() {
        // A small input can otherwise retain and emit a copy of the literal
        // for every alias. The budget spans declarations, not just expressions.
        let head = format!("enum E{{A0='{}'}}", "a".repeat(16_384));
        let mut tail = String::from("enum E{");
        for index in 1..=64 {
            tail.push_str(&format!("A{index}=A0,"));
        }
        tail.push('}');
        assert_eq!(
            lower(&format!("{head} {tail}")),
            Err("enum retained constant budget")
        );
        let namespaced = format!("namespace N{{export {head}}} namespace N{{export {tail}}}");
        assert_eq!(
            namespaces::lower(&namespaced, str::to_owned),
            Err("enum retained constant budget")
        );
    }

    #[test]
    fn emitted_output_budget_is_cumulative_and_exact() {
        let mut budget = Budget::default();
        budget.reserve_output(MAX_EMITTED_ENUM_BYTES - 1).unwrap();
        budget.reserve_output(1).unwrap();
        assert_eq!(budget.reserve_output(1), Err("enum emitted output budget"));
        assert_eq!(budget.emitted, MAX_EMITTED_ENUM_BYTES);
    }

    #[test]
    fn enums_nested_inside_initializer_functions_are_explicitly_refused() {
        assert!(
            lower("enum Outer { A = (() => { enum Inner { X = 3 }; return Inner.X; })() }")
                .is_err()
        );
    }
}
