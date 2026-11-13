//! Lower TypeScript namespaces at their declaration sites.
//!
//! Exported variables are properties, not copied lexical locals. A binding
//! resolver distinguishes those references from parameters, private locals,
//! property names and literal text. The caller supplies its annotation eraser;
//! this pass is shared by both ingestion paths without an external parser dependency.

use std::collections::{BTreeMap, BTreeSet};

mod bindings;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TokenKind {
    Word,
    Literal,
    Punct,
    TemplateHead,
    TemplateMiddle,
    TemplateTail,
}

#[derive(Clone, Debug)]
pub(super) struct Token {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) text: String,
    pub(super) kind: TokenKind,
}

#[derive(Debug)]
pub(super) struct Lexed {
    pub(super) tokens: Vec<Token>,
    pub(super) pairs: Vec<Option<usize>>,
}

#[derive(Clone, Debug)]
pub(super) struct Edit {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) replacement: String,
}

const INVALID_NAMESPACE: &str = "unsupported namespace declaration form";
const INVALID_EXPORT: &str = "unsupported namespace export form";
const MAX_NESTING: usize = 256;

fn word_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || matches!(ch, '_' | '$') || (!ch.is_ascii() && !ch.is_whitespace())
}

fn word_part(ch: char) -> bool {
    word_start(ch) || ch.is_ascii_digit()
}

struct Lexer<'a> {
    source: &'a str,
    cursor: usize,
    tokens: Vec<Token>,
    pairs: Vec<Option<usize>>,
    groups: Vec<(usize, char, bool)>,
    expression_expected: bool,
}

impl<'a> Lexer<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            cursor: 0,
            tokens: Vec::new(),
            pairs: Vec::new(),
            groups: Vec::new(),
            expression_expected: true,
        }
    }

    fn push(&mut self, start: usize, kind: TokenKind, text: String) -> usize {
        let index = self.tokens.len();
        self.tokens.push(Token {
            start,
            end: self.cursor,
            text,
            kind,
        });
        self.pairs.push(None);
        index
    }

    fn previous(&self) -> &str {
        self.tokens.last().map_or("", |token| token.text.as_str())
    }

    fn identifier(&mut self) -> Result<String, &'static str> {
        let mut decoded = String::new();
        while self.cursor < self.source.len() {
            let ch = self.source[self.cursor..].chars().next().unwrap();
            if ch == '\\' {
                let rest = &self.source[self.cursor..];
                if !rest.starts_with("\\u") {
                    return Err("invalid escape in namespace identifier");
                }
                let begin = self.cursor + 2;
                let (digits, end) = if self.source[begin..].starts_with('{') {
                    let close = self.source[begin + 1..]
                        .find('}')
                        .map(|offset| begin + 1 + offset)
                        .ok_or("invalid escape in namespace identifier")?;
                    (&self.source[begin + 1..close], close + 1)
                } else {
                    let end = begin + 4;
                    (
                        self.source
                            .get(begin..end)
                            .ok_or("invalid escape in namespace identifier")?,
                        end,
                    )
                };
                let code = u32::from_str_radix(digits, 16)
                    .ok()
                    .and_then(char::from_u32)
                    .ok_or("invalid escape in namespace identifier")?;
                if !(if decoded.is_empty() {
                    word_start(code)
                } else {
                    word_part(code)
                }) {
                    return Err("invalid escape in namespace identifier");
                }
                decoded.push(code);
                self.cursor = end;
            } else if if decoded.is_empty() {
                word_start(ch)
            } else {
                word_part(ch)
            } {
                decoded.push(ch);
                self.cursor += ch.len_utf8();
            } else {
                break;
            }
        }
        Ok(decoded)
    }

    fn quoted(&mut self, quote: u8) -> Result<(), &'static str> {
        self.cursor += 1;
        let bytes = self.source.as_bytes();
        while self.cursor < bytes.len() {
            match bytes[self.cursor] {
                b'\\' => {
                    self.cursor += 1;
                    let ch = self.source[self.cursor..]
                        .chars()
                        .next()
                        .ok_or("unterminated namespace string")?;
                    self.cursor += ch.len_utf8();
                }
                byte if byte == quote => {
                    self.cursor += 1;
                    return Ok(());
                }
                _ => {
                    self.cursor += self.source[self.cursor..]
                        .chars()
                        .next()
                        .unwrap()
                        .len_utf8();
                }
            }
        }
        Err("unterminated namespace string")
    }

    fn regexp_end(&self) -> Option<usize> {
        let mut escaped = false;
        let mut in_class = false;
        for (offset, ch) in self.source[self.cursor + 1..].char_indices() {
            match ch {
                '\n' | '\r' | '\u{2028}' | '\u{2029}' => return None,
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '[' => in_class = true,
                ']' => in_class = false,
                '/' if !in_class => {
                    let mut end = self.cursor + 1 + offset + 1;
                    while let Some(ch) = self.source[end..].chars().next() {
                        if !word_part(ch) {
                            break;
                        }
                        end += ch.len_utf8();
                    }
                    return Some(end);
                }
                _ => {}
            }
        }
        None
    }

    fn template(&mut self, depth: usize) -> Result<(), &'static str> {
        if depth > MAX_NESTING {
            return Err("namespace template nesting limit");
        }
        let mut start = self.cursor;
        self.cursor += 1;
        let mut first = true;
        loop {
            match self.source.as_bytes().get(self.cursor).copied() {
                None => return Err("unterminated namespace template"),
                Some(b'\\') => {
                    self.cursor += 1;
                    let ch = self.source[self.cursor..]
                        .chars()
                        .next()
                        .ok_or("unterminated namespace template")?;
                    self.cursor += ch.len_utf8();
                }
                Some(b'\x60') => {
                    self.cursor += 1;
                    self.push(
                        start,
                        if first {
                            TokenKind::Literal
                        } else {
                            TokenKind::TemplateTail
                        },
                        String::new(),
                    );
                    self.expression_expected = false;
                    return Ok(());
                }
                Some(b'$') if self.source[self.cursor..].starts_with("\x24{") => {
                    self.push(
                        start,
                        if first {
                            TokenKind::TemplateHead
                        } else {
                            TokenKind::TemplateMiddle
                        },
                        String::new(),
                    );
                    let open = self.cursor;
                    self.cursor += 2;
                    let token = self.push(open, TokenKind::Punct, "\x24{".to_string());
                    let level = self.groups.len();
                    self.groups.push((token, '{', false));
                    self.expression_expected = true;
                    while self.groups.len() > level {
                        if self.cursor >= self.source.len() {
                            return Err("unterminated namespace template substitution");
                        }
                        self.step(depth + 1)?;
                    }
                    first = false;
                    start = self.cursor;
                }
                Some(_) => {
                    self.cursor += self.source[self.cursor..]
                        .chars()
                        .next()
                        .unwrap()
                        .len_utf8();
                }
            }
        }
    }

    fn step(&mut self, depth: usize) -> Result<(), &'static str> {
        let start = self.cursor;
        let ch = self.source[start..].chars().next().unwrap();
        if ch.is_whitespace() {
            self.cursor += ch.len_utf8();
            return Ok(());
        }
        if self.source[start..].starts_with("//") {
            self.cursor = self.source[start..]
                .find(['\n', '\r', '\u{2028}', '\u{2029}'])
                .map_or(self.source.len(), |offset| start + offset);
            return Ok(());
        }
        if self.source[start..].starts_with("/*") {
            self.cursor = self.source[start + 2..]
                .find("*/")
                .map(|offset| start + 2 + offset + 2)
                .ok_or("unterminated namespace comment")?;
            return Ok(());
        }
        if matches!(ch, '\'' | '"') {
            self.quoted(ch as u8)?;
            self.push(start, TokenKind::Literal, String::new());
            self.expression_expected = false;
            return Ok(());
        }
        if ch == '\x60' {
            return self.template(depth);
        }
        if ch == '/'
            && self.expression_expected
            && let Some(end) = self.regexp_end()
        {
            self.cursor = end;
            self.push(start, TokenKind::Literal, String::new());
            self.expression_expected = false;
            return Ok(());
        }
        if word_start(ch) || ch == '\\' {
            let property_name = matches!(self.previous(), "." | "?.");
            let name = self.identifier()?;
            self.expression_expected = !property_name
                && matches!(
                    name.as_str(),
                    "return"
                        | "throw"
                        | "case"
                        | "delete"
                        | "void"
                        | "typeof"
                        | "new"
                        | "in"
                        | "instanceof"
                        | "yield"
                        | "await"
                        | "else"
                        | "do"
                        | "of"
                );
            self.push(start, TokenKind::Word, name);
            return Ok(());
        }
        if ch.is_ascii_digit()
            || (ch == '.'
                && self
                    .source
                    .as_bytes()
                    .get(start + 1)
                    .is_some_and(u8::is_ascii_digit))
        {
            self.cursor += ch.len_utf8();
            while let Some(byte) = self.source.as_bytes().get(self.cursor).copied() {
                if byte.is_ascii_alphanumeric()
                    || matches!(byte, b'_' | b'.')
                    || (matches!(byte, b'+' | b'-')
                        && matches!(self.source.as_bytes()[self.cursor - 1], b'e' | b'E'))
                {
                    self.cursor += 1;
                } else {
                    break;
                }
            }
            self.push(start, TokenKind::Literal, String::new());
            self.expression_expected = false;
            return Ok(());
        }
        let operator = [
            ">>>=", "===", "!==", "**=", "&&=", "||=", "??=", ">>>", "<<=", ">>=", "...", "=>",
            "?.", "++", "--", "**", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "??", "+=",
            "-=", "*=", "/=", "%=", "&=", "|=", "^=",
        ]
        .into_iter()
        .find(|operator| self.source[start..].starts_with(operator));
        let text = operator.map_or_else(|| ch.to_string(), str::to_owned);
        self.cursor += text.len();
        let previous = self.previous().to_owned();
        if matches!(text.as_str(), "(" | "[" | "{") {
            let statement_end = if text == "(" {
                matches!(
                    previous.as_str(),
                    "if" | "while" | "for" | "with" | "switch" | "catch"
                )
            } else if text == "{" {
                matches!(
                    previous.as_str(),
                    "" | ")" | "=>" | ";" | "}" | "else" | "try" | "finally" | "do"
                ) || self
                    .tokens
                    .iter()
                    .rev()
                    .take_while(|token| !matches!(token.text.as_str(), ";" | "{" | "}"))
                    .any(|token| matches!(token.text.as_str(), "class" | "namespace"))
            } else {
                false
            };
            let index = self.push(start, TokenKind::Punct, text.clone());
            if self.groups.len() >= MAX_NESTING {
                return Err("namespace delimiter nesting limit");
            }
            self.groups.push((index, ch, statement_end));
            self.expression_expected = true;
        } else if matches!(text.as_str(), ")" | "]" | "}") {
            let (open, delimiter, statement_end) =
                self.groups.pop().ok_or("unbalanced namespace delimiter")?;
            if !matches!((delimiter, ch), ('(', ')') | ('[', ']') | ('{', '}')) {
                return Err("unbalanced namespace delimiter");
            }
            let close = self.push(start, TokenKind::Punct, text);
            self.pairs[open] = Some(close);
            self.pairs[close] = Some(open);
            self.expression_expected = statement_end;
        } else {
            self.expression_expected = !matches!(text.as_str(), "." | "?." | "++" | "--");
            self.push(start, TokenKind::Punct, text);
        }
        Ok(())
    }
}

pub(super) fn lex(source: &str) -> Result<Lexed, &'static str> {
    let mut lexer = Lexer::new(source);
    while lexer.cursor < source.len() {
        lexer.step(0)?;
    }
    if !lexer.groups.is_empty() {
        return Err("unbalanced namespace delimiter");
    }
    Ok(Lexed {
        tokens: lexer.tokens,
        pairs: lexer.pairs,
    })
}

fn text(lexed: &Lexed, index: usize) -> &str {
    lexed
        .tokens
        .get(index)
        .map_or("", |token| token.text.as_str())
}

fn is_namespace(lexed: &Lexed, index: usize) -> bool {
    text(lexed, index) == "namespace"
        && !matches!(
            index.checked_sub(1).map(|i| text(lexed, i)),
            Some("." | "?.")
        )
        && (text(lexed, index + 1) == "{"
            || (lexed
                .tokens
                .get(index + 1)
                .is_some_and(|token| token.kind == TokenKind::Word)
                && !matches!(text(lexed, index + 1), "in" | "instanceof")
                && matches!(text(lexed, index + 2), "{" | "." | "")))
}

#[derive(Debug)]
struct Variable {
    name: String,
    token: usize,
    initializer: Option<(usize, usize)>,
}

#[derive(Debug)]
enum Export {
    Variables {
        start: usize,
        end: usize,
        declarations: Vec<Variable>,
    },
    Function {
        start: usize,
        keyword_end: usize,
        end: usize,
        name: String,
    },
}

#[derive(Debug)]
struct Body {
    source: String,
    lexed: Lexed,
    exports: Vec<Export>,
}

fn statement_end(lexed: &Lexed, source: &str, mut cursor: usize) -> usize {
    let first = cursor;
    while cursor < lexed.tokens.len() {
        if text(lexed, cursor) == ";" {
            return cursor + 1;
        }
        if cursor > first {
            let token = &lexed.tokens[cursor];
            let previous = &lexed.tokens[cursor - 1];
            let newline = source[previous.end..token.start].contains(['\n', '\r']);
            let prior_complete = (previous.kind != TokenKind::Punct
                || matches!(previous.text.as_str(), ")" | "]" | "}" | "++" | "--"))
                && !matches!(
                    previous.text.as_str(),
                    "await"
                        | "yield"
                        | "new"
                        | "typeof"
                        | "delete"
                        | "void"
                        | "in"
                        | "instanceof"
                        | "of"
                        | "function"
                        | "async"
                );
            if newline
                && prior_complete
                && token.kind == TokenKind::Word
                && !matches!(token.text.as_str(), "in" | "instanceof" | "of")
            {
                return cursor;
            }
        }
        if matches!(text(lexed, cursor), "(" | "[" | "{" | "\x24{") {
            cursor = lexed.pairs[cursor].unwrap() + 1;
        } else {
            cursor += 1;
        }
    }
    cursor
}

fn variable_exports(
    lexed: &Lexed,
    source: &str,
    start: usize,
) -> Result<(Export, usize), &'static str> {
    let end = statement_end(lexed, source, start + 2);
    let content_end = if end > 0 && text(lexed, end - 1) == ";" {
        end - 1
    } else {
        end
    };
    let mut declarations = Vec::new();
    let mut cursor = start + 2;
    while cursor < content_end {
        let name = lexed
            .tokens
            .get(cursor)
            .filter(|token| token.kind == TokenKind::Word)
            .ok_or(INVALID_EXPORT)?;
        let token = cursor;
        cursor += 1;
        let initializer = if text(lexed, cursor) == "=" {
            cursor += 1;
            let expression_start = cursor;
            while cursor < content_end && text(lexed, cursor) != "," {
                if matches!(text(lexed, cursor), "(" | "[" | "{" | "\x24{") {
                    cursor = lexed.pairs[cursor].unwrap() + 1;
                } else {
                    cursor += 1;
                }
            }
            if cursor == expression_start {
                return Err(INVALID_EXPORT);
            }
            Some((
                lexed.tokens[expression_start].start,
                lexed.tokens[cursor - 1].end,
            ))
        } else {
            if text(lexed, start + 1) == "const" {
                return Err(INVALID_EXPORT);
            }
            None
        };
        declarations.push(Variable {
            name: name.text.clone(),
            token,
            initializer,
        });
        if cursor < content_end {
            if text(lexed, cursor) != "," {
                return Err(INVALID_EXPORT);
            }
            cursor += 1;
            if cursor == content_end {
                return Err(INVALID_EXPORT);
            }
        }
    }
    if declarations.is_empty() {
        return Err(INVALID_EXPORT);
    }
    Ok((
        Export::Variables {
            start: lexed.tokens[start].start,
            end: lexed.tokens[end - 1].end,
            declarations,
        },
        end,
    ))
}

fn body(source: &str, erase_types: fn(&str) -> String) -> Result<Body, &'static str> {
    let source = erase_types(source);
    let lexed = lex(&source)?;
    let mut exports = Vec::new();
    let mut cursor = 0;
    while cursor < lexed.tokens.len() {
        if is_namespace(&lexed, cursor) {
            return Err("nested namespace declarations are not yet supported");
        }
        if text(&lexed, cursor) == "export" {
            let next = text(&lexed, cursor + 1);
            if matches!(next, "const" | "let" | "var") {
                let (export, end) = variable_exports(&lexed, &source, cursor)?;
                exports.push(export);
                cursor = end;
                continue;
            }
            let mut function = cursor + 1;
            if text(&lexed, function) == "async" {
                function += 1;
            }
            if text(&lexed, function) != "function" {
                return Err(INVALID_EXPORT);
            }
            let mut name = function + 1;
            if text(&lexed, name) == "*" {
                name += 1;
            }
            if lexed
                .tokens
                .get(name)
                .is_none_or(|token| token.kind != TokenKind::Word)
                || text(&lexed, name + 1) != "("
            {
                return Err(INVALID_EXPORT);
            }
            let params_end = lexed.pairs[name + 1].ok_or(INVALID_EXPORT)?;
            let open = params_end + 1;
            if text(&lexed, open) != "{" {
                return Err(INVALID_EXPORT);
            }
            let end = lexed.pairs[open].ok_or(INVALID_EXPORT)? + 1;
            exports.push(Export::Function {
                start: lexed.tokens[cursor].start,
                keyword_end: lexed.tokens[cursor].end,
                end: lexed.tokens[end - 1].end,
                name: lexed.tokens[name].text.clone(),
            });
            cursor = end;
            continue;
        }
        if matches!(text(&lexed, cursor), "(" | "[" | "{" | "\x24{") {
            cursor = lexed.pairs[cursor].unwrap() + 1;
        } else {
            cursor += 1;
        }
    }
    Ok(Body {
        source,
        lexed,
        exports,
    })
}

#[derive(Debug)]
struct Site {
    start: usize,
    end: usize,
    name: String,
    exported: bool,
    body: Body,
}

fn apply(source: &str, edits: &[Edit], start: usize, end: usize) -> Result<String, &'static str> {
    let mut out = String::new();
    let mut cursor = start;
    for edit in edits
        .iter()
        .filter(|edit| edit.start >= start && edit.end <= end)
    {
        if edit.start < cursor {
            return Err("overlapping namespace source edits");
        }
        out.push_str(&source[cursor..edit.start]);
        out.push_str(&edit.replacement);
        cursor = edit.end;
    }
    out.push_str(&source[cursor..end]);
    Ok(out)
}

fn render_body(
    site: &Site,
    members: &BTreeSet<String>,
    alias: &str,
) -> Result<String, &'static str> {
    let body = &site.body;
    let mut replacements = BTreeMap::from([(site.name.clone(), alias.to_owned())]);
    for member in members {
        replacements.insert(member.clone(), format!("{alias}.{member}"));
    }
    let ignored = body
        .exports
        .iter()
        .flat_map(|export| match export {
            Export::Variables { declarations, .. } => {
                declarations.iter().map(|item| item.token).collect()
            }
            Export::Function { .. } => Vec::new(),
        })
        .collect::<BTreeSet<_>>();
    let references = bindings::rewrite(&body.source, &body.lexed, &replacements, &ignored)?;
    let mut edits = references.iter().filter(|edit| !body.exports.iter().any(|export| {
        matches!(export, Export::Variables { start, end, .. } if edit.start >= *start && edit.end <= *end)
    })).cloned().collect::<Vec<_>>();
    for export in &body.exports {
        match export {
            Export::Variables {
                start,
                end,
                declarations,
            } => {
                let mut replacement = String::new();
                for declaration in declarations {
                    if let Some((begin, finish)) = declaration.initializer {
                        let expression = apply(&body.source, &references, begin, finish)?;
                        replacement
                            .push_str(&format!("{alias}.{} = {expression};", declaration.name));
                    }
                }
                // Keep erased declarations' original line terminators even
                // when an uninitialized export has no runtime assignment.
                let original_lines = body.source[*start..*end].matches('\n').count();
                let generated_lines = replacement.matches('\n').count();
                replacement.extend(std::iter::repeat_n(
                    '\n',
                    original_lines.saturating_sub(generated_lines),
                ));
                edits.push(Edit {
                    start: *start,
                    end: *end,
                    replacement,
                });
            }
            Export::Function {
                start,
                keyword_end,
                end,
                name,
            } => {
                edits.push(Edit {
                    start: *start,
                    end: *keyword_end,
                    replacement: String::new(),
                });
                edits.push(Edit {
                    start: *end,
                    end: *end,
                    replacement: format!(" {alias}.{name} = {name};"),
                });
            }
        }
    }
    edits.sort_by_key(|edit| (edit.start, edit.end));
    apply(&body.source, &edits, 0, body.source.len())
}

/// Lower supported namespaces using the caller's real annotation eraser.
///
/// A new function activation at each declaration site preserves private
/// locals and evaluation order. Only exported variable references become
/// namespace properties; local function declarations retain their bindings.
pub fn lower(source: &str, erase_types: fn(&str) -> String) -> Result<String, &'static str> {
    if !source.contains("namespace") {
        return Ok(source.to_owned());
    }
    let lexed = lex(source)?;
    let mut sites = Vec::new();
    let mut bindings = BTreeSet::new();
    let mut named_exports = BTreeSet::new();
    let mut identifiers = lexed
        .tokens
        .iter()
        .filter(|token| token.kind == TokenKind::Word)
        .map(|token| token.text.clone())
        .collect::<BTreeSet<_>>();
    let mut cursor = 0;
    while cursor < lexed.tokens.len() {
        let exported = text(&lexed, cursor) == "export";
        let declaration = if exported { cursor + 1 } else { cursor };
        if is_namespace(&lexed, declaration) {
            let name = lexed
                .tokens
                .get(declaration + 1)
                .filter(|token| token.kind == TokenKind::Word)
                .ok_or(INVALID_NAMESPACE)?;
            let open = declaration + 2;
            if text(&lexed, open) != "{" {
                return Err(INVALID_NAMESPACE);
            }
            let close = lexed.pairs[open].ok_or(INVALID_NAMESPACE)?;
            let finish = if text(&lexed, close + 1) == ";" {
                close + 2
            } else {
                close + 1
            };
            let namespace_body = body(
                &source[lexed.tokens[open].end..lexed.tokens[close].start],
                erase_types,
            )?;
            sites.push(Site {
                start: lexed.tokens[cursor].start,
                end: lexed.tokens[finish - 1].end,
                name: name.text.clone(),
                exported,
                body: namespace_body,
            });
            cursor = finish;
            continue;
        }
        let mut head = declaration;
        if text(&lexed, head) == "async" {
            head += 1;
        }
        if matches!(
            text(&lexed, head),
            "class" | "function" | "const" | "let" | "var" | "enum"
        ) {
            let mut name = head + 1;
            if text(&lexed, name) == "*" {
                name += 1;
            }
            if let Some(token) = lexed
                .tokens
                .get(name)
                .filter(|token| token.kind == TokenKind::Word)
            {
                bindings.insert(token.text.clone());
                if exported {
                    named_exports.insert(token.text.clone());
                }
            }
        }
        if matches!(text(&lexed, cursor), "(" | "[" | "{" | "\x24{") {
            let end = lexed.pairs[cursor].unwrap();
            if (cursor + 1..end).any(|index| is_namespace(&lexed, index)) {
                return Err("namespace declarations require module or namespace scope");
            }
            cursor = end + 1;
        } else {
            cursor += 1;
        }
    }
    if sites.is_empty() {
        return Ok(source.to_owned());
    }
    let mut groups = BTreeMap::<String, BTreeSet<String>>::new();
    for site in &sites {
        let members = groups.entry(site.name.clone()).or_default();
        for export in &site.body.exports {
            match export {
                Export::Variables { declarations, .. } => {
                    members.extend(declarations.iter().map(|item| item.name.clone()))
                }
                Export::Function { name, .. } => {
                    members.insert(name.clone());
                }
            }
        }
        identifiers.extend(
            site.body
                .lexed
                .tokens
                .iter()
                .filter(|token| token.kind == TokenKind::Word)
                .map(|token| token.text.clone()),
        );
    }
    let mut out = String::with_capacity(source.len());
    let mut copied = 0;
    let mut next_alias = 0usize;
    for site in sites {
        let alias = loop {
            let candidate = format!("__franken_namespace_{next_alias}");
            next_alias += 1;
            if identifiers.insert(candidate.clone()) {
                break candidate;
            }
        };
        let body = render_body(&site, &groups[&site.name], &alias)?;
        out.push_str(&source[copied..site.start]);
        if bindings.insert(site.name.clone()) {
            out.push_str(&format!("var {}; ", site.name));
        }
        if site.exported && named_exports.insert(site.name.clone()) {
            out.push_str(&format!("export {{ {} }}; ", site.name));
        }
        out.push_str(&format!(
            "(function ({alias}) {{{body}\n}})({name} || ({name} = {{}}));",
            name = site.name
        ));
        copied = site.end;
    }
    out.push_str(&source[copied..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declarations_stay_at_their_original_sites() {
        let source = "namespace N { export let x = first(); }\nstep();\nnamespace N { export const y = x + last(); }";
        let actual = lower(source, str::to_owned).unwrap();
        assert_eq!(actual.matches("var N;").count(), 1);
        assert_eq!(actual.matches("(function (").count(), 2);
        assert!(actual.find("first()").unwrap() < actual.find("step()").unwrap());
        assert!(actual.find("step()").unwrap() < actual.find("last()").unwrap());
        assert!(actual.contains("__franken_namespace_1.y = __franken_namespace_1.x + last();"));
    }

    #[test]
    fn uninitialized_exports_do_not_reset_existing_properties() {
        let actual = lower(
            "namespace N { export let x = 1; } namespace N { export let x; export var y; }",
            str::to_owned,
        )
        .unwrap();
        assert_eq!(actual.matches(".x =").count(), 1);
        assert!(!actual.contains(".y ="));
        assert_eq!(actual.matches("(function (").count(), 2);
        assert_eq!(
            lower("namespace N { export const x; }", str::to_owned),
            Err(INVALID_EXPORT)
        );
    }

    #[test]
    fn identifiers_are_hygienic_even_when_unicode_escaped() {
        let actual = lower("const __franken_namespace_\\u0030 = 9; namespace N { export const x = __franken_namespace_0; }", str::to_owned).unwrap();
        assert!(actual.contains("(function (__franken_namespace_1)"));
        assert!(actual.contains(".x = __franken_namespace_0;"));
    }

    #[test]
    fn same_site_functions_remain_local_and_cross_site_functions_use_properties() {
        let actual = lower("namespace N { export function self() { return self; } export function read() { return later(); } } namespace N { export function later() { return 2; } }", str::to_owned).unwrap();
        assert!(actual.contains("return self;"));
        assert!(actual.contains("return __franken_namespace_0.later();"));
        assert!(actual.contains("__franken_namespace_0.self = self;"));
    }

    #[test]
    fn exported_namespace_reuses_class_binding() {
        let actual = lower("export class Box {} export namespace Box { export const value = 1; } export namespace Box { export const other = value; }", str::to_owned).unwrap();
        assert!(!actual.contains("var Box;"));
        assert!(!actual.contains("export { Box };"));
        assert!(actual.contains("__franken_namespace_1.other = __franken_namespace_1.value;"));
    }

    #[test]
    fn literal_and_comment_namespace_text_is_not_replaced() {
        let source = "const text = '/*__namespace:N__*/'; namespace N { export const value = /namespace N/.source; }";
        let actual = lower(source, str::to_owned).unwrap();
        assert!(actual.contains("'/*__namespace:N__*/'"));
        assert!(actual.contains("/namespace N/.source"));
    }

    #[test]
    fn multiline_declarations_keep_initializer_boundaries() {
        let actual = lower(
            "namespace N { export let\nx =\n1\nexport const y =\nx + 1\n}",
            str::to_owned,
        )
        .unwrap();
        assert!(actual.contains("__franken_namespace_0.x = 1;"));
        assert!(actual.contains("__franken_namespace_0.y = __franken_namespace_0.x + 1;"));
        let actual = lower(
            "namespace N { export const read = async () => await\nPromise.resolve(2); }",
            str::to_owned,
        )
        .unwrap();
        assert!(actual.contains("async () => await\nPromise.resolve(2)"));
    }

    #[test]
    fn reserved_property_names_do_not_turn_division_into_a_regexp() {
        let actual = lower(
            "namespace N { export const divisor = 2; export const value = object.return / divisor / 3; export const optional = object?.in / divisor / 3; }",
            str::to_owned,
        )
        .unwrap();
        assert!(actual.contains("object.return / __franken_namespace_0.divisor / 3"));
        assert!(actual.contains("object?.in / __franken_namespace_0.divisor / 3"));
    }
}
