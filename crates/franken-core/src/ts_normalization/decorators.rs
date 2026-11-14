//! Token-directed legacy TypeScript decorators.
//!
//! Decorator expressions are removed before the ordinary annotation eraser,
//! then attached to complete class, member and parameter sites. Expressions
//! evaluate at the same sites as TypeScript's legacy `__decorate` emitter:
//! instance members, static members, then the class and its constructor
//! parameters. Each list evaluates forwards and applies backwards. This is
//! the legacy experimental-decorators contract, not stage-three decorators.

use std::collections::{BTreeMap, BTreeSet};

use super::namespaces::{self, Edit, Lexed, TokenKind};

const INVALID_DECORATOR: &str = "unsupported decorator declaration form";
const INVALID_TARGET: &str = "unsupported decorator target";
const MAX_DECORATORS: usize = 4096;
const MAX_DEPTH: usize = 128;
const MAX_ADDED_BYTES: usize = 8_388_608;

#[derive(Debug)]
struct Annotation {
    target: usize,
    expressions: Vec<String>,
}

#[derive(Default)]
struct Names {
    used: BTreeSet<String>,
    next: usize,
}

impl Names {
    fn fresh(&mut self, base: &str) -> String {
        if self.used.insert(base.to_owned()) {
            return base.to_owned();
        }
        loop {
            let candidate = format!("{base}_{}", self.next);
            self.next += 1;
            if self.used.insert(candidate.clone()) {
                return candidate;
            }
        }
    }
}

fn text(lexed: &Lexed, index: usize) -> &str {
    lexed
        .tokens
        .get(index)
        .map_or("", |token| token.text.as_str())
}

fn group_end(lexed: &Lexed, index: usize) -> Option<usize> {
    matches!(text(lexed, index), "(" | "[" | "{" | "${")
        .then(|| lexed.pairs.get(index).copied().flatten())
        .flatten()
        .map(|close| close + 1)
}

fn blank(source: &str) -> String {
    source
        .chars()
        .map(|ch| match ch {
            '\n' | '\r' | '\u{2028}' | '\u{2029}' => ch.to_string(),
            _ => " ".repeat(ch.len_utf8()),
        })
        .collect()
}

fn apply_bounded(
    source: &str,
    edits: &[Edit],
    start: usize,
    end: usize,
) -> Result<String, &'static str> {
    let mut size = end - start;
    for edit in edits
        .iter()
        .filter(|edit| edit.start >= start && edit.end <= end)
    {
        size = size
            .checked_sub(edit.end - edit.start)
            .and_then(|size| size.checked_add(edit.replacement.len()))
            .ok_or("decorator emitted output budget")?;
        if size.saturating_sub(end - start) > MAX_ADDED_BYTES {
            return Err("decorator emitted output budget");
        }
    }
    namespaces::apply(source, edits, start, end)
}

/// A decorator is a left-hand-side expression, including factories and
/// parenthesized expressions. Balanced arguments keep commas, comments,
/// regular expressions and template interpolation out of target detection.
fn expression_end(lexed: &Lexed, start: usize) -> Result<usize, &'static str> {
    let mut cursor = start;
    if text(lexed, cursor) == "(" {
        cursor = group_end(lexed, cursor).ok_or(INVALID_DECORATOR)?;
    } else if lexed.tokens.get(cursor).is_some_and(|token| {
        token.kind == TokenKind::Word
            && !matches!(
                token.text.as_str(),
                "class" | "export" | "default" | "function" | "const" | "let" | "var"
            )
    }) {
        cursor += 1;
    } else {
        return Err(INVALID_DECORATOR);
    }
    loop {
        match text(lexed, cursor) {
            "." => {
                if lexed
                    .tokens
                    .get(cursor + 1)
                    .is_none_or(|token| token.kind != TokenKind::Word)
                {
                    return Err(INVALID_DECORATOR);
                }
                cursor += 2;
            }
            // In legacy decorator grammar a following `[` starts a
            // computed member name. Element access in the decorator itself
            // must be parenthesized, as in `@(registry[key])`.
            "(" => cursor = group_end(lexed, cursor).ok_or(INVALID_DECORATOR)?,
            "<" => {
                let mut depth = 1usize;
                cursor += 1;
                while cursor < lexed.tokens.len() && depth > 0 {
                    match text(lexed, cursor) {
                        "<" => depth += 1,
                        ">" => depth = depth.saturating_sub(1),
                        ">>" => depth = depth.saturating_sub(2),
                        ">>>" => depth = depth.saturating_sub(3),
                        _ => {}
                    }
                    if depth > MAX_DEPTH {
                        return Err("decorator type argument nesting limit");
                    }
                    cursor = group_end(lexed, cursor).unwrap_or(cursor + 1);
                }
                if depth != 0 || text(lexed, cursor) != "(" {
                    return Err(INVALID_DECORATOR);
                }
            }
            _ => return Ok(cursor),
        }
    }
}

fn annotations(source: &str, lexed: &Lexed) -> Result<(String, Vec<Annotation>), &'static str> {
    let mut annotations = Vec::new();
    let mut edits = Vec::new();
    let mut cursor = 0;
    let mut count = 0usize;
    while cursor < lexed.tokens.len() {
        if text(lexed, cursor) != "@" {
            cursor += 1;
            continue;
        }
        let mut expressions = Vec::new();
        while text(lexed, cursor) == "@" {
            count += 1;
            if count > MAX_DECORATORS {
                return Err("decorator count limit");
            }
            let start = cursor;
            let expression = cursor + 1;
            cursor = expression_end(lexed, expression)?;
            let end = lexed.tokens[cursor - 1].end;
            expressions.push(source[lexed.tokens[expression].start..end].to_owned());
            edits.push(Edit {
                start: lexed.tokens[start].start,
                end,
                replacement: blank(&source[lexed.tokens[start].start..end]),
            });
            if text(lexed, cursor) == ";" {
                edits.push(Edit {
                    start: lexed.tokens[cursor].start,
                    end: lexed.tokens[cursor].end,
                    replacement: " ".to_owned(),
                });
                cursor += 1;
            }
        }
        let target = lexed.tokens.get(cursor).ok_or(INVALID_TARGET)?.start;
        annotations.push(Annotation {
            target,
            expressions,
        });
    }
    Ok((
        namespaces::apply(source, &edits, 0, source.len())?,
        annotations,
    ))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Method,
    Getter,
    Setter,
    Property,
    Constructor,
}

struct Member {
    kind: Kind,
    is_static: bool,
    key: String,
    identity: String,
    decorators: Vec<String>,
    parameters: Vec<(usize, String)>,
}

struct Lowering<'a> {
    source: &'a str,
    lexed: Lexed,
    annotations: BTreeMap<usize, Vec<String>>,
    names: Names,
    helper: String,
    parameter_helper: String,
    used_parameters: bool,
    added_bytes: usize,
}

impl Lowering<'_> {
    fn take(&mut self, token: usize) -> Vec<String> {
        self.lexed
            .tokens
            .get(token)
            .and_then(|token| self.annotations.remove(&token.start))
            .unwrap_or_default()
    }

    fn text(&self, index: usize) -> &str {
        text(&self.lexed, index)
    }

    fn group(&self, index: usize) -> Result<usize, &'static str> {
        group_end(&self.lexed, index).ok_or(INVALID_TARGET)
    }

    fn newline_before(&self, index: usize) -> bool {
        index > 0
            && self.source[self.lexed.tokens[index - 1].end..self.lexed.tokens[index].start]
                .contains(['\n', '\r', '\u{2028}', '\u{2029}'])
    }

    fn member_key(&self, index: usize) -> bool {
        self.lexed.tokens.get(index).is_some_and(|token| {
            token.kind == TokenKind::Word
                || token.kind == TokenKind::Literal
                    && self.source[token.start..token.end]
                        .starts_with(|ch: char| ch.is_ascii_digit() || matches!(ch, '\'' | '"'))
        })
    }

    fn class_body(&self, start: usize, limit: usize, depth: usize) -> Result<usize, &'static str> {
        if depth >= MAX_DEPTH {
            return Err("decorator class nesting limit");
        }
        let mut cursor = start + 1;
        if self.lexed.tokens.get(cursor).is_some_and(|token| {
            token.kind == TokenKind::Word
                && !matches!(token.text.as_str(), "extends" | "implements")
        }) {
            cursor += 1;
        }
        while cursor < limit {
            if self.text(cursor) == "{" {
                return Ok(cursor);
            }
            if self.text(cursor) == "class" && !matches!(self.text(cursor - 1), "." | "?.") {
                let body = self.class_body(cursor, limit, depth + 1)?;
                cursor = self.group(body)?;
            } else {
                cursor = group_end(&self.lexed, cursor).unwrap_or(cursor + 1);
            }
        }
        Err(INVALID_TARGET)
    }

    fn parameters(&mut self, open: usize) -> Result<Vec<(usize, String)>, &'static str> {
        let close = self.group(open)? - 1;
        let mut cursor = open + 1;
        let mut index = 0;
        let mut decorators = Vec::new();
        while cursor < close {
            for expression in self.take(cursor) {
                decorators.push((index, expression));
            }
            while cursor < close && self.text(cursor) != "," {
                cursor = group_end(&self.lexed, cursor).unwrap_or(cursor + 1);
            }
            cursor += usize::from(cursor < close);
            index += 1;
        }
        Ok(decorators)
    }

    fn field_end(&self, start: usize, limit: usize) -> Result<usize, &'static str> {
        let mut cursor = start;
        while cursor < limit {
            if self.text(cursor) == ";" {
                return Ok(cursor + 1);
            }
            if cursor > start
                && self.newline_before(cursor)
                && (self.member_key(cursor) || matches!(self.text(cursor), "#" | "*"))
                && (self.member_key(cursor - 1)
                    || matches!(self.text(cursor - 1), ")" | "]" | "}" | "++" | "--"))
                && !matches!(
                    self.text(cursor - 1),
                    "new" | "class" | "function" | "extends"
                )
            {
                return Ok(cursor);
            }
            cursor = if self.text(cursor) == "class"
                && cursor > 0
                && !matches!(self.text(cursor - 1), "." | "?.")
            {
                self.group(self.class_body(cursor, limit, 0)?)?
            } else {
                group_end(&self.lexed, cursor).unwrap_or(cursor + 1)
            };
        }
        Ok(cursor)
    }

    fn members(
        &mut self,
        body: usize,
        close: usize,
        edits: &mut Vec<Edit>,
        temporaries: &mut Vec<String>,
    ) -> Result<Vec<Member>, &'static str> {
        let mut cursor = body + 1;
        let mut members = Vec::new();
        while cursor < close {
            if self.text(cursor) == ";" {
                cursor += 1;
                continue;
            }
            let decorators = self.take(cursor);
            let is_static = self.text(cursor) == "static"
                && (self.member_key(cursor + 1)
                    || matches!(self.text(cursor + 1), "[" | "#" | "*" | "{"));
            cursor += usize::from(is_static);
            if is_static && self.text(cursor) == "{" {
                if !decorators.is_empty() {
                    return Err(INVALID_TARGET);
                }
                cursor = self.group(cursor)?;
                continue;
            }
            let mut kind = Kind::Method;
            if matches!(self.text(cursor), "get" | "set" | "async" | "accessor")
                && (self.member_key(cursor + 1) || matches!(self.text(cursor + 1), "[" | "#" | "*"))
                && (self.text(cursor) != "async" || !self.newline_before(cursor + 1))
            {
                kind = match self.text(cursor) {
                    "get" => Kind::Getter,
                    "set" => Kind::Setter,
                    "accessor" if !decorators.is_empty() => {
                        return Err("legacy decorators on auto-accessors are not supported");
                    }
                    _ => Kind::Method,
                };
                cursor += 1;
            }
            if self.text(cursor) == "*" {
                cursor += 1;
            }
            let private = self.text(cursor) == "#";
            cursor += usize::from(private);
            let key_index = cursor;
            let computed = self.text(cursor) == "[";
            let key_close;
            let (mut key, identity) = if computed {
                key_close = self.group(cursor)? - 1;
                let expression = self.source
                    [self.lexed.tokens[cursor].end..self.lexed.tokens[key_close].start]
                    .to_owned();
                cursor = key_close + 1;
                // Dynamic computed accessor names are distinct declaration
                // sites even when their source expressions are identical.
                (expression, format!("computed:{key_index}"))
            } else if self.member_key(cursor) {
                key_close = cursor;
                let token = &self.lexed.tokens[cursor];
                let raw = &self.source[token.start..token.end];
                let key = if token.kind == TokenKind::Word {
                    super::enums::quoted_key(&token.text)
                } else {
                    raw.to_owned()
                };
                let identity = if token.kind == TokenKind::Word {
                    token.text.clone()
                } else {
                    super::enums::string_member_name(raw).unwrap_or_else(|| raw.to_owned())
                };
                cursor += 1;
                (key, identity)
            } else {
                return Err(INVALID_TARGET);
            };
            let parameters = if self.text(cursor) == "(" {
                let parameters = self.parameters(cursor)?;
                cursor = self.group(cursor)?;
                if self.text(cursor) != "{" {
                    return Err("legacy decorators require an implemented class member");
                }
                cursor = self.group(cursor)?;
                if !is_static && !computed && !private && identity == "constructor" {
                    kind = Kind::Constructor;
                }
                parameters
            } else {
                kind = Kind::Property;
                cursor = if self.text(cursor) == "=" {
                    self.field_end(cursor + 1, close)?
                } else if self.text(cursor) == ";" {
                    cursor + 1
                } else if cursor == close || self.newline_before(cursor) {
                    cursor
                } else {
                    return Err(INVALID_TARGET);
                };
                Vec::new()
            };
            let decorated = !decorators.is_empty() || !parameters.is_empty();
            if private && decorated {
                return Err("legacy decorators on private names are not supported");
            }
            if kind == Kind::Constructor && !decorators.is_empty() {
                return Err(INVALID_TARGET);
            }
            if computed && decorated {
                if kind == Kind::Property {
                    return Err("legacy decorators on computed fields are not supported");
                }
                let temporary = self.names.fresh("__franken_decorator_key");
                edits.push(Edit {
                    start: self.lexed.tokens[key_index].end,
                    end: self.lexed.tokens[key_close].start,
                    replacement: format!("{temporary} = ({key})"),
                });
                key = temporary.clone();
                temporaries.push(temporary);
            }
            members.push(Member {
                kind,
                is_static,
                key,
                identity,
                decorators,
                parameters,
            });
        }
        Ok(members)
    }

    fn list(&mut self, decorators: &[String], parameters: &[(usize, String)]) -> String {
        let mut expressions = decorators.to_vec();
        for (index, expression) in parameters {
            self.used_parameters = true;
            expressions.push(format!("{}({index}, {expression})", self.parameter_helper));
        }
        expressions.join(", ")
    }

    fn render_range(
        &mut self,
        start: usize,
        end: usize,
        depth: usize,
    ) -> Result<Vec<Edit>, &'static str> {
        if depth >= MAX_DEPTH {
            return Err("decorator class nesting limit");
        }
        let mut edits = Vec::new();
        let mut cursor = start;
        while cursor < end {
            if self.text(cursor) != "class"
                || cursor > 0 && matches!(self.text(cursor - 1), "." | "?.")
                || matches!(self.text(cursor + 1), "(" | ":" | "=")
            {
                cursor += 1;
                continue;
            }
            let body = self.class_body(cursor, end, depth + 1)?;
            let close = self.group(body)? - 1;
            let mut prefix = cursor;
            while prefix > start
                && matches!(self.text(prefix - 1), "export" | "default" | "abstract")
            {
                prefix -= 1;
            }
            let mut decorators = Vec::new();
            for token in prefix..=cursor {
                decorators.extend(self.take(token));
            }
            let mut class_edits = self.render_range(body + 1, close, depth + 1)?;
            let mut temporaries = Vec::new();
            let members = self.members(body, close, &mut class_edits, &mut temporaries)?;
            let decorated = !decorators.is_empty()
                || members
                    .iter()
                    .any(|member| !member.decorators.is_empty() || !member.parameters.is_empty());
            if !decorated {
                edits.extend(class_edits);
                cursor = close + 1;
                continue;
            }
            let exported = self.text(prefix) == "export";
            let default_export = exported && self.text(prefix + 1) == "default";
            if !exported
                && prefix > 0
                && !matches!(self.text(prefix - 1), ";" | "{" | "}" | ":")
                && !self.newline_before(prefix)
            {
                return Err("legacy decorators require a class declaration");
            }
            let name_token = self.lexed.tokens.get(cursor + 1).ok_or(INVALID_TARGET)?;
            if name_token.kind != TokenKind::Word
                || matches!(name_token.text.as_str(), "extends" | "implements")
            {
                return Err("legacy decorators require a named class");
            }
            let name = name_token.text.clone();
            let name_source = self.source[name_token.start..name_token.end].to_owned();
            let constructor_parameters = members
                .iter()
                .find(|member| member.kind == Kind::Constructor)
                .map_or_else(Vec::new, |member| member.parameters.clone());
            let replaces_class = !decorators.is_empty() || !constructor_parameters.is_empty();
            class_edits.sort_by_key(|edit| (edit.start, edit.end));
            let mut class_source = apply_bounded(
                self.source,
                &class_edits,
                self.lexed.tokens[cursor].start,
                self.lexed.tokens[close].end,
            )?;
            let mut output = String::new();
            if !temporaries.is_empty() {
                output.push_str(&format!("let {}; ", temporaries.join(", ")));
            }
            let alias = if replaces_class {
                let alias = self.names.fresh("__franken_decorated_class");
                let initialized = self.names.fresh("__franken_class_initialized");
                // A named class expression's immutable self binding would
                // otherwise keep returning the undecorated constructor.
                // Resolve only actual references, preserving shadowing and
                // shorthand keys. During static initialization the original
                // class is still the value, before the alias is initialized.
                class_source = super::parameter_properties::lower(&class_source);
                let lexed = namespaces::lex(&class_source)?;
                let rewrites = namespaces::bindings::rewrite_class_self(
                    &class_source,
                    &lexed,
                    &BTreeMap::from([(
                        name.clone(),
                        format!("({initialized} ? {alias} : {name_source})"),
                    )]),
                    &BTreeSet::from([1]),
                )?;
                for rewrite in &rewrites {
                    let following = class_source[rewrite.end..].trim_start();
                    if following.starts_with("++")
                        || following.starts_with("--")
                        || following.starts_with('=') && !following.starts_with("==")
                    {
                        return Err(
                            "assignment to a decorated class self binding is not supported",
                        );
                    }
                }
                class_source = apply_bounded(&class_source, &rewrites, 0, class_source.len())?;
                output.push_str(&format!(
                    "let {alias}; let {initialized} = false; let {name_source} = {class_source}; {alias} = {name_source}; {initialized} = true;\n"
                ));
                Some(alias)
            } else {
                output.push_str(&class_source);
                output.push('\n');
                None
            };
            let mut applied_accessors = BTreeSet::new();
            let mut accessor_groups = BTreeMap::<(bool, &str), Vec<&Member>>::new();
            for member in &members {
                if matches!(member.kind, Kind::Getter | Kind::Setter) {
                    accessor_groups
                        .entry((member.is_static, member.identity.as_str()))
                        .or_default()
                        .push(member);
                }
            }
            for is_static in [false, true] {
                for member in &members {
                    if member.is_static != is_static || member.kind == Kind::Constructor {
                        continue;
                    }
                    let mut member_decorators = member.decorators.clone();
                    let mut parameters = member.parameters.clone();
                    if matches!(member.kind, Kind::Getter | Kind::Setter) {
                        let key = (is_static, member.identity.clone());
                        if !applied_accessors.insert(key) {
                            continue;
                        }
                        for &other in &accessor_groups[&(is_static, member.identity.as_str())] {
                            if !std::ptr::eq(other, member) {
                                if !member_decorators.is_empty() && !other.decorators.is_empty() {
                                    return Err(
                                        "legacy decorators cannot decorate both accessors of one property",
                                    );
                                }
                                member_decorators.extend(other.decorators.clone());
                                parameters.extend(other.parameters.clone());
                            }
                        }
                    }
                    if member_decorators.is_empty() && parameters.is_empty() {
                        continue;
                    }
                    let list = self.list(&member_decorators, &parameters);
                    let target = if is_static {
                        name_source.clone()
                    } else {
                        format!("{name_source}.prototype")
                    };
                    let descriptor = if member.kind == Kind::Property {
                        "void 0"
                    } else {
                        "null"
                    };
                    output.push_str(&format!(
                        "{}([{list}], {target}, {}, {descriptor});\n",
                        self.helper, member.key
                    ));
                }
            }
            if let Some(alias) = alias {
                let list = self.list(&decorators, &constructor_parameters);
                output.push_str(&format!(
                    "{name_source} = {alias} = {}([{list}], {name_source});\n",
                    self.helper
                ));
            }
            if default_export {
                output.push_str(&format!("export default {name_source};\n"));
            } else if exported {
                // Namespace lowering publishes this local only after all
                // decorators have succeeded. Module exports remain live.
                output.push_str(&format!("export {{ {name_source} }};\n"));
            }
            let begin = self.lexed.tokens[prefix].start;
            let finish = self.lexed.tokens[close].end;
            self.added_bytes = self
                .added_bytes
                .saturating_add(output.len().saturating_sub(finish - begin));
            if self.added_bytes > MAX_ADDED_BYTES {
                return Err("decorator emitted output budget");
            }
            edits.push(Edit {
                start: begin,
                end: finish,
                replacement: output,
            });
            cursor = close + 1;
        }
        Ok(edits)
    }
}

fn helpers(helper: &str, parameter: Option<&str>) -> String {
    let mut source = format!(
        "function {helper}(decorators, target, key, descriptor) {{\n\
         let count = arguments.length;\n\
         let result = count < 3 ? target : descriptor === null ? descriptor = Object.getOwnPropertyDescriptor(target, key) : descriptor;\n\
         if (typeof Reflect === \"object\" && typeof Reflect.decorate === \"function\") {{ result = Reflect.decorate(decorators, target, key, descriptor); }}\n\
         else {{ for (let index = decorators.length - 1; index >= 0; index--) {{ let decorator = decorators[index]; if (decorator) {{ result = (count < 3 ? decorator(result) : count > 3 ? decorator(target, key, result) : decorator(target, key)) || result; }} }} }}\n\
         if (count > 3 && result) {{ Object.defineProperty(target, key, result); }} return result;\n\
         }}\n"
    );
    if let Some(parameter) = parameter {
        source.push_str(&format!(
            "function {parameter}(index, decorator) {{ return function (target, key) {{ decorator(target, key, index); }}; }}\n"
        ));
    }
    source
}

/// Lower legacy class, method, accessor, property and parameter decorators.
/// Unsupported targets are rejected rather than erased or partially emitted.
pub fn lower(source: &str) -> Result<String, &'static str> {
    if !source.contains('@') {
        return Ok(source.to_owned());
    }
    let original = namespaces::lex(source)?;
    let (masked, annotations) = annotations(source, &original)?;
    if annotations.is_empty() {
        return Ok(source.to_owned());
    }
    let mut names = Names::default();
    names.used.extend(
        original
            .tokens
            .iter()
            .filter(|token| token.kind == TokenKind::Word)
            .map(|token| token.text.clone()),
    );
    let helper = names.fresh("__applyClassDecorator");
    let parameter_helper = names.fresh("__franken_parameter_decorator");
    // The eraser preserves byte offsets and line terminators. Masking the
    // annotations first lets it see ordinary class and parameter grammar.
    let erased = super::type_erasure::erase(&masked);
    let lexed = namespaces::lex(&erased)?;
    let mut attached: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    for annotation in annotations {
        let token = lexed
            .tokens
            .partition_point(|token| token.start < annotation.target);
        let target = lexed.tokens.get(token).ok_or(INVALID_TARGET)?.start;
        // An erased abstract/ambient declaration must not transfer its
        // decorator to the following runtime member. Only modifier tokens
        // may disappear between an annotation and its surviving target.
        let skipped_start = original
            .tokens
            .partition_point(|token| token.start < annotation.target);
        let skipped_end = original
            .tokens
            .partition_point(|token| token.start < target);
        for skipped in &original.tokens[skipped_start..skipped_end] {
            if !matches!(
                skipped.text.as_str(),
                "public"
                    | "private"
                    | "protected"
                    | "readonly"
                    | "override"
                    | "abstract"
                    | "declare"
            ) {
                return Err(INVALID_TARGET);
            }
        }
        attached
            .entry(target)
            .or_default()
            .extend(annotation.expressions);
    }
    let mut lowering = Lowering {
        source: &erased,
        lexed,
        annotations: attached,
        names,
        helper: helper.clone(),
        parameter_helper: parameter_helper.clone(),
        used_parameters: false,
        added_bytes: 0,
    };
    let mut edits = lowering.render_range(0, lowering.lexed.tokens.len(), 0)?;
    if !lowering.annotations.is_empty() {
        return Err(INVALID_TARGET);
    }
    // A helper before a directive would accidentally disable strict mode.
    let mut insertion = 0;
    let mut token = 0;
    while let Some(current) = lowering.lexed.tokens.get(token) {
        if current.kind != TokenKind::Literal
            || !erased[current.start..current.end].starts_with(['\'', '"'])
        {
            break;
        }
        if lowering.text(token + 1) == ";" {
            insertion = lowering.lexed.tokens[token + 1].end;
            token += 2;
        } else if token + 1 == lowering.lexed.tokens.len()
            || lowering.newline_before(token + 1)
                && lowering.lexed.tokens[token + 1].kind == TokenKind::Word
                && !matches!(lowering.text(token + 1), "in" | "instanceof")
        {
            insertion = current.end;
            token += 1;
        } else {
            break;
        }
    }
    edits.push(Edit {
        start: insertion,
        end: insertion,
        replacement: format!(
            "\n{}",
            helpers(
                &helper,
                lowering
                    .used_parameters
                    .then_some(parameter_helper.as_str())
            )
        ),
    });
    edits.sort_by_key(|edit| (edit.start, edit.end));
    apply_bounded(&erased, &edits, 0, erased.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_comment_and_template_text_are_byte_identical() {
        let source = "const literal = '@decorator'; const regex = /@sealed/; // @wrong\nconst template = `@no ${'@alsoNo'}`;";
        assert_eq!(lower(source).unwrap(), source);
    }

    #[test]
    fn multiline_inline_and_stacked_classes_keep_complete_bodies() {
        let source = "@outer(1)\n@inner\nclass Example {\n value: number = 3;\n self() { return Example; }\n}\n@outer(2) class Other {}";
        let lowered = lower(source).unwrap();
        assert!(lowered.contains("[outer(1), inner], Example)"));
        assert!(lowered.contains("[outer(2)], Other)"));
        assert!(lowered.contains("this.value = 3;"));
        assert!(lowered.contains(
            "return (__franken_class_initialized ? __franken_decorated_class : Example)"
        ));
        assert_eq!(
            lowered.matches("function __applyClassDecorator(").count(),
            1
        );
    }

    #[test]
    fn instance_and_static_lists_precede_constructor_and_class_lists() {
        let source = "@classDec class C { @staticDec static method() {} @instanceDec method(@first x: number, @second y: number) {} constructor(@ctor public value: number) {} }";
        let lowered = lower(source).unwrap();
        let instance = lowered.find("[instanceDec, __franken_parameter_decorator(0, first), __franken_parameter_decorator(1, second)]").unwrap();
        let static_member = lowered.find("[staticDec], C,").unwrap();
        let class = lowered
            .find("[classDec, __franken_parameter_decorator(0, ctor)]")
            .unwrap();
        assert!(instance < static_member && static_member < class);
        assert!(lowered.contains("this.value = value"));
    }

    #[test]
    fn accessor_pairs_share_one_descriptor_application() {
        let lowered = lower(
            "class C { get value() { return 1; } @method set value(@parameter x: number) {} }",
        )
        .unwrap();
        assert_eq!(
            lowered.matches("], C.prototype, \"value\", null)").count(),
            1
        );
        assert!(lowered.contains("[method, __franken_parameter_decorator(0, parameter)]"));
    }

    #[test]
    fn computed_accessor_sites_are_distinct_and_keys_are_captured_once() {
        let lowered = lower(
            "class C { @getDec get [next()]() { return 1; } @setDec set [next()](value) {} }",
        )
        .unwrap();
        assert_eq!(lowered.matches("next()").count(), 2);
        assert!(lowered.contains("[__franken_decorator_key = (next())]"));
        assert_eq!(lowered.matches("], C.prototype,").count(), 2);
    }

    #[test]
    fn uninitialized_fields_do_not_consume_following_decorated_members() {
        let lowered = lower("class C {\n empty: number\n @mark method() {}\n @field other: number\n @last final() {}\n}").unwrap();
        assert!(lowered.contains("[mark], C.prototype, \"method\", null)"));
        assert!(lowered.contains("[field], C.prototype, \"other\", void 0)"));
        assert!(lowered.contains("[last], C.prototype, \"final\", null)"));
    }

    #[test]
    fn helpers_avoid_escaped_identifiers_and_preserve_directive_prologues() {
        let lowered = lower("'use strict'; const __applyClassDecorator = 1; const __applyClassDecorator_\\u0030 = 2; @d class C {}").unwrap();
        assert!(lowered.starts_with("'use strict';\nfunction __applyClassDecorator_1("));
        assert!(lowered.contains("__applyClassDecorator_1([d], C)"));
    }

    #[test]
    fn nested_local_classes_keep_separate_aliases_and_shadowed_names() {
        let lowered = lower("@dec class C { make() { @dec class C { self() { return C; } } return C; } shadow(C) { return C; } }").unwrap();
        assert!(lowered.contains("shadow(C) { return C; }"));
        assert_eq!(
            lowered
                .matches(" = __applyClassDecorator([dec], C)")
                .count(),
            2
        );
        assert!(lowered.contains("let __franken_decorated_class_"));
    }

    #[test]
    fn namespace_publication_follows_decorators_and_preserves_enum_order() {
        let source = "namespace N { export enum E { A = 1 } @dec export class C { self() { return C; } } step(); export namespace C { export const value = E.A; } }";
        let lowered = lower(source).unwrap();
        let lowered = namespaces::lower(&lowered, super::super::type_erasure::erase).unwrap();
        let application = lowered.find("__applyClassDecorator([dec], C)").unwrap();
        let publication = lowered.find(".C = C;").unwrap();
        let step = lowered.find("step();").unwrap();
        assert!(application < publication && publication < step);
        assert!(lowered.contains(".value = E.A;"));
    }

    #[test]
    fn exported_class_namespace_merge_does_not_duplicate_module_exports() {
        let lowered =
            lower("@dec export class C {} export namespace C { export const value = 1; }").unwrap();
        let lowered = namespaces::lower(&lowered, super::super::type_erasure::erase).unwrap();
        assert_eq!(lowered.matches("export { C }").count(), 1);
        assert!(!lowered.contains("var C;"));
    }

    #[test]
    fn generic_factory_arguments_and_parenthesized_expressions_are_retained() {
        let lowered =
            lower("@factory<Map<string, Box<number>>>() @(choose ? first : second) class C {}")
                .unwrap();
        assert!(
            lowered.contains("[factory<Map<string, Box<number>>>(), (choose ? first : second)]")
        );
    }

    #[test]
    fn invalid_targets_are_rejected_without_retargeting_erased_members() {
        for source in [
            "@dec function f() {}",
            "class C { @dec abstract missing(): void; next() {} }",
            "class C { @dec declare missing: number; next() {} }",
            "class C { @dec #private() {} }",
            "class C { @dec [key()] = 1; }",
            "class C { @dec accessor value = 1; }",
            "class C { @a get x() { return 1; } @b set x(value) {} }",
        ] {
            assert!(lower(source).is_err(), "accepted {source}");
        }
        assert_eq!(lower("@orphan"), Err(INVALID_TARGET));
        assert_eq!(lower("@\nclass C {}"), Err(INVALID_DECORATOR));
    }

    #[test]
    fn decorator_count_is_bounded_before_emission() {
        let source = format!("{} class C {{}}", "@d ".repeat(MAX_DECORATORS + 1));
        assert_eq!(lower(&source), Err("decorator count limit"));
    }
}
