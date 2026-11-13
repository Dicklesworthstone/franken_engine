//! Erase annotations only at binding/signature sites, never at runtime colons.
//!
//! This is the annotation pass, not a TypeScript type checker or an alternate
//! JavaScript parser. Unrecognized annotation sites and unbalanced delimiters
//! are retained for the ordinary parser. Tokens borrow the input; balanced
//! groups are indexed once; type-space contents are not semantically checked.
//! Replacing accepted type spans with whitespace retains their byte offsets and
//! line terminators. In particular, object properties, destructuring aliases,
//! labels, switch cases and conditional expressions are not annotation sites.

mod classes;
mod expressions;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Word,
    Literal,
    Punctuation,
}

#[derive(Clone, Copy, Debug)]
struct Token<'a> {
    text: &'a str,
    start: usize,
    end: usize,
    kind: Kind,
}

const MAX_TYPE_DEPTH: usize = 128;

/// Erase recognized type-only syntax while preserving runtime bytes and source offsets.
pub fn erase(source: &str) -> String {
    let Some(eraser) = analyze(source, 0) else {
        return source.to_owned();
    };
    eraser.finish()
}

/// Erase TypeScript's prefix type assertions (`<T>value`), syntax only a
/// `.ts` file has: in a `.tsx` file the same text is a JSX element
/// (bd-9vouw.426). A generic arrow function (`<T>(x: T) => x`) is left to
/// [`erase`], as is everything else.
pub fn erase_angle_assertions(source: &str) -> String {
    let Some(tokens) = tokenize(source) else {
        return source.to_owned();
    };
    let Some(pairs) = delimiter_pairs(&tokens) else {
        return source.to_owned();
    };
    let mut eraser = Eraser {
        source,
        removed: vec![false; tokens.len()],
        tokens,
        pairs,
        spans: Vec::new(),
        module_marker: None,
    };
    eraser.erase_prefix_assertions();
    eraser.finish()
}

fn analyze(source: &str, depth: usize) -> Option<Eraser<'_>> {
    if depth >= MAX_TYPE_DEPTH {
        return None;
    }
    let tokens = tokenize(source)?;
    let pairs = delimiter_pairs(&tokens)?;
    let mut eraser = Eraser {
        source,
        removed: vec![false; tokens.len()],
        tokens,
        pairs,
        spans: Vec::new(),
        module_marker: None,
    };
    // Track runtime conditional operators at each delimiter depth. A colon
    // after a parenthesized/call expression in a conditional can introduce an
    // arrow *branch*, not a return annotation: `yes ? f(x) : value => value`.
    let mut conditionals = vec![0usize];
    for index in 0..eraser.tokens.len() {
        if eraser.removed[index] {
            continue;
        }
        match eraser.text(index) {
            "const" | "let" | "var" if !eraser.property_name(index) => {
                eraser.bindings(index + 1, eraser.tokens.len(), false);
            }
            "(" => {
                eraser.signature(index, conditionals.last().copied().unwrap_or(0) != 0);
                conditionals.push(0);
            }
            "[" | "{" => conditionals.push(0),
            ")" | "]" | "}" => {
                if conditionals.len() > 1 {
                    conditionals.pop();
                }
            }
            "?" => *conditionals.last_mut().expect("root conditional scope") += 1,
            ":" => {
                let pending = conditionals.last_mut().expect("root conditional scope");
                *pending = pending.saturating_sub(1);
            }
            ";" => *conditionals.last_mut().expect("root conditional scope") = 0,
            "class" if !eraser.property_name(index) => eraser.class_fields(index),
            _ => {}
        }
    }
    eraser.erase_expression_types(depth == 0);
    eraser.erase_template_expressions(depth);
    Some(eraser)
}

struct Eraser<'a> {
    source: &'a str,
    tokens: Vec<Token<'a>>,
    pairs: Vec<Option<usize>>,
    removed: Vec<bool>,
    spans: Vec<(usize, usize)>,
    // An erased exported declaration must still make the output a module.
    // Emit one empty export inside its original span, retaining byte offsets.
    module_marker: Option<usize>,
}

impl Eraser<'_> {
    fn text(&self, index: usize) -> &str {
        self.tokens.get(index).map_or("", |token| token.text)
    }

    fn property_name(&self, index: usize) -> bool {
        index > 0 && matches!(self.text(index - 1), "." | "?.")
    }

    fn group_end(&self, index: usize) -> Option<usize> {
        match self.text(index) {
            "(" | "[" | "{" => self.pairs.get(index).copied().flatten().map(|end| end + 1),
            _ => None,
        }
    }

    fn mark(&mut self, start: usize, end: usize) {
        if start >= end || end > self.tokens.len() {
            return;
        }
        self.spans
            .push((self.tokens[start].start, self.tokens[end - 1].end));
        self.removed[start..end].fill(true);
    }

    /// Parameters and variable declarators share BindingPattern, but a colon
    /// *inside* a destructuring pattern denotes a runtime alias, not a type.
    fn binding_end(&self, index: usize) -> Option<usize> {
        if matches!(self.text(index), "[" | "{") {
            self.group_end(index)
        } else if self.tokens.get(index)?.kind == Kind::Word {
            Some(index + 1)
        } else {
            None
        }
    }

    fn bindings(&mut self, mut cursor: usize, end: usize, parameters: bool) {
        let first = cursor;
        while cursor < end {
            let start = cursor;
            if parameters {
                if self.text(cursor) == "..." {
                    cursor += 1;
                }
                // Parameter-property lowering still owns these modifiers. A
                // modifier word followed by no binding is the parameter's
                // own name (`override: unknown`, bd-9vouw.435).
                while matches!(
                    self.text(cursor),
                    "public" | "private" | "protected" | "readonly" | "override"
                ) && (self
                    .tokens
                    .get(cursor + 1)
                    .is_some_and(|token| token.kind == Kind::Word)
                    || matches!(self.text(cursor + 1), "{" | "["))
                {
                    cursor += 1;
                }
            }
            let binding = cursor;
            let Some(after_binding) = self.binding_end(cursor) else {
                return;
            };
            if after_binding > end {
                return;
            }
            cursor = after_binding;
            let optional = parameters && self.text(cursor) == "?";
            let annotation = cursor + usize::from(optional);
            if self.text(annotation) == ":" {
                let Some(after_type) = self.type_end(annotation + 1, 0) else {
                    return;
                };
                if after_type > end
                    || (after_type < end
                        && !matches!(self.text(after_type), "=" | "," | ";" | "in" | "of" | ")")
                        && !self.newline_before(after_type))
                {
                    return;
                }
                if parameters && self.text(binding) == "this" {
                    // TypeScript's receiver parameter is not a JavaScript
                    // formal parameter. It can only occur first.
                    if start != first || start != binding {
                        return;
                    }
                    let after_receiver = after_type + usize::from(self.text(after_type) == ",");
                    self.mark(start, after_receiver);
                    cursor = after_receiver;
                    continue;
                }
                self.mark(cursor, after_type);
                cursor = after_type;
            } else if optional && matches!(self.text(annotation), "," | ")" | "=") {
                self.mark(cursor, annotation);
                cursor = annotation;
            }
            if self.text(cursor) == "=" {
                cursor = self.initializer_end(cursor + 1, end, false);
            }
            if self.text(cursor) != "," {
                return;
            }
            cursor += 1;
        }
    }

    /// A formal parameter list is recognized from its following body/arrow,
    /// not from a colon inside arbitrary parentheses. Control-flow heads and
    /// ordinary calls must not erase conditionals or named object arguments.
    fn signature(&mut self, open: usize, conditional: bool) {
        let Some(close) = self.pairs[open] else {
            return;
        };
        let previous = open.checked_sub(1).map_or("", |index| self.text(index));
        if matches!(previous, "if" | "for" | "while" | "switch" | "with")
            && self.text(close + 1) != ":"
            && !self.parameters_have_annotation(open + 1, close)
        {
            return;
        }
        // Reserved words are valid method names. A parameter/return type
        // distinguishes a typed `if(value: T): U { ... }` method from a real
        // control-flow head. The body check below still owns signature
        // admission; a conditional inside `if (x ? y : z)` is not a type.
        let after = close + 1;
        let mut body = after;
        if self.text(after) == ":" {
            if conditional
                && !self.declared_function_before(open)
                && !self.parameters_have_annotation(open + 1, close)
            {
                // An untyped parenthesized/call expression followed by a
                // colon can be a runtime branch, not a return annotation.
                return;
            }
            let Some(end) = self.type_end(after + 1, 0) else {
                return;
            };
            body = end;
        }
        let arrow = self.text(body) == "=>";
        if arrow
            && after != body
            && open.checked_sub(1).is_some_and(|index| {
                (self.tokens[index].kind != Kind::Punctuation && previous != "async")
                    || matches!(previous, ")" | "]")
            })
        {
            return;
        }
        let named = matches!(previous, "function" | "*" | "]" | ">")
            || open.checked_sub(1).is_some_and(|index| {
                matches!(self.tokens[index].kind, Kind::Word | Kind::Literal)
                    && !matches!(previous, "return" | "throw" | "yield" | "await" | "new")
            });
        if !arrow && !(named && self.text(body) == "{") {
            return;
        }
        if let Some(generic) = self.type_parameters_before(open)
            && (arrow || self.declared_function_before(open))
        {
            self.mark(generic, open);
        }
        if after != body {
            self.mark(after, body);
        }
        self.bindings(open + 1, close, true);
    }

    fn newline_before(&self, index: usize) -> bool {
        if index == 0 || index >= self.tokens.len() {
            return false;
        }
        self.source[self.tokens[index - 1].end..self.tokens[index].start]
            .contains(['\n', '\r', '\u{2028}', '\u{2029}'])
    }

    /// Whether the word at `index` is a class member modifier followed by
    /// the member it modifies (a name, `[`, `#`, `*`, or `{` after `static`).
    fn member_modifier_at(&self, index: usize) -> bool {
        matches!(
            self.text(index),
            "public"
                | "private"
                | "protected"
                | "readonly"
                | "static"
                | "declare"
                | "abstract"
                | "override"
                | "async"
                | "get"
                | "set"
                | "accessor"
        ) && (self
            .tokens
            .get(index + 1)
            .is_some_and(|token| token.kind == Kind::Word)
            || matches!(self.text(index + 1), "[" | "#" | "*")
            || (self.text(index) == "static" && self.text(index + 1) == "{"))
    }

    fn initializer_end(&self, mut cursor: usize, end: usize, field: bool) -> usize {
        let start = cursor;
        while cursor < end {
            if matches!(self.text(cursor), "," | ";" | ")" | "}") {
                break;
            }
            // A line starting the next member ends a field's initializer
            // (ASI): `name:`, `name =`, `name(`, or a modifier before a
            // member name (`private busy: boolean = false`, `static count
            // = 0`, `protected get total()`). The modifier form was read
            // as part of the initializer above it, so its modifier was
            // never erased (bd-9vouw.432).
            if field
                && cursor > start
                && self.newline_before(cursor)
                && self.tokens[cursor].kind == Kind::Word
                && (matches!(self.text(cursor + 1), ":" | "?" | "!" | "=" | "(")
                    || self.member_modifier_at(cursor))
                && !matches!(self.text(cursor - 1), "." | "?." | "?" | ":" | "=" | "=>")
            {
                break;
            }
            // A call's type arguments (`new Map<K, V>()`) hold commas that do
            // not end the initializer; the expression pass erases them later
            // (bd-9vouw.432).
            if field
                && self.text(cursor) == "<"
                && let Some(after) = self.expression_type_arguments_end(cursor)
                && self.text(after) == "("
            {
                cursor = after;
                continue;
            }
            cursor = self.group_end(cursor).unwrap_or(cursor + 1);
        }
        cursor
    }

    /// Parse just enough type grammar to find its end. Commas inside type
    /// arguments, object/tuple members, and function parameters stay inside
    /// their balanced group; a union is never truncated at its first member.
    fn type_end(&self, start: usize, depth: usize) -> Option<usize> {
        if depth >= MAX_TYPE_DEPTH {
            return None;
        }
        let mut cursor = self.union_end(start, depth + 1)?;
        if self.text(cursor) == "extends" {
            cursor = self.union_end(cursor + 1, depth + 1)?;
            if self.text(cursor) != "?" {
                return None;
            }
            cursor = self.type_end(cursor + 1, depth + 1)?;
            if self.text(cursor) != ":" {
                return None;
            }
            cursor = self.type_end(cursor + 1, depth + 1)?;
        }
        Some(cursor)
    }

    fn union_end(&self, mut cursor: usize, depth: usize) -> Option<usize> {
        if depth >= MAX_TYPE_DEPTH {
            return None;
        }
        if matches!(self.text(cursor), "|" | "&") {
            cursor += 1;
        }
        cursor = self.primary_end(cursor, depth + 1)?;
        while matches!(self.text(cursor), "|" | "&") {
            cursor = self.primary_end(cursor + 1, depth + 1)?;
        }
        Some(cursor)
    }

    fn primary_end(&self, mut cursor: usize, depth: usize) -> Option<usize> {
        if depth >= MAX_TYPE_DEPTH {
            return None;
        }
        while matches!(
            self.text(cursor),
            "keyof" | "readonly" | "unique" | "typeof" | "infer" | "abstract"
        ) {
            cursor += 1;
        }
        if self.text(cursor) == "asserts" {
            cursor += 1;
            if self.tokens.get(cursor)?.kind != Kind::Word {
                return None;
            }
            cursor += 1;
            return if self.text(cursor) == "is" {
                self.type_end(cursor + 1, depth + 1)
            } else {
                Some(cursor)
            };
        }
        if self.text(cursor) == "new" {
            cursor += 1;
        }
        if self.text(cursor) == "<" {
            cursor = self.angle_end(cursor)?;
        }
        if matches!(self.text(cursor), "-" | "+") {
            cursor += 1;
            if self.tokens.get(cursor)?.kind != Kind::Literal {
                return None;
            }
        }
        let token = self.tokens.get(cursor)?;
        let mut type_arguments = token.kind == Kind::Word
            && !matches!(
                token.text,
                "any"
                    | "unknown"
                    | "number"
                    | "bigint"
                    | "boolean"
                    | "string"
                    | "symbol"
                    | "object"
                    | "void"
                    | "undefined"
                    | "null"
                    | "never"
                    | "true"
                    | "false"
                    | "this"
            );
        let function_parameters = token.text == "(" && self.type_parameter_list(cursor, depth + 1);
        if matches!(token.text, "(" | "[" | "{") {
            cursor = self.group_end(cursor)?;
        } else if token.kind == Kind::Word || token.kind == Kind::Literal {
            cursor += 1;
            if token.text == "import" && self.text(cursor) == "(" {
                cursor = self.group_end(cursor)?;
            }
        } else {
            return None;
        }
        loop {
            match self.text(cursor) {
                "." if self
                    .tokens
                    .get(cursor + 1)
                    .is_some_and(|token| token.kind == Kind::Word) =>
                {
                    cursor += 2;
                    type_arguments = true;
                }
                "<" if type_arguments => {
                    // In an expression assertion, an unmatched `<` starts a
                    // runtime comparison, not a type-argument list. Binding
                    // annotations still reject this boundary at their caller.
                    let Some(end) = self.angle_end(cursor) else {
                        break;
                    };
                    cursor = end;
                    type_arguments = false;
                }
                "[" => {
                    cursor = self.group_end(cursor)?;
                    type_arguments = false;
                }
                _ => break,
            }
        }
        if self.text(cursor) == "is" || (function_parameters && self.text(cursor) == "=>") {
            cursor = self.type_end(cursor + 1, depth + 1)?;
        }
        Some(cursor)
    }

    /// A parenthesized type is not automatically a function parameter list.
    /// In `(): ((x: T) => U) => x => x`, consuming the outer runtime arrow
    /// as part of the return type would silently delete a returned closure.
    fn type_parameter_list(&self, open: usize, depth: usize) -> bool {
        if depth >= MAX_TYPE_DEPTH {
            return false;
        }
        let Some(close) = self.pairs[open] else {
            return false;
        };
        let mut cursor = open + 1;
        while cursor < close {
            if self.text(cursor) == "..." {
                cursor += 1;
            }
            let Some(end) = self.binding_end(cursor) else {
                return false;
            };
            cursor = end;
            if self.text(cursor) == "?" {
                cursor += 1;
            }
            if self.text(cursor) == ":" {
                let Some(end) = self.type_end(cursor + 1, depth + 1) else {
                    return false;
                };
                cursor = end;
            }
            if cursor == close {
                return true;
            }
            if cursor > close || self.text(cursor) != "," {
                return false;
            }
            cursor += 1;
        }
        cursor == close
    }

    fn declared_function_before(&self, open: usize) -> bool {
        let before_parameters = self.type_parameters_before(open).unwrap_or(open);
        let Some(name) = before_parameters.checked_sub(1) else {
            return false;
        };
        self.text(name) == "function"
            || name
                .checked_sub(1)
                .is_some_and(|before| self.text(before) == "function")
            || (name >= 2 && self.text(name - 1) == "*" && self.text(name - 2) == "function")
    }

    fn parameters_have_annotation(&self, mut cursor: usize, close: usize) -> bool {
        while cursor < close {
            if self.text(cursor) == "..." {
                cursor += 1;
            }
            let Some(end) = self.binding_end(cursor) else {
                return false;
            };
            cursor = end;
            if self.text(cursor) == "?" {
                cursor += 1;
            }
            if self.text(cursor) == ":" {
                return true;
            }
            if self.text(cursor) == "=" {
                cursor = self.initializer_end(cursor + 1, close, false);
            }
            if self.text(cursor) != "," {
                return false;
            }
            cursor += 1;
        }
        false
    }

    fn type_parameters_before(&self, open: usize) -> Option<usize> {
        let mut cursor = open.checked_sub(1)?;
        if self.text(cursor) != ">" {
            return None;
        }
        let mut depth = 0usize;
        loop {
            match self.text(cursor) {
                ">" => depth += 1,
                "<" => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return Some(cursor);
                    }
                }
                ")" | "]" | "}" => cursor = self.pairs[cursor]?,
                ";" => return None,
                _ => {}
            }
            cursor = cursor.checked_sub(1)?;
        }
    }

    fn angle_end(&self, start: usize) -> Option<usize> {
        let mut depth = 0usize;
        let mut cursor = start;
        while cursor < self.tokens.len() {
            match self.text(cursor) {
                "<" => depth += 1,
                ">" => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return Some(cursor + 1);
                    }
                }
                ";" => return None,
                _ => {}
            }
            cursor = self.group_end(cursor).unwrap_or(cursor + 1);
        }
        None
    }

    fn finish(mut self) -> String {
        if self.spans.is_empty() {
            return self.source.to_owned();
        }
        self.spans.sort_unstable();
        let mut output = String::with_capacity(self.source.len());
        let mut copied = 0;
        for (start, end) in self.spans {
            if end <= copied {
                continue;
            }
            let start = start.max(copied);
            output.push_str(&self.source[copied..start]);
            let mut marker = if self.module_marker == Some(start) {
                "export{};"
            } else {
                ""
            }
            .chars();
            for ch in self.source[start..end].chars() {
                if matches!(ch, '\n' | '\r' | '\u{2028}' | '\u{2029}') {
                    output.push(ch);
                } else {
                    for _ in 0..ch.len_utf8() {
                        output.push(marker.next().unwrap_or(' '));
                    }
                }
            }
            debug_assert!(marker.next().is_none(), "declaration fits empty export");
            copied = end;
        }
        output.push_str(&self.source[copied..]);
        output
    }
}

fn delimiter_pairs(tokens: &[Token<'_>]) -> Option<Vec<Option<usize>>> {
    let mut result = vec![None; tokens.len()];
    let mut stack = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        match token.text {
            "(" | "[" | "{" => stack.push(index),
            ")" | "]" | "}" => {
                let open = stack.pop()?;
                if !matches!(
                    (tokens[open].text, token.text),
                    ("(", ")") | ("[", "]") | ("{", "}")
                ) {
                    return None;
                }
                result[open] = Some(index);
                result[index] = Some(open);
            }
            _ => {}
        }
    }
    stack.is_empty().then_some(result)
}

fn tokenize(source: &str) -> Option<Vec<Token<'_>>> {
    let mut tokens: Vec<Token<'_>> = Vec::new();
    let mut cursor = 0;
    let mut regex_allowed = true;
    let mut control_parens = Vec::new();
    let mut previous = "";
    let mut before_previous = "";
    while let Some(token) = next_token(source, &mut cursor, regex_allowed, 0)? {
        regex_allowed = regex_after_token(&token, previous, before_previous, &mut control_parens);
        before_previous = previous;
        previous = token.text;
        tokens.push(token);
    }
    Some(tokens)
}

// Some(None) is clean EOF; None is malformed lexical input. Both the outer
// token stream and interpolation-boundary scanner use this one lexer so a
// division after `)` cannot become a regex swallowing `}` and template text.
fn next_token<'a>(
    source: &'a str,
    cursor: &mut usize,
    regex_allowed: bool,
    depth: usize,
) -> Option<Option<Token<'a>>> {
    while *cursor < source.len() {
        let ch = source[*cursor..].chars().next()?;
        if ch.is_whitespace() || ch == '\u{feff}' {
            *cursor += ch.len_utf8();
            continue;
        }
        if source[*cursor..].starts_with("//") {
            *cursor = line_comment_end(source, *cursor + 2);
            continue;
        }
        if source[*cursor..].starts_with("/*") {
            *cursor += source[*cursor + 2..].find("*/")? + 4;
            continue;
        }
        let start = *cursor;
        let kind = if matches!(ch, '\'' | '"') {
            *cursor = quoted_end(source, *cursor, ch)?;
            Kind::Literal
        } else if ch == '`' {
            *cursor = template_end(source, *cursor, depth)?;
            Kind::Literal
        } else if ch == '/' && regex_allowed && regex_end(source, *cursor).is_some() {
            *cursor = regex_end(source, *cursor)?;
            Kind::Literal
        } else if ch == '_' || ch == '$' || ch.is_alphabetic() {
            *cursor += ch.len_utf8();
            while let Some(next) = source[*cursor..].chars().next() {
                if next == '_' || next == '$' || next.is_alphanumeric() {
                    *cursor += next.len_utf8();
                } else {
                    break;
                }
            }
            Kind::Word
        } else if ch.is_ascii_digit() {
            *cursor += 1;
            while let Some(next) = source[*cursor..].chars().next() {
                if next.is_ascii_alphanumeric()
                    || matches!(next, '.' | '_')
                    || (matches!(next, '+' | '-')
                        && matches!(source.as_bytes()[*cursor - 1], b'e' | b'E'))
                {
                    *cursor += 1;
                } else {
                    break;
                }
            }
            Kind::Literal
        } else {
            let width = ["...", "=>", "?.", "++", "--", "&&", "||", "??", "==", "!="]
                .into_iter()
                .find(|punct| source[*cursor..].starts_with(*punct))
                .map_or(ch.len_utf8(), str::len);
            *cursor += width;
            Kind::Punctuation
        };
        return Some(Some(Token {
            text: &source[start..*cursor],
            start,
            end: *cursor,
            kind,
        }));
    }
    Some(None)
}

fn regex_after_token(
    token: &Token<'_>,
    previous: &str,
    before_previous: &str,
    control_parens: &mut Vec<bool>,
) -> bool {
    if token.text == "(" {
        control_parens.push(
            !matches!(before_previous, "." | "?.")
                && matches!(
                    previous,
                    "if" | "while" | "for" | "with" | "switch" | "catch"
                ),
        );
        true
    } else if token.text == ")" {
        control_parens.pop().unwrap_or(false)
    } else {
        regex_may_follow(token.text, token.kind)
    }
}

fn regex_may_follow(text: &str, kind: Kind) -> bool {
    match kind {
        Kind::Literal => false,
        Kind::Word => matches!(
            text,
            "return"
                | "throw"
                | "case"
                | "delete"
                | "void"
                | "typeof"
                | "new"
                | "in"
                | "of"
                | "yield"
                | "await"
                | "else"
                | "do"
        ),
        Kind::Punctuation => !matches!(text, "]" | ")" | "." | "?." | "++" | "--"),
    }
}

fn line_comment_end(source: &str, start: usize) -> usize {
    source[start..]
        .find(['\n', '\r', '\u{2028}', '\u{2029}'])
        .map_or(source.len(), |offset| start + offset)
}

fn quoted_end(source: &str, start: usize, quote: char) -> Option<usize> {
    let mut chars = source[start + quote.len_utf8()..].char_indices();
    while let Some((offset, ch)) = chars.next() {
        if ch == '\\' {
            chars.next()?;
        } else if ch == quote {
            return Some(start + quote.len_utf8() + offset + ch.len_utf8());
        } else if matches!(ch, '\n' | '\r') {
            return None;
        }
    }
    None
}

fn regex_end(source: &str, start: usize) -> Option<usize> {
    let mut class = false;
    let mut chars = source[start + 1..].char_indices();
    while let Some((offset, ch)) = chars.next() {
        match ch {
            '\\' => {
                chars.next()?;
            }
            '[' => class = true,
            ']' => class = false,
            '\n' | '\r' | '\u{2028}' | '\u{2029}' => return None,
            '/' if !class => {
                let mut end = start + offset + 2;
                while let Some(flag) = source[end..].chars().next() {
                    if !flag.is_alphabetic() {
                        break;
                    }
                    end += flag.len_utf8();
                }
                return Some(end);
            }
            _ => {}
        }
    }
    None
}

/// Lexing keeps templates as opaque tokens. Walk nested interpolation syntax
/// to find the real closing backtick; the transform visits expressions later.
fn template_end(source: &str, start: usize, depth: usize) -> Option<usize> {
    if depth >= MAX_TYPE_DEPTH {
        return None;
    }
    let mut cursor = start + 1;
    while cursor < source.len() {
        let ch = source[cursor..].chars().next()?;
        if ch == '\\' {
            cursor += 1;
            cursor += source[cursor..].chars().next()?.len_utf8();
        } else if ch == '`' {
            return Some(cursor + 1);
        } else if source[cursor..].starts_with("${") {
            cursor = interpolation_end(source, cursor + 2, depth + 1)?;
        } else {
            cursor += ch.len_utf8();
        }
    }
    None
}

fn interpolation_end(source: &str, mut cursor: usize, depth: usize) -> Option<usize> {
    let mut braces = 1usize;
    let mut regex_allowed = true;
    let mut control_parens = Vec::new();
    let mut previous = "";
    let mut before_previous = "";
    while let Some(token) = next_token(source, &mut cursor, regex_allowed, depth)? {
        match token.text {
            "{" => braces += 1,
            "}" => {
                braces -= 1;
                if braces == 0 {
                    return Some(cursor);
                }
            }
            _ => {}
        }
        regex_allowed = regex_after_token(&token, previous, before_previous, &mut control_parens);
        before_previous = previous;
        previous = token.text;
    }
    None
}
