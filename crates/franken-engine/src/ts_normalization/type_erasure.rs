//! Erase annotations only at binding/signature sites, never at runtime colons.
//!
//! This is the annotation pass, not a TypeScript type checker or an alternate
//! JavaScript parser. Unrecognized annotation sites and unbalanced delimiters
//! are retained for the ordinary parser. Tokens borrow the input; balanced
//! groups are indexed once; type-space contents are not semantically checked.
//! Replacing accepted type spans with whitespace retains their byte offsets and
//! line terminators. In particular, object properties, destructuring aliases,
//! labels, switch cases and conditional expressions are not annotation sites.

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

pub(super) fn erase(source: &str) -> String {
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
    eraser.erase_expression_types();
    eraser.finish()
}

struct Eraser<'a> {
    source: &'a str,
    tokens: Vec<Token<'a>>,
    pairs: Vec<Option<usize>>,
    removed: Vec<bool>,
    spans: Vec<(usize, usize)>,
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
                // Parameter-property lowering still owns these modifiers.
                while matches!(
                    self.text(cursor),
                    "public" | "private" | "protected" | "readonly" | "override"
                ) {
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
        if matches!(previous, "if" | "for" | "while" | "switch" | "with") {
            return;
        }
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
        if arrow && after != body
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
        if let Some(generic) = self.type_parameters_before(open) {
            if arrow || self.declared_function_before(open) {
                self.mark(generic, open);
            }
        }
        if after != body {
            self.mark(after, body);
        }
        self.bindings(open + 1, close, true);
    }

    fn class_fields(&mut self, index: usize) {
        let mut cursor = index + 1;
        if self.tokens.get(cursor).is_some_and(|token| token.kind == Kind::Word)
            && self.text(cursor) != "extends"
        {
            cursor += 1;
        }
        if self.text(cursor) == "<" {
            let Some(end) = self.angle_end(cursor) else {
                return;
            };
            self.mark(cursor, end);
            cursor = end;
        }
        if matches!(self.text(cursor), "extends" | "implements") {
            cursor += 1;
            while cursor < self.tokens.len() && self.text(cursor) != "{" {
                if matches!(self.text(cursor), ";" | "}") {
                    return;
                }
                cursor = self.group_end(cursor).unwrap_or(cursor + 1);
            }
        }
        if self.text(cursor) != "{" {
            return;
        }
        let Some(close) = self.pairs[cursor] else {
            return;
        };
        cursor += 1;
        while cursor < close {
            if self.text(cursor) == ";" {
                cursor += 1;
                continue;
            }
            while matches!(
                self.text(cursor),
                "public" | "private" | "protected" | "readonly" | "abstract" | "declare"
                    | "override" | "static" | "get" | "set" | "async"
            ) && !matches!(self.text(cursor + 1), ":" | "=" | ";" | "(" | "?")
            {
                if matches!(self.text(cursor), "public" | "private" | "protected" | "readonly" | "override") {
                    self.mark(cursor, cursor + 1);
                }
                cursor += 1;
            }
            if self.text(cursor) == "{" {
                // A static block, not an object-shaped field type.
                cursor = self.group_end(cursor).unwrap_or(close);
                continue;
            }
            if self.text(cursor) == "*" || self.text(cursor) == "#" {
                cursor += 1;
            }
            cursor = if self.text(cursor) == "[" {
                match self.group_end(cursor) {
                    Some(end) => end,
                    None => return,
                }
            } else if self.tokens.get(cursor).is_some_and(|token| token.kind != Kind::Punctuation) {
                cursor + 1
            } else {
                return;
            };
            if self.text(cursor) == "<" {
                let Some(end) = self.angle_end(cursor) else {
                    return;
                };
                if self.text(end) != "(" {
                    return;
                };
                self.mark(cursor, end);
                cursor = end;
            }
            let marker = cursor;
            if matches!(self.text(cursor), "?" | "!") {
                cursor += 1;
            }
            if self.text(cursor) == "(" {
                let Some(after_params) = self.group_end(cursor) else {
                    return;
                };
                cursor = after_params;
                if self.text(cursor) == ":" {
                    let Some(end) = self.type_end(cursor + 1, 0) else {
                        return;
                    };
                    cursor = end;
                }
                if self.text(cursor) == "{" {
                    cursor = self.group_end(cursor).unwrap_or(close);
                }
                continue;
            }
            if self.text(cursor) == ":" {
                let Some(end) = self.type_end(cursor + 1, 0) else {
                    return;
                };
                if end > close
                    || (end < close
                        && !matches!(self.text(end), "=" | ";" | "}")
                        && !self.newline_before(end))
                {
                    return;
                }
                self.mark(marker, end);
                cursor = end;
            }
            if self.text(cursor) == "=" {
                cursor = self.initializer_end(cursor + 1, close, true);
            } else if cursor == marker {
                // Untyped field without an initializer.
                if self.text(cursor) != ";" && cursor < close && !self.newline_before(cursor) {
                    return;
                }
            }
        }
    }

    fn newline_before(&self, index: usize) -> bool {
        if index == 0 || index >= self.tokens.len() {
            return false;
        }
        self.source[self.tokens[index - 1].end..self.tokens[index].start]
            .contains(['\n', '\r', '\u{2028}', '\u{2029}'])
    }

    fn initializer_end(&self, mut cursor: usize, end: usize, field: bool) -> usize {
        let start = cursor;
        while cursor < end {
            if matches!(self.text(cursor), "," | ";" | ")" | "}") {
                break;
            }
            if field && cursor > start && self.newline_before(cursor)
                && self.tokens[cursor].kind == Kind::Word
                && matches!(self.text(cursor + 1), ":" | "?" | "!" | "=" | "(")
                && !matches!(self.text(cursor - 1), "." | "?." | "?" | ":" | "=" | "=>")
            {
                break;
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
        while matches!(self.text(cursor), "keyof" | "readonly" | "unique" | "typeof" | "infer" | "abstract") {
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
                "any" | "unknown" | "number" | "bigint" | "boolean" | "string"
                    | "symbol" | "object" | "void" | "undefined" | "null" | "never"
                    | "true" | "false" | "this"
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
                "." if self.tokens.get(cursor + 1).is_some_and(|token| token.kind == Kind::Word) => {
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
            || name.checked_sub(1).is_some_and(|before| self.text(before) == "function")
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
            for ch in self.source[start..end].chars() {
                if matches!(ch, '\n' | '\r' | '\u{2028}' | '\u{2029}') {
                    output.push(ch);
                } else {
                    for _ in 0..ch.len_utf8() {
                        output.push(' ');
                    }
                }
            }
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
                if !matches!((tokens[open].text, token.text), ("(", ")") | ("[", "]") | ("{", "}")) {
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
    while cursor < source.len() {
        let ch = source[cursor..].chars().next()?;
        if ch.is_whitespace() || ch == '\u{feff}' {
            cursor += ch.len_utf8();
            continue;
        }
        if source[cursor..].starts_with("//") {
            cursor = line_comment_end(source, cursor + 2);
            continue;
        }
        if source[cursor..].starts_with("/*") {
            cursor += source[cursor + 2..].find("*/")? + 4;
            continue;
        }
        let start = cursor;
        let kind;
        if matches!(ch, '\'' | '"') {
            cursor = quoted_end(source, cursor, ch)?;
            kind = Kind::Literal;
        } else if ch == '`' {
            cursor = template_end(source, cursor, 0)?;
            kind = Kind::Literal;
        } else if ch == '/' && regex_allowed && regex_end(source, cursor).is_some() {
            cursor = regex_end(source, cursor)?;
            kind = Kind::Literal;
        } else if ch == '_' || ch == '$' || ch.is_alphabetic() {
            cursor += ch.len_utf8();
            while let Some(next) = source[cursor..].chars().next() {
                if next == '_' || next == '$' || next.is_alphanumeric() {
                    cursor += next.len_utf8();
                } else {
                    break;
                }
            }
            kind = Kind::Word;
        } else if ch.is_ascii_digit() {
            cursor += 1;
            while let Some(next) = source[cursor..].chars().next() {
                if next.is_ascii_alphanumeric()
                    || matches!(next, '.' | '_')
                    || (matches!(next, '+' | '-')
                        && matches!(source.as_bytes()[cursor - 1], b'e' | b'E'))
                {
                    cursor += 1;
                } else {
                    break;
                }
            }
            kind = Kind::Literal;
        } else {
            let width = ["...", "=>", "?.", "++", "--", "&&", "||", "??", "==", "!="]
                .into_iter()
                .find(|punct| source[cursor..].starts_with(*punct))
                .map_or(ch.len_utf8(), str::len);
            cursor += width;
            kind = Kind::Punctuation;
        }
        let text = &source[start..cursor];
        let previous = tokens.last().map_or("", |token| token.text);
        regex_allowed = if text == "(" {
            control_parens.push(matches!(previous, "if" | "while" | "for" | "with" | "switch" | "catch"));
            true
        } else if text == ")" {
            control_parens.pop().unwrap_or(false)
        } else {
            regex_may_follow(text, kind)
        };
        tokens.push(Token { text, start, end: cursor, kind });
    }
    Some(tokens)
}

fn regex_may_follow(text: &str, kind: Kind) -> bool {
    match kind {
        Kind::Literal => false,
        Kind::Word => matches!(text, "return" | "throw" | "case" | "delete" | "void" | "typeof" | "new" | "in" | "of" | "yield" | "await" | "else" | "do"),
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
            '\\' => { chars.next()?; }
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

/// Templates are opaque to this pass. Walk nested interpolation syntax only
/// to find the real closing backtick; never treat template text as declarations.
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
    while cursor < source.len() {
        let ch = source[cursor..].chars().next()?;
        if ch.is_whitespace() {
            cursor += ch.len_utf8();
            continue;
        }
        if source[cursor..].starts_with("//") {
            cursor = line_comment_end(source, cursor + 2);
            continue;
        }
        if source[cursor..].starts_with("/*") {
            cursor += source[cursor + 2..].find("*/")? + 4;
            continue;
        }
        match ch {
            '\'' | '"' => { cursor = quoted_end(source, cursor, ch)?; regex_allowed = false; }
            '`' => { cursor = template_end(source, cursor, depth)?; regex_allowed = false; }
            '/' if regex_allowed && regex_end(source, cursor).is_some() => {
                cursor = regex_end(source, cursor)?;
                regex_allowed = false;
            }
            '{' => { braces += 1; cursor += 1; regex_allowed = true; }
            '}' => {
                braces -= 1;
                cursor += 1;
                if braces == 0 { return Some(cursor); }
                regex_allowed = true;
            }
            _ if ch == '_' || ch == '$' || ch.is_alphabetic() => {
                let start = cursor;
                cursor += ch.len_utf8();
                while let Some(next) = source[cursor..].chars().next() {
                    if next == '_' || next == '$' || next.is_alphanumeric() { cursor += next.len_utf8(); }
                    else { break; }
                }
                regex_allowed = regex_may_follow(&source[start..cursor], Kind::Word);
            }
            _ => {
                cursor += ch.len_utf8();
                regex_allowed = !ch.is_ascii_digit() && !matches!(ch, ']' | '.');
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mark the exact erased spans. Everything else, including whitespace and
    // runtime colons, must remain byte-for-byte identical to the source.
    pub(super) fn check(marked: &str) {
        let mut source = String::new();
        let mut expected = String::new();
        let mut rest = marked;
        while let Some(open) = rest.find('⟦') {
            source.push_str(&rest[..open]);
            expected.push_str(&rest[..open]);
            rest = &rest[open + '⟦'.len_utf8()..];
            let close = rest.find('⟧').expect("closed test marker");
            let annotation = &rest[..close];
            source.push_str(annotation);
            for ch in annotation.chars() {
                if matches!(ch, '\n' | '\r' | '\u{2028}' | '\u{2029}') {
                    expected.push(ch);
                } else {
                    expected.extend(std::iter::repeat_n(' ', ch.len_utf8()));
                }
            }
            rest = &rest[close + '⟧'.len_utf8()..];
        }
        source.push_str(rest);
        expected.push_str(rest);
        assert_eq!(erase(&source), expected, "source: {source}");
        assert_eq!(source.len(), expected.len(), "erasure preserves byte offsets");
        assert_eq!(erase(&expected), expected, "erasure is idempotent");
    }

    #[test]
    fn generic_declaration_parameters_are_not_runtime_comparison_operators() {
        check("function identity⟦<T extends {value: number}>⟧(input⟦: T⟧)⟦: T⟧ { return input; }");
        check("const identity = ⟦<T>⟧(input⟦: T⟧)⟦: T⟧ => input;");
        check("class Box⟦<T>⟧ { value⟦: T⟧; choose⟦<U>⟧(value⟦: U⟧)⟦: U⟧ { return value; } }");
        check("const value = a < b > (c); const other = (a < b) ? c : d;");
        check("a < b > (c)\n{ work(); }");
    }

    #[test]
    fn class_access_modifiers_are_erased_but_runtime_modifiers_and_names_remain() {
        check("class Box { ⟦public⟧ ⟦readonly⟧ value⟦: number⟧ = 1; ⟦private⟧ run(x⟦: number⟧)⟦: number⟧ { return x; } }");
        check("class Box { static value⟦: number⟧ = 1; get count()⟦: number⟧ { return 1; } }");
        check("class Box { readonly⟦: number⟧ = 1; public⟦: number⟧ = 2; }");
    }

    #[test]
    fn variables_and_destructuring_erase_only_outer_annotations() {
        check("let a⟦: number⟧ = 1, b⟦: string | null⟧ = null;");
        check("const {left: a, right: b}⟦: {left: number; right: number}⟧ = {left: 1, right: 2};");
        check("const [head, ...tail]⟦: [number, ...number[]]⟧ = [1, 2, 3];");
        check("for (const entry⟦: number⟧ of entries) { const value⟦: number⟧ = entry; }");
    }

    #[test]
    fn initializers_keep_conditionals_objects_and_nested_callbacks() {
        check("const a⟦: number⟧ = yes ? first : second, b⟦: number⟧ = 4;");
        check("const o⟦: {value: number}⟧ = {value: yes ? 1 : 2};");
        check("const f = (x⟦: number⟧, o⟦: {value: number}⟧ = {value: 3})⟦: number⟧ => x + o.value;");
    }

    #[test]
    fn functions_methods_and_object_returns_keep_their_bodies() {
        check("function make(x⟦: number⟧)⟦: {value: number}⟧ { return {value: x}; }");
        check("const o = { run(x⟦: number⟧)⟦: number⟧ { return x ? 1 : 0; } };");
        check("const o = { 'run'(x⟦: number⟧)⟦: number⟧ { return x; } };");
        check("function* values(x⟦: number⟧)⟦: Iterable<number>⟧ { yield x; }");
        check("try { work(); } catch (error⟦: unknown⟧) { throw error; }");
    }

    #[test]
    fn higher_order_return_types_do_not_consume_the_runtime_arrow() {
        check("const make = ()⟦: ((x: number) => number)⟧ => x => x + 1;");
        check("const make = ()⟦: () => number⟧ => () => 3;");
        check("const invoke⟦: (x: number, rest: [number, number]) => number⟧ = (x, rest) => x;");
    }

    #[test]
    fn nested_type_arguments_tuples_and_conditional_types_are_whole_spans() {
        for ty in [
            "Record<string, Array<{value: number} | null>>",
            "readonly [first: number, second?: string]",
            "T extends U ? {yes: T} : {no: U}",
            "{ [K in keyof T]?: T[K] }",
            "keyof typeof object",
            "typeof import('package').Value",
            "new <T>(value: T) => {value: T}",
            "`prefix${number}`",
        ] {
            check(&format!("const value⟦: {ty}⟧ = original;"));
        }
    }

    #[test]
    fn receiver_and_optional_parameters_keep_runtime_arity() {
        check("function read(⟦this: {base: number},⟧ offset⟦?: number⟧)⟦: number⟧ { return this.base; }");
        check("function rest(first⟦?: number⟧, ...values⟦: number[]⟧) { return values; }");
        check("function receiverOnly(⟦this: object⟧) { return this; }");
    }

    #[test]
    fn class_fields_do_not_erase_runtime_object_properties() {
        check("class Box { value⟦: {count: number}⟧ = {count: 3}; run(x⟦: number⟧)⟦: number⟧ { return x; } }");
        check("class Box { missing⟦?: string⟧; assigned⟦!: number⟧; ['key']⟦: string⟧ = 'value'; }");
        check("class Box implements Contract { value⟦: number⟧ = 1; }");
        check("class Box { value⟦: number⟧ = 1\n other⟦: string⟧ = 'x'\n }");
    }

    #[test]
    fn runtime_colons_and_arrow_branches_remain_unchanged() {
        for source in [
            "const o = {left: 1, right: yes ? 2 : 3};",
            "const {left: renamed} = value;",
            "outer: for (;;) { break outer; }",
            "switch (value) { case 1: work(); break; default: stop(); }",
            "const choose = yes ? f(value) : other => other;",
            "const choose = yes ? (value) : other => other;",
            "const choose = yes ? first ? f(x) : g(x) : other => other;",
            "const o = {const: 1, let: 2, var: 3, class: 4};",
            "const f = (x = yes ? first : second) => ({value: x});",
        ] {
            check(source);
        }
    }

    #[test]
    fn strings_comments_and_regular_expressions_are_opaque() {
        check(r#"const label⟦: string⟧ = 'const x: T'; const pattern⟦: RegExp⟧ = /a:b[{}]/;"#);
        check("// const x: number;\nconst value⟦: number⟧ = 1; /* function f(x: T): U {} */");
        check(r#"if (ready) /const x: T/.test(text); const value⟦: number⟧ = 1;"#);
    }

    #[test]
    fn templates_preserve_nested_interpolations_and_raw_text() {
        check("const text⟦: string⟧ = `raw ${true ? 'a:b' : 'c:d'}: text`; ");
        check("const text⟦: string⟧ = `outer ${`inner ${true ? 1 : 2}`} done`; ");
        check("const text⟦: string⟧ = `${(a)/b/2}`;");
    }

    #[test]
    fn source_offsets_and_all_line_terminators_are_preserved() {
        check("const value⟦: {\r\n 名: 'é';\u{2028} ok: boolean\u{2029}}⟧ = {名: 'é', ok: true};");
        check("function identity(value⟦:\n number⟧)⟦:\n number⟧ { return value; }");
    }

    #[test]
    fn unbalanced_and_unrecognized_annotations_are_left_for_the_parser() {
        for source in [
            "const x: {value: number = 1;",
            "const x: number = 'unterminated",
            "const x: = 1;",
            "const x: ? = 1;",
            "const x: number /* unterminated",
            "const x: Array<number = 1;",
        ] {
            assert_eq!(erase(source), source);
        }
    }

    #[test]
    fn excessive_type_recursion_is_bounded_without_partial_type_removal() {
        let source = format!("const value: {}number = original;", "() => ".repeat(256));
        assert_eq!(erase(&source), source);
    }
}
