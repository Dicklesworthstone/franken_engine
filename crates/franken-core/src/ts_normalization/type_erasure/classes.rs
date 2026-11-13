//! Class heritage and member types share the annotation eraser's token stream.
//!
//! Find the complete header before committing any erasure: `{` inside a base
//! type argument or implements type is not the class body. The base expression
//! itself is retained, including calls, computed keys and parenthesized code.

use super::{Eraser, Kind, MAX_TYPE_DEPTH};

struct ClassHeader {
    body: usize,
    erased: Vec<(usize, usize)>,
}

impl Eraser<'_> {
    fn class_header(&self, index: usize, depth: usize) -> Option<ClassHeader> {
        if depth >= MAX_TYPE_DEPTH || self.property_name(index) {
            return None;
        }
        let mut cursor = index + 1;
        let mut erased = Vec::new();
        if self.tokens.get(cursor)?.kind == Kind::Word
            && !matches!(self.text(cursor), "extends" | "implements")
        {
            cursor += 1;
        }
        if self.text(cursor) == "<" {
            let end = self.angle_end(cursor)?;
            erased.push((cursor, end));
            cursor = end;
        }
        if self.text(cursor) == "extends" {
            cursor = self.heritage_expression_end(cursor + 1, &mut erased, depth + 1)?;
        }
        if self.text(cursor) == "implements" {
            let start = cursor;
            loop {
                cursor = self.type_end(cursor + 1, 0)?;
                if self.text(cursor) != "," {
                    break;
                }
            }
            erased.push((start, cursor));
        }
        if self.text(cursor) != "{" || self.pairs[cursor].is_none() {
            return None;
        }
        Some(ClassHeader {
            body: cursor,
            erased,
        })
    }

    /// Parse the left-hand-side expression in an extends clause. Balanced
    /// runtime subexpressions remain opaque here; the ordinary expression
    /// pass handles their own types later. No base expression is evaluated,
    /// duplicated, parenthesized differently or replaced with a wrapper.
    fn heritage_expression_end(
        &self,
        mut cursor: usize,
        erased: &mut Vec<(usize, usize)>,
        depth: usize,
    ) -> Option<usize> {
        if depth >= MAX_TYPE_DEPTH {
            return None;
        }
        while self.text(cursor) == "new" {
            cursor += 1;
        }
        cursor = match self.text(cursor) {
            "(" => self.group_end(cursor)?,
            "class" => {
                // A nested class expression is an atom, not the outer body.
                // Its own iteration of the main pass owns its type erasure.
                let nested = self.class_header(cursor, depth + 1)?;
                self.group_end(nested.body)?
            }
            "function" => {
                cursor += 1;
                if self.text(cursor) == "*" {
                    cursor += 1;
                }
                if self.tokens.get(cursor)?.kind == Kind::Word {
                    cursor += 1;
                }
                if self.text(cursor) == "<" {
                    cursor = self.angle_end(cursor)?;
                }
                if self.text(cursor) != "(" {
                    return None;
                }
                cursor = self.group_end(cursor)?;
                if self.text(cursor) == ":" {
                    cursor = self.type_end(cursor + 1, 0)?;
                }
                if self.text(cursor) != "{" {
                    return None;
                }
                self.group_end(cursor)?
            }
            _ if matches!(self.tokens.get(cursor)?.kind, Kind::Word | Kind::Literal) => cursor + 1,
            _ => return None,
        };
        loop {
            match self.text(cursor) {
                "." => {
                    cursor += 1;
                    if self.text(cursor) == "#" {
                        cursor += 1;
                    }
                    if self.tokens.get(cursor)?.kind != Kind::Word {
                        return None;
                    }
                    cursor += 1;
                }
                "[" | "(" => cursor = self.group_end(cursor)?,
                "<" => {
                    let end = self.heritage_arguments_end(cursor)?;
                    erased.push((cursor, end));
                    cursor = end;
                }
                "!" => {
                    erased.push((cursor, cursor + 1));
                    cursor += 1;
                }
                _ if self.tokens.get(cursor).is_some_and(|token| {
                    token.kind == Kind::Literal && token.text.starts_with('`')
                }) =>
                {
                    cursor += 1
                }
                _ => return Some(cursor),
            }
        }
    }

    fn heritage_arguments_end(&self, open: usize) -> Option<usize> {
        let mut cursor = open + 1;
        loop {
            let end = self.type_end(cursor, 0)?;
            match self.text(end) {
                ">" => return Some(end + 1),
                "," => {
                    cursor = end + 1;
                    if self.text(cursor) == ">" {
                        return Some(cursor + 1);
                    }
                }
                _ => return None,
            }
        }
    }

    pub(super) fn class_fields(&mut self, index: usize) {
        let Some(header) = self.class_header(index, 0) else {
            return;
        };
        for (start, end) in header.erased {
            self.mark(start, end);
        }
        let mut cursor = header.body;
        let close = self.pairs[cursor].expect("validated class body");
        cursor += 1;
        while cursor < close {
            if self.text(cursor) == ";" {
                cursor += 1;
                continue;
            }
            let member_start = cursor;
            let mut type_only = false;
            while matches!(
                self.text(cursor),
                "public"
                    | "private"
                    | "protected"
                    | "readonly"
                    | "abstract"
                    | "declare"
                    | "override"
                    | "static"
                    | "get"
                    | "set"
                    | "async"
            ) && !matches!(
                self.text(cursor + 1),
                ":" | "=" | ";" | "(" | "?" | "!" | "<"
            ) {
                type_only |= matches!(self.text(cursor), "abstract" | "declare");
                if matches!(
                    self.text(cursor),
                    "public" | "private" | "protected" | "readonly" | "override"
                ) {
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
                // An index signature declares a type, not a computed key.
                // Only `[name: Type]` qualifies; runtime conditionals, symbol
                // accesses and key-producing calls must remain executable.
                type_only |= self.class_index_signature(cursor);
                match self.group_end(cursor) {
                    Some(end) => end,
                    None => return,
                }
            } else if self
                .tokens
                .get(cursor)
                .is_some_and(|token| token.kind != Kind::Punctuation)
            {
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
                    // Never erase an implementation body, even when invalid
                    // input prefixes it with abstract/declare. Leave those
                    // keywords for the ordinary parser to reject.
                    cursor = self.group_end(cursor).unwrap_or(close);
                } else if let Some(end) = self.class_declaration_end(cursor, close) {
                    // Constructor/method overloads and abstract accessors have
                    // no runtime slot, function object or argument evaluation.
                    self.mark(member_start, end);
                    cursor = end;
                } else {
                    return;
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
            if type_only && let Some(end) = self.class_declaration_end(cursor, close) {
                self.mark(member_start, end);
                cursor = end;
                continue;
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

    fn class_index_signature(&self, open: usize) -> bool {
        let Some(close) = self.pairs[open] else {
            return false;
        };
        self.tokens
            .get(open + 1)
            .is_some_and(|token| token.kind == Kind::Word)
            && self.text(open + 2) == ":"
            && self.type_end(open + 3, 0) == Some(close)
    }

    fn class_declaration_end(&self, cursor: usize, close: usize) -> Option<usize> {
        if cursor > close {
            return None;
        }
        if self.text(cursor) == ";" {
            return Some(cursor + 1);
        }
        if cursor == close
            || (self.newline_before(cursor)
                && (self.tokens[cursor].kind != Kind::Punctuation
                    || matches!(self.text(cursor), "[" | "*" | "#")))
        {
            Some(cursor)
        } else {
            None
        }
    }
}
