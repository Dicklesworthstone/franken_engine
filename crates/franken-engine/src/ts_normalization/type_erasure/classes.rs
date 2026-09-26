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
        Some(ClassHeader { body: cursor, erased })
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
                }) => cursor += 1,
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

}

#[cfg(test)]
mod tests {
    use super::super::tests::check;

    #[test]
    fn generic_heritage_finds_the_body_after_nested_types() {
        check("class Child extends Base⟦<number>⟧ { value⟦: number⟧ = 2; }");
        check("class Child⟦<T>⟧ extends Base⟦<{value: T}, readonly [number, string]>⟧ { value⟦: T⟧; }");
        check("class Child extends Base⟦<(x: number) => {result: string}>⟧ { run(x⟦: number⟧) { return x; } }");
    }

    #[test]
    fn implements_clauses_are_type_only_and_can_span_lines() {
        check("class Child ⟦implements Named, Store<{value: number}>⟧ { value⟦: number⟧ = 2; }");
        check("class Child extends Base⟦<number>⟧\n⟦implements\n Named,\n Store<{value: number}>⟧ { value⟦: number⟧ = 2; }");
        check("class Child ⟦implements 名称<{名: 'é'}>⟧ { value⟦: number⟧ = 2; }");
    }

    #[test]
    fn heritage_preserves_factory_calls_getters_and_computed_keys() {
        check("class Child extends mixin⟦<number>⟧(Base)⟦<{value: number}>⟧ { value⟦: number⟧ = 2; }");
        check("class Child extends namespace[key()]⟦<number>⟧ { run()⟦: number⟧ { return 1; } }");
        check("const Child = class extends (choose ? First : Second)⟦<number>⟧ { value⟦: number⟧ = 2; };");
    }

    #[test]
    fn class_atoms_in_heritage_do_not_steal_the_outer_body() {
        check("class Child extends class Base⟦<T>⟧ { inner⟦: number⟧ = 1; } { outer⟦: number⟧ = 2; }");
        check("class Child extends function Base() { this.inner = 1; } { outer⟦: number⟧ = 2; }");
        check("class Child extends null ⟦implements Named⟧ { value⟦: number⟧; }");
    }

    #[test]
    fn class_words_and_comparisons_outside_headers_remain_runtime_code() {
        check("object.class<Type>.value; object.extends<Type>.value;");
        check("const object = {class: 1, extends: 2, implements: 3};");
        check("class Child extends (a < b ? First : Second) { run() { return a < b > c; } }");
        check("class Child extends Base<Type + Other> { run() { return 1; } }");
        check("class Child extends Base<Type, , Other> { run() { return 1; } }");
    }

    #[test]
    fn template_and_literal_text_do_not_become_heritage_clauses() {
        check("const text = 'class Child extends Base<Type> implements Named {}';");
        check("const text = `class Child extends Base<Type> {}`;");
        check("const text = `${(class extends Base⟦<number>⟧ { value⟦: number⟧ = 2; }).name}`;");
    }
}
