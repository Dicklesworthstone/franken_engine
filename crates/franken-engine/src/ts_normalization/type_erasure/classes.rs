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
            let member_start = cursor;
            let mut type_only = false;
            while matches!(
                self.text(cursor),
                "public" | "private" | "protected" | "readonly" | "abstract" | "declare"
                    | "override" | "static" | "get" | "set" | "async"
            ) && !matches!(self.text(cursor + 1), ":" | "=" | ";" | "(" | "?" | "!" | "<")
            {
                type_only |= matches!(self.text(cursor), "abstract" | "declare");
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
                // An index signature declares a type, not a computed key.
                // Only `[name: Type]` qualifies; runtime conditionals, symbol
                // accesses and key-producing calls must remain executable.
                type_only |= self.class_index_signature(cursor);
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
        self.tokens.get(open + 1).is_some_and(|token| token.kind == Kind::Word)
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

#[cfg(test)]
mod tests {
    use super::super::tests::check;

    #[test]
    fn overload_signatures_are_erased_without_replacing_implementations() {
        check("class C { ⟦constructor(value: number);⟧ constructor(value⟦: number | string⟧) { this.value = value; } }");
        check("class C { ⟦run(value: number): number;⟧ ⟦run(value: string): string;⟧ run(value⟦: unknown⟧) { return value; } }");
        check("class C { ⟦static choose<T>(value: T): T;⟧ static choose(value⟦: unknown⟧) { return value; } }");
    }

    #[test]
    fn semicolonless_signatures_stop_at_the_next_member() {
        check("class C { ⟦run(value: number): number⟧\nrun(value⟦: unknown⟧) { return value; } }");
        check("class C { ⟦declare value: number⟧\nrun() { return 2; } }");
        check("class C { ⟦abstract read(): number⟧ }");
    }

    #[test]
    fn abstract_and_declared_members_create_no_runtime_properties() {
        check("abstract class C { ⟦abstract run(value: number): number;⟧ ⟦abstract get size(): number;⟧ ⟦abstract set size(value: number);⟧ }");
        check("class C { ⟦declare value: number;⟧ ⟦declare readonly missing?: string;⟧ ⟦declare static count: number;⟧ }");
        check("abstract class C { ⟦protected abstract readonly value: {count: number};⟧ run() { return 1; } }");
    }

    #[test]
    fn index_signatures_are_not_computed_runtime_keys() {
        check("class C { ⟦[key: string]: number;⟧ ⟦readonly [key: symbol]: unknown;⟧ run() { return 1; } }");
        check("class C { [Symbol.iterator]() { return iterator; } [key()]⟦: number⟧ = value; }");
        check("class C { [(ready ? first : second)]⟦: number⟧ = value; }");
    }

    #[test]
    fn contextual_modifier_names_with_bodies_remain_runtime_members() {
        check("class C { abstract⟦<T>⟧(value⟦: T⟧)⟦: T⟧ { return value; } declare() { return 2; } }");
        check("class C { abstract⟦: number⟧ = 1; declare⟦: number⟧ = 2; get readonly() { return 3; } }");
        check("class C { ⟦public⟧ abstract() { return 1; } ⟦private⟧ declare() { return 2; } }");
    }

    #[test]
    fn runtime_method_bodies_and_static_blocks_are_never_signature_lists() {
        check("class C { run() { call(); nested.call(); } static { call(); } }");
        check("class C { run()\n{ call(); } }");
        check("const o = {run() { call(); }}; object.run();");
    }

    #[test]
    fn invalid_type_only_bodies_and_initializers_are_retained_for_diagnostics() {
        check("abstract class C { abstract run() { effect(); } }");
        check("class C { declare value⟦: number⟧ = effect(); }");
        check("abstract class C { abstract value⟦: number⟧ = effect(); }");
    }

    #[test]
    fn type_only_computed_names_and_unicode_spans_are_erased_as_a_unit() {
        check("class C { ⟦declare [Symbol.iterator]: () => Iterator<number>;⟧ }");
        check("abstract class C { ⟦abstract 名称(値: 'é'):\n {名: string};⟧ }");
        check("class C { ⟦run(...values: readonly [number, string]): number;⟧ run(...values⟦: unknown[]⟧) { return values.length; } }");
    }

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
