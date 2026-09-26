//! Type-only expression suffixes on the same token/span stream as annotations.
//!
//! Assertions perform no conversion, validation, or evaluation. Keep their
//! operand and its reference identity: `(object.method as Callable)()` still
//! calls with `object` as receiver, and `target!.field = value` is still a Set.

use super::{Eraser, Kind};

impl Eraser<'_> {
    pub(super) fn erase_expression_types(&mut self) {
        let mut cursor = 0;
        let mut previous = None;
        while cursor < self.tokens.len() {
            if self.removed[cursor] {
                cursor += 1;
                continue;
            }
            // `as` in a module binding clause names a runtime binding. Skip
            // only the clause, not export-default expressions or import().
            if let Some(end) = self.module_clause_end(cursor) {
                previous = end.checked_sub(1);
                cursor = end;
                continue;
            }
            if matches!(self.text(cursor), "as" | "satisfies" | "!")
                && !self.newline_before(cursor)
                && previous.is_some_and(|index| self.suffix_operand(index))
            {
                match self.text(cursor) {
                    "as" | "satisfies" if !self.property_name(cursor) => {
                        if let Some(end) = self.type_end(cursor + 1, 0)
                            && self.expression_type_boundary(end)
                        {
                            self.mark(cursor, end);
                            cursor = end;
                            continue;
                        }
                    }
                    "!" if self.expression_type_boundary(cursor + 1) => {
                        self.mark(cursor, cursor + 1);
                        cursor += 1;
                        continue;
                    }
                    _ => {}
                }
            }
            previous = Some(cursor);
            cursor += 1;
        }
    }

    fn suffix_operand(&self, previous: usize) -> bool {
        let token = self.tokens[previous];
        match token.kind {
            Kind::Literal => true,
            Kind::Word => {
                // Keywords are property names after a dot, including `new`
                // and `return`. Otherwise these tokens start/continue syntax,
                // not the operand of a postfix assertion.
                self.property_name(previous)
                    || !matches!(
                        token.text,
                        "return" | "throw" | "yield" | "await" | "void" | "typeof"
                            | "delete" | "new" | "in" | "instanceof" | "of" | "case"
                            | "else" | "do" | "const" | "let" | "var" | "function"
                            | "class" | "extends" | "implements" | "import" | "export"
                            | "default"
                    )
            }
            Kind::Punctuation => match token.text {
                "]" | "}" => true,
                ")" => {
                    let Some(open) = self.pairs[previous] else {
                        return false;
                    };
                    !open.checked_sub(1).is_some_and(|head| {
                        !self.property_name(head)
                            && matches!(
                                self.text(head),
                                "if" | "while" | "for" | "with" | "switch" | "catch"
                            )
                    })
                }
                _ => false,
            },
        }
    }

    fn expression_type_boundary(&self, index: usize) -> bool {
        index == self.tokens.len()
            || self.newline_before(index)
            || self.tokens.get(index).is_some_and(|token| {
                token.kind == Kind::Literal && token.text.starts_with('`')
            })
            || matches!(
                self.text(index),
                ";" | "," | ")" | "]" | "}" | "(" | "[" | "." | "?."
                    | "?" | ":" | "!" | "=" | "==" | "!=" | "+" | "-"
                    | "*" | "/" | "%" | "<" | ">" | "&" | "|" | "^"
                    | "&&" | "||" | "??" | "++" | "--" | "in" | "instanceof"
                    | "as" | "satisfies"
            )
    }

    fn module_clause_end(&self, index: usize) -> Option<usize> {
        if self.property_name(index) {
            return None;
        }
        let mut cursor = index + 1;
        match self.text(index) {
            "export" => match self.text(cursor) {
                "{" => return self.group_end(cursor),
                "*" => cursor += 1,
                _ => return None,
            },
            "import" => {
                if self.tokens.get(cursor)?.kind == Kind::Literal {
                    return Some(cursor + 1);
                }
                if self.tokens.get(cursor)?.kind == Kind::Word {
                    cursor += 1;
                    if self.text(cursor) == "," {
                        cursor += 1;
                    }
                }
                match self.text(cursor) {
                    "{" => cursor = self.group_end(cursor)?,
                    "*" => cursor += 1,
                    "from" => {}
                    _ => return None,
                }
            }
            _ => return None,
        }
        if self.text(cursor) == "as" {
            if self.tokens.get(cursor + 1)?.kind != Kind::Word {
                return None;
            }
            cursor += 2;
        }
        if self.text(cursor) == "from" && self.tokens.get(cursor + 1)?.kind == Kind::Literal {
            Some(cursor + 2)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::check;

    #[test]
    fn assertions_erase_whole_nested_types_without_evaluating_them() {
        check("const value = original ⟦as Record<string, {value: number}[]>⟧;");
        check("const value = original ⟦as unknown⟧ ⟦as {value: number}⟧;");
        check("const value = ({port: 80}) ⟦satisfies {port: number}⟧;");
        check("const value = original ⟦as T extends U ? {yes: T} : {no: U}⟧;");
    }

    #[test]
    fn asserted_calls_and_assignment_targets_keep_reference_identity() {
        check("(object.method ⟦as (value: number) => number⟧)(3);");
        check("object⟦!⟧.field = value; array[index]⟦!⟧ += 1;");
        check("const value = (get()⟦!⟧ ⟦as {value: number}⟧).value;");
    }

    #[test]
    fn non_null_is_postfix_not_a_boolean_negation_or_inequality() {
        check("const a = value⟦!⟧; const b = value⟦!⟧⟦!⟧.field;");
        check("!value; !!value; value != other; value !== other;");
        check("if (value) !(other); while (value) !other;");
        check("value\n!other; value\n!(other);");
        check("object.if(value)⟦!⟧; object.return⟦!⟧.value;");
    }

    #[test]
    fn module_aliases_and_runtime_property_names_are_preserved() {
        check("import {value as Type, satisfies as other} from 'pkg';");
        check("import primary, {value as Type} from 'pkg';");
        check("import * as namespace from 'pkg'; export * as namespace from 'pkg';");
        check("export {value as Type, satisfies as other};");
        check("export default (value ⟦as number⟧); import(value ⟦as string⟧);");
        check("const as = 1; const satisfies = 2; const o = {as, satisfies};");
        check("function as(value) { return value; } object.as(value);");
        check("const o = {as: 1, satisfies: 2, get as() { return 1; }};");
    }

    #[test]
    fn assertion_boundaries_preserve_operators_and_conditional_branches() {
        check("const value = yes ? first ⟦as number⟧ : second ⟦as number⟧;");
        check("const value = (left ⟦as number⟧) + (right ⟦as number⟧);");
        check("const value = first ⟦as number⟧ < second;");
        check("const value = first ⟦as number⟧ < second > (third);");
        check("const value = first ⟦as (number)⟧ < second > third;");
        check("const value = first ⟦as number[]⟧ < second > third;");
        check("const value = first ⟦as number⟧ === second;");
        check("const value = first ⟦as number⟧\nconst next = 2;");
    }

    #[test]
    fn literal_text_and_newline_separated_names_are_not_assertions() {
        check("const text = 'value as number'; const r = /value! as number/;");
        check("const text = `value satisfies Shape`;");
        check("value\nas(Type); value\nsatisfies(Type);");
        check("const value = source ⟦as /* note */ {\n名: 'é'}⟧;");
    }
}
