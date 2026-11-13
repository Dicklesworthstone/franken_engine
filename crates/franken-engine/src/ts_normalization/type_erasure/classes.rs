//! Class heritage and member erasure regressions through the shared core facade.

#[cfg(test)]
mod tests {
    use super::super::tests::check;

    #[test]
    fn overload_signatures_are_erased_without_replacing_implementations() {
        check(
            "class C { ⟦constructor(value: number);⟧ constructor(value⟦: number | string⟧) { this.value = value; } }",
        );
        check(
            "class C { ⟦run(value: number): number;⟧ ⟦run(value: string): string;⟧ run(value⟦: unknown⟧) { return value; } }",
        );
        check(
            "class C { ⟦static choose<T>(value: T): T;⟧ static choose(value⟦: unknown⟧) { return value; } }",
        );
    }

    #[test]
    fn semicolonless_signatures_stop_at_the_next_member() {
        check("class C { ⟦run(value: number): number⟧\nrun(value⟦: unknown⟧) { return value; } }");
        check("class C { ⟦declare value: number⟧\nrun() { return 2; } }");
        check("class C { ⟦abstract read(): number⟧ }");
    }

    /// bd-9vouw.432: without semicolons, a field's initializer ends where a
    /// line starts the next member with a modifier; its modifiers were read
    /// as part of the initializer and never erased.
    #[test]
    fn semicolonless_initializers_stop_at_a_modified_member() {
        check(
            "class C {\n  ⟦private⟧ queue⟦: number[]⟧ = []\n  ⟦private⟧ busy⟦: boolean⟧ = false\n  ⟦private⟧ ⟦readonly⟧ size = 2\n  static count = 0\n  ⟦protected⟧ get total() { return 1 }\n  run() { return this.busy }\n}",
        );
        // A call's type arguments hold commas that do not end the field.
        check(
            "class Cache⟦<K, V>⟧ {\n  ⟦private⟧ cache = new Map⟦<K, V>⟧();\n  ⟦private⟧ maxSize⟦: number⟧;\n  get(key⟦: K⟧) { return this.cache.get(key); }\n}",
        );
    }

    #[test]
    fn abstract_and_declared_members_create_no_runtime_properties() {
        check(
            "abstract class C { ⟦abstract run(value: number): number;⟧ ⟦abstract get size(): number;⟧ ⟦abstract set size(value: number);⟧ }",
        );
        check(
            "class C { ⟦declare value: number;⟧ ⟦declare readonly missing?: string;⟧ ⟦declare static count: number;⟧ }",
        );
        check(
            "abstract class C { ⟦protected abstract readonly value: {count: number};⟧ run() { return 1; } }",
        );
    }

    #[test]
    fn index_signatures_are_not_computed_runtime_keys() {
        check(
            "class C { ⟦[key: string]: number;⟧ ⟦readonly [key: symbol]: unknown;⟧ run() { return 1; } }",
        );
        check("class C { [Symbol.iterator]() { return iterator; } [key()]⟦: number⟧ = value; }");
        check("class C { [(ready ? first : second)]⟦: number⟧ = value; }");
    }

    #[test]
    fn contextual_modifier_names_with_bodies_remain_runtime_members() {
        check(
            "class C { abstract⟦<T>⟧(value⟦: T⟧)⟦: T⟧ { return value; } declare() { return 2; } }",
        );
        check(
            "class C { abstract⟦: number⟧ = 1; declare⟦: number⟧ = 2; get readonly() { return 3; } }",
        );
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
        check(
            "class C { ⟦run(...values: readonly [number, string]): number;⟧ run(...values⟦: unknown[]⟧) { return values.length; } }",
        );
    }

    #[test]
    fn generic_heritage_finds_the_body_after_nested_types() {
        check("class Child extends Base⟦<number>⟧ { value⟦: number⟧ = 2; }");
        check(
            "class Child⟦<T>⟧ extends Base⟦<{value: T}, readonly [number, string]>⟧ { value⟦: T⟧; }",
        );
        check(
            "class Child extends Base⟦<(x: number) => {result: string}>⟧ { run(x⟦: number⟧) { return x; } }",
        );
    }

    #[test]
    fn implements_clauses_are_type_only_and_can_span_lines() {
        check("class Child ⟦implements Named, Store<{value: number}>⟧ { value⟦: number⟧ = 2; }");
        check(
            "class Child extends Base⟦<number>⟧\n⟦implements\n Named,\n Store<{value: number}>⟧ { value⟦: number⟧ = 2; }",
        );
        check("class Child ⟦implements 名称<{名: 'é'}>⟧ { value⟦: number⟧ = 2; }");
    }

    #[test]
    fn heritage_preserves_factory_calls_getters_and_computed_keys() {
        check(
            "class Child extends mixin⟦<number>⟧(Base)⟦<{value: number}>⟧ { value⟦: number⟧ = 2; }",
        );
        check("class Child extends namespace[key()]⟦<number>⟧ { run()⟦: number⟧ { return 1; } }");
        check(
            "const Child = class extends (choose ? First : Second)⟦<number>⟧ { value⟦: number⟧ = 2; };",
        );
    }

    #[test]
    fn class_atoms_in_heritage_do_not_steal_the_outer_body() {
        check(
            "class Child extends class Base⟦<T>⟧ { inner⟦: number⟧ = 1; } { outer⟦: number⟧ = 2; }",
        );
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
