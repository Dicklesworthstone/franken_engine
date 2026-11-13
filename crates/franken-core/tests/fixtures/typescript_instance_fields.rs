//! Reference programs compiled with TypeScript 5.9.3, target ES2020,
//! module ESNext, strict enabled, and its default assignment field semantics.
//! Every program has zero TypeScript diagnostics. Expected output is from
//! executing that emitted JavaScript in Node.js 24.22.1.

pub const CASES: &[(&str, &str, &[&str])] = &[
    (
        "parameter_defaults_and_field_order",
        r#"
let trace = '';
function mark(tag: string, value: number): number { trace += tag + '|'; return value; }
class Service {
    first = mark('first', this.value);
    absent?: number;
    second = mark('second', this.first + 1);
    read = () => this.value + this.second;
    constructor(public value: number = mark('default', 3)) { mark('body', this.second); }
}
const service = new Service();
console.log(trace, service.first, service.second, service.read());
console.log(Object.keys(service).join(','));
"#,
        &[
            "default|first|second|body| 3 4 7",
            "value,first,second,read",
        ],
    ),
    (
        "derived_super_and_early_return",
        r#"
let trace = '';
function mark(tag: string, value: number): number { trace += tag + '|'; return value; }
class Base { constructor() { trace += 'base|'; } }
class Child extends Base {
    field = mark('field', this.value + 1);
    constructor(public value: number = mark('default', 3), skip = false) {
        trace += 'pre|';
        if (skip) return {value: 99, field: 100};
        (super());
        trace += 'body|';
    }
}
const child = new Child();
console.log(trace, child.value, child.field);
trace = '';
const skipped = new Child(8, true);
console.log(trace, skipped.value, skipped.field);
"#,
        &["default|pre|base|field|body| 3 4", "pre| 99 100"],
    ),
    (
        "base_class_expressions_and_nested_initializers",
        r#"
const Factory = class {
    value = 2;
    'hy-phen' = 3;
    42 = 4;
    get = 5;
    set = 6;
    async = 7;
    read = () => this.value;
    Inner = class { field = 8; };
};
const item = new Factory();
console.log(item.value, item['hy-phen'], item[42], item.get, item.set, item.async, item.read());
console.log(new item.Inner().field);
"#,
        &["2 3 4 5 6 7 2", "8"],
    ),
    (
        "assignment_semantics_use_inherited_setters",
        r#"
let observed = 0;
class Base { set value(value: number) { observed = value; } }
const Parent: any = Base;
class Child extends Parent {
    value = 7;
    absent?: number;
    constructor() { super(); }
}
const child = new Child();
console.log(observed, Object.keys(child).length);
"#,
        &["7 0"],
    ),
    (
        "namespace_live_bindings_survive_field_relocation",
        r#"
namespace Values {
    export let current = 2;
    export const Reader = class {
        value = current;
        read = () => current;
    };
}
const first = new Values.Reader();
Values.current = 5;
console.log(first.value, first.read(), new Values.Reader().value);
"#,
        &["2 5 5"],
    ),
    (
        "uninitialized_derived_fields_preserve_implicit_forwarding",
        r#"
class Base { constructor(public value = 3) {} }
class Child extends Base { absent?: number; }
const child = new Child(8);
console.log(child.value, Object.keys(child).join(','));
"#,
        &["8 value"],
    ),
    (
        "abrupt_initializers_skip_later_fields_and_body",
        r#"
let trace = '';
const failure = {code: 17};
function fail(): never { trace += 'field|'; throw failure; }
class Broken {
    first = fail();
    second = trace += 'second|';
    constructor() { trace += 'body|'; }
}
let same = false;
try { new Broken(); } catch (error) { same = error === failure; }
console.log(trace, same);
"#,
        &["field| true"],
    ),
];
