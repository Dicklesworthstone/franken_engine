//! Observable locale lists and supportedLocalesOf across Intl services.
//! Provider assertions follow the engine's available locale data. These tests
//! execute real source through HybridRouter without test doubles.

use frankenengine_engine::HybridRouter;

fn output(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("locale-list program failed: {error}"))
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn locale_lists_visit_sparse_inherited_and_live_properties_in_order() {
    let source = r#"
        const log = [];
        const inherited = { 1: 'de-de' };
        const locales = Object.create(inherited);
        Object.defineProperty(locales, 'length', {
            get() { log.push('length'); return { valueOf() { log.push('size'); return 4.9; } }; }
        });
        Object.defineProperty(locales, '0', {
            get() {
                log.push('0');
                locales[3] = 'EN-us';
                return { toString() { log.push('tag'); return 'en-US'; } };
            }
        });
        console.log(Intl.getCanonicalLocales(locales).join('|'), log.join('|'));
        console.log(Intl.getCanonicalLocales([, 'ja', , 'JA']).join('|'));
    "#;
    assert_eq!(output(source), "en-US|de-DE length|size|0|tag\nja");
}

#[test]
fn locale_lists_preserve_proxy_has_get_and_conversion_order() {
    let source = r#"
        const log = [];
        const item = { [Symbol.toPrimitive](hint) { log.push('convert:' + hint); return 'fr-FR'; } };
        const locales = new Proxy({ 1: item, length: 3 }, {
            get(target, key, receiver) { log.push('get:' + key); return Reflect.get(target, key, receiver); },
            has(target, key) { log.push('has:' + key); return Reflect.has(target, key); }
        });
        console.log(Intl.getCanonicalLocales(locales).join('|'));
        console.log(log.join('|'));
    "#;
    assert_eq!(
        output(source),
        "fr-FR\nget:length|has:0|has:1|get:1|convert:string|has:2"
    );
}

#[test]
fn locale_lists_box_inputs_but_reject_non_string_primitive_elements() {
    let source = r#"
        const out = [];
        for (const value of [undefined, true, 12, 12n, Symbol('locale')]) {
            out.push(Intl.getCanonicalLocales(value).length);
        }
        for (const value of [null, [undefined], [null], [true], [12], [12n], [Symbol('locale')]]) {
            try { Intl.getCanonicalLocales(value); out.push('missed'); }
            catch (error) { out.push(error.constructor.name); }
        }
        function locales() {}
        Object.defineProperty(locales, 'length', { value: 1 });
        Object.defineProperty(locales, '0', { get() { return this === locales ? 'ja' : 'de'; } });
        out.push(Intl.getCanonicalLocales(locales).join('|'));
        console.log(out.join('|'));
    "#;
    assert_eq!(
        output(source),
        "0|0|0|0|0|TypeError|TypeError|TypeError|TypeError|TypeError|TypeError|TypeError|ja"
    );
}

#[test]
fn locale_lists_stop_at_the_first_abrupt_completion() {
    let source = r#"
        const marker = {};
        const log = [];
        const locales = {
            get length() { log.push('length'); return 3; },
            get 0() { log.push('0'); return 'en'; },
            get 1() { log.push('1'); return { toString() { log.push('throw'); throw marker; } }; },
            get 2() { log.push('unreachable'); return 'de'; }
        };
        try { Intl.getCanonicalLocales(locales); } catch (error) { console.log(error === marker); }
        console.log(log.join('|'));
        const invalid = { length: 2, 0: 'not_a_locale', get 1() { throw marker; } };
        try { Intl.getCanonicalLocales(invalid); } catch (error) { console.log(error.constructor.name); }
    "#;
    assert_eq!(output(source), "true\nlength|0|1|throw\nRangeError");
}

#[test]
fn intl_constructors_and_locale_methods_share_observable_locale_lists() {
    let source = r#"
        let count = 0;
        const locales = { length: 1, get 0() { count++; return { toString() { return 'de-DE'; } }; } };
        console.log(new Intl.NumberFormat(locales).format(1234.5));
        console.log((1234.5).toLocaleString(locales));
        console.log(new Date(0).toLocaleDateString(locales, { timeZone: 'UTC' }));
        console.log(new Intl.DateTimeFormat(locales).resolvedOptions().locale);
        console.log(count);
    "#;
    assert_eq!(output(source), "1.234,5\n1.234,5\n1.1.1970\nde-DE\n4");
}

#[test]
fn locale_conversion_precedes_option_validation_and_keeps_length_fixed() {
    let source = r#"
        const marker = {};
        const broken = { get length() { throw marker; } };
        const out = [];
        for (const run of [
            () => new Intl.NumberFormat(broken, null),
            () => new Intl.DateTimeFormat(broken, null),
            () => (1).toLocaleString(broken, null),
            () => new Date(0).toLocaleDateString(broken, null)
        ]) {
            try { run(); out.push(false); } catch (error) { out.push(error === marker); }
        }
        const locales = { length: 2, get 0() { this.length = 0; this[1] = 'de'; return 'en'; } };
        out.push(Intl.getCanonicalLocales(locales).join(','));
        console.log(out.join('|'));
    "#;
    assert_eq!(output(source), "true|true|true|true|en,de");
}

#[test]
fn enormous_sparse_locale_lists_consume_the_instruction_budget() {
    let error = HybridRouter::default()
        .eval_with_instruction_budget("Intl.getCanonicalLocales({ length: Infinity });", 1_000)
        .expect_err("a native sparse traversal must not bypass execution limits")
        .to_string();
    assert!(
        error.to_ascii_lowercase().contains("budget"),
        "expected the resource refusal, got {error}"
    );
}

fn supported_locales_output(body: &str) -> String {
    output(&format!(
        r#"
        for (const Service of [
            Intl.NumberFormat, Intl.DateTimeFormat, Intl.Collator, Intl.PluralRules,
            Intl.RelativeTimeFormat, Intl.ListFormat, Intl.Segmenter
        ]) {{
            {body}
        }}
        "#
    ))
}

#[test]
fn supported_locales_methods_have_static_descriptors_and_ignore_the_receiver() {
    let source = r#"
        const method = Service.supportedLocalesOf;
        const property = Object.getOwnPropertyDescriptor(Service, 'supportedLocalesOf');
        const name = Object.getOwnPropertyDescriptor(method, 'name');
        const length = Object.getOwnPropertyDescriptor(method, 'length');
        const receiver = new Proxy({}, { get() { throw 'unexpected receiver access'; } });
        let visited = 0;
        let construct = 'missed';
        try { new method({ get length() { visited++; return 0; } }); }
        catch (error) { construct = error.constructor.name; }
        console.log(
            typeof method, method.name, method.length,
            property.value === method, property.writable, property.enumerable, property.configurable,
            name.writable, name.enumerable, name.configurable,
            length.writable, length.enumerable, length.configurable,
            Object.getPrototypeOf(method) === Function.prototype,
            Object.prototype.hasOwnProperty.call(method, 'prototype'),
            method.call(receiver, 'EN-us').join('|'), construct, visited
        );
        Service.supportedLocalesOf = 17;
        const replaced = Service.supportedLocalesOf === 17;
        delete Service.supportedLocalesOf;
        const removed = !('supportedLocalesOf' in Service);
        Object.defineProperty(Service, 'supportedLocalesOf', property);
        console.log(replaced, removed, Service.supportedLocalesOf === method);
    "#;
    let expected = "function supportedLocalesOf 1 true true false true false false true \
                    false false true true false en-US TypeError 0\ntrue true true";
    assert_eq!(supported_locales_output(source), [expected; 7].join("\n"));
}

#[test]
fn supported_locales_preserve_canonical_requests_and_return_fresh_mutable_arrays() {
    let source = r#"
        const requested = [
            'generic', 'EN-us', 'en', 'en-US', 'en-CH',
            'en-US-u-ca-buddhist', 'en-Latn-US-1996', 'en-US-x-lab'
        ];
        const lookup = Service.supportedLocalesOf(requested, { localeMatcher: 'lookup' });
        const bestFit = Service.supportedLocalesOf(requested, { localeMatcher: 'best fit' });
        console.log(
            lookup.join('|'), lookup.join('|') === bestFit.join('|'),
            lookup.join('|') === Service.supportedLocalesOf(requested).join('|'), requested[1]
        );
        const first = Service.supportedLocalesOf('en');
        const second = Service.supportedLocalesOf('en');
        const index = Object.getOwnPropertyDescriptor(first, '0');
        const length = Object.getOwnPropertyDescriptor(first, 'length');
        first[0] = 'en-US';
        first.push('en-GB');
        delete first[0];
        console.log(
            first !== second, Array.isArray(first), Object.getPrototypeOf(first) === Array.prototype,
            index.writable, index.enumerable, index.configurable,
            length.writable, length.enumerable, length.configurable,
            first.length, !('0' in first), second.join('|'),
            Service.supportedLocalesOf().length, Service.supportedLocalesOf([]).length
        );
    "#;
    let expected = "en-US|en|en-CH|en-US-u-ca-buddhist|en-Latn-US-1996|en-US-x-lab true true EN-us\n\
                    true true true true true true true false false 2 true en 0 0";
    assert_eq!(supported_locales_output(source), [expected; 7].join("\n"));
}

#[test]
fn supported_locales_use_service_provider_data_and_constructor_negotiation() {
    // Availability is deliberately narrower than ICU. The declared subsets
    // must agree with both resolvedOptions and usable service operations.
    let source = r#"
        const requests = ['en', 'de', 'fr', 'ja', 'zh', 'ko', 'it', 'nl', 'pt', 'zz', 'generic'];
        const cases = [
            ['NumberFormat', 'fr', 'de'],
            ['DateTimeFormat', 'zh', 'fr'],
            ['Collator', 'ja', 'fr'],
            ['PluralRules', 'it', 'ja'],
            ['RelativeTimeFormat', 'fr', 'de'],
            ['ListFormat', 'fr', 'de'],
            ['Segmenter', 'ja', 'en']
        ];
        function usable(name, instance) {
            if (name === 'NumberFormat') return typeof instance.format(1234.5) === 'string';
            if (name === 'DateTimeFormat') return typeof instance.format(0) === 'string';
            if (name === 'Collator') return instance.compare('a', 'b') < 0;
            if (name === 'PluralRules') return typeof instance.select(1) === 'string';
            if (name === 'RelativeTimeFormat') return typeof instance.format(1, 'day') === 'string';
            if (name === 'ListFormat') return typeof instance.format(['a', 'b']) === 'string';
            return instance.segment('ab').containing(0).segment === 'a';
        }
        for (const row of cases) {
            const name = row[0];
            const Service = Intl[name];
            const supported = Service.supportedLocalesOf(requests, { localeMatcher: 'lookup' });
            let usableCount = 0;
            for (const tag of supported) {
                const instance = new Service(tag);
                if (instance.resolvedOptions().locale === tag && usable(name, instance)) usableCount++;
            }
            const selected = new Service([row[1], row[2]], { localeMatcher: 'lookup' });
            const parent = new Service(['zz', 'en-CH'], { localeMatcher: 'lookup' });
            const fallback = new Service(['zz', 'generic']);
            console.log(
                name, supported.join('|'), usableCount === supported.length,
                selected.resolvedOptions().locale,
                parent.resolvedOptions().locale, fallback.resolvedOptions().locale,
                Service.supportedLocalesOf(['zz', 'generic']).length
            );
        }
        console.log(new Intl.NumberFormat('en-CH').format(1234.5));
        console.log(new Intl.NumberFormat('de-CH').format(1234.5));
    "#;
    assert_eq!(
        output(source),
        "NumberFormat en|de|ja|zh|ko true de en en-US 0\n\
         DateTimeFormat en|de|fr|ja true fr en en-US 0\n\
         Collator en|de|fr|it|nl|pt true fr en en-US 0\n\
         PluralRules en|de|fr|ja|zh|ko true ja en en-US 0\n\
         RelativeTimeFormat en|de|ja|zh|ko true de en en-US 0\n\
         ListFormat en|de|ja|zh|ko true de en en-US 0\n\
         Segmenter en true en en en-US 0\n\
         1,234.5\n1.234,5"
    );
}

#[test]
fn supported_locales_validate_locales_and_matchers_even_for_empty_requests() {
    let source = r#"
        const sizes = [];
        for (const value of [undefined, true, 12, 12n, Symbol('locale'), {}, []]) {
            sizes.push(Service.supportedLocalesOf(value).length);
        }
        console.log(sizes.join('|'));
        const errors = [];
        for (const value of [
            null, [undefined], [null], [true], [12], [12n], [Symbol('locale')],
            ['en_US'], ['en--US'], ['1n'], [''],
            ['en-u'], ['en-a-foo-a-bar'], ['sl-rozaj-rozaj'], ['en-x']
        ]) {
            try { Service.supportedLocalesOf(value); errors.push('missed'); }
            catch (error) { errors.push(error.constructor.name); }
        }
        console.log(errors.join('|'));
        const matcherErrors = [];
        for (const value of [null, '', 'LOOKUP', 'best-fit', false, 3, Symbol('matcher')]) {
            try { Service.supportedLocalesOf([], { localeMatcher: value }); matcherErrors.push('missed'); }
            catch (error) { matcherErrors.push(error.constructor.name); }
        }
        try { Service.supportedLocalesOf([], null); matcherErrors.push('missed'); }
        catch (error) { matcherErrors.push(error.constructor.name); }
        console.log(matcherErrors.join('|'));
        const valid = [];
        for (const value of [undefined, 'lookup', 'best fit']) {
            valid.push(Service.supportedLocalesOf('EN-us', { localeMatcher: value }).join('|'));
        }
        console.log(valid.join('|'));
    "#;
    let expected = "0|0|0|0|0|0|0\n\
                    TypeError|TypeError|TypeError|TypeError|TypeError|TypeError|TypeError|\
                    RangeError|RangeError|RangeError|RangeError|RangeError|RangeError|RangeError|RangeError\n\
                    RangeError|RangeError|RangeError|RangeError|RangeError|RangeError|TypeError|TypeError\n\
                    en-US|en-US|en-US";
    assert_eq!(supported_locales_output(source), [expected; 7].join("\n"));
}

#[test]
fn supported_locales_observe_sparse_inherited_proxy_lists_before_options() {
    let source = r#"
        const log = [];
        const target = Object.create({ 1: 'en-GB' });
        target.length = { [Symbol.toPrimitive](hint) { log.push('length:' + hint); return 4.9; } };
        Object.defineProperty(target, '0', {
            get() {
                log.push('receiver:' + (this === locales));
                target.length = 0;
                target[3] = 'EN-us';
                return { [Symbol.toPrimitive](hint) { log.push('tag:' + hint); return 'en-US'; } };
            }
        });
        const locales = new Proxy(target, {
            get(target, key, receiver) { log.push('get:' + key); return Reflect.get(target, key, receiver); },
            has(target, key) { log.push('has:' + key); return Reflect.has(target, key); }
        });
        const options = new Proxy({
            get localeMatcher() {
                log.push('matcher-receiver:' + (this === options));
                return { [Symbol.toPrimitive](hint) { log.push('matcher:' + hint); return 'lookup'; } };
            },
            get style() { throw 'unrelated option'; },
            get granularity() { throw 'unrelated option'; }
        }, {
            get(target, key, receiver) {
                log.push('option:' + key);
                return Reflect.get(target, key, receiver);
            },
            has() { throw 'GetOption must not call HasProperty'; }
        });
        console.log(Service.supportedLocalesOf(locales, options).join('|'));
        console.log(log.join('|'));
    "#;
    let expected = "en-US|en-GB\n\
                    get:length|length:number|has:0|get:0|receiver:true|tag:string|\
                    has:1|get:1|has:2|has:3|get:3|option:localeMatcher|matcher-receiver:true|matcher:string";
    assert_eq!(supported_locales_output(source), [expected; 7].join("\n"));
}

#[test]
fn supported_locales_stop_at_abrupt_completions_before_later_reads() {
    let source = r#"
        const marker = {};
        const log = [];
        const options = { get localeMatcher() { log.push('options'); throw marker; } };
        const locales = {
            length: 3, 0: 'en',
            get 1() {
                log.push('get:1');
                return { toString() { log.push('convert'); throw marker; } };
            },
            get 2() { log.push('unreachable'); return 'en-US'; }
        };
        try { Service.supportedLocalesOf(locales, options); }
        catch (error) { console.log(error === marker, log.join('|')); }
        log.length = 0;
        try { Service.supportedLocalesOf({ get length() { throw marker; } }, null); }
        catch (error) { console.log(error === marker); }
        const invalid = [];
        for (const tag of ['not_a_locale', 'en-u', 'en-a-foo-a-bar', 'sl-rozaj-rozaj', 'en-x']) {
            try { Service.supportedLocalesOf([tag], options); invalid.push('missed'); }
            catch (error) { invalid.push(error.constructor.name); }
        }
        console.log(invalid.join('|'), log.length);
        try { Service.supportedLocalesOf(['en'], options); }
        catch (error) { console.log(error === marker, log.join('|')); }
        log.length = 0;
        try {
            Service.supportedLocalesOf('en', {
                localeMatcher: { [Symbol.toPrimitive](hint) { log.push(hint); throw marker; } }
            });
        } catch (error) { console.log(error === marker, log.join('|')); }
        let next = 0;
        const trapped = new Proxy({ length: 2, 0: 'en' }, {
            has(target, key) {
                if (key === '0') throw marker;
                next++;
                return Reflect.has(target, key);
            },
            get(target, key, receiver) {
                if (key !== 'length') next++;
                return Reflect.get(target, key, receiver);
            }
        });
        try { Service.supportedLocalesOf(trapped, options); }
        catch (error) { console.log(error === marker, next); }
    "#;
    let expected = "true get:1|convert\ntrue\n\
                    RangeError|RangeError|RangeError|RangeError|RangeError 0\n\
                    true options\ntrue string\ntrue 0";
    assert_eq!(supported_locales_output(source), [expected; 7].join("\n"));
}

#[test]
fn supported_locales_box_options_and_read_callable_and_inherited_matchers() {
    let source = r#"
        const results = [];
        const receivers = [];
        for (const row of [
            [true, Boolean.prototype], [7, Number.prototype], ['options', String.prototype],
            [12n, BigInt.prototype], [Symbol('options'), Symbol.prototype]
        ]) {
            Object.defineProperty(row[1], 'localeMatcher', {
                configurable: true,
                get() {
                    receivers.push(typeof this === 'object' && this.valueOf() === row[0]);
                    return 'lookup';
                }
            });
            results.push(Service.supportedLocalesOf('en', row[0]).join('|'));
            delete row[1].localeMatcher;
        }
        function options() {}
        Object.defineProperty(options, 'localeMatcher', {
            get() { receivers.push(this === options); return 'lookup'; }
        });
        results.push(Service.supportedLocalesOf('en', options).join('|'));
        const inherited = Object.create({
            get localeMatcher() { receivers.push(this === inherited); return 'lookup'; }
        });
        results.push(Service.supportedLocalesOf('en', inherited).join('|'));
        console.log(results.join('|'), receivers.join('|'));
        Object.defineProperty(Object.prototype, 'localeMatcher', {
            configurable: true,
            get() { throw 'unexpected inherited option'; }
        });
        console.log(
            Service.supportedLocalesOf('en').join('|'),
            Service.supportedLocalesOf('en', undefined).join('|')
        );
        delete Object.prototype.localeMatcher;
    "#;
    let expected = "en|en|en|en|en|en|en true|true|true|true|true|true|true\nen en";
    assert_eq!(supported_locales_output(source), [expected; 7].join("\n"));
}

#[test]
fn supported_locales_static_properties_participate_in_first_access_and_mutation() {
    // Each case starts a fresh realm so a prior get cannot materialize the
    // constructor's backing object and hide a first-operation defect.
    for (source, expected) in [
        (
            r#"
            console.log(
                Object.getOwnPropertyNames(Service).join('|'),
                Object.keys(Service).includes('supportedLocalesOf')
            );
            "#,
            "length|name|prototype|supportedLocalesOf false",
        ),
        (
            r#"
            console.log(
                'supportedLocalesOf' in Service,
                Reflect.has(Service, 'supportedLocalesOf')
            );
            "#,
            "true true",
        ),
        (
            r#"
            const method = Reflect.get(Service, 'supportedLocalesOf');
            console.log(
                typeof method, method('en').join('|'),
                Service.prototype.constructor === Service,
                Service.prototype.constructor.supportedLocalesOf === method
            );
            "#,
            "function en true true",
        ),
        (
            r#"
            const removed = delete Service.supportedLocalesOf;
            console.log(
                removed, 'supportedLocalesOf' in Service, Reflect.has(Service, 'supportedLocalesOf'),
                Object.getOwnPropertyNames(Service).includes('supportedLocalesOf'),
                typeof Reflect.get(Service, 'supportedLocalesOf'),
                typeof Service.supportedLocalesOf,
                typeof Service.prototype.constructor.supportedLocalesOf
            );
            "#,
            "true false false false undefined undefined undefined",
        ),
        (
            r#"
            const marker = {};
            Service.supportedLocalesOf = marker;
            console.log(
                Service.supportedLocalesOf === marker,
                Reflect.get(Service, 'supportedLocalesOf') === marker,
                Object.getOwnPropertyDescriptor(Service, 'supportedLocalesOf').value === marker,
                Service.prototype.constructor.supportedLocalesOf === marker
            );
            "#,
            "true true true true",
        ),
        (
            r#"
            Object.defineProperty(Service, 'supportedLocalesOf', {
                value: 19, writable: false, enumerable: true, configurable: false
            });
            const property = Object.getOwnPropertyDescriptor(Service, 'supportedLocalesOf');
            console.log(
                Service.supportedLocalesOf, property.writable, property.enumerable, property.configurable,
                Object.keys(Service).includes('supportedLocalesOf'),
                Reflect.deleteProperty(Service, 'supportedLocalesOf')
            );
            "#,
            "19 false true false true false",
        ),
    ] {
        assert_eq!(
            supported_locales_output(source),
            [expected; 7].join("\n"),
            "{source}"
        );
    }
}

#[test]
fn supported_locale_extensions_do_not_silently_change_service_behavior() {
    let source = r#"
        const refused = [
            ['NumberFormat', 'en-US-u-nu-arab'],
            ['DateTimeFormat', 'en-US-u-hc-h23', { hour: 'numeric', timeZone: 'UTC' }],
            ['DateTimeFormat', 'en-US-u-ca-buddhist'],
            ['DateTimeFormat', 'en-US-u-nu-arab'],
            ['Collator', 'en-US-u-kn'],
            ['Collator', 'en-US-u-kf-upper'],
            ['Collator', 'en-US-u-co-phonebk']
        ];
        for (const row of refused) {
            const Service = Intl[row[0]];
            let outcome = 'silently ignored';
            try { new Service(row[1], row[2]); }
            catch (error) { outcome = error.constructor.name; }
            console.log(
                row[0], Service.supportedLocalesOf(row[1], { localeMatcher: 'lookup' }).join('|'),
                outcome
            );
        }
        const nf = new Intl.NumberFormat('en-US-u-nu-latn');
        const date = new Intl.DateTimeFormat('en-US-u-ca-gregory-hc-h23-nu-latn', {
            hour: 'numeric', hour12: false, timeZone: 'UTC'
        });
        const collator = new Intl.Collator('en-US-u-kn', { numeric: true });
        console.log(nf.format(1234.5), nf.resolvedOptions().numberingSystem);
        console.log(
            date.format(0), date.resolvedOptions().calendar,
            date.resolvedOptions().numberingSystem, date.resolvedOptions().hourCycle
        );
        console.log(collator.compare('2', '10'), collator.resolvedOptions().numeric);
        for (const tag of ['en-US-u-co-phonebk', 'en-US-x-u-nu-arab']) {
            const instance = new Intl.NumberFormat(tag);
            console.log(
                'NumberFormat', Intl.NumberFormat.supportedLocalesOf(tag)[0] === tag,
                instance.format(1234.5), instance.resolvedOptions().numberingSystem
            );
        }
        for (const tag of ['en-US-u-kn', 'en-US-x-u-hc-h23']) {
            const instance = new Intl.DateTimeFormat(tag, { hour: 'numeric', timeZone: 'UTC' });
            console.log(
                'DateTimeFormat', Intl.DateTimeFormat.supportedLocalesOf(tag)[0] === tag,
                instance.format(0), instance.resolvedOptions().hourCycle
            );
        }
        for (const tag of ['en-US-u-nu-arab', 'en-US-x-u-kn-true']) {
            const instance = new Intl.Collator(tag);
            console.log(
                'Collator', Intl.Collator.supportedLocalesOf(tag)[0] === tag,
                instance.compare('2', '10'), instance.resolvedOptions().numeric
            );
        }
    "#;
    // Querying availability ignores Unicode mode requests, but construction
    // must either apply the requested mode or refuse it. The current providers
    // cannot negotiate the refused modes; they must not silently use defaults.
    assert_eq!(
        output(source),
        "NumberFormat en-US-u-nu-arab TypeError\n\
         DateTimeFormat en-US-u-hc-h23 TypeError\n\
         DateTimeFormat en-US-u-ca-buddhist TypeError\n\
         DateTimeFormat en-US-u-nu-arab TypeError\n\
         Collator en-US-u-kn TypeError\n\
         Collator en-US-u-kf-upper TypeError\n\
         Collator en-US-u-co-phonebk TypeError\n\
         1,234.5 latn\n\
         00 gregory latn h23\n\
         -1 true\n\
         NumberFormat true 1,234.5 latn\n\
         NumberFormat true 1,234.5 latn\n\
         DateTimeFormat true 12 AM h12\n\
         DateTimeFormat true 12 AM h12\n\
         Collator true 1 false\n\
         Collator true 1 false"
    );
}

#[test]
fn unicode_locale_keywords_canonicalize_before_deduplication_and_matching() {
    let source = r#"
        const requests = [
            'EN-us-u-NU-latn-nu-arab', 'en-US-u-nu-latn', 'en-US-u-nu-arab-nu-latn',
            'en-US-u-NU-latn-CA-gregory', 'en-US-u-ca-gregory-nu-latn',
            'en-US-u-FOO-bar-foo-KN-true', 'en-US-u-BAR-foo-kn',
            'en-US-u-kn-TRUE', 'en-US-u-kn', 'en-US-u-kn-true-extra',
            'en-US-u-kn-true-x-NU-latn-nu-arab', 'en-US-u-kn-x-nu-latn-nu-arab',
            'en-US-x-u-NU-latn-nu-arab', 'en-US-x-u-nu-latn'
        ];
        console.log(Intl.getCanonicalLocales(requests).join('|'));
        for (const Service of [
            Intl.NumberFormat, Intl.DateTimeFormat, Intl.Collator, Intl.PluralRules,
            Intl.RelativeTimeFormat, Intl.ListFormat, Intl.Segmenter
        ]) {
            console.log(Service.supportedLocalesOf(requests, { localeMatcher: 'lookup' }).join('|'));
        }
    "#;
    // First keyword values win before sorting. A sole "true" type is omitted;
    // longer values and the entire private-use tail remain distinct.
    let expected = "en-US-u-nu-latn|en-US-u-nu-arab|en-US-u-ca-gregory-nu-latn|\
                    en-US-u-bar-foo-kn|en-US-u-kn|en-US-u-kn-true-extra|\
                    en-US-u-kn-x-nu-latn-nu-arab|en-US-x-u-nu-latn-nu-arab|en-US-x-u-nu-latn";
    assert_eq!(output(source), [expected; 8].join("\n"));
}
