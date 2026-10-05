//! A minimal ECMA-402 `Intl` over the engine's locale formatters.
//!
//! `Intl` was not defined, so code that formats through it (`new
//! Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' })`,
//! `Intl.DateTimeFormat().resolvedOptions().timeZone`, luxon) threw a
//! ReferenceError. This provides NumberFormat, DateTimeFormat, Collator and
//! PluralRules over number_locale, date_locale and collation,
//! RelativeTimeFormat and ListFormat over pattern tables generated from Node
//! v22.2.0's ICU (en, de, ja, zh, ko; bd-9vouw.171), and
//! getCanonicalLocales. A service object reads its options once, at
//! construction, into the object `resolvedOptions()` copies; its `format` /
//! `compare` / `select` are bound to it, so `values.map(nf.format)` works.
//!
//! A locale, option or combination the formatters do not cover is a typed
//! refusal at construction, never output that differs from Node's.
//!
//! No-claim: no ICU and no locale negotiation (an unsupported locale throws
//! instead of falling back, except a five-to-eight-letter language such as
//! `generic`, which falls back to en-US as in Node); DateTimeFormat has
//! formatToParts (the pieces `format` joins), NumberFormat does not; no
//! formatRange, BigInt formatting, DisplayNames, Locale or Segmenter, and no
//! supportedLocalesOf. The methods are own properties of each
//! object, not prototype methods: `Intl.DateTimeFormat.prototype` is
//! undefined and `instanceof Intl.NumberFormat` is false.

use super::*;

use date_locale::{DateComponents, Digits, FormatStyle, MonthStyle, TextWidth};

/// The parts of a formatted relative time or list: each part's `type`, its
/// text and, for a relative time's number, its `unit`.
type FormattedParts = Vec<(&'static str, String, Option<&'static str>)>;

/// Which caller's ToDateTimeOptions `required` / `defaults` apply (ECMA-402
/// 11.1.2): the DateTimeFormat constructor (any, date) or
/// Date.prototype.toLocaleDateString (date, date), toLocaleTimeString
/// (time, time) and toLocaleString (any, all).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DateOptionsFor {
    Constructor,
    DateString,
    TimeString,
    String,
}

/// The service constructors on `Intl`.
const SERVICES: [&str; 6] = [
    "NumberFormat",
    "DateTimeFormat",
    "Collator",
    "PluralRules",
    "RelativeTimeFormat",
    "ListFormat",
];

/// The languages RelativeTimeFormat and ListFormat have patterns for (and
/// whose numbers number_locale formats).
const PATTERN_LANGUAGES: [&str; 5] = ["en", "de", "ja", "zh", "ko"];

/// RelativeTimeFormat units, singular (ECMA-402 SingularRelativeTimeUnit).
const RELATIVE_TIME_UNITS: [&str; 8] = [
    "second", "minute", "hour", "day", "week", "month", "quarter", "year",
];

/// NumberFormat options the formatter has no support for, with the value
/// that leaves formatting unchanged (a present default is accepted).
const NUMBER_FORMAT_DEFAULTED_OPTIONS: [(&str, &str); 9] = [
    ("notation", "standard"),
    ("signDisplay", "auto"),
    ("currencyDisplay", "symbol"),
    ("currencySign", "standard"),
    ("minimumIntegerDigits", "1"),
    ("roundingMode", "halfExpand"),
    ("roundingPriority", "auto"),
    ("roundingIncrement", "1"),
    ("trailingZeroDisplay", "auto"),
];

impl InterpreterCore {
    /// The `Intl` namespace object.
    pub(super) fn alloc_intl_object(&mut self) -> Result<ObjectId, InterpreterError> {
        let mut members: Vec<(&str, Value)> = SERVICES
            .iter()
            .map(|service| {
                (
                    *service,
                    Value::BuiltinFunction(BuiltinFunction {
                        kind: BuiltinFunctionKind::IntlConstructor,
                        module_specifier: BuiltinModuleSpecifier::from_nonempty(service),
                        iterator_handle: None,
                        bound_object: None,
                    }),
                )
            })
            .collect();
        members.push((
            "getCanonicalLocales",
            Value::BuiltinFunction(BuiltinFunction::new_kind(
                BuiltinFunctionKind::IntlGetCanonicalLocales,
            )),
        ));
        let intl = self.alloc_object_with_properties(&members)?;
        for (name, _) in &members {
            self.set_own_property_attributes(
                intl,
                &RuntimePropertyKey::String(JsString::from(*name)),
                NON_ENUMERABLE_DATA_ATTRIBUTES,
            )?;
        }
        self.intl_to_string_tag(intl, "Intl")?;
        Ok(intl)
    }

    fn intl_to_string_tag(&mut self, object: ObjectId, tag: &str) -> Result<(), InterpreterError> {
        let key = RuntimePropertyKey::Symbol(WellKnownSymbol::ToStringTag.id());
        self.set_object_runtime_property(object, key.clone(), Value::str(tag))?;
        self.set_own_property_attributes(
            object,
            &key,
            PropertyAttributes {
                writable: false,
                enumerable: false,
                configurable: true,
            },
        )
    }

    /// `new Intl.<service>(locales, options)`; calling one without `new`
    /// constructs too.
    pub(super) fn construct_intl_service(
        &mut self,
        module: &Ir3Module,
        service: &str,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let locales = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let options = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
        if matches!(options, Value::Null) {
            return Err(InterpreterError::TypeError {
                expected: format!("an options object for Intl.{service}"),
                got: "null".to_string(),
            });
        }
        let requested = self.intl_requested_locale(&locales)?;
        let resolved = match service {
            "NumberFormat" => self.intl_number_format_options(module, requested, &options)?,
            "DateTimeFormat" => self.intl_date_time_format_options(
                module,
                requested,
                &options,
                DateOptionsFor::Constructor,
            )?,
            "Collator" => self.intl_collator_options(module, requested, &options)?,
            "PluralRules" => self.intl_plural_rules_options(module, requested, &options)?,
            "RelativeTimeFormat" => {
                self.intl_relative_time_format_options(module, requested, &options)?
            }
            "ListFormat" => self.intl_list_format_options(module, requested, &options)?,
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "an Intl service constructor".to_string(),
                    got: other.to_string(),
                });
            }
        };
        let resolved_id = self.alloc_object_with_properties(&resolved)?;
        let object = self.alloc_object_with_prototype(None)?;
        self.set_object_brand(object, &format!("Intl.{service}"))?;
        self.set_object_property(object, "__resolved".to_string(), Value::Object(resolved_id))?;
        let methods: &[&str] = match service {
            "NumberFormat" => &["format", "resolvedOptions"],
            "DateTimeFormat" => &["format", "formatToParts", "resolvedOptions"],
            "Collator" => &["compare", "resolvedOptions"],
            "RelativeTimeFormat" | "ListFormat" => &["format", "formatToParts", "resolvedOptions"],
            _ => &["select", "resolvedOptions"],
        };
        for method in methods {
            let bound = Value::BuiltinFunction(BuiltinFunction {
                kind: BuiltinFunctionKind::IntlMethod,
                module_specifier: BuiltinModuleSpecifier::from_nonempty(&format!(
                    "{service}.{method}"
                )),
                iterator_handle: None,
                bound_object: Some(object.0),
            });
            self.set_object_property(object, (*method).to_string(), bound)?;
        }
        let mut hidden = vec!["__resolved"];
        hidden.extend_from_slice(methods);
        self.hide_internal_slots(object, &hidden)?;
        self.intl_to_string_tag(object, &format!("Intl.{service}"))?;
        Ok(Value::Object(object))
    }

    /// A bound service method: `format`, `compare`, `select` or
    /// `resolvedOptions`.
    pub(super) fn intl_method(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let name = builtin
            .module_specifier
            .0
            .as_deref()
            .unwrap_or_default()
            .to_string();
        let (service, method) = name.split_once('.').unwrap_or(("", ""));
        let resolved = builtin
            .bound_object
            .map(ObjectId)
            .and_then(|object| self.heap.get(object.0 as usize))
            .and_then(|object| object.properties.get("__resolved").cloned());
        let Some(Value::Object(resolved)) = resolved else {
            return Err(InterpreterError::TypeError {
                expected: format!("an Intl.{service} object"),
                got: "an object without Intl state".to_string(),
            });
        };
        let arg = |core: &Self, index: u32| -> Result<Value, InterpreterError> {
            Ok(core.builtin_arg(args, index)?.unwrap_or(Value::Undefined))
        };
        match method {
            "resolvedOptions" => {
                let copy = self.alloc_object_with_prototype(None)?;
                let entries: Vec<(String, Value)> = self
                    .heap
                    .get(resolved.0 as usize)
                    .map(|object| {
                        object
                            .properties
                            .exact_entries()
                            .into_iter()
                            .map(|(key, value)| (key.to_string(), value.clone()))
                            .collect()
                    })
                    .unwrap_or_default();
                for (key, value) in entries {
                    let value = match value {
                        // pluralCategories: a fresh array each call.
                        Value::Object(list) => {
                            let values = self.array_like_values(list)?;
                            Value::Object(self.alloc_array_from_values(&values)?)
                        }
                        other => other,
                    };
                    self.set_object_property(copy, key, value)?;
                }
                Ok(Value::Object(copy))
            }
            "format" if service == "NumberFormat" => {
                let value = arg(self, 0)?;
                if matches!(value, Value::BigInt(_)) {
                    return Err(InterpreterError::TypeError {
                        expected: "a Number Intl.NumberFormat formats".to_string(),
                        got: "BigInt".to_string(),
                    });
                }
                let number = self.intl_to_number(module, value)?;
                let (locale, options) = self.intl_number_options_from(resolved)?;
                number_locale::format_number_locale(number, Some(&locale), &options)
                    .map(Value::str)
                    .map_err(Self::intl_number_error)
            }
            // ECMA-402 17.3.3-4: ToNumber(value), ToString(unit), then the
            // pattern for the unit, sign and plural category.
            "format" | "formatToParts" if service == "RelativeTimeFormat" => {
                let value = self.intl_to_number(module, arg(self, 0)?)?;
                let unit = arg(self, 1)?;
                let unit = self.intl_to_string(module, unit)?;
                let parts = self.intl_relative_time_parts(resolved, value, &unit, method)?;
                self.intl_parts_result(method, parts)
            }
            // ECMA-402 13.3.3-4: StringListFromIterable, then the patterns.
            "format" | "formatToParts" if service == "ListFormat" => {
                let items = match arg(self, 0)? {
                    Value::Undefined => Vec::new(),
                    _ => self.intl_string_list(module, args)?,
                };
                let parts = self.intl_list_parts(resolved, &items)?;
                self.intl_parts_result(method, parts)
            }
            // format and formatToParts (ECMA-402 11.4.3, 11.4.4) lay out
            // the same pieces; formatToParts returns them as { type, value }.
            "format" | "formatToParts" => {
                let date = arg(self, 0)?;
                let time = match date {
                    Value::Undefined => {
                        let now = self.dispatch_builtin_hostcall(
                            "builtin:DateNow",
                            RegRange {
                                start: args.start,
                                count: 0,
                            },
                            Some(module),
                        )?;
                        self.intl_to_number(module, now)?
                    }
                    Value::Object(id)
                        if self
                            .heap
                            .get(id.0 as usize)
                            .and_then(|object| object.properties.get("__timestamp"))
                            .is_some() =>
                    {
                        match self
                            .heap
                            .get(id.0 as usize)
                            .and_then(|object| object.properties.get("__timestamp"))
                        {
                            Some(Value::Int(value)) => *value as f64,
                            Some(Value::Float(value)) => value.inner(),
                            _ => f64::NAN,
                        }
                    }
                    other => self.intl_to_number(module, other)?,
                };
                if !time.is_finite() || time.abs() > 8.64e15 {
                    return Err(InterpreterError::RangeError {
                        message: "Invalid time value".to_string(),
                    });
                }
                let request = self.intl_date_request_from(resolved)?;
                let parts = self
                    .intl_format_date_parts(time.trunc(), &request)
                    .map_err(|what| InterpreterError::TypeError {
                        expected: "a date Intl.DateTimeFormat formats".to_string(),
                        got: what,
                    })?;
                if method == "format" {
                    return Ok(Value::str(parts.joined()));
                }
                let mut list = Vec::with_capacity(parts.0.len());
                for (kind, text) in parts.0 {
                    let part = self.alloc_object_with_properties(&[
                        ("type", Value::str(kind.name())),
                        ("value", Value::str(text)),
                    ])?;
                    list.push(Value::Object(part));
                }
                Ok(Value::Object(self.alloc_array_from_values(&list)?))
            }
            "compare" => {
                let (a, b) = (arg(self, 0)?, arg(self, 1)?);
                let a = self.intl_to_string(module, a)?;
                let b = self.intl_to_string(module, b)?;
                let options = self.intl_collation_options_from(resolved);
                let ordering = collation::locale_compare(&a, &b, &options);
                Ok(Value::Int(ordering as i64))
            }
            "select" => {
                let number = self.intl_to_number(module, arg(self, 0)?)?;
                let locale = self.intl_resolved_string(resolved, "locale");
                let ordinal = self.intl_resolved_string(resolved, "type") == "ordinal";
                Ok(Value::str(intl_plural_category(&locale, ordinal, number)))
            }
            other => Err(InterpreterError::TypeError {
                expected: "an Intl service method".to_string(),
                got: other.to_string(),
            }),
        }
    }

    /// `Intl.getCanonicalLocales(locales)` (ECMA-402 8.3.1).
    pub(super) fn intl_get_canonical_locales(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let locales = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let list: Vec<Value> = self
            .intl_locale_list(&locales)?
            .into_iter()
            .map(Value::str)
            .collect();
        Ok(Value::Object(self.alloc_array_from_values(&list)?))
    }

    /// CanonicalizeLocaleList (ECMA-402 9.2.1): the canonical, unique tags.
    fn intl_locale_list(&self, locales: &Value) -> Result<Vec<String>, InterpreterError> {
        let tags = match locales {
            Value::Undefined => return Ok(Vec::new()),
            Value::Str(tag) => vec![tag.to_string()],
            Value::Object(list) => {
                let values = self.array_like_values(*list)?;
                let mut tags = Vec::with_capacity(values.len());
                for value in values {
                    match value {
                        Value::Str(tag) => tags.push(tag.to_string()),
                        other => {
                            return Err(InterpreterError::TypeError {
                                expected: "a string locale tag".to_string(),
                                got: other.type_name().to_string(),
                            });
                        }
                    }
                }
                tags
            }
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "a locale tag or a list of them".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        let mut canonical: Vec<String> = Vec::with_capacity(tags.len());
        for tag in tags {
            let tag =
                canonicalize_locale_tag(&tag).ok_or_else(|| InterpreterError::RangeError {
                    message: format!("Incorrect locale information provided: {tag}"),
                })?;
            if !canonical.contains(&tag) {
                canonical.push(tag);
            }
        }
        Ok(canonical)
    }

    fn intl_option(
        &mut self,
        module: &Ir3Module,
        options: &Value,
        key: &str,
    ) -> Result<Value, InterpreterError> {
        match options {
            Value::Object(id) => {
                self.proxy_aware_get_property(Some(module), *id, key, options.clone(), 0)
            }
            _ => Ok(Value::Undefined),
        }
    }

    /// GetOption for a string option restricted to `allowed`.
    fn intl_string_option(
        &mut self,
        module: &Ir3Module,
        options: &Value,
        key: &str,
        allowed: &[&str],
        service: &str,
    ) -> Result<Option<String>, InterpreterError> {
        let value = self.intl_option(module, options, key)?;
        if matches!(value, Value::Undefined) {
            return Ok(None);
        }
        let text = self.intl_to_string(module, value)?;
        if !allowed.contains(&text.as_str()) {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "Value {text} out of range for Intl.{service} options property {key}"
                ),
            });
        }
        Ok(Some(text))
    }

    fn intl_bool_option(
        &mut self,
        module: &Ir3Module,
        options: &Value,
        key: &str,
    ) -> Result<Option<bool>, InterpreterError> {
        let value = self.intl_option(module, options, key)?;
        Ok((!matches!(value, Value::Undefined)).then(|| value.is_truthy()))
    }

    fn intl_refusal(service: &str, what: String) -> InterpreterError {
        InterpreterError::TypeError {
            expected: format!("a locale and options Intl.{service} supports"),
            got: what,
        }
    }

    fn intl_number_error(error: number_locale::NumberLocaleError) -> InterpreterError {
        match error {
            number_locale::NumberLocaleError::Range(message) => {
                InterpreterError::RangeError { message }
            }
            number_locale::NumberLocaleError::Unsupported(what) => {
                Self::intl_refusal("NumberFormat", what)
            }
        }
    }

    fn intl_number_format_options(
        &mut self,
        module: &Ir3Module,
        requested: Option<String>,
        options: &Value,
    ) -> Result<Vec<(&'static str, Value)>, InterpreterError> {
        const SERVICE: &str = "NumberFormat";
        self.intl_string_option(
            module,
            options,
            "localeMatcher",
            &["lookup", "best fit"],
            SERVICE,
        )?;
        let numbering = self.intl_option(module, options, "numberingSystem")?;
        if !matches!(numbering, Value::Undefined)
            && self.intl_to_string(module, numbering)? != "latn"
        {
            return Err(Self::intl_refusal(
                SERVICE,
                "a numberingSystem other than latn".to_string(),
            ));
        }
        let style = self
            .intl_string_option(
                module,
                options,
                "style",
                &["decimal", "percent", "currency", "unit"],
                SERVICE,
            )?
            .unwrap_or_else(|| "decimal".to_string());
        let currency = self.intl_option(module, options, "currency")?;
        let currency = match currency {
            Value::Undefined => None,
            other => Some(self.intl_to_string(module, other)?.to_ascii_uppercase()),
        };
        for (key, default) in NUMBER_FORMAT_DEFAULTED_OPTIONS {
            let value = self.intl_option(module, options, key)?;
            if matches!(value, Value::Undefined) {
                continue;
            }
            if self.intl_to_string(module, value)? != default {
                return Err(Self::intl_refusal(SERVICE, format!("option {key}")));
            }
        }
        for key in [
            "unit",
            "minimumSignificantDigits",
            "maximumSignificantDigits",
        ] {
            if !matches!(self.intl_option(module, options, key)?, Value::Undefined) {
                return Err(Self::intl_refusal(SERVICE, format!("option {key}")));
            }
        }
        let locale_style = match style.as_str() {
            "decimal" => number_locale::NumberLocaleStyle::Decimal,
            "percent" => number_locale::NumberLocaleStyle::Percent,
            "currency" => match &currency {
                Some(code) => number_locale::NumberLocaleStyle::Currency(code.clone()),
                None => {
                    return Err(InterpreterError::TypeError {
                        expected: "a currency code with style \"currency\"".to_string(),
                        got: "undefined".to_string(),
                    });
                }
            },
            _ => return Err(Self::intl_refusal(SERVICE, "style \"unit\"".to_string())),
        };
        let mut parsed = number_locale::NumberLocaleOptions {
            style: locale_style,
            ..Default::default()
        };
        for (key, slot) in [
            ("minimumFractionDigits", &mut parsed.minimum_fraction_digits),
            ("maximumFractionDigits", &mut parsed.maximum_fraction_digits),
        ] {
            let value = self.intl_option(module, options, key)?;
            if matches!(value, Value::Undefined) {
                continue;
            }
            let number = self.intl_to_number(module, value)?;
            if !(0.0..=100.0).contains(&number) {
                return Err(InterpreterError::RangeError {
                    message: format!("{key} value is out of range."),
                });
            }
            *slot = Some(number.floor() as u32);
        }
        let grouping = self.intl_option(module, options, "useGrouping")?;
        // ES2023 GetBooleanOrStringNumberFormatOption: true is "always", any
        // falsy value (0, "", null, NaN) false, the strings "true" and
        // "false" the default; temporal-polyfill passes `useGrouping: 0`.
        let use_grouping = match &grouping {
            Value::Undefined => Value::str("auto"),
            Value::Bool(true) => Value::str("always"),
            falsy if !falsy.is_truthy() => Value::Bool(false),
            other => {
                let text = self.intl_to_string(module, other.clone())?;
                match text.as_str() {
                    "always" | "auto" => Value::str(text),
                    "true" | "false" => Value::str("auto"),
                    "min2" => {
                        return Err(Self::intl_refusal(SERVICE, "useGrouping min2".to_string()));
                    }
                    _ => {
                        return Err(InterpreterError::RangeError {
                            message: format!(
                                "Value {text} out of range for Intl.NumberFormat options property useGrouping"
                            ),
                        });
                    }
                }
            }
        };
        parsed.use_grouping = !matches!(use_grouping, Value::Bool(false));
        let locale = requested.unwrap_or_else(|| "en-US".to_string());
        let (minimum, maximum) = number_locale::resolved_fraction_digits(Some(&locale), &parsed)
            .map_err(Self::intl_number_error)?;
        let mut resolved = vec![
            ("locale", Value::str(locale)),
            ("numberingSystem", Value::str("latn")),
            ("style", Value::str(style)),
        ];
        if let number_locale::NumberLocaleStyle::Currency(code) = &parsed.style {
            resolved.push(("currency", Value::str(code.clone())));
            resolved.push(("currencyDisplay", Value::str("symbol")));
            resolved.push(("currencySign", Value::str("standard")));
        }
        resolved.extend([
            ("minimumIntegerDigits", Value::Int(1)),
            ("minimumFractionDigits", Value::Int(i64::from(minimum))),
            ("maximumFractionDigits", Value::Int(i64::from(maximum))),
            ("useGrouping", use_grouping),
            ("notation", Value::str("standard")),
            ("signDisplay", Value::str("auto")),
            ("roundingIncrement", Value::Int(1)),
            ("roundingMode", Value::str("halfExpand")),
            ("roundingPriority", Value::str("auto")),
            ("trailingZeroDisplay", Value::str("auto")),
        ]);
        Ok(resolved)
    }

    /// The locale and formatter options a NumberFormat resolved to.
    fn intl_number_options_from(
        &self,
        resolved: ObjectId,
    ) -> Result<(String, number_locale::NumberLocaleOptions), InterpreterError> {
        Ok(intl_number_options_from_lookup(|key| {
            self.intl_resolved_value(resolved, key)
        }))
    }

    /// The service locale a `locales` argument requests: its first tag. A
    /// well-formed tag whose language subtag has five to eight letters
    /// (`new Intl.Collator('generic')`, fast-levenshtein; temporal-polyfill's
    /// `toLocaleString('fullwide')`) names no locale ICU has data for: Node
    /// falls back to its default locale, en-US, as the services do here
    /// (`None`). A real language the formatters do not cover still refuses.
    pub(super) fn intl_requested_locale(
        &self,
        locales: &Value,
    ) -> Result<Option<String>, InterpreterError> {
        Ok(self
            .intl_locale_list(locales)?
            .into_iter()
            .next()
            .filter(|tag| !(5..=8).contains(&tag.split('-').next().unwrap_or_default().len())))
    }

    /// ECMA-402 15.4.1 Number.prototype.toLocaleString(locales, options):
    /// format as `new Intl.NumberFormat(locales, options).format(x)` would,
    /// with the same option reading and refusals (no service object).
    pub(super) fn intl_format_number(
        &mut self,
        module: &Ir3Module,
        number: f64,
        locales: &Value,
        options: &Value,
    ) -> Result<Value, InterpreterError> {
        if matches!(options, Value::Null) {
            return Err(InterpreterError::TypeError {
                expected: "an options object for toLocaleString".to_string(),
                got: "null".to_string(),
            });
        }
        let requested = self.intl_requested_locale(locales)?;
        let resolved = self.intl_number_format_options(module, requested, options)?;
        let (locale, options) = intl_number_options_from_lookup(|key| {
            resolved
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| value.clone())
        });
        number_locale::format_number_locale(number, Some(&locale), &options)
            .map(Value::str)
            .map_err(Self::intl_number_error)
    }

    fn intl_date_time_format_options(
        &mut self,
        module: &Ir3Module,
        requested: Option<String>,
        options: &Value,
        caller: DateOptionsFor,
    ) -> Result<Vec<(&'static str, Value)>, InterpreterError> {
        const SERVICE: &str = "DateTimeFormat";
        const NUMERIC: [&str; 2] = ["numeric", "2-digit"];
        const TEXT: [&str; 3] = ["long", "short", "narrow"];
        const MONTH: [&str; 5] = ["numeric", "2-digit", "long", "short", "narrow"];
        const STYLES: [&str; 4] = ["full", "long", "medium", "short"];
        self.intl_string_option(
            module,
            options,
            "localeMatcher",
            &["lookup", "best fit"],
            SERVICE,
        )?;
        for (key, only) in [("calendar", "gregory"), ("numberingSystem", "latn")] {
            let value = self.intl_option(module, options, key)?;
            if !matches!(value, Value::Undefined) && self.intl_to_string(module, value)? != only {
                return Err(Self::intl_refusal(
                    SERVICE,
                    format!("a {key} other than {only}"),
                ));
            }
        }
        let hour12 = self.intl_bool_option(module, options, "hour12")?;
        let hour_cycle = self.intl_string_option(
            module,
            options,
            "hourCycle",
            &["h11", "h12", "h23", "h24"],
            SERVICE,
        )?;
        let zone = self.intl_option(module, options, "timeZone")?;
        if !matches!(zone, Value::Undefined) {
            let zone = self.intl_to_string(module, zone)?;
            if !["utc", "etc/utc", "gmt", "etc/gmt"].contains(&zone.to_ascii_lowercase().as_str()) {
                return Err(Self::intl_refusal(
                    SERVICE,
                    format!("timeZone {zone} (UTC only)"),
                ));
            }
        }
        let weekday = self.intl_string_option(module, options, "weekday", &TEXT, SERVICE)?;
        for key in ["era", "dayPeriod", "fractionalSecondDigits"] {
            if !matches!(self.intl_option(module, options, key)?, Value::Undefined) {
                return Err(Self::intl_refusal(SERVICE, format!("option {key}")));
            }
        }
        let year = self.intl_string_option(module, options, "year", &NUMERIC, SERVICE)?;
        let month = self.intl_string_option(module, options, "month", &MONTH, SERVICE)?;
        let day = self.intl_string_option(module, options, "day", &NUMERIC, SERVICE)?;
        let hour = self.intl_string_option(module, options, "hour", &NUMERIC, SERVICE)?;
        let minute = self.intl_string_option(module, options, "minute", &NUMERIC, SERVICE)?;
        let second = self.intl_string_option(module, options, "second", &NUMERIC, SERVICE)?;
        let time_zone_name = self.intl_option(module, options, "timeZoneName")?;
        let time_zone_name = match time_zone_name {
            Value::Undefined => None,
            other => match self.intl_to_string(module, other)?.as_str() {
                "short" => Some("short"),
                "long" => Some("long"),
                other => return Err(Self::intl_refusal(SERVICE, format!("timeZoneName {other}"))),
            },
        };
        self.intl_string_option(
            module,
            options,
            "formatMatcher",
            &["basic", "best fit"],
            SERVICE,
        )?;
        let date_style = self.intl_string_option(module, options, "dateStyle", &STYLES, SERVICE)?;
        let time_style = self.intl_string_option(module, options, "timeStyle", &STYLES, SERVICE)?;
        let has_date = [&weekday, &year, &month, &day]
            .iter()
            .any(|value| value.is_some());
        let has_time = [&hour, &minute, &second]
            .iter()
            .any(|value| value.is_some());
        let has_components = has_date || has_time || time_zone_name.is_some();
        if (date_style.is_some() || time_style.is_some()) && has_components {
            return Err(InterpreterError::TypeError {
                expected: "dateStyle and timeStyle without date-time component options".to_string(),
                got: "both".to_string(),
            });
        }
        if (caller == DateOptionsFor::DateString && time_style.is_some())
            || (caller == DateOptionsFor::TimeString && date_style.is_some())
        {
            return Err(InterpreterError::TypeError {
                expected: "a style the method formats".to_string(),
                got: "timeStyle for a date string, or dateStyle for a time string".to_string(),
            });
        }
        // ToDateTimeOptions: the required fields decide whether the
        // defaults are added.
        let styled = date_style.is_some() || time_style.is_some();
        let need_defaults = !styled
            && match caller {
                DateOptionsFor::DateString => !has_date,
                DateOptionsFor::TimeString => !has_time,
                DateOptionsFor::Constructor | DateOptionsFor::String => !has_date && !has_time,
            };
        let default_date = need_defaults
            && matches!(
                caller,
                DateOptionsFor::Constructor | DateOptionsFor::DateString | DateOptionsFor::String
            );
        let default_time =
            need_defaults && matches!(caller, DateOptionsFor::TimeString | DateOptionsFor::String);
        let locale = requested.unwrap_or_else(|| "en-US".to_string());
        let english = locale.eq_ignore_ascii_case("en") || locale.eq_ignore_ascii_case("en-US");
        let cycle = match (hour12, hour_cycle.as_deref()) {
            (Some(true), _) => "h12",
            (Some(false), _) => "h23",
            (None, Some("h12")) => "h12",
            (None, Some("h23")) => "h23",
            (None, Some(other)) => {
                return Err(Self::intl_refusal(SERVICE, format!("hourCycle {other}")));
            }
            (None, None) if english => "h12",
            (None, None) => "h23",
        };
        let mut resolved = vec![
            ("locale", Value::str(locale.clone())),
            ("calendar", Value::str("gregory")),
            ("numberingSystem", Value::str("latn")),
            ("timeZone", Value::str("UTC")),
        ];
        let numeric = || Some("numeric".to_string());
        let (year, month, day) = if default_date {
            (numeric(), numeric(), numeric())
        } else {
            (year, month, day)
        };
        let (hour, minute, second) = if default_time {
            (numeric(), numeric(), numeric())
        } else {
            (hour, minute, second)
        };
        if hour.is_some() || time_style.is_some() {
            resolved.push(("hourCycle", Value::str(cycle)));
            resolved.push(("hour12", Value::Bool(cycle == "h12")));
        }
        for (key, value) in [
            ("weekday", weekday),
            ("year", year),
            ("month", month),
            ("day", day),
            ("hour", hour),
            ("minute", minute),
            ("second", second),
            ("timeZoneName", time_zone_name.map(str::to_string)),
            ("dateStyle", date_style),
            ("timeStyle", time_style),
        ] {
            if let Some(value) = value {
                resolved.push((key, Value::str(value)));
            }
        }
        // Validate against a fixed date: a layout the formatter lacks is a
        // refusal now, not on the first format call.
        let resolved_id = self.alloc_object_with_properties(&resolved)?;
        let request = self.intl_date_request_from(resolved_id)?;
        if let Err(what) = self.intl_format_date(0.0, &request) {
            return Err(Self::intl_refusal(SERVICE, what));
        }
        Ok(resolved)
    }

    /// Date.prototype.toLocaleString / toLocaleDateString /
    /// toLocaleTimeString with options (ECMA-402 20.4.1-3): a
    /// DateTimeFormat over ToDateTimeOptions for the method. `time` is the
    /// date's finite time value.
    pub(super) fn date_to_locale_with_options(
        &mut self,
        module: &Ir3Module,
        caller: DateOptionsFor,
        time: f64,
        locales: &Value,
        options: &Value,
    ) -> Result<Value, InterpreterError> {
        if matches!(options, Value::Null) {
            return Err(InterpreterError::TypeError {
                expected: "an options object for Date.prototype.toLocaleString".to_string(),
                got: "null".to_string(),
            });
        }
        let requested = self.intl_locale_list(locales)?.into_iter().next();
        let resolved = self.intl_date_time_format_options(module, requested, options, caller)?;
        let resolved_id = self.alloc_object_with_properties(&resolved)?;
        let request = self.intl_date_request_from(resolved_id)?;
        self.intl_format_date(time, &request)
            .map(Value::str)
            .map_err(|what| Self::intl_refusal("DateTimeFormat", what))
    }

    /// What a DateTimeFormat formats, read back from its resolved options.
    fn intl_date_request_from(
        &self,
        resolved: ObjectId,
    ) -> Result<IntlDateRequest, InterpreterError> {
        let text = |key: &str| {
            let value = self.intl_resolved_string(resolved, key);
            (!value.is_empty()).then_some(value)
        };
        let digits = |value: Option<String>| {
            value.map(|value| match value.as_str() {
                "2-digit" => Digits::TwoDigit,
                _ => Digits::Numeric,
            })
        };
        let width = |value: Option<String>| {
            value.map(|value| match value.as_str() {
                "long" => TextWidth::Long,
                "narrow" => TextWidth::Narrow,
                _ => TextWidth::Short,
            })
        };
        let style = |value: Option<String>| {
            value.map(|value| match value.as_str() {
                "full" => FormatStyle::Full,
                "long" => FormatStyle::Long,
                "medium" => FormatStyle::Medium,
                _ => FormatStyle::Short,
            })
        };
        let month = text("month").map(|month| match month.as_str() {
            "numeric" => MonthStyle::Digits(Digits::Numeric),
            "2-digit" => MonthStyle::Digits(Digits::TwoDigit),
            "long" => MonthStyle::Text(TextWidth::Long),
            "narrow" => MonthStyle::Text(TextWidth::Narrow),
            _ => MonthStyle::Text(TextWidth::Short),
        });
        let hour12 = !matches!(
            self.intl_resolved_value(resolved, "hour12"),
            Some(Value::Bool(false))
        ) && (self.intl_resolved_value(resolved, "hour12").is_some()
            || matches!(
                self.intl_resolved_string(resolved, "locale")
                    .to_ascii_lowercase()
                    .as_str(),
                "en" | "en-us"
            ));
        Ok(IntlDateRequest {
            locale: self.intl_resolved_string(resolved, "locale"),
            date_style: style(text("dateStyle")),
            time_style: style(text("timeStyle")),
            components: DateComponents {
                weekday: width(text("weekday")),
                year: digits(text("year")),
                month,
                day: digits(text("day")),
                hour: digits(text("hour")),
                minute: digits(text("minute")),
                second: digits(text("second")),
                hour12,
                time_zone_name: width(text("timeZoneName")),
            },
        })
    }

    fn intl_format_date(&self, time: f64, request: &IntlDateRequest) -> Result<String, String> {
        self.intl_format_date_parts(time, request)
            .map(|parts| parts.joined())
    }

    /// The typed pieces of a formatted date (formatToParts; `format` joins
    /// them).
    fn intl_format_date_parts(
        &self,
        time: f64,
        request: &IntlDateRequest,
    ) -> Result<date_locale::DateParts, String> {
        use date_math::*;
        let fields = date_locale::DateFields {
            year: year_from_time(time) as i64,
            month: month_from_time(time) as u32,
            day: date_from_time(time) as u32,
            hour: hour(time) as u32,
            minute: minute(time) as u32,
            second: second(time) as u32,
        };
        let locale = Some(request.locale.as_str());
        if request.date_style.is_some() || request.time_style.is_some() {
            return date_locale::format_date_styles_parts(
                fields,
                locale,
                request.date_style,
                request.time_style,
                request.components.hour12,
            );
        }
        // The locale's default numeric date, time or both (the layouts every
        // formatted locale has), with its default hour cycle.
        let english = matches!(request.locale.to_ascii_lowercase().as_str(), "en" | "en-us");
        let numeric = Some(Digits::Numeric);
        let date = DateComponents {
            weekday: None,
            year: numeric,
            month: Some(MonthStyle::Digits(Digits::Numeric)),
            day: numeric,
            hour: None,
            minute: None,
            second: None,
            hour12: english,
            time_zone_name: None,
        };
        let time = DateComponents {
            year: None,
            month: None,
            day: None,
            hour: numeric,
            minute: numeric,
            second: numeric,
            ..date
        };
        let both = DateComponents {
            hour: numeric,
            minute: numeric,
            second: numeric,
            ..date
        };
        let kind = if request.components == date {
            Some(date_locale::DateLocaleKind::Date)
        } else if request.components == time {
            Some(date_locale::DateLocaleKind::Time)
        } else if request.components == both {
            Some(date_locale::DateLocaleKind::DateTime)
        } else {
            None
        };
        match kind {
            Some(kind) => date_locale::format_date_locale_parts(fields, locale, kind),
            None => date_locale::format_date_components_parts(fields, locale, &request.components),
        }
    }

    fn intl_collator_options(
        &mut self,
        module: &Ir3Module,
        requested: Option<String>,
        options: &Value,
    ) -> Result<Vec<(&'static str, Value)>, InterpreterError> {
        const SERVICE: &str = "Collator";
        let usage = self
            .intl_string_option(module, options, "usage", &["sort", "search"], SERVICE)?
            .unwrap_or_else(|| "sort".to_string());
        self.intl_string_option(
            module,
            options,
            "localeMatcher",
            &["lookup", "best fit"],
            SERVICE,
        )?;
        let collation = self.intl_option(module, options, "collation")?;
        if !matches!(collation, Value::Undefined)
            && self.intl_to_string(module, collation)? != "default"
        {
            return Err(Self::intl_refusal(
                SERVICE,
                "a collation other than default".to_string(),
            ));
        }
        let numeric = self
            .intl_bool_option(module, options, "numeric")?
            .unwrap_or(false);
        let case_first = self
            .intl_string_option(
                module,
                options,
                "caseFirst",
                &["upper", "lower", "false"],
                SERVICE,
            )?
            .unwrap_or_else(|| "false".to_string());
        if case_first != "false" {
            return Err(Self::intl_refusal(
                SERVICE,
                format!("caseFirst {case_first}"),
            ));
        }
        let sensitivity = self
            .intl_string_option(
                module,
                options,
                "sensitivity",
                &["base", "accent", "case", "variant"],
                SERVICE,
            )?
            .unwrap_or_else(|| "variant".to_string());
        let ignore_punctuation = self
            .intl_bool_option(module, options, "ignorePunctuation")?
            .unwrap_or(false);
        let locale = requested.unwrap_or_else(|| "en-US".to_string());
        let language = locale.split('-').next().unwrap_or_default();
        // Languages whose collation is the root order the engine implements.
        if !["en", "de", "fr", "it", "nl", "pt"].contains(&language) {
            return Err(Self::intl_refusal(
                SERVICE,
                format!("locale {locale:?} (root-order locales: en, de, fr, it, nl, pt)"),
            ));
        }
        Ok(vec![
            ("locale", Value::str(locale)),
            ("usage", Value::str(usage)),
            ("sensitivity", Value::str(sensitivity)),
            ("ignorePunctuation", Value::Bool(ignore_punctuation)),
            ("collation", Value::str("default")),
            ("numeric", Value::Bool(numeric)),
            ("caseFirst", Value::str(case_first)),
        ])
    }

    fn intl_collation_options_from(&self, resolved: ObjectId) -> collation::CollationOptions {
        collation::CollationOptions {
            sensitivity: match self.intl_resolved_string(resolved, "sensitivity").as_str() {
                "base" => collation::Sensitivity::Base,
                "accent" => collation::Sensitivity::Accent,
                "case" => collation::Sensitivity::Case,
                _ => collation::Sensitivity::Variant,
            },
            numeric: matches!(
                self.intl_resolved_value(resolved, "numeric"),
                Some(Value::Bool(true))
            ),
            ignore_punctuation: matches!(
                self.intl_resolved_value(resolved, "ignorePunctuation"),
                Some(Value::Bool(true))
            ),
        }
    }

    fn intl_plural_rules_options(
        &mut self,
        module: &Ir3Module,
        requested: Option<String>,
        options: &Value,
    ) -> Result<Vec<(&'static str, Value)>, InterpreterError> {
        const SERVICE: &str = "PluralRules";
        self.intl_string_option(
            module,
            options,
            "localeMatcher",
            &["lookup", "best fit"],
            SERVICE,
        )?;
        let plural_type = self
            .intl_string_option(module, options, "type", &["cardinal", "ordinal"], SERVICE)?
            .unwrap_or_else(|| "cardinal".to_string());
        for key in [
            "minimumIntegerDigits",
            "minimumFractionDigits",
            "maximumFractionDigits",
            "minimumSignificantDigits",
            "maximumSignificantDigits",
        ] {
            if !matches!(self.intl_option(module, options, key)?, Value::Undefined) {
                return Err(Self::intl_refusal(SERVICE, format!("option {key}")));
            }
        }
        let locale = requested.unwrap_or_else(|| "en-US".to_string());
        let categories =
            intl_plural_categories(&locale, plural_type == "ordinal").ok_or_else(|| {
                Self::intl_refusal(
                    SERVICE,
                    format!("locale {locale:?} (plural locales: en, de, fr, ja, zh, ko)"),
                )
            })?;
        let categories: Vec<Value> = categories
            .iter()
            .map(|category| Value::str(*category))
            .collect();
        let categories = Value::Object(self.alloc_array_from_values(&categories)?);
        Ok(vec![
            ("locale", Value::str(locale)),
            ("type", Value::str(plural_type)),
            ("minimumIntegerDigits", Value::Int(1)),
            ("minimumFractionDigits", Value::Int(0)),
            ("maximumFractionDigits", Value::Int(3)),
            ("pluralCategories", categories),
            ("roundingIncrement", Value::Int(1)),
            ("roundingMode", Value::str("halfExpand")),
            ("roundingPriority", Value::str("auto")),
            ("trailingZeroDisplay", Value::str("auto")),
        ])
    }

    /// `new Intl.RelativeTimeFormat(locales, options)` (ECMA-402 17.1.1):
    /// localeMatcher, numberingSystem (Latin digits only), style, numeric.
    fn intl_relative_time_format_options(
        &mut self,
        module: &Ir3Module,
        requested: Option<String>,
        options: &Value,
    ) -> Result<Vec<(&'static str, Value)>, InterpreterError> {
        const SERVICE: &str = "RelativeTimeFormat";
        self.intl_string_option(
            module,
            options,
            "localeMatcher",
            &["lookup", "best fit"],
            SERVICE,
        )?;
        let numbering_system = self.intl_option(module, options, "numberingSystem")?;
        if !matches!(numbering_system, Value::Undefined) {
            let system = self.intl_to_string(module, numbering_system)?;
            if system != "latn" {
                return Err(Self::intl_refusal(
                    SERVICE,
                    format!("numberingSystem {system:?}"),
                ));
            }
        }
        let style = self
            .intl_string_option(
                module,
                options,
                "style",
                &["long", "short", "narrow"],
                SERVICE,
            )?
            .unwrap_or_else(|| "long".to_string());
        let numeric = self
            .intl_string_option(module, options, "numeric", &["always", "auto"], SERVICE)?
            .unwrap_or_else(|| "always".to_string());
        let locale = Self::intl_pattern_locale(SERVICE, requested)?;
        Ok(vec![
            ("locale", Value::str(locale)),
            ("style", Value::str(style)),
            ("numeric", Value::str(numeric)),
            ("numberingSystem", Value::str("latn")),
        ])
    }

    /// `new Intl.ListFormat(locales, options)` (ECMA-402 13.1.1):
    /// localeMatcher, type, style.
    fn intl_list_format_options(
        &mut self,
        module: &Ir3Module,
        requested: Option<String>,
        options: &Value,
    ) -> Result<Vec<(&'static str, Value)>, InterpreterError> {
        const SERVICE: &str = "ListFormat";
        self.intl_string_option(
            module,
            options,
            "localeMatcher",
            &["lookup", "best fit"],
            SERVICE,
        )?;
        let list_type = self
            .intl_string_option(
                module,
                options,
                "type",
                &["conjunction", "disjunction", "unit"],
                SERVICE,
            )?
            .unwrap_or_else(|| "conjunction".to_string());
        let style = self
            .intl_string_option(
                module,
                options,
                "style",
                &["long", "short", "narrow"],
                SERVICE,
            )?
            .unwrap_or_else(|| "long".to_string());
        let locale = Self::intl_pattern_locale(SERVICE, requested)?;
        Ok(vec![
            ("locale", Value::str(locale)),
            ("type", Value::str(list_type)),
            ("style", Value::str(style)),
        ])
    }

    /// The requested locale (default en-US) when the pattern tables cover
    /// its language, else a typed refusal.
    fn intl_pattern_locale(
        service: &str,
        requested: Option<String>,
    ) -> Result<String, InterpreterError> {
        let locale = requested.unwrap_or_else(|| "en-US".to_string());
        if intl_pattern_language(&locale).is_none() {
            return Err(Self::intl_refusal(
                service,
                format!("locale {locale:?} (pattern locales: en, de, ja, zh, ko)"),
            ));
        }
        Ok(locale)
    }

    /// ECMA-402 17.5.2 PartitionRelativeTimePattern: a `numeric: "auto"`
    /// phrase for the value if the locale has one, else the number between
    /// the pattern's literals for the unit, sign and plural category.
    fn intl_relative_time_parts(
        &self,
        resolved: ObjectId,
        value: f64,
        unit: &str,
        method: &str,
    ) -> Result<FormattedParts, InterpreterError> {
        if !value.is_finite() {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "Value need to be finite number for Intl.RelativeTimeFormat.prototype.{method}()"
                ),
            });
        }
        let singular = unit.strip_suffix('s').unwrap_or(unit);
        let Some(unit) = RELATIVE_TIME_UNITS
            .iter()
            .copied()
            .find(|candidate| *candidate == singular)
        else {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "Invalid unit argument for Intl.RelativeTimeFormat.prototype.{method}() '{unit}'"
                ),
            });
        };
        let locale = self.intl_resolved_string(resolved, "locale");
        let style = self.intl_resolved_string(resolved, "style");
        let language = intl_pattern_language(&locale).unwrap_or("en");
        let Some((_, _, _, patterns, auto)) =
            RELATIVE_TIME_PATTERNS
                .iter()
                .find(|(lang, pattern_style, pattern_unit, _, _)| {
                    *lang == language && *pattern_style == style && *pattern_unit == unit
                })
        else {
            return Err(Self::intl_refusal(
                "RelativeTimeFormat",
                format!("{style} {unit} patterns for {locale:?}"),
            ));
        };
        if self.intl_resolved_string(resolved, "numeric") == "auto"
            && value.fract() == 0.0
            && value.abs() <= 2.0
        {
            // ToString(-0) is "0", so -0 takes the 0 phrase too.
            let key = value as i8;
            if let Some((_, phrase)) = auto.iter().find(|(entry, _)| *entry == key) {
                return Ok(vec![("literal", (*phrase).to_string(), None)]);
            }
        }
        let past = value < 0.0 || (value == 0.0 && value.is_sign_negative());
        let formatted = number_locale::format_number_locale(
            value.abs(),
            Some(&locale),
            &number_locale::NumberLocaleOptions::default(),
        )
        .map_err(Self::intl_number_error)?;
        // ResolvePlural sees the number as formatted (1.0001 is "1").
        let one = formatted == "1" && intl_plural_category(&locale, false, 1.0) == "one";
        let pattern = patterns[usize::from(past) * 2 + usize::from(!one)];
        let (prefix, suffix) = pattern.split_once("{0}").unwrap_or((pattern, ""));
        let (group, decimal) = if language == "de" {
            ('.', ',')
        } else {
            (',', '.')
        };
        let mut parts = Vec::new();
        if !prefix.is_empty() {
            parts.push(("literal", prefix.to_string(), None));
        }
        parts.extend(
            intl_number_parts(&formatted, group, decimal)
                .into_iter()
                .map(|(kind, text)| (kind, text, Some(unit))),
        );
        if !suffix.is_empty() {
            parts.push(("literal", suffix.to_string(), None));
        }
        Ok(parts)
    }

    /// ECMA-402 13.5.3 StringListFromIterable over the first argument: a
    /// non-string element is a TypeError.
    fn intl_string_list(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
    ) -> Result<Vec<String>, InterpreterError> {
        let list = self.iterable_to_array(
            Some(module),
            RegRange {
                start: args.start,
                count: 1,
            },
        )?;
        let Value::Object(list) = list else {
            return Err(InterpreterError::TypeError {
                expected: "an iterable of strings".to_string(),
                got: list.type_name().to_string(),
            });
        };
        let mut items = Vec::new();
        for value in self.array_like_values(list)? {
            match value {
                Value::Str(text) => items.push(text.to_string()),
                other => {
                    return Err(InterpreterError::TypeError {
                        expected: "an iterable of strings for Intl.ListFormat".to_string(),
                        got: other.type_name().to_string(),
                    });
                }
            }
        }
        Ok(items)
    }

    /// ECMA-402 13.5.2 CreatePartsFromList: the elements with the pair, or
    /// the start, middle and end separators, between them.
    fn intl_list_parts(
        &self,
        resolved: ObjectId,
        items: &[String],
    ) -> Result<FormattedParts, InterpreterError> {
        let locale = self.intl_resolved_string(resolved, "locale");
        let list_type = self.intl_resolved_string(resolved, "type");
        let style = self.intl_resolved_string(resolved, "style");
        let language = intl_pattern_language(&locale).unwrap_or("en");
        let Some((_, _, _, [pair, start, middle, end])) =
            LIST_PATTERNS
                .iter()
                .find(|(lang, pattern_type, pattern_style, _)| {
                    *lang == language && *pattern_type == list_type && *pattern_style == style
                })
        else {
            return Err(Self::intl_refusal(
                "ListFormat",
                format!("{list_type} {style} patterns for {locale:?}"),
            ));
        };
        let mut parts = Vec::with_capacity(items.len().saturating_mul(2));
        for (index, item) in items.iter().enumerate() {
            if index > 0 {
                let separator = match (items.len(), index) {
                    (2, _) => pair,
                    (_, 1) => start,
                    (count, index) if index == count - 1 => end,
                    _ => middle,
                };
                parts.push(("literal", (*separator).to_string(), None));
            }
            parts.push(("element", item.clone(), None));
        }
        Ok(parts)
    }

    /// `format` joins the parts; `formatToParts` returns them as
    /// `{ type, value }` objects (with `unit` for a relative time's number).
    fn intl_parts_result(
        &mut self,
        method: &str,
        parts: FormattedParts,
    ) -> Result<Value, InterpreterError> {
        if method == "format" {
            return Ok(Value::str(
                parts
                    .iter()
                    .map(|(_, text, _)| text.as_str())
                    .collect::<String>(),
            ));
        }
        let mut list = Vec::with_capacity(parts.len());
        for (kind, text, unit) in parts {
            let mut properties = vec![("type", Value::str(kind)), ("value", Value::str(text))];
            if let Some(unit) = unit {
                properties.push(("unit", Value::str(unit)));
            }
            list.push(Value::Object(
                self.alloc_object_with_properties(&properties)?,
            ));
        }
        Ok(Value::Object(self.alloc_array_from_values(&list)?))
    }

    fn intl_resolved_value(&self, resolved: ObjectId, key: &str) -> Option<Value> {
        self.heap
            .get(resolved.0 as usize)
            .and_then(|object| object.properties.get(key).cloned())
    }

    fn intl_resolved_string(&self, resolved: ObjectId, key: &str) -> String {
        match self.intl_resolved_value(resolved, key) {
            Some(Value::Str(text)) => text.to_string(),
            _ => String::new(),
        }
    }

    fn intl_to_number(
        &mut self,
        module: &Ir3Module,
        value: Value,
    ) -> Result<f64, InterpreterError> {
        let primitive = if value.is_object_like() {
            self.coerce_runtime_primitive(Some(module), value, false)?
        } else {
            value
        };
        Self::coerce_to_float(&primitive).ok_or_else(|| InterpreterError::TypeError {
            expected: "a value convertible to a number".to_string(),
            got: primitive.type_name().to_string(),
        })
    }

    fn intl_to_string(
        &mut self,
        module: &Ir3Module,
        value: Value,
    ) -> Result<String, InterpreterError> {
        let primitive = if value.is_object_like() {
            self.coerce_runtime_primitive(Some(module), value, true)?
        } else {
            value
        };
        if matches!(primitive, Value::Symbol(_)) {
            return Err(Self::symbol_to_string_error());
        }
        Ok(self.value_to_string(&primitive))
    }
}

/// What an Intl.DateTimeFormat lays out.
struct IntlDateRequest {
    locale: String,
    date_style: Option<FormatStyle>,
    time_style: Option<FormatStyle>,
    components: DateComponents,
}

/// A BCP 47 tag in canonical case (language lower, script title, region
/// upper), or `None` when it is not well formed.
/// The locale and formatter options of resolved NumberFormat options read
/// through `lookup` (a service's resolved object or the entries directly).
fn intl_number_options_from_lookup(
    lookup: impl Fn(&str) -> Option<Value>,
) -> (String, number_locale::NumberLocaleOptions) {
    let string = |key: &str| match lookup(key) {
        Some(Value::Str(text)) => text.to_string(),
        _ => String::new(),
    };
    let style = match string("style").as_str() {
        "percent" => number_locale::NumberLocaleStyle::Percent,
        "currency" => number_locale::NumberLocaleStyle::Currency(string("currency")),
        _ => number_locale::NumberLocaleStyle::Decimal,
    };
    let digits = |key: &str| match lookup(key) {
        Some(Value::Int(value)) => u32::try_from(value).ok(),
        _ => None,
    };
    (
        string("locale"),
        number_locale::NumberLocaleOptions {
            style,
            minimum_fraction_digits: digits("minimumFractionDigits"),
            maximum_fraction_digits: digits("maximumFractionDigits"),
            use_grouping: !matches!(lookup("useGrouping"), Some(Value::Bool(false))),
        },
    )
}

fn canonicalize_locale_tag(tag: &str) -> Option<String> {
    let mut subtags = tag.split('-');
    let language = subtags.next()?;
    let language_ok = matches!(language.len(), 2..=3 | 5..=8)
        && language.bytes().all(|byte| byte.is_ascii_alphabetic());
    if !language_ok {
        return None;
    }
    let mut out = language.to_ascii_lowercase();
    let mut in_extension = false;
    for subtag in subtags {
        if subtag.is_empty()
            || subtag.len() > 8
            || !subtag.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return None;
        }
        out.push('-');
        if subtag.len() == 1 {
            in_extension = true;
        }
        if in_extension {
            out.push_str(&subtag.to_ascii_lowercase());
        } else if subtag.len() == 4 && subtag.bytes().all(|byte| byte.is_ascii_alphabetic()) {
            let mut chars = subtag.chars();
            if let Some(first) = chars.next() {
                out.push(first.to_ascii_uppercase());
            }
            out.push_str(&chars.as_str().to_ascii_lowercase());
        } else if (subtag.len() == 2 && subtag.bytes().all(|byte| byte.is_ascii_alphabetic()))
            || (subtag.len() == 3 && subtag.bytes().all(|byte| byte.is_ascii_digit()))
        {
            out.push_str(&subtag.to_ascii_uppercase());
        } else {
            out.push_str(&subtag.to_ascii_lowercase());
        }
    }
    Some(out)
}

/// The pattern-table language of `locale`, if the tables cover it.
fn intl_pattern_language(locale: &str) -> Option<&'static str> {
    let language = intl_plural_language(locale);
    PATTERN_LANGUAGES
        .iter()
        .copied()
        .find(|candidate| *candidate == language)
}

/// A formatted number as NumberFormat parts: integer digits, group
/// separators, the decimal separator and fraction digits.
fn intl_number_parts(formatted: &str, group: char, decimal: char) -> Vec<(&'static str, String)> {
    let mut parts = Vec::new();
    let mut digits = String::new();
    let mut fraction = false;
    for ch in formatted.chars() {
        if ch == group || ch == decimal {
            if !digits.is_empty() {
                let kind = if fraction { "fraction" } else { "integer" };
                parts.push((kind, std::mem::take(&mut digits)));
            }
            if ch == decimal {
                fraction = true;
                parts.push(("decimal", ch.to_string()));
            } else {
                parts.push(("group", ch.to_string()));
            }
        } else {
            digits.push(ch);
        }
    }
    if !digits.is_empty() {
        let kind = if fraction { "fraction" } else { "integer" };
        parts.push((kind, digits));
    }
    parts
}

fn intl_plural_language(locale: &str) -> String {
    locale
        .split('-')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// The CLDR plural categories of `locale` in Node's order, or `None` for a
/// locale without rules here.
fn intl_plural_categories(locale: &str, ordinal: bool) -> Option<&'static [&'static str]> {
    Some(match (intl_plural_language(locale).as_str(), ordinal) {
        ("en", false) | ("de", false) => &["one", "other"],
        ("en", true) => &["few", "one", "two", "other"],
        ("fr", false) => &["many", "one", "other"],
        ("fr", true) => &["one", "other"],
        ("de", true) | ("ja" | "zh" | "ko", _) => &["other"],
        _ => return None,
    })
}

/// The plural category of `number` (CLDR rules for the supported locales).
fn intl_plural_category(locale: &str, ordinal: bool, number: f64) -> &'static str {
    let magnitude = number.abs();
    let integer = magnitude.fract() == 0.0 && magnitude.is_finite();
    match (intl_plural_language(locale).as_str(), ordinal) {
        ("en" | "de", false) if magnitude == 1.0 => "one",
        ("fr", false) if magnitude < 2.0 => "one",
        ("fr", true) if magnitude == 1.0 => "one",
        ("en", true) if integer => {
            let (ten, hundred) = (magnitude % 10.0, magnitude % 100.0);
            if ten == 1.0 && hundred != 11.0 {
                "one"
            } else if ten == 2.0 && hundred != 12.0 {
                "two"
            } else if ten == 3.0 && hundred != 13.0 {
                "few"
            } else {
                "other"
            }
        }
        _ => "other",
    }
}

/// Relative-time patterns by (language, style, unit): future one, future
/// other, past one, past other (`{0}` is the formatted number), and the
/// `numeric: "auto"` phrases by value. Generated from Node v22.2.0 (ICU 74)
/// output, not transcribed (bd-9vouw.171).
#[allow(clippy::type_complexity)]
const RELATIVE_TIME_PATTERNS: &[(&str, &str, &str, [&str; 4], &[(i8, &str)])] = &[
    (
        "en",
        "long",
        "second",
        [
            "in {0} second",
            "in {0} seconds",
            "{0} second ago",
            "{0} seconds ago",
        ],
        &[(0, "now")],
    ),
    (
        "en",
        "long",
        "minute",
        [
            "in {0} minute",
            "in {0} minutes",
            "{0} minute ago",
            "{0} minutes ago",
        ],
        &[(0, "this minute")],
    ),
    (
        "en",
        "long",
        "hour",
        [
            "in {0} hour",
            "in {0} hours",
            "{0} hour ago",
            "{0} hours ago",
        ],
        &[(0, "this hour")],
    ),
    (
        "en",
        "long",
        "day",
        ["in {0} day", "in {0} days", "{0} day ago", "{0} days ago"],
        &[(-1, "yesterday"), (0, "today"), (1, "tomorrow")],
    ),
    (
        "en",
        "long",
        "week",
        [
            "in {0} week",
            "in {0} weeks",
            "{0} week ago",
            "{0} weeks ago",
        ],
        &[(-1, "last week"), (0, "this week"), (1, "next week")],
    ),
    (
        "en",
        "long",
        "month",
        [
            "in {0} month",
            "in {0} months",
            "{0} month ago",
            "{0} months ago",
        ],
        &[(-1, "last month"), (0, "this month"), (1, "next month")],
    ),
    (
        "en",
        "long",
        "quarter",
        [
            "in {0} quarter",
            "in {0} quarters",
            "{0} quarter ago",
            "{0} quarters ago",
        ],
        &[
            (-1, "last quarter"),
            (0, "this quarter"),
            (1, "next quarter"),
        ],
    ),
    (
        "en",
        "long",
        "year",
        [
            "in {0} year",
            "in {0} years",
            "{0} year ago",
            "{0} years ago",
        ],
        &[(-1, "last year"), (0, "this year"), (1, "next year")],
    ),
    (
        "en",
        "short",
        "second",
        ["in {0} sec.", "in {0} sec.", "{0} sec. ago", "{0} sec. ago"],
        &[(0, "now")],
    ),
    (
        "en",
        "short",
        "minute",
        ["in {0} min.", "in {0} min.", "{0} min. ago", "{0} min. ago"],
        &[(0, "this minute")],
    ),
    (
        "en",
        "short",
        "hour",
        ["in {0} hr.", "in {0} hr.", "{0} hr. ago", "{0} hr. ago"],
        &[(0, "this hour")],
    ),
    (
        "en",
        "short",
        "day",
        ["in {0} day", "in {0} days", "{0} day ago", "{0} days ago"],
        &[(-1, "yesterday"), (0, "today"), (1, "tomorrow")],
    ),
    (
        "en",
        "short",
        "week",
        ["in {0} wk.", "in {0} wk.", "{0} wk. ago", "{0} wk. ago"],
        &[(-1, "last wk."), (0, "this wk."), (1, "next wk.")],
    ),
    (
        "en",
        "short",
        "month",
        ["in {0} mo.", "in {0} mo.", "{0} mo. ago", "{0} mo. ago"],
        &[(-1, "last mo."), (0, "this mo."), (1, "next mo.")],
    ),
    (
        "en",
        "short",
        "quarter",
        [
            "in {0} qtr.",
            "in {0} qtrs.",
            "{0} qtr. ago",
            "{0} qtrs. ago",
        ],
        &[(-1, "last qtr."), (0, "this qtr."), (1, "next qtr.")],
    ),
    (
        "en",
        "short",
        "year",
        ["in {0} yr.", "in {0} yr.", "{0} yr. ago", "{0} yr. ago"],
        &[(-1, "last yr."), (0, "this yr."), (1, "next yr.")],
    ),
    (
        "en",
        "narrow",
        "second",
        ["in {0}s", "in {0}s", "{0}s ago", "{0}s ago"],
        &[(0, "now")],
    ),
    (
        "en",
        "narrow",
        "minute",
        ["in {0}m", "in {0}m", "{0}m ago", "{0}m ago"],
        &[(0, "this minute")],
    ),
    (
        "en",
        "narrow",
        "hour",
        ["in {0}h", "in {0}h", "{0}h ago", "{0}h ago"],
        &[(0, "this hour")],
    ),
    (
        "en",
        "narrow",
        "day",
        ["in {0}d", "in {0}d", "{0}d ago", "{0}d ago"],
        &[(-1, "yesterday"), (0, "today"), (1, "tomorrow")],
    ),
    (
        "en",
        "narrow",
        "week",
        ["in {0}w", "in {0}w", "{0}w ago", "{0}w ago"],
        &[(-1, "last wk."), (0, "this wk."), (1, "next wk.")],
    ),
    (
        "en",
        "narrow",
        "month",
        ["in {0}mo", "in {0}mo", "{0}mo ago", "{0}mo ago"],
        &[(-1, "last mo."), (0, "this mo."), (1, "next mo.")],
    ),
    (
        "en",
        "narrow",
        "quarter",
        ["in {0}q", "in {0}q", "{0}q ago", "{0}q ago"],
        &[(-1, "last qtr."), (0, "this qtr."), (1, "next qtr.")],
    ),
    (
        "en",
        "narrow",
        "year",
        ["in {0}y", "in {0}y", "{0}y ago", "{0}y ago"],
        &[(-1, "last yr."), (0, "this yr."), (1, "next yr.")],
    ),
    (
        "de",
        "long",
        "second",
        [
            "in {0} Sekunde",
            "in {0} Sekunden",
            "vor {0} Sekunde",
            "vor {0} Sekunden",
        ],
        &[(0, "jetzt")],
    ),
    (
        "de",
        "long",
        "minute",
        [
            "in {0} Minute",
            "in {0} Minuten",
            "vor {0} Minute",
            "vor {0} Minuten",
        ],
        &[(0, "in dieser Minute")],
    ),
    (
        "de",
        "long",
        "hour",
        [
            "in {0} Stunde",
            "in {0} Stunden",
            "vor {0} Stunde",
            "vor {0} Stunden",
        ],
        &[(0, "in dieser Stunde")],
    ),
    (
        "de",
        "long",
        "day",
        ["in {0} Tag", "in {0} Tagen", "vor {0} Tag", "vor {0} Tagen"],
        &[
            (-2, "vorgestern"),
            (-1, "gestern"),
            (0, "heute"),
            (1, "morgen"),
            (2, "\u{fc}bermorgen"),
        ],
    ),
    (
        "de",
        "long",
        "week",
        [
            "in {0} Woche",
            "in {0} Wochen",
            "vor {0} Woche",
            "vor {0} Wochen",
        ],
        &[
            (-1, "letzte Woche"),
            (0, "diese Woche"),
            (1, "n\u{e4}chste Woche"),
        ],
    ),
    (
        "de",
        "long",
        "month",
        [
            "in {0} Monat",
            "in {0} Monaten",
            "vor {0} Monat",
            "vor {0} Monaten",
        ],
        &[
            (-1, "letzten Monat"),
            (0, "diesen Monat"),
            (1, "n\u{e4}chsten Monat"),
        ],
    ),
    (
        "de",
        "long",
        "quarter",
        [
            "in {0} Quartal",
            "in {0} Quartalen",
            "vor {0} Quartal",
            "vor {0} Quartalen",
        ],
        &[
            (-1, "letztes Quartal"),
            (0, "dieses Quartal"),
            (1, "n\u{e4}chstes Quartal"),
        ],
    ),
    (
        "de",
        "long",
        "year",
        [
            "in {0} Jahr",
            "in {0} Jahren",
            "vor {0} Jahr",
            "vor {0} Jahren",
        ],
        &[
            (-1, "letztes Jahr"),
            (0, "dieses Jahr"),
            (1, "n\u{e4}chstes Jahr"),
        ],
    ),
    (
        "de",
        "short",
        "second",
        ["in {0} Sek.", "in {0} Sek.", "vor {0} Sek.", "vor {0} Sek."],
        &[(0, "jetzt")],
    ),
    (
        "de",
        "short",
        "minute",
        ["in {0} Min.", "in {0} Min.", "vor {0} Min.", "vor {0} Min."],
        &[(0, "in dieser Minute")],
    ),
    (
        "de",
        "short",
        "hour",
        ["in {0} Std.", "in {0} Std.", "vor {0} Std.", "vor {0} Std."],
        &[(0, "in dieser Stunde")],
    ),
    (
        "de",
        "short",
        "day",
        ["in {0} Tag", "in {0} Tagen", "vor {0} Tag", "vor {0} Tagen"],
        &[
            (-2, "vorgestern"),
            (-1, "gestern"),
            (0, "heute"),
            (1, "morgen"),
            (2, "\u{fc}bermorgen"),
        ],
    ),
    (
        "de",
        "short",
        "week",
        [
            "in {0} Woche",
            "in {0} Wochen",
            "vor {0} Woche",
            "vor {0} Wochen",
        ],
        &[
            (-1, "letzte Woche"),
            (0, "diese Woche"),
            (1, "n\u{e4}chste Woche"),
        ],
    ),
    (
        "de",
        "short",
        "month",
        [
            "in {0} Monat",
            "in {0} Monaten",
            "vor {0} Monat",
            "vor {0}\u{a0}Monaten",
        ],
        &[
            (-1, "letzten Monat"),
            (0, "diesen Monat"),
            (1, "n\u{e4}chsten Monat"),
        ],
    ),
    (
        "de",
        "short",
        "quarter",
        [
            "in {0} Quart.",
            "in {0} Quart.",
            "vor {0} Quart.",
            "vor {0} Quart.",
        ],
        &[
            (-1, "letztes Quartal"),
            (0, "dieses Quartal"),
            (1, "n\u{e4}chstes Quartal"),
        ],
    ),
    (
        "de",
        "short",
        "year",
        [
            "in {0} Jahr",
            "in {0} Jahren",
            "vor {0} Jahr",
            "vor {0} Jahren",
        ],
        &[
            (-1, "letztes Jahr"),
            (0, "dieses Jahr"),
            (1, "n\u{e4}chstes Jahr"),
        ],
    ),
    (
        "de",
        "narrow",
        "second",
        ["in {0} s", "in {0} s", "vor {0} s", "vor {0} s"],
        &[(0, "jetzt")],
    ),
    (
        "de",
        "narrow",
        "minute",
        ["in {0} m", "in {0} m", "vor {0} m", "vor {0} m"],
        &[(0, "in dieser Minute")],
    ),
    (
        "de",
        "narrow",
        "hour",
        ["in {0} Std.", "in {0} Std.", "vor {0} Std.", "vor {0} Std."],
        &[(0, "in dieser Stunde")],
    ),
    (
        "de",
        "narrow",
        "day",
        ["in {0} Tag", "in {0} Tagen", "vor {0} Tag", "vor {0} Tagen"],
        &[
            (-2, "vorgestern"),
            (-1, "gestern"),
            (0, "heute"),
            (1, "morgen"),
            (2, "\u{fc}bermorgen"),
        ],
    ),
    (
        "de",
        "narrow",
        "week",
        ["in {0} Wo.", "in {0} Wo.", "vor {0} Wo.", "vor {0} Wo."],
        &[
            (-1, "letzte Woche"),
            (0, "diese Woche"),
            (1, "n\u{e4}chste Woche"),
        ],
    ),
    (
        "de",
        "narrow",
        "month",
        [
            "in {0} Monat",
            "in {0} Monaten",
            "vor {0}\u{a0}Monat",
            "vor {0} Monaten",
        ],
        &[
            (-1, "letzten Monat"),
            (0, "diesen Monat"),
            (1, "n\u{e4}chsten Monat"),
        ],
    ),
    (
        "de",
        "narrow",
        "quarter",
        ["in {0} Q", "in {0} Q", "vor {0} Q", "vor {0} Q"],
        &[
            (-1, "letztes Quartal"),
            (0, "dieses Quartal"),
            (1, "n\u{e4}chstes Quartal"),
        ],
    ),
    (
        "de",
        "narrow",
        "year",
        [
            "in {0} Jahr",
            "in {0} Jahren",
            "vor {0} Jahr",
            "vor {0} Jahren",
        ],
        &[
            (-1, "letztes Jahr"),
            (0, "dieses Jahr"),
            (1, "n\u{e4}chstes Jahr"),
        ],
    ),
    (
        "ja",
        "long",
        "second",
        [
            "{0} \u{79d2}\u{5f8c}",
            "{0} \u{79d2}\u{5f8c}",
            "{0} \u{79d2}\u{524d}",
            "{0} \u{79d2}\u{524d}",
        ],
        &[(0, "\u{4eca}")],
    ),
    (
        "ja",
        "long",
        "minute",
        [
            "{0} \u{5206}\u{5f8c}",
            "{0} \u{5206}\u{5f8c}",
            "{0} \u{5206}\u{524d}",
            "{0} \u{5206}\u{524d}",
        ],
        &[(0, "1 \u{5206}\u{4ee5}\u{5185}")],
    ),
    (
        "ja",
        "long",
        "hour",
        [
            "{0} \u{6642}\u{9593}\u{5f8c}",
            "{0} \u{6642}\u{9593}\u{5f8c}",
            "{0} \u{6642}\u{9593}\u{524d}",
            "{0} \u{6642}\u{9593}\u{524d}",
        ],
        &[(0, "1 \u{6642}\u{9593}\u{4ee5}\u{5185}")],
    ),
    (
        "ja",
        "long",
        "day",
        [
            "{0} \u{65e5}\u{5f8c}",
            "{0} \u{65e5}\u{5f8c}",
            "{0} \u{65e5}\u{524d}",
            "{0} \u{65e5}\u{524d}",
        ],
        &[
            (-2, "\u{4e00}\u{6628}\u{65e5}"),
            (-1, "\u{6628}\u{65e5}"),
            (0, "\u{4eca}\u{65e5}"),
            (1, "\u{660e}\u{65e5}"),
            (2, "\u{660e}\u{5f8c}\u{65e5}"),
        ],
    ),
    (
        "ja",
        "long",
        "week",
        [
            "{0} \u{9031}\u{9593}\u{5f8c}",
            "{0} \u{9031}\u{9593}\u{5f8c}",
            "{0} \u{9031}\u{9593}\u{524d}",
            "{0} \u{9031}\u{9593}\u{524d}",
        ],
        &[
            (-1, "\u{5148}\u{9031}"),
            (0, "\u{4eca}\u{9031}"),
            (1, "\u{6765}\u{9031}"),
        ],
    ),
    (
        "ja",
        "long",
        "month",
        [
            "{0} \u{304b}\u{6708}\u{5f8c}",
            "{0} \u{304b}\u{6708}\u{5f8c}",
            "{0} \u{304b}\u{6708}\u{524d}",
            "{0} \u{304b}\u{6708}\u{524d}",
        ],
        &[
            (-1, "\u{5148}\u{6708}"),
            (0, "\u{4eca}\u{6708}"),
            (1, "\u{6765}\u{6708}"),
        ],
    ),
    (
        "ja",
        "long",
        "quarter",
        [
            "{0} \u{56db}\u{534a}\u{671f}\u{5f8c}",
            "{0} \u{56db}\u{534a}\u{671f}\u{5f8c}",
            "{0} \u{56db}\u{534a}\u{671f}\u{524d}",
            "{0} \u{56db}\u{534a}\u{671f}\u{524d}",
        ],
        &[
            (-1, "\u{524d}\u{56db}\u{534a}\u{671f}"),
            (0, "\u{4eca}\u{56db}\u{534a}\u{671f}"),
            (1, "\u{7fcc}\u{56db}\u{534a}\u{671f}"),
        ],
    ),
    (
        "ja",
        "long",
        "year",
        [
            "{0} \u{5e74}\u{5f8c}",
            "{0} \u{5e74}\u{5f8c}",
            "{0} \u{5e74}\u{524d}",
            "{0} \u{5e74}\u{524d}",
        ],
        &[
            (-1, "\u{6628}\u{5e74}"),
            (0, "\u{4eca}\u{5e74}"),
            (1, "\u{6765}\u{5e74}"),
        ],
    ),
    (
        "ja",
        "short",
        "second",
        [
            "{0} \u{79d2}\u{5f8c}",
            "{0} \u{79d2}\u{5f8c}",
            "{0} \u{79d2}\u{524d}",
            "{0} \u{79d2}\u{524d}",
        ],
        &[(0, "\u{4eca}")],
    ),
    (
        "ja",
        "short",
        "minute",
        [
            "{0} \u{5206}\u{5f8c}",
            "{0} \u{5206}\u{5f8c}",
            "{0} \u{5206}\u{524d}",
            "{0} \u{5206}\u{524d}",
        ],
        &[(0, "1 \u{5206}\u{4ee5}\u{5185}")],
    ),
    (
        "ja",
        "short",
        "hour",
        [
            "{0} \u{6642}\u{9593}\u{5f8c}",
            "{0} \u{6642}\u{9593}\u{5f8c}",
            "{0} \u{6642}\u{9593}\u{524d}",
            "{0} \u{6642}\u{9593}\u{524d}",
        ],
        &[(0, "1 \u{6642}\u{9593}\u{4ee5}\u{5185}")],
    ),
    (
        "ja",
        "short",
        "day",
        [
            "{0} \u{65e5}\u{5f8c}",
            "{0} \u{65e5}\u{5f8c}",
            "{0} \u{65e5}\u{524d}",
            "{0} \u{65e5}\u{524d}",
        ],
        &[
            (-2, "\u{4e00}\u{6628}\u{65e5}"),
            (-1, "\u{6628}\u{65e5}"),
            (0, "\u{4eca}\u{65e5}"),
            (1, "\u{660e}\u{65e5}"),
            (2, "\u{660e}\u{5f8c}\u{65e5}"),
        ],
    ),
    (
        "ja",
        "short",
        "week",
        [
            "{0} \u{9031}\u{9593}\u{5f8c}",
            "{0} \u{9031}\u{9593}\u{5f8c}",
            "{0} \u{9031}\u{9593}\u{524d}",
            "{0} \u{9031}\u{9593}\u{524d}",
        ],
        &[
            (-1, "\u{5148}\u{9031}"),
            (0, "\u{4eca}\u{9031}"),
            (1, "\u{6765}\u{9031}"),
        ],
    ),
    (
        "ja",
        "short",
        "month",
        [
            "{0} \u{304b}\u{6708}\u{5f8c}",
            "{0} \u{304b}\u{6708}\u{5f8c}",
            "{0} \u{304b}\u{6708}\u{524d}",
            "{0} \u{304b}\u{6708}\u{524d}",
        ],
        &[
            (-1, "\u{5148}\u{6708}"),
            (0, "\u{4eca}\u{6708}"),
            (1, "\u{6765}\u{6708}"),
        ],
    ),
    (
        "ja",
        "short",
        "quarter",
        [
            "{0} \u{56db}\u{534a}\u{671f}\u{5f8c}",
            "{0} \u{56db}\u{534a}\u{671f}\u{5f8c}",
            "{0} \u{56db}\u{534a}\u{671f}\u{524d}",
            "{0} \u{56db}\u{534a}\u{671f}\u{524d}",
        ],
        &[
            (-1, "\u{524d}\u{56db}\u{534a}\u{671f}"),
            (0, "\u{4eca}\u{56db}\u{534a}\u{671f}"),
            (1, "\u{7fcc}\u{56db}\u{534a}\u{671f}"),
        ],
    ),
    (
        "ja",
        "short",
        "year",
        [
            "{0} \u{5e74}\u{5f8c}",
            "{0} \u{5e74}\u{5f8c}",
            "{0} \u{5e74}\u{524d}",
            "{0} \u{5e74}\u{524d}",
        ],
        &[
            (-1, "\u{6628}\u{5e74}"),
            (0, "\u{4eca}\u{5e74}"),
            (1, "\u{6765}\u{5e74}"),
        ],
    ),
    (
        "ja",
        "narrow",
        "second",
        [
            "{0}\u{79d2}\u{5f8c}",
            "{0}\u{79d2}\u{5f8c}",
            "{0}\u{79d2}\u{524d}",
            "{0}\u{79d2}\u{524d}",
        ],
        &[(0, "\u{4eca}")],
    ),
    (
        "ja",
        "narrow",
        "minute",
        [
            "{0}\u{5206}\u{5f8c}",
            "{0}\u{5206}\u{5f8c}",
            "{0}\u{5206}\u{524d}",
            "{0}\u{5206}\u{524d}",
        ],
        &[(0, "1 \u{5206}\u{4ee5}\u{5185}")],
    ),
    (
        "ja",
        "narrow",
        "hour",
        [
            "{0}\u{6642}\u{9593}\u{5f8c}",
            "{0}\u{6642}\u{9593}\u{5f8c}",
            "{0}\u{6642}\u{9593}\u{524d}",
            "{0}\u{6642}\u{9593}\u{524d}",
        ],
        &[(0, "1 \u{6642}\u{9593}\u{4ee5}\u{5185}")],
    ),
    (
        "ja",
        "narrow",
        "day",
        [
            "{0}\u{65e5}\u{5f8c}",
            "{0}\u{65e5}\u{5f8c}",
            "{0}\u{65e5}\u{524d}",
            "{0}\u{65e5}\u{524d}",
        ],
        &[
            (-2, "\u{4e00}\u{6628}\u{65e5}"),
            (-1, "\u{6628}\u{65e5}"),
            (0, "\u{4eca}\u{65e5}"),
            (1, "\u{660e}\u{65e5}"),
            (2, "\u{660e}\u{5f8c}\u{65e5}"),
        ],
    ),
    (
        "ja",
        "narrow",
        "week",
        [
            "{0}\u{9031}\u{9593}\u{5f8c}",
            "{0}\u{9031}\u{9593}\u{5f8c}",
            "{0}\u{9031}\u{9593}\u{524d}",
            "{0}\u{9031}\u{9593}\u{524d}",
        ],
        &[
            (-1, "\u{5148}\u{9031}"),
            (0, "\u{4eca}\u{9031}"),
            (1, "\u{6765}\u{9031}"),
        ],
    ),
    (
        "ja",
        "narrow",
        "month",
        [
            "{0}\u{304b}\u{6708}\u{5f8c}",
            "{0}\u{304b}\u{6708}\u{5f8c}",
            "{0}\u{304b}\u{6708}\u{524d}",
            "{0}\u{304b}\u{6708}\u{524d}",
        ],
        &[
            (-1, "\u{5148}\u{6708}"),
            (0, "\u{4eca}\u{6708}"),
            (1, "\u{6765}\u{6708}"),
        ],
    ),
    (
        "ja",
        "narrow",
        "quarter",
        [
            "{0}\u{56db}\u{534a}\u{671f}\u{5f8c}",
            "{0}\u{56db}\u{534a}\u{671f}\u{5f8c}",
            "{0}\u{56db}\u{534a}\u{671f}\u{524d}",
            "{0}\u{56db}\u{534a}\u{671f}\u{524d}",
        ],
        &[
            (-1, "\u{524d}\u{56db}\u{534a}\u{671f}"),
            (0, "\u{4eca}\u{56db}\u{534a}\u{671f}"),
            (1, "\u{7fcc}\u{56db}\u{534a}\u{671f}"),
        ],
    ),
    (
        "ja",
        "narrow",
        "year",
        [
            "{0}\u{5e74}\u{5f8c}",
            "{0}\u{5e74}\u{5f8c}",
            "{0}\u{5e74}\u{524d}",
            "{0}\u{5e74}\u{524d}",
        ],
        &[
            (-1, "\u{6628}\u{5e74}"),
            (0, "\u{4eca}\u{5e74}"),
            (1, "\u{6765}\u{5e74}"),
        ],
    ),
    (
        "zh",
        "long",
        "second",
        [
            "{0}\u{79d2}\u{949f}\u{540e}",
            "{0}\u{79d2}\u{949f}\u{540e}",
            "{0}\u{79d2}\u{949f}\u{524d}",
            "{0}\u{79d2}\u{949f}\u{524d}",
        ],
        &[(0, "\u{73b0}\u{5728}")],
    ),
    (
        "zh",
        "long",
        "minute",
        [
            "{0}\u{5206}\u{949f}\u{540e}",
            "{0}\u{5206}\u{949f}\u{540e}",
            "{0}\u{5206}\u{949f}\u{524d}",
            "{0}\u{5206}\u{949f}\u{524d}",
        ],
        &[(0, "\u{6b64}\u{523b}")],
    ),
    (
        "zh",
        "long",
        "hour",
        [
            "{0}\u{5c0f}\u{65f6}\u{540e}",
            "{0}\u{5c0f}\u{65f6}\u{540e}",
            "{0}\u{5c0f}\u{65f6}\u{524d}",
            "{0}\u{5c0f}\u{65f6}\u{524d}",
        ],
        &[(0, "\u{8fd9}\u{4e00}\u{65f6}\u{95f4} / \u{6b64}\u{65f6}")],
    ),
    (
        "zh",
        "long",
        "day",
        [
            "{0}\u{5929}\u{540e}",
            "{0}\u{5929}\u{540e}",
            "{0}\u{5929}\u{524d}",
            "{0}\u{5929}\u{524d}",
        ],
        &[
            (-2, "\u{524d}\u{5929}"),
            (-1, "\u{6628}\u{5929}"),
            (0, "\u{4eca}\u{5929}"),
            (1, "\u{660e}\u{5929}"),
            (2, "\u{540e}\u{5929}"),
        ],
    ),
    (
        "zh",
        "long",
        "week",
        [
            "{0}\u{5468}\u{540e}",
            "{0}\u{5468}\u{540e}",
            "{0}\u{5468}\u{524d}",
            "{0}\u{5468}\u{524d}",
        ],
        &[
            (-1, "\u{4e0a}\u{5468}"),
            (0, "\u{672c}\u{5468}"),
            (1, "\u{4e0b}\u{5468}"),
        ],
    ),
    (
        "zh",
        "long",
        "month",
        [
            "{0}\u{4e2a}\u{6708}\u{540e}",
            "{0}\u{4e2a}\u{6708}\u{540e}",
            "{0}\u{4e2a}\u{6708}\u{524d}",
            "{0}\u{4e2a}\u{6708}\u{524d}",
        ],
        &[
            (-1, "\u{4e0a}\u{4e2a}\u{6708}"),
            (0, "\u{672c}\u{6708}"),
            (1, "\u{4e0b}\u{4e2a}\u{6708}"),
        ],
    ),
    (
        "zh",
        "long",
        "quarter",
        [
            "{0}\u{4e2a}\u{5b63}\u{5ea6}\u{540e}",
            "{0}\u{4e2a}\u{5b63}\u{5ea6}\u{540e}",
            "{0}\u{4e2a}\u{5b63}\u{5ea6}\u{524d}",
            "{0}\u{4e2a}\u{5b63}\u{5ea6}\u{524d}",
        ],
        &[
            (-1, "\u{4e0a}\u{5b63}\u{5ea6}"),
            (0, "\u{672c}\u{5b63}\u{5ea6}"),
            (1, "\u{4e0b}\u{5b63}\u{5ea6}"),
        ],
    ),
    (
        "zh",
        "long",
        "year",
        [
            "{0}\u{5e74}\u{540e}",
            "{0}\u{5e74}\u{540e}",
            "{0}\u{5e74}\u{524d}",
            "{0}\u{5e74}\u{524d}",
        ],
        &[
            (-1, "\u{53bb}\u{5e74}"),
            (0, "\u{4eca}\u{5e74}"),
            (1, "\u{660e}\u{5e74}"),
        ],
    ),
    (
        "zh",
        "short",
        "second",
        [
            "{0}\u{79d2}\u{540e}",
            "{0}\u{79d2}\u{540e}",
            "{0}\u{79d2}\u{524d}",
            "{0}\u{79d2}\u{524d}",
        ],
        &[(0, "\u{73b0}\u{5728}")],
    ),
    (
        "zh",
        "short",
        "minute",
        [
            "{0}\u{5206}\u{949f}\u{540e}",
            "{0}\u{5206}\u{949f}\u{540e}",
            "{0}\u{5206}\u{949f}\u{524d}",
            "{0}\u{5206}\u{949f}\u{524d}",
        ],
        &[(0, "\u{6b64}\u{523b}")],
    ),
    (
        "zh",
        "short",
        "hour",
        [
            "{0}\u{5c0f}\u{65f6}\u{540e}",
            "{0}\u{5c0f}\u{65f6}\u{540e}",
            "{0}\u{5c0f}\u{65f6}\u{524d}",
            "{0}\u{5c0f}\u{65f6}\u{524d}",
        ],
        &[(0, "\u{8fd9}\u{4e00}\u{65f6}\u{95f4} / \u{6b64}\u{65f6}")],
    ),
    (
        "zh",
        "short",
        "day",
        [
            "{0}\u{5929}\u{540e}",
            "{0}\u{5929}\u{540e}",
            "{0}\u{5929}\u{524d}",
            "{0}\u{5929}\u{524d}",
        ],
        &[
            (-2, "\u{524d}\u{5929}"),
            (-1, "\u{6628}\u{5929}"),
            (0, "\u{4eca}\u{5929}"),
            (1, "\u{660e}\u{5929}"),
            (2, "\u{540e}\u{5929}"),
        ],
    ),
    (
        "zh",
        "short",
        "week",
        [
            "{0}\u{5468}\u{540e}",
            "{0}\u{5468}\u{540e}",
            "{0}\u{5468}\u{524d}",
            "{0}\u{5468}\u{524d}",
        ],
        &[
            (-1, "\u{4e0a}\u{5468}"),
            (0, "\u{672c}\u{5468}"),
            (1, "\u{4e0b}\u{5468}"),
        ],
    ),
    (
        "zh",
        "short",
        "month",
        [
            "{0}\u{4e2a}\u{6708}\u{540e}",
            "{0}\u{4e2a}\u{6708}\u{540e}",
            "{0}\u{4e2a}\u{6708}\u{524d}",
            "{0}\u{4e2a}\u{6708}\u{524d}",
        ],
        &[
            (-1, "\u{4e0a}\u{4e2a}\u{6708}"),
            (0, "\u{672c}\u{6708}"),
            (1, "\u{4e0b}\u{4e2a}\u{6708}"),
        ],
    ),
    (
        "zh",
        "short",
        "quarter",
        [
            "{0}\u{4e2a}\u{5b63}\u{5ea6}\u{540e}",
            "{0}\u{4e2a}\u{5b63}\u{5ea6}\u{540e}",
            "{0}\u{4e2a}\u{5b63}\u{5ea6}\u{524d}",
            "{0}\u{4e2a}\u{5b63}\u{5ea6}\u{524d}",
        ],
        &[
            (-1, "\u{4e0a}\u{5b63}\u{5ea6}"),
            (0, "\u{672c}\u{5b63}\u{5ea6}"),
            (1, "\u{4e0b}\u{5b63}\u{5ea6}"),
        ],
    ),
    (
        "zh",
        "short",
        "year",
        [
            "{0}\u{5e74}\u{540e}",
            "{0}\u{5e74}\u{540e}",
            "{0}\u{5e74}\u{524d}",
            "{0}\u{5e74}\u{524d}",
        ],
        &[
            (-1, "\u{53bb}\u{5e74}"),
            (0, "\u{4eca}\u{5e74}"),
            (1, "\u{660e}\u{5e74}"),
        ],
    ),
    (
        "zh",
        "narrow",
        "second",
        [
            "{0}\u{79d2}\u{540e}",
            "{0}\u{79d2}\u{540e}",
            "{0}\u{79d2}\u{524d}",
            "{0}\u{79d2}\u{524d}",
        ],
        &[(0, "\u{73b0}\u{5728}")],
    ),
    (
        "zh",
        "narrow",
        "minute",
        [
            "{0}\u{5206}\u{949f}\u{540e}",
            "{0}\u{5206}\u{949f}\u{540e}",
            "{0}\u{5206}\u{949f}\u{524d}",
            "{0}\u{5206}\u{949f}\u{524d}",
        ],
        &[(0, "\u{6b64}\u{523b}")],
    ),
    (
        "zh",
        "narrow",
        "hour",
        [
            "{0}\u{5c0f}\u{65f6}\u{540e}",
            "{0}\u{5c0f}\u{65f6}\u{540e}",
            "{0}\u{5c0f}\u{65f6}\u{524d}",
            "{0}\u{5c0f}\u{65f6}\u{524d}",
        ],
        &[(0, "\u{8fd9}\u{4e00}\u{65f6}\u{95f4} / \u{6b64}\u{65f6}")],
    ),
    (
        "zh",
        "narrow",
        "day",
        [
            "{0}\u{5929}\u{540e}",
            "{0}\u{5929}\u{540e}",
            "{0}\u{5929}\u{524d}",
            "{0}\u{5929}\u{524d}",
        ],
        &[
            (-2, "\u{524d}\u{5929}"),
            (-1, "\u{6628}\u{5929}"),
            (0, "\u{4eca}\u{5929}"),
            (1, "\u{660e}\u{5929}"),
            (2, "\u{540e}\u{5929}"),
        ],
    ),
    (
        "zh",
        "narrow",
        "week",
        [
            "{0}\u{5468}\u{540e}",
            "{0}\u{5468}\u{540e}",
            "{0}\u{5468}\u{524d}",
            "{0}\u{5468}\u{524d}",
        ],
        &[
            (-1, "\u{4e0a}\u{5468}"),
            (0, "\u{672c}\u{5468}"),
            (1, "\u{4e0b}\u{5468}"),
        ],
    ),
    (
        "zh",
        "narrow",
        "month",
        [
            "{0}\u{4e2a}\u{6708}\u{540e}",
            "{0}\u{4e2a}\u{6708}\u{540e}",
            "{0}\u{4e2a}\u{6708}\u{524d}",
            "{0}\u{4e2a}\u{6708}\u{524d}",
        ],
        &[
            (-1, "\u{4e0a}\u{4e2a}\u{6708}"),
            (0, "\u{672c}\u{6708}"),
            (1, "\u{4e0b}\u{4e2a}\u{6708}"),
        ],
    ),
    (
        "zh",
        "narrow",
        "quarter",
        [
            "{0}\u{4e2a}\u{5b63}\u{5ea6}\u{540e}",
            "{0}\u{4e2a}\u{5b63}\u{5ea6}\u{540e}",
            "{0}\u{4e2a}\u{5b63}\u{5ea6}\u{524d}",
            "{0}\u{4e2a}\u{5b63}\u{5ea6}\u{524d}",
        ],
        &[
            (-1, "\u{4e0a}\u{5b63}\u{5ea6}"),
            (0, "\u{672c}\u{5b63}\u{5ea6}"),
            (1, "\u{4e0b}\u{5b63}\u{5ea6}"),
        ],
    ),
    (
        "zh",
        "narrow",
        "year",
        [
            "{0}\u{5e74}\u{540e}",
            "{0}\u{5e74}\u{540e}",
            "{0}\u{5e74}\u{524d}",
            "{0}\u{5e74}\u{524d}",
        ],
        &[
            (-1, "\u{53bb}\u{5e74}"),
            (0, "\u{4eca}\u{5e74}"),
            (1, "\u{660e}\u{5e74}"),
        ],
    ),
    (
        "ko",
        "long",
        "second",
        [
            "{0}\u{cd08} \u{d6c4}",
            "{0}\u{cd08} \u{d6c4}",
            "{0}\u{cd08} \u{c804}",
            "{0}\u{cd08} \u{c804}",
        ],
        &[(0, "\u{c9c0}\u{ae08}")],
    ),
    (
        "ko",
        "long",
        "minute",
        [
            "{0}\u{bd84} \u{d6c4}",
            "{0}\u{bd84} \u{d6c4}",
            "{0}\u{bd84} \u{c804}",
            "{0}\u{bd84} \u{c804}",
        ],
        &[(0, "\u{d604}\u{c7ac} \u{bd84}")],
    ),
    (
        "ko",
        "long",
        "hour",
        [
            "{0}\u{c2dc}\u{ac04} \u{d6c4}",
            "{0}\u{c2dc}\u{ac04} \u{d6c4}",
            "{0}\u{c2dc}\u{ac04} \u{c804}",
            "{0}\u{c2dc}\u{ac04} \u{c804}",
        ],
        &[(0, "\u{d604}\u{c7ac} \u{c2dc}\u{ac04}")],
    ),
    (
        "ko",
        "long",
        "day",
        [
            "{0}\u{c77c} \u{d6c4}",
            "{0}\u{c77c} \u{d6c4}",
            "{0}\u{c77c} \u{c804}",
            "{0}\u{c77c} \u{c804}",
        ],
        &[
            (-2, "\u{adf8}\u{c800}\u{aed8}"),
            (-1, "\u{c5b4}\u{c81c}"),
            (0, "\u{c624}\u{b298}"),
            (1, "\u{b0b4}\u{c77c}"),
            (2, "\u{baa8}\u{b808}"),
        ],
    ),
    (
        "ko",
        "long",
        "week",
        [
            "{0}\u{c8fc} \u{d6c4}",
            "{0}\u{c8fc} \u{d6c4}",
            "{0}\u{c8fc} \u{c804}",
            "{0}\u{c8fc} \u{c804}",
        ],
        &[
            (-1, "\u{c9c0}\u{b09c}\u{c8fc}"),
            (0, "\u{c774}\u{bc88} \u{c8fc}"),
            (1, "\u{b2e4}\u{c74c} \u{c8fc}"),
        ],
    ),
    (
        "ko",
        "long",
        "month",
        [
            "{0}\u{ac1c}\u{c6d4} \u{d6c4}",
            "{0}\u{ac1c}\u{c6d4} \u{d6c4}",
            "{0}\u{ac1c}\u{c6d4} \u{c804}",
            "{0}\u{ac1c}\u{c6d4} \u{c804}",
        ],
        &[
            (-1, "\u{c9c0}\u{b09c}\u{b2ec}"),
            (0, "\u{c774}\u{bc88} \u{b2ec}"),
            (1, "\u{b2e4}\u{c74c} \u{b2ec}"),
        ],
    ),
    (
        "ko",
        "long",
        "quarter",
        [
            "{0}\u{bd84}\u{ae30} \u{d6c4}",
            "{0}\u{bd84}\u{ae30} \u{d6c4}",
            "{0}\u{bd84}\u{ae30} \u{c804}",
            "{0}\u{bd84}\u{ae30} \u{c804}",
        ],
        &[
            (-1, "\u{c9c0}\u{b09c} \u{bd84}\u{ae30}"),
            (0, "\u{c774}\u{bc88} \u{bd84}\u{ae30}"),
            (1, "\u{b2e4}\u{c74c} \u{bd84}\u{ae30}"),
        ],
    ),
    (
        "ko",
        "long",
        "year",
        [
            "{0}\u{b144} \u{d6c4}",
            "{0}\u{b144} \u{d6c4}",
            "{0}\u{b144} \u{c804}",
            "{0}\u{b144} \u{c804}",
        ],
        &[
            (-1, "\u{c791}\u{b144}"),
            (0, "\u{c62c}\u{d574}"),
            (1, "\u{b0b4}\u{b144}"),
        ],
    ),
    (
        "ko",
        "short",
        "second",
        [
            "{0}\u{cd08} \u{d6c4}",
            "{0}\u{cd08} \u{d6c4}",
            "{0}\u{cd08} \u{c804}",
            "{0}\u{cd08} \u{c804}",
        ],
        &[(0, "\u{c9c0}\u{ae08}")],
    ),
    (
        "ko",
        "short",
        "minute",
        [
            "{0}\u{bd84} \u{d6c4}",
            "{0}\u{bd84} \u{d6c4}",
            "{0}\u{bd84} \u{c804}",
            "{0}\u{bd84} \u{c804}",
        ],
        &[(0, "\u{d604}\u{c7ac} \u{bd84}")],
    ),
    (
        "ko",
        "short",
        "hour",
        [
            "{0}\u{c2dc}\u{ac04} \u{d6c4}",
            "{0}\u{c2dc}\u{ac04} \u{d6c4}",
            "{0}\u{c2dc}\u{ac04} \u{c804}",
            "{0}\u{c2dc}\u{ac04} \u{c804}",
        ],
        &[(0, "\u{d604}\u{c7ac} \u{c2dc}\u{ac04}")],
    ),
    (
        "ko",
        "short",
        "day",
        [
            "{0}\u{c77c} \u{d6c4}",
            "{0}\u{c77c} \u{d6c4}",
            "{0}\u{c77c} \u{c804}",
            "{0}\u{c77c} \u{c804}",
        ],
        &[
            (-2, "\u{adf8}\u{c800}\u{aed8}"),
            (-1, "\u{c5b4}\u{c81c}"),
            (0, "\u{c624}\u{b298}"),
            (1, "\u{b0b4}\u{c77c}"),
            (2, "\u{baa8}\u{b808}"),
        ],
    ),
    (
        "ko",
        "short",
        "week",
        [
            "{0}\u{c8fc} \u{d6c4}",
            "{0}\u{c8fc} \u{d6c4}",
            "{0}\u{c8fc} \u{c804}",
            "{0}\u{c8fc} \u{c804}",
        ],
        &[
            (-1, "\u{c9c0}\u{b09c}\u{c8fc}"),
            (0, "\u{c774}\u{bc88} \u{c8fc}"),
            (1, "\u{b2e4}\u{c74c} \u{c8fc}"),
        ],
    ),
    (
        "ko",
        "short",
        "month",
        [
            "{0}\u{ac1c}\u{c6d4} \u{d6c4}",
            "{0}\u{ac1c}\u{c6d4} \u{d6c4}",
            "{0}\u{ac1c}\u{c6d4} \u{c804}",
            "{0}\u{ac1c}\u{c6d4} \u{c804}",
        ],
        &[
            (-1, "\u{c9c0}\u{b09c}\u{b2ec}"),
            (0, "\u{c774}\u{bc88} \u{b2ec}"),
            (1, "\u{b2e4}\u{c74c} \u{b2ec}"),
        ],
    ),
    (
        "ko",
        "short",
        "quarter",
        [
            "{0}\u{bd84}\u{ae30} \u{d6c4}",
            "{0}\u{bd84}\u{ae30} \u{d6c4}",
            "{0}\u{bd84}\u{ae30} \u{c804}",
            "{0}\u{bd84}\u{ae30} \u{c804}",
        ],
        &[
            (-1, "\u{c9c0}\u{b09c} \u{bd84}\u{ae30}"),
            (0, "\u{c774}\u{bc88} \u{bd84}\u{ae30}"),
            (1, "\u{b2e4}\u{c74c} \u{bd84}\u{ae30}"),
        ],
    ),
    (
        "ko",
        "short",
        "year",
        [
            "{0}\u{b144} \u{d6c4}",
            "{0}\u{b144} \u{d6c4}",
            "{0}\u{b144} \u{c804}",
            "{0}\u{b144} \u{c804}",
        ],
        &[
            (-1, "\u{c791}\u{b144}"),
            (0, "\u{c62c}\u{d574}"),
            (1, "\u{b0b4}\u{b144}"),
        ],
    ),
    (
        "ko",
        "narrow",
        "second",
        [
            "{0}\u{cd08} \u{d6c4}",
            "{0}\u{cd08} \u{d6c4}",
            "{0}\u{cd08} \u{c804}",
            "{0}\u{cd08} \u{c804}",
        ],
        &[(0, "\u{c9c0}\u{ae08}")],
    ),
    (
        "ko",
        "narrow",
        "minute",
        [
            "{0}\u{bd84} \u{d6c4}",
            "{0}\u{bd84} \u{d6c4}",
            "{0}\u{bd84} \u{c804}",
            "{0}\u{bd84} \u{c804}",
        ],
        &[(0, "\u{d604}\u{c7ac} \u{bd84}")],
    ),
    (
        "ko",
        "narrow",
        "hour",
        [
            "{0}\u{c2dc}\u{ac04} \u{d6c4}",
            "{0}\u{c2dc}\u{ac04} \u{d6c4}",
            "{0}\u{c2dc}\u{ac04} \u{c804}",
            "{0}\u{c2dc}\u{ac04} \u{c804}",
        ],
        &[(0, "\u{d604}\u{c7ac} \u{c2dc}\u{ac04}")],
    ),
    (
        "ko",
        "narrow",
        "day",
        [
            "{0}\u{c77c} \u{d6c4}",
            "{0}\u{c77c} \u{d6c4}",
            "{0}\u{c77c} \u{c804}",
            "{0}\u{c77c} \u{c804}",
        ],
        &[
            (-2, "\u{adf8}\u{c800}\u{aed8}"),
            (-1, "\u{c5b4}\u{c81c}"),
            (0, "\u{c624}\u{b298}"),
            (1, "\u{b0b4}\u{c77c}"),
            (2, "\u{baa8}\u{b808}"),
        ],
    ),
    (
        "ko",
        "narrow",
        "week",
        [
            "{0}\u{c8fc} \u{d6c4}",
            "{0}\u{c8fc} \u{d6c4}",
            "{0}\u{c8fc} \u{c804}",
            "{0}\u{c8fc} \u{c804}",
        ],
        &[
            (-1, "\u{c9c0}\u{b09c}\u{c8fc}"),
            (0, "\u{c774}\u{bc88} \u{c8fc}"),
            (1, "\u{b2e4}\u{c74c} \u{c8fc}"),
        ],
    ),
    (
        "ko",
        "narrow",
        "month",
        [
            "{0}\u{ac1c}\u{c6d4} \u{d6c4}",
            "{0}\u{ac1c}\u{c6d4} \u{d6c4}",
            "{0}\u{ac1c}\u{c6d4} \u{c804}",
            "{0}\u{ac1c}\u{c6d4} \u{c804}",
        ],
        &[
            (-1, "\u{c9c0}\u{b09c}\u{b2ec}"),
            (0, "\u{c774}\u{bc88} \u{b2ec}"),
            (1, "\u{b2e4}\u{c74c} \u{b2ec}"),
        ],
    ),
    (
        "ko",
        "narrow",
        "quarter",
        [
            "{0}\u{bd84}\u{ae30} \u{d6c4}",
            "{0}\u{bd84}\u{ae30} \u{d6c4}",
            "{0}\u{bd84}\u{ae30} \u{c804}",
            "{0}\u{bd84}\u{ae30} \u{c804}",
        ],
        &[
            (-1, "\u{c9c0}\u{b09c} \u{bd84}\u{ae30}"),
            (0, "\u{c774}\u{bc88} \u{bd84}\u{ae30}"),
            (1, "\u{b2e4}\u{c74c} \u{bd84}\u{ae30}"),
        ],
    ),
    (
        "ko",
        "narrow",
        "year",
        [
            "{0}\u{b144} \u{d6c4}",
            "{0}\u{b144} \u{d6c4}",
            "{0}\u{b144} \u{c804}",
            "{0}\u{b144} \u{c804}",
        ],
        &[
            (-1, "\u{c791}\u{b144}"),
            (0, "\u{c62c}\u{d574}"),
            (1, "\u{b0b4}\u{b144}"),
        ],
    ),
];

/// List separators by (language, type, style): between the two items of
/// a pair, and after the first, each middle and the next-to-last item of a
/// longer list. Generated from Node v22.2.0 (ICU 74) output (bd-9vouw.171).
const LIST_PATTERNS: &[(&str, &str, &str, [&str; 4])] = &[
    ("en", "conjunction", "long", [" and ", ", ", ", ", ", and "]),
    ("en", "conjunction", "short", [" & ", ", ", ", ", ", & "]),
    ("en", "conjunction", "narrow", [", ", ", ", ", ", ", "]),
    ("en", "disjunction", "long", [" or ", ", ", ", ", ", or "]),
    ("en", "disjunction", "short", [" or ", ", ", ", ", ", or "]),
    ("en", "disjunction", "narrow", [" or ", ", ", ", ", ", or "]),
    ("en", "unit", "long", [", ", ", ", ", ", ", "]),
    ("en", "unit", "short", [", ", ", ", ", ", ", "]),
    ("en", "unit", "narrow", [" ", " ", " ", " "]),
    ("de", "conjunction", "long", [" und ", ", ", ", ", " und "]),
    ("de", "conjunction", "short", [" und ", ", ", ", ", " und "]),
    (
        "de",
        "conjunction",
        "narrow",
        [" und ", ", ", ", ", " und "],
    ),
    (
        "de",
        "disjunction",
        "long",
        [" oder ", ", ", ", ", " oder "],
    ),
    (
        "de",
        "disjunction",
        "short",
        [" oder ", ", ", ", ", " oder "],
    ),
    (
        "de",
        "disjunction",
        "narrow",
        [" oder ", ", ", ", ", " oder "],
    ),
    ("de", "unit", "long", [", ", ", ", ", ", " und "]),
    ("de", "unit", "short", [", ", ", ", ", ", " und "]),
    ("de", "unit", "narrow", [", ", ", ", ", ", " und "]),
    (
        "ja",
        "conjunction",
        "long",
        ["\u{3001}", "\u{3001}", "\u{3001}", "\u{3001}"],
    ),
    (
        "ja",
        "conjunction",
        "short",
        ["\u{3001}", "\u{3001}", "\u{3001}", "\u{3001}"],
    ),
    (
        "ja",
        "conjunction",
        "narrow",
        ["\u{3001}", "\u{3001}", "\u{3001}", "\u{3001}"],
    ),
    (
        "ja",
        "disjunction",
        "long",
        [
            "\u{307e}\u{305f}\u{306f}",
            "\u{3001}",
            "\u{3001}",
            "\u{3001}\u{307e}\u{305f}\u{306f}",
        ],
    ),
    (
        "ja",
        "disjunction",
        "short",
        [
            "\u{307e}\u{305f}\u{306f}",
            "\u{3001}",
            "\u{3001}",
            "\u{3001}\u{307e}\u{305f}\u{306f}",
        ],
    ),
    (
        "ja",
        "disjunction",
        "narrow",
        [
            "\u{307e}\u{305f}\u{306f}",
            "\u{3001}",
            "\u{3001}",
            "\u{3001}\u{307e}\u{305f}\u{306f}",
        ],
    ),
    ("ja", "unit", "long", [" ", " ", " ", " "]),
    ("ja", "unit", "short", [" ", " ", " ", " "]),
    ("ja", "unit", "narrow", ["", "", "", ""]),
    (
        "zh",
        "conjunction",
        "long",
        ["\u{548c}", "\u{3001}", "\u{3001}", "\u{548c}"],
    ),
    (
        "zh",
        "conjunction",
        "short",
        ["\u{548c}", "\u{3001}", "\u{3001}", "\u{548c}"],
    ),
    (
        "zh",
        "conjunction",
        "narrow",
        ["\u{3001}", "\u{3001}", "\u{3001}", "\u{3001}"],
    ),
    (
        "zh",
        "disjunction",
        "long",
        ["\u{6216}", "\u{3001}", "\u{3001}", "\u{6216}"],
    ),
    (
        "zh",
        "disjunction",
        "short",
        ["\u{6216}", "\u{3001}", "\u{3001}", "\u{6216}"],
    ),
    (
        "zh",
        "disjunction",
        "narrow",
        ["\u{6216}", "\u{3001}", "\u{3001}", "\u{6216}"],
    ),
    ("zh", "unit", "long", ["", "", "", ""]),
    ("zh", "unit", "short", ["", "", "", ""]),
    ("zh", "unit", "narrow", ["", "", "", ""]),
    (
        "ko",
        "conjunction",
        "long",
        [" \u{bc0f} ", ", ", ", ", " \u{bc0f} "],
    ),
    (
        "ko",
        "conjunction",
        "short",
        [" \u{bc0f} ", ", ", ", ", " \u{bc0f} "],
    ),
    (
        "ko",
        "conjunction",
        "narrow",
        [" \u{bc0f} ", ", ", ", ", " \u{bc0f} "],
    ),
    (
        "ko",
        "disjunction",
        "long",
        [" \u{b610}\u{b294} ", ", ", ", ", " \u{b610}\u{b294} "],
    ),
    (
        "ko",
        "disjunction",
        "short",
        [" \u{b610}\u{b294} ", ", ", ", ", " \u{b610}\u{b294} "],
    ),
    (
        "ko",
        "disjunction",
        "narrow",
        [" \u{b610}\u{b294} ", ", ", ", ", " \u{b610}\u{b294} "],
    ),
    ("ko", "unit", "long", [" ", " ", " ", " "]),
    ("ko", "unit", "short", [" ", " ", " ", " "]),
    ("ko", "unit", "narrow", [" ", " ", " ", " "]),
];
