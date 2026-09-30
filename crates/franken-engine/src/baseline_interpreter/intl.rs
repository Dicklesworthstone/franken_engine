//! A minimal ECMA-402 `Intl` over the engine's locale formatters.
//!
//! `Intl` was not defined, so code that formats through it (`new
//! Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' })`,
//! `Intl.DateTimeFormat().resolvedOptions().timeZone`, luxon) threw a
//! ReferenceError. This provides NumberFormat, DateTimeFormat, Collator and
//! PluralRules over number_locale, date_locale and collation, and
//! getCanonicalLocales. A service object reads its options once, at
//! construction, into the object `resolvedOptions()` copies; its `format` /
//! `compare` / `select` are bound to it, so `values.map(nf.format)` works.
//!
//! A locale, option or combination the formatters do not cover is a typed
//! refusal at construction, never output that differs from Node's.
//!
//! No-claim: no ICU and no locale negotiation (an unsupported locale throws
//! instead of falling back); no formatToParts, formatRange, BigInt
//! formatting, RelativeTimeFormat, ListFormat, DisplayNames, Locale or
//! Segmenter. The methods are own properties of each object, not prototype
//! accessors, and `instanceof Intl.NumberFormat` is false.

use super::*;

use date_locale::{DateComponents, Digits, FormatStyle, MonthStyle, TextWidth};

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
const SERVICES: [&str; 4] = ["NumberFormat", "DateTimeFormat", "Collator", "PluralRules"];

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
        let requested = self.intl_locale_list(&locales)?.into_iter().next();
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
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "an Intl service constructor".to_string(),
                    got: other.to_string(),
                });
            }
        };
        let resolved_id = self.alloc_object_with_properties(&resolved)?;
        let object = self.alloc_object_with_prototype(None)?;
        self.set_object_property(
            object,
            "__type".to_string(),
            Value::str(format!("Intl.{service}")),
        )?;
        self.set_object_property(object, "__resolved".to_string(), Value::Object(resolved_id))?;
        let methods: &[&str] = match service {
            "NumberFormat" | "DateTimeFormat" => &["format", "resolvedOptions"],
            "Collator" => &["compare", "resolvedOptions"],
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
        let mut hidden = vec!["__type", "__resolved"];
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
            "format" => {
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
                self.intl_format_date(time.trunc(), &request)
                    .map(Value::str)
                    .map_err(|what| InterpreterError::TypeError {
                        expected: "a date Intl.DateTimeFormat formats".to_string(),
                        got: what,
                    })
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
            .intl_locale_list(module, &locales)?
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
        let use_grouping = match &grouping {
            Value::Undefined => Value::str("auto"),
            Value::Bool(false) => Value::Bool(false),
            Value::Bool(true) => Value::str("always"),
            other => {
                let text = self.intl_to_string(module, other.clone())?;
                match text.as_str() {
                    "always" | "auto" => Value::str(text),
                    "min2" => {
                        return Err(Self::intl_refusal(SERVICE, "useGrouping min2".to_string()));
                    }
                    "false" | "" => Value::Bool(false),
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
        let style = match self.intl_resolved_string(resolved, "style").as_str() {
            "percent" => number_locale::NumberLocaleStyle::Percent,
            "currency" => number_locale::NumberLocaleStyle::Currency(
                self.intl_resolved_string(resolved, "currency"),
            ),
            _ => number_locale::NumberLocaleStyle::Decimal,
        };
        let digits = |key: &str| match self.intl_resolved_value(resolved, key) {
            Some(Value::Int(value)) => u32::try_from(value).ok(),
            _ => None,
        };
        Ok((
            self.intl_resolved_string(resolved, "locale"),
            number_locale::NumberLocaleOptions {
                style,
                minimum_fraction_digits: digits("minimumFractionDigits"),
                maximum_fraction_digits: digits("maximumFractionDigits"),
                use_grouping: !matches!(
                    self.intl_resolved_value(resolved, "useGrouping"),
                    Some(Value::Bool(false))
                ),
            },
        ))
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
            return date_locale::format_date_styles(
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
            Some(kind) => date_locale::format_date_locale(fields, locale, kind),
            None => date_locale::format_date_components(fields, locale, &request.components),
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
