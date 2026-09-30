//! `Number.prototype.toLocaleString` formatting (ECMA-402 subset).
//!
//! The engine has no ICU. It formats the locales whose number symbols it
//! knows (English, Japanese, Chinese and Korean: `1,234.5`; German:
//! `1.234,5`) in decimal style, and percent and a few currencies in the
//! English-like locales, with the fraction-digit and grouping options.
//! Everything else is a typed refusal, never a silently different string.
//! Digits are rounded half-expand on the shortest round-trip decimal form of
//! the number, as ICU does, so `(1.0005).toLocaleString()` is "1.001" while
//! `(1.0005).toFixed(3)` is "1.000".

/// A formatting style (`style` option).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum NumberLocaleStyle {
    Decimal,
    Percent,
    /// ISO 4217 code, upper case.
    Currency(String),
}

/// The options toLocaleString honors; `None` fraction digits take the
/// style's defaults (ECMA-402 SetNumberFormatDigitOptions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NumberLocaleOptions {
    pub(super) style: NumberLocaleStyle,
    pub(super) minimum_fraction_digits: Option<u32>,
    pub(super) maximum_fraction_digits: Option<u32>,
    pub(super) use_grouping: bool,
}

impl Default for NumberLocaleOptions {
    fn default() -> Self {
        Self {
            style: NumberLocaleStyle::Decimal,
            minimum_fraction_digits: None,
            maximum_fraction_digits: None,
            use_grouping: true,
        }
    }
}

/// Why a number could not be formatted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum NumberLocaleError {
    /// An option value ECMA-402 rejects (a RangeError in JavaScript).
    Range(String),
    /// A locale or option the engine does not format (typed refusal).
    Unsupported(String),
}

struct LocaleSymbols {
    group: char,
    decimal: char,
    /// Whether percent and currency layouts are known for the locale.
    english_layout: bool,
}

fn locale_symbols(locale: Option<&str>) -> Result<LocaleSymbols, NumberLocaleError> {
    let tag = locale.unwrap_or("en-US");
    let language = tag.split(['-', '_']).next().unwrap_or(tag);
    match language.to_ascii_lowercase().as_str() {
        "en" | "ja" | "zh" | "ko" => Ok(LocaleSymbols {
            group: ',',
            decimal: '.',
            english_layout: true,
        }),
        "de" => Ok(LocaleSymbols {
            group: '.',
            decimal: ',',
            english_layout: false,
        }),
        _ => Err(NumberLocaleError::Unsupported(format!(
            "locale {tag:?} (formatted locales: en, ja, zh, ko, de)"
        ))),
    }
}

/// Symbol and fraction digits of the currencies the engine formats.
fn currency_layout(code: &str) -> Option<(&'static str, u32)> {
    match code {
        "USD" => Some(("$", 2)),
        "EUR" => Some(("€", 2)),
        "GBP" => Some(("£", 2)),
        "JPY" => Some(("¥", 0)),
        _ => None,
    }
}

/// The fraction digits `options` resolve to for `locale` (ECMA-402
/// SetNumberFormatDigitOptions), after checking that the engine formats the
/// locale, style and currency.
pub(super) fn resolved_fraction_digits(
    locale: Option<&str>,
    options: &NumberLocaleOptions,
) -> Result<(u32, u32), NumberLocaleError> {
    let layout = layout_and_digits(locale, options)?;
    Ok((layout.minimum, layout.maximum))
}

/// The locale's symbols, the style's prefix and suffix, and the resolved
/// fraction digits.
struct NumberLayout {
    symbols: LocaleSymbols,
    prefix: &'static str,
    suffix: &'static str,
    minimum: u32,
    maximum: u32,
}

fn layout_and_digits(
    locale: Option<&str>,
    options: &NumberLocaleOptions,
) -> Result<NumberLayout, NumberLocaleError> {
    let symbols = locale_symbols(locale)?;
    let (prefix, suffix, default_min, default_max) = match &options.style {
        NumberLocaleStyle::Decimal => ("", "", 0, 3),
        NumberLocaleStyle::Percent | NumberLocaleStyle::Currency(_) if !symbols.english_layout => {
            return Err(NumberLocaleError::Unsupported(format!(
                "style {:?} for locale {:?}",
                options.style,
                locale.unwrap_or("en-US")
            )));
        }
        NumberLocaleStyle::Percent => ("", "%", 0, 0),
        NumberLocaleStyle::Currency(code) => {
            let (symbol, digits) = currency_layout(code).ok_or_else(|| {
                NumberLocaleError::Unsupported(format!(
                    "currency {code:?} (formatted currencies: USD, EUR, GBP, JPY)"
                ))
            })?;
            (symbol, "", digits, digits)
        }
    };
    for digits in [
        options.minimum_fraction_digits,
        options.maximum_fraction_digits,
    ]
    .into_iter()
    .flatten()
    {
        if digits > 100 {
            return Err(NumberLocaleError::Range(format!(
                "fraction digits value is out of range: {digits}"
            )));
        }
    }
    let (minimum, maximum) = match (
        options.minimum_fraction_digits,
        options.maximum_fraction_digits,
    ) {
        (Some(min), Some(max)) if min > max => {
            return Err(NumberLocaleError::Range(format!(
                "maximumFractionDigits value is out of range: {max} < {min}"
            )));
        }
        (Some(min), Some(max)) => (min, max),
        (Some(min), None) => (min, default_max.max(min)),
        (None, Some(max)) => (default_min.min(max), max),
        (None, None) => (default_min, default_max),
    };
    Ok(NumberLayout {
        symbols,
        prefix,
        suffix,
        minimum,
        maximum,
    })
}

/// Format `value` as `Number.prototype.toLocaleString(locale, options)`.
pub(super) fn format_number_locale(
    value: f64,
    locale: Option<&str>,
    options: &NumberLocaleOptions,
) -> Result<String, NumberLocaleError> {
    let NumberLayout {
        symbols,
        prefix,
        suffix,
        minimum,
        maximum,
    } = layout_and_digits(locale, options)?;
    let negative = value.is_sign_negative() && !value.is_nan();
    let body = if value.is_nan() {
        "NaN".to_string()
    } else if value.is_infinite() {
        "∞".to_string()
    } else {
        let shift = if options.style == NumberLocaleStyle::Percent {
            2
        } else {
            0
        };
        let (integer, fraction) = round_half_expand(value.abs(), shift, minimum, maximum);
        let integer = if options.use_grouping {
            group_digits(&integer, symbols.group)
        } else {
            integer
        };
        if fraction.is_empty() {
            integer
        } else {
            format!("{integer}{}{fraction}", symbols.decimal)
        }
    };
    let sign = if negative { "-" } else { "" };
    Ok(format!("{sign}{prefix}{body}{suffix}"))
}

/// The integer and fraction digits of `magnitude` times 10^`shift`, from its
/// shortest round-trip decimal form, rounded half-expand to at most
/// `maximum` fraction digits and padded to at least `minimum`.
fn round_half_expand(magnitude: f64, shift: usize, minimum: u32, maximum: u32) -> (String, String) {
    // Rust's `Display` for f64 is the shortest round-trip form, never in
    // exponent notation.
    let text = format!("{magnitude}");
    let (integer, fraction) = text.split_once('.').unwrap_or((&text, ""));
    let mut digits: Vec<u8> = integer
        .bytes()
        .chain(fraction.bytes())
        .map(|b| b - b'0')
        .collect();
    let mut point = integer.len() + shift;
    while digits.len() < point {
        digits.push(0);
    }
    let keep = point + maximum as usize;
    if digits.len() > keep {
        let round_up = digits[keep] >= 5;
        digits.truncate(keep);
        if round_up {
            let mut index = keep;
            loop {
                if index == 0 {
                    digits.insert(0, 1);
                    point += 1;
                    break;
                }
                index -= 1;
                if digits[index] == 9 {
                    digits[index] = 0;
                } else {
                    digits[index] += 1;
                    break;
                }
            }
        }
    }
    let to_text = |slice: &[u8]| {
        slice
            .iter()
            .map(|d| char::from(b'0' + d))
            .collect::<String>()
    };
    let integer = to_text(&digits[..point]);
    let integer = integer.trim_start_matches('0');
    let integer = if integer.is_empty() { "0" } else { integer }.to_string();
    let mut fraction = to_text(&digits[point..]);
    while fraction.len() > minimum as usize && fraction.ends_with('0') {
        fraction.pop();
    }
    while fraction.len() < minimum as usize {
        fraction.push('0');
    }
    (integer, fraction)
}

/// `1234567` → `1,234,567` with `separator`.
fn group_digits(integer: &str, separator: char) -> String {
    let mut out = String::with_capacity(integer.len() + integer.len() / 3);
    for (index, digit) in integer.chars().enumerate() {
        if index > 0 && (integer.len() - index).is_multiple_of(3) {
            out.push(separator);
        }
        out.push(digit);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn en(value: f64) -> String {
        format_number_locale(value, None, &NumberLocaleOptions::default()).expect("en format")
    }

    fn with(value: f64, locale: &str, options: NumberLocaleOptions) -> String {
        format_number_locale(value, Some(locale), &options).expect("format")
    }

    #[test]
    fn decimal_defaults_group_and_round_to_three_digits() {
        // Node v22.2.0 (ICU) values.
        assert_eq!(en(1234567.891), "1,234,567.891");
        assert_eq!(en(1.23456), "1.235");
        assert_eq!(en(1.0005), "1.001");
        assert_eq!(en(0.9999), "1");
        assert_eq!(en(999.9996), "1,000");
        assert_eq!(en(-1234.5), "-1,234.5");
        assert_eq!(en(-0.0), "-0");
        assert_eq!(en(-0.0001), "-0");
        assert_eq!(en(1e21), "1,000,000,000,000,000,000,000");
        assert_eq!(en(0.000001), "0");
        assert_eq!(en(f64::NAN), "NaN");
        assert_eq!(en(f64::INFINITY), "∞");
        assert_eq!(en(f64::NEG_INFINITY), "-∞");
    }

    #[test]
    fn options_and_locales() {
        let digits = |min, max| NumberLocaleOptions {
            minimum_fraction_digits: min,
            maximum_fraction_digits: max,
            ..NumberLocaleOptions::default()
        };
        assert_eq!(with(1.5, "en-US", digits(Some(2), None)), "1.50");
        assert_eq!(with(1.23456, "en-US", digits(None, Some(1))), "1.2");
        assert_eq!(with(2.0, "en-US", digits(Some(1), Some(1))), "2.0");
        assert_eq!(
            with(1234.5, "de-DE", NumberLocaleOptions::default()),
            "1.234,5"
        );
        let ungrouped = NumberLocaleOptions {
            use_grouping: false,
            ..NumberLocaleOptions::default()
        };
        assert_eq!(with(1234567.0, "en-US", ungrouped), "1234567");
        let percent = NumberLocaleOptions {
            style: NumberLocaleStyle::Percent,
            ..NumberLocaleOptions::default()
        };
        assert_eq!(with(0.256, "en-US", percent.clone()), "26%");
        assert_eq!(with(0.2555, "en", percent), "26%");
        let currency = |code: &str| NumberLocaleOptions {
            style: NumberLocaleStyle::Currency(code.to_string()),
            ..NumberLocaleOptions::default()
        };
        assert_eq!(with(1234.5, "en-US", currency("USD")), "$1,234.50");
        assert_eq!(with(-3.0, "en-US", currency("EUR")), "-€3.00");
        assert_eq!(with(1234.5, "en-US", currency("JPY")), "¥1,235");
    }

    #[test]
    fn invalid_or_unsupported_input_is_refused() {
        let bad_range = NumberLocaleOptions {
            minimum_fraction_digits: Some(3),
            maximum_fraction_digits: Some(1),
            ..NumberLocaleOptions::default()
        };
        assert!(matches!(
            format_number_locale(1.0, None, &bad_range),
            Err(NumberLocaleError::Range(_))
        ));
        assert!(matches!(
            format_number_locale(1.0, Some("fr-FR"), &NumberLocaleOptions::default()),
            Err(NumberLocaleError::Unsupported(_))
        ));
        let percent = NumberLocaleOptions {
            style: NumberLocaleStyle::Percent,
            ..NumberLocaleOptions::default()
        };
        assert!(matches!(
            format_number_locale(1.0, Some("de-DE"), &percent),
            Err(NumberLocaleError::Unsupported(_))
        ));
    }
}
