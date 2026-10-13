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

/// When a sign is written (`signDisplay`, ECMA-402 15.5.11); "zero" is the
/// rounded value, so `-0.0004` is a negative zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum SignDisplay {
    /// `-` for negative numbers and negative zero.
    #[default]
    Auto,
    Never,
    /// `+` or `-` on every number, zero included.
    Always,
    /// `+` or `-`, but none on zero or NaN.
    ExceptZero,
    /// `-` for negative numbers other than zero.
    Negative,
}

impl SignDisplay {
    pub(super) fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "auto" => Self::Auto,
            "never" => Self::Never,
            "always" => Self::Always,
            "exceptZero" => Self::ExceptZero,
            "negative" => Self::Negative,
            _ => return None,
        })
    }

    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Never => "never",
            Self::Always => "always",
            Self::ExceptZero => "exceptZero",
            Self::Negative => "negative",
        }
    }
}

/// The options toLocaleString honors; `None` fraction digits take the
/// style's defaults (ECMA-402 SetNumberFormatDigitOptions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NumberLocaleOptions {
    pub(super) style: NumberLocaleStyle,
    pub(super) minimum_fraction_digits: Option<u32>,
    pub(super) maximum_fraction_digits: Option<u32>,
    /// Minimum and maximum significant digits (1..=21). When present they
    /// decide the rounding and the fraction digits are not used
    /// (roundingPriority "auto"), as in ICU.
    pub(super) significant_digits: Option<(u32, u32)>,
    pub(super) sign_display: SignDisplay,
    pub(super) use_grouping: bool,
}

impl Default for NumberLocaleOptions {
    fn default() -> Self {
        Self {
            style: NumberLocaleStyle::Decimal,
            minimum_fraction_digits: None,
            maximum_fraction_digits: None,
            significant_digits: None,
            sign_display: SignDisplay::Auto,
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
    /// Whether the percent layout (`26%`) is known for the locale.
    english_layout: bool,
    /// `12,34,567`: three digits, then pairs (en-IN).
    indian_grouping: bool,
    /// How the locale writes the currencies the engine formats, if its
    /// currency layout (`-$1,234.50`) is known.
    currencies: Option<CurrencySymbols>,
}

/// The symbols CLDR (Node v22.2.0's ICU) gives USD, EUR, GBP and JPY in a
/// locale group whose currency layout is `<sign><symbol><number>`.
#[derive(Clone, Copy)]
enum CurrencySymbols {
    /// en, en-US, en-PH: `$ € £ ¥`.
    UnitedStates,
    /// en-GB and most English regions, zh, zh-CN, zh-SG, ko: `US$ € £ JP¥`.
    International,
    /// en-IN: `$ € £ JP¥`.
    India,
    /// ja: `$ € £ ￥`.
    Japan,
    /// zh-TW, zh-HK, zh-Hant: `US$ € £ ¥`.
    TraditionalChinese,
}

impl CurrencySymbols {
    fn symbol(self, code: &str) -> Option<&'static str> {
        use CurrencySymbols::{India, International, Japan, TraditionalChinese, UnitedStates};
        Some(match (code, self) {
            ("USD", UnitedStates | India | Japan) => "$",
            ("USD", International | TraditionalChinese) => "US$",
            ("EUR", _) => "€",
            ("GBP", _) => "£",
            ("JPY", UnitedStates | TraditionalChinese) => "¥",
            ("JPY", International | India) => "JP¥",
            ("JPY", Japan) => "￥",
            _ => return None,
        })
    }
}

/// The language, script and region subtags of a BCP 47 tag (`zh-Hant-TW`),
/// and whether it carries a Unicode `nu` (numbering system) keyword.
fn locale_subtags(tag: &str) -> (String, Option<String>, Option<String>, bool) {
    let mut subtags = tag.split(['-', '_']);
    let language = subtags.next().unwrap_or_default().to_ascii_lowercase();
    let (mut script, mut region) = (None, None);
    let mut numbering = false;
    let mut in_extension = false;
    for subtag in subtags {
        if subtag.len() == 1 {
            in_extension = true;
            continue;
        }
        if in_extension {
            numbering |= subtag.eq_ignore_ascii_case("nu");
        } else if subtag.len() == 4 && subtag.bytes().all(|b| b.is_ascii_alphabetic()) {
            script.get_or_insert_with(|| subtag.to_ascii_lowercase());
        } else if (subtag.len() == 2 && subtag.bytes().all(|b| b.is_ascii_alphabetic()))
            || (subtag.len() == 3 && subtag.bytes().all(|b| b.is_ascii_digit()))
        {
            region.get_or_insert_with(|| subtag.to_ascii_uppercase());
        }
    }
    (language, script, region, numbering)
}

/// The locales whose number symbols the engine knows, region by region:
/// a region of a known language that writes numbers differently (en-CH
/// `1’234’567.891`, en-DE and de-AT, de-CH) is refused rather than
/// formatted as the language's default (bd-9vouw.462). Values are Node
/// v22.2.0's (ICU).
fn locale_symbols(locale: Option<&str>) -> Result<LocaleSymbols, NumberLocaleError> {
    let tag = locale.unwrap_or("en-US");
    let (language, script, region, numbering) = locale_subtags(tag);
    let unsupported = || {
        NumberLocaleError::Unsupported(format!(
            "locale {tag:?} (formatted: en and its regions US GB AU CA NZ IE SG HK PH NG KE \
             ZA IN 150 MY PK JM 001; ja; zh; ko; de, de-DE, de-LU, de-BE, de-IT)"
        ))
    };
    if numbering {
        return Err(unsupported());
    }
    let english_like = |currencies| LocaleSymbols {
        group: ',',
        decimal: '.',
        english_layout: true,
        indian_grouping: false,
        currencies,
    };
    use CurrencySymbols::{India, International, Japan, TraditionalChinese, UnitedStates};
    match (language.as_str(), region.as_deref()) {
        ("en", None | Some("US" | "PH")) => Ok(english_like(Some(UnitedStates))),
        (
            "en",
            Some(
                "GB" | "CA" | "NZ" | "IE" | "SG" | "HK" | "NG" | "KE" | "ZA" | "MY" | "PK" | "JM"
                | "001",
            ),
        ) => Ok(english_like(Some(International))),
        // en-AU writes `USD 1,234.50` and en-150 `1,234.50 US$`: numbers
        // and percent as in English, currency refused.
        ("en", Some("AU" | "150")) => Ok(english_like(None)),
        ("en", Some("IN")) => Ok(LocaleSymbols {
            indian_grouping: true,
            ..english_like(Some(India))
        }),
        ("ja", None | Some("JP")) => Ok(english_like(Some(Japan))),
        ("zh", Some("TW" | "HK")) => Ok(english_like(Some(TraditionalChinese))),
        ("zh", None) if script.as_deref() == Some("hant") => {
            Ok(english_like(Some(TraditionalChinese)))
        }
        ("zh", None | Some("CN" | "SG")) => Ok(english_like(Some(International))),
        ("ko", None | Some("KR" | "KP")) => Ok(english_like(Some(International))),
        ("de", None | Some("DE" | "LU" | "BE" | "IT")) => Ok(LocaleSymbols {
            group: '.',
            decimal: ',',
            english_layout: false,
            indian_grouping: false,
            currencies: None,
        }),
        _ => Err(unsupported()),
    }
}

/// Fraction digits of the currencies the engine formats.
fn currency_digits(code: &str) -> Option<u32> {
    match code {
        "USD" | "EUR" | "GBP" => Some(2),
        "JPY" => Some(0),
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
    let unsupported_style = || {
        NumberLocaleError::Unsupported(format!(
            "style {:?} for locale {:?}",
            options.style,
            locale.unwrap_or("en-US")
        ))
    };
    let (prefix, suffix, default_min, default_max) = match &options.style {
        NumberLocaleStyle::Decimal => ("", "", 0, 3),
        NumberLocaleStyle::Percent if !symbols.english_layout => {
            return Err(unsupported_style());
        }
        NumberLocaleStyle::Percent => ("", "%", 0, 0),
        NumberLocaleStyle::Currency(code) => {
            let digits = currency_digits(code).ok_or_else(|| {
                NumberLocaleError::Unsupported(format!(
                    "currency {code:?} (formatted currencies: USD, EUR, GBP, JPY)"
                ))
            })?;
            let symbol = symbols
                .currencies
                .and_then(|currencies| currencies.symbol(code))
                .ok_or_else(unsupported_style)?;
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
    let mut rounded_zero = false;
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
        let (integer, fraction) = match options.significant_digits {
            Some((minimum_significant, maximum_significant)) => {
                round_significant(value.abs(), shift, minimum_significant, maximum_significant)
            }
            None => round_half_expand(value.abs(), shift, minimum, maximum),
        };
        rounded_zero = integer.bytes().chain(fraction.bytes()).all(|b| b == b'0');
        let integer = if !options.use_grouping {
            integer
        } else if symbols.indian_grouping {
            group_digits_indian(&integer, symbols.group)
        } else {
            group_digits(&integer, symbols.group)
        };
        if fraction.is_empty() {
            integer
        } else {
            format!("{integer}{}{fraction}", symbols.decimal)
        }
    };
    let sign = match options.sign_display {
        SignDisplay::Auto if negative => "-",
        SignDisplay::Auto | SignDisplay::Never => "",
        SignDisplay::Always if negative => "-",
        SignDisplay::Always => "+",
        SignDisplay::ExceptZero if value.is_nan() || rounded_zero => "",
        SignDisplay::ExceptZero if negative => "-",
        SignDisplay::ExceptZero => "+",
        SignDisplay::Negative if negative && !rounded_zero => "-",
        SignDisplay::Negative => "",
    };
    Ok(format!("{sign}{prefix}{body}{suffix}"))
}

/// The integer and fraction digits of `magnitude` times 10^`shift`, rounded
/// half-expand to at most `maximum` significant digits and shown with at
/// least `minimum` (ECMA-402 ToRawPrecision), from its shortest round-trip
/// decimal form: `1234.5678` to 3 is `1230`, `0.0004` with at least 3 is
/// `0.000400`, zero with at least 3 is `0.00`.
fn round_significant(magnitude: f64, shift: usize, minimum: u32, maximum: u32) -> (String, String) {
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
    let to_text = |slice: &[u8]| {
        slice
            .iter()
            .map(|d| char::from(b'0' + d))
            .collect::<String>()
    };
    let Some(first) = digits.iter().position(|&d| d != 0) else {
        let zeros = minimum.saturating_sub(1) as usize;
        return ("0".to_string(), "0".repeat(zeros));
    };
    let keep = first + maximum as usize;
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
    while digits.len() < point {
        digits.push(0);
    }
    let integer = to_text(&digits[..point]);
    let integer = integer.trim_start_matches('0');
    let integer = if integer.is_empty() { "0" } else { integer }.to_string();
    let mut fraction = to_text(&digits[point..]);
    let shown = |integer: &str, fraction: &str| {
        if integer == "0" {
            fraction.trim_start_matches('0').len()
        } else {
            integer.len() + fraction.len()
        }
    };
    while fraction.ends_with('0') && shown(&integer, &fraction) > minimum as usize {
        fraction.pop();
    }
    while shown(&integer, &fraction) < minimum as usize {
        fraction.push('0');
    }
    (integer, fraction)
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

/// `1234567` → `12,34,567`: the last three digits, then groups of two
/// (Indian grouping, en-IN).
fn group_digits_indian(integer: &str, separator: char) -> String {
    if integer.len() <= 3 {
        return integer.to_string();
    }
    let (head, tail) = integer.split_at(integer.len() - 3);
    let mut out = String::with_capacity(integer.len() + integer.len() / 2);
    for (index, digit) in head.chars().enumerate() {
        if index > 0 && (head.len() - index).is_multiple_of(2) {
            out.push(separator);
        }
        out.push(digit);
    }
    out.push(separator);
    out.push_str(tail);
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

    #[test]
    fn regions_and_currencies_follow_icu_or_are_refused() {
        // Node v22.2.0 (ICU) values (bd-9vouw.462).
        let default = NumberLocaleOptions::default;
        let currency = |code: &str| NumberLocaleOptions {
            style: NumberLocaleStyle::Currency(code.to_string()),
            ..NumberLocaleOptions::default()
        };
        assert_eq!(with(1234567.891, "en-IN", default()), "12,34,567.891");
        assert_eq!(with(-123.0, "en-IN", default()), "-123");
        assert_eq!(with(1234567.891, "en-GB", default()), "1,234,567.891");
        assert_eq!(with(1234567.891, "de-LU", default()), "1.234.567,891");
        assert_eq!(with(1234567.891, "zh-Hant-TW", default()), "1,234,567.891");
        assert_eq!(with(-1234.5, "en-GB", currency("USD")), "-US$1,234.50");
        assert_eq!(with(-1234.5, "en-GB", currency("JPY")), "-JP¥1,235");
        assert_eq!(with(-1234.5, "en-PH", currency("USD")), "-$1,234.50");
        assert_eq!(with(-1234.5, "en-IN", currency("JPY")), "-JP¥1,235");
        assert_eq!(with(-1234.5, "ja-JP", currency("JPY")), "-￥1,235");
        assert_eq!(with(-1234.5, "zh-CN", currency("USD")), "-US$1,234.50");
        assert_eq!(with(-1234.5, "zh-TW", currency("JPY")), "-¥1,235");
        assert_eq!(with(-1234.5, "zh-Hant", currency("JPY")), "-¥1,235");
        assert_eq!(with(-1234.5, "ko-KR", currency("GBP")), "-£1,234.50");
        for (locale, options) in [
            ("en-CH", default()),
            ("en-DE", default()),
            ("en-SE", default()),
            ("de-AT", default()),
            ("de-CH", default()),
            ("en-US-u-nu-arab", default()),
            ("en-AU", currency("USD")),
            ("en-150", currency("EUR")),
            ("de-DE", currency("EUR")),
        ] {
            assert!(
                matches!(
                    format_number_locale(1.0, Some(locale), &options),
                    Err(NumberLocaleError::Unsupported(_))
                ),
                "{locale} must be refused"
            );
        }
    }

    #[test]
    fn sign_display_and_significant_digits_match_icu() {
        // Node v22.2.0 (ICU), en-US (bd-9vouw.463).
        let fmt = |value: f64, options: NumberLocaleOptions| {
            format_number_locale(value, Some("en-US"), &options).expect("format")
        };
        let sign = |display: SignDisplay| NumberLocaleOptions {
            sign_display: display,
            ..NumberLocaleOptions::default()
        };
        let sig = |minimum: u32, maximum: u32| NumberLocaleOptions {
            significant_digits: Some((minimum, maximum)),
            ..NumberLocaleOptions::default()
        };
        let cases: [(f64, NumberLocaleOptions, &str); 37] = [
            (0.0, sign(SignDisplay::Always), "+0"),
            (-0.0, sign(SignDisplay::Always), "-0"),
            (1.0, sign(SignDisplay::Always), "+1"),
            (0.0004, sign(SignDisplay::Always), "+0"),
            (-0.0004, sign(SignDisplay::Always), "-0"),
            (f64::NAN, sign(SignDisplay::Always), "+NaN"),
            (f64::INFINITY, sign(SignDisplay::Always), "+∞"),
            (-1.0, sign(SignDisplay::Never), "1"),
            (f64::NEG_INFINITY, sign(SignDisplay::Never), "∞"),
            (0.0, sign(SignDisplay::ExceptZero), "0"),
            (-0.0004, sign(SignDisplay::ExceptZero), "0"),
            (1.0, sign(SignDisplay::ExceptZero), "+1"),
            (f64::NAN, sign(SignDisplay::ExceptZero), "NaN"),
            (f64::NEG_INFINITY, sign(SignDisplay::ExceptZero), "-∞"),
            (-0.0, sign(SignDisplay::Negative), "0"),
            (-1.0, sign(SignDisplay::Negative), "-1"),
            (-0.0004, sign(SignDisplay::Negative), "0"),
            (-0.0004, sign(SignDisplay::Auto), "-0"),
            (1234.5678, sig(1, 3), "1,230"),
            (123456.0, sig(1, 3), "123,000"),
            (0.000123456, sig(1, 3), "0.000123"),
            (99.95, sig(1, 3), "100"),
            (999.95, sig(1, 3), "1,000"),
            (0.0004, sig(1, 3), "0.0004"),
            (0.0, sig(3, 21), "0.00"),
            (1.0, sig(3, 21), "1.00"),
            (0.0004, sig(3, 21), "0.000400"),
            (1234.5678, sig(3, 21), "1,234.5678"),
            (1234.5678, sig(2, 4), "1,235"),
            (123456.0, sig(2, 4), "123,500"),
            (0.000123456, sig(2, 4), "0.0001235"),
            (999.95, sig(2, 4), "1,000"),
            (0.0, sig(2, 4), "0.0"),
            (-0.0, sig(2, 4), "-0.0"),
            (1234.5678, sig(1, 1), "1,000"),
            (99.95, sig(1, 1), "100"),
            (99.95, sig(2, 4), "99.95"),
        ];
        for (value, options, expected) in cases {
            assert_eq!(fmt(value, options.clone()), expected, "{value} {options:?}");
        }
        let percent = NumberLocaleOptions {
            style: NumberLocaleStyle::Percent,
            significant_digits: Some((1, 2)),
            ..NumberLocaleOptions::default()
        };
        assert_eq!(fmt(0.0004, percent.clone()), "0.04%");
        assert_eq!(fmt(1234.5678, percent), "120,000%");
        let dollars = |significant_digits, sign_display| NumberLocaleOptions {
            style: NumberLocaleStyle::Currency("USD".to_string()),
            significant_digits,
            sign_display,
            ..NumberLocaleOptions::default()
        };
        assert_eq!(
            fmt(1234.5678, dollars(Some((1, 2)), SignDisplay::Auto)),
            "$1,200"
        );
        assert_eq!(
            fmt(0.000123456, dollars(Some((1, 2)), SignDisplay::Auto)),
            "$0.00012"
        );
        assert_eq!(fmt(1.0, dollars(None, SignDisplay::Always)), "+$1.00");
        assert_eq!(fmt(-0.0, dollars(None, SignDisplay::Always)), "-$0.00");
    }
}
