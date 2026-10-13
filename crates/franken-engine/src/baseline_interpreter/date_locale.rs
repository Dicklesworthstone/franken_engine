//! `Date.prototype.toLocaleString` / `toLocaleDateString` /
//! `toLocaleTimeString` formatting (ECMA-402 subset).
//!
//! The engine is hermetic: local time is UTC, so these format the UTC
//! fields, as Node does with `TZ=UTC`. Without ICU it knows the default
//! numeric layouts of a few locales (en-US, en-GB, de, fr, ja), and for
//! en-US the Intl.DateTimeFormat components (`{ month: 'long', day:
//! 'numeric' }`) and date/time styles; anything else is a typed refusal,
//! never a string that differs from Node's.

/// Which of the three methods is formatting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DateLocaleKind {
    DateTime,
    Date,
    Time,
}

/// A date's UTC fields; `month` is 0-based, `year` proleptic Gregorian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DateFields {
    pub(super) year: i64,
    pub(super) month: u32,
    pub(super) day: u32,
    pub(super) hour: u32,
    pub(super) minute: u32,
    pub(super) second: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Layout {
    /// en-US: `12/25/2020, 3:30:05 PM`.
    UnitedStates,
    /// en-GB: `25/12/2020, 15:30:05`.
    Britain,
    /// de: `25.12.2020, 15:30:05` (day and month unpadded).
    German,
    /// fr: `25/12/2020 15:30:05`.
    French,
    /// ja: `2020/12/25 15:30:05` (month, day and hour unpadded).
    Japanese,
}

/// The layout of a locale, region by region where its regions differ: fr-CA
/// (`2024-02-09 03 h 05 min 09 s`) and fr-CH (`09.02.2024`) are not
/// French's layout, so they are refused rather than formatted as fr
/// (bd-9vouw.462). Every German region Node v22.2.0 was checked with shares
/// one layout.
fn layout(locale: Option<&str>) -> Result<Layout, String> {
    let tag = locale.unwrap_or("en-US");
    let lower = tag.to_ascii_lowercase().replace('_', "-");
    let mut subtags = lower.split('-');
    let language = subtags.next().unwrap_or("");
    let rest: Vec<&str> = subtags.collect();
    // An extension (`-u-hc-h23`, `-u-ca-…`) can change the layout: refused.
    let has_extension = rest.iter().any(|subtag| subtag.len() == 1);
    let region = rest.iter().copied().find(|subtag| {
        (subtag.len() == 2 && subtag.bytes().all(|b| b.is_ascii_alphabetic()))
            || (subtag.len() == 3 && subtag.bytes().all(|b| b.is_ascii_digit()))
    });
    match (language, region) {
        _ if has_extension => Err(format!(
            "locale {tag:?} (extensions are not formatted for dates)"
        )),
        ("en", None | Some("us" | "ph")) => Ok(Layout::UnitedStates),
        ("en", Some("gb")) => Ok(Layout::Britain),
        ("de", _) => Ok(Layout::German),
        ("fr", None | Some("fr" | "be" | "lu" | "ma" | "sn")) => Ok(Layout::French),
        ("ja", None | Some("jp")) => Ok(Layout::Japanese),
        _ => Err(format!(
            "locale {tag:?} (formatted date locales: en, en-US, en-PH, en-GB, de, fr, fr-FR, \
             fr-BE, fr-LU, fr-MA, fr-SN, ja, ja-JP)"
        )),
    }
}

/// The type of one formatted piece, as Intl.DateTimeFormat's
/// formatToParts names it (ECMA-402 11.4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PartType {
    Weekday,
    Year,
    Month,
    Day,
    DayPeriod,
    Hour,
    Minute,
    Second,
    TimeZoneName,
    Literal,
}

impl PartType {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Weekday => "weekday",
            Self::Year => "year",
            Self::Month => "month",
            Self::Day => "day",
            Self::DayPeriod => "dayPeriod",
            Self::Hour => "hour",
            Self::Minute => "minute",
            Self::Second => "second",
            Self::TimeZoneName => "timeZoneName",
            Self::Literal => "literal",
        }
    }
}

/// The literal ICU puts before a day period (`10:00` + U+202F + `AM`).
/// formatToParts returns it; `format` gives an ASCII space there, as V8
/// does (Node v22.2.0: the parts join to a different string than format).
const DAY_PERIOD_SEPARATOR: &str = "\u{202f}";

/// A formatted date as typed pieces. Every layout builds these and the
/// formatted string is their concatenation (with an ASCII space for
/// [`DAY_PERIOD_SEPARATOR`]), so `format` and `formatToParts` cannot
/// otherwise disagree. Adjacent literals merge, as ICU's do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct DateParts(pub(super) Vec<(PartType, String)>);

impl DateParts {
    fn push(&mut self, kind: PartType, text: impl Into<String>) {
        let text = text.into();
        if text.is_empty() {
            return;
        }
        if kind == PartType::Literal
            && let Some((PartType::Literal, last)) = self.0.last_mut()
        {
            last.push_str(&text);
            return;
        }
        self.0.push((kind, text));
    }

    fn literal(&mut self, text: &str) {
        self.push(PartType::Literal, text);
    }

    fn append(&mut self, other: DateParts) {
        for (kind, text) in other.0 {
            self.push(kind, text);
        }
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(super) fn joined(&self) -> String {
        self.0
            .iter()
            .map(|(_, text)| text.replace(DAY_PERIOD_SEPARATOR, " "))
            .collect()
    }
}

/// Format `fields` for `locale`, or name what the engine does not format.
pub(super) fn format_date_locale(
    fields: DateFields,
    locale: Option<&str>,
    kind: DateLocaleKind,
) -> Result<String, String> {
    format_date_locale_parts(fields, locale, kind).map(|parts| parts.joined())
}

/// [`format_date_locale`] as typed pieces.
pub(super) fn format_date_locale_parts(
    fields: DateFields,
    locale: Option<&str>,
    kind: DateLocaleKind,
) -> Result<DateParts, String> {
    use PartType::{Day, DayPeriod, Hour, Minute, Month, Second, Year};
    let layout = layout(locale)?;
    // ICU's `y` is the year of the era: 1 BC is year 1.
    let year = era_year(&fields).to_string();
    let (month, day) = (fields.month + 1, fields.day);
    let (hour, minute, second) = (fields.hour, fields.minute, fields.second);
    let mut date = DateParts::default();
    let (first, second_field, third, glue) = match layout {
        Layout::UnitedStates => (
            (Month, month.to_string()),
            (Day, day.to_string()),
            (Year, year),
            "/",
        ),
        Layout::Britain | Layout::French => (
            (Day, format!("{day:02}")),
            (Month, format!("{month:02}")),
            (Year, year),
            "/",
        ),
        Layout::German => (
            (Day, day.to_string()),
            (Month, month.to_string()),
            (Year, year),
            ".",
        ),
        Layout::Japanese => (
            (Year, year),
            (Month, month.to_string()),
            (Day, day.to_string()),
            "/",
        ),
    };
    date.push(first.0, first.1);
    date.literal(glue);
    date.push(second_field.0, second_field.1);
    date.literal(glue);
    date.push(third.0, third.1);
    let mut time = DateParts::default();
    match layout {
        Layout::UnitedStates => {
            let twelve = match hour % 12 {
                0 => 12,
                other => other,
            };
            time.push(Hour, twelve.to_string());
            time.literal(":");
            time.push(Minute, format!("{minute:02}"));
            time.literal(":");
            time.push(Second, format!("{second:02}"));
            time.literal(DAY_PERIOD_SEPARATOR);
            time.push(DayPeriod, if hour < 12 { "AM" } else { "PM" });
        }
        Layout::Japanese => {
            time.push(Hour, hour.to_string());
            time.literal(":");
            time.push(Minute, format!("{minute:02}"));
            time.literal(":");
            time.push(Second, format!("{second:02}"));
        }
        _ => {
            time.push(Hour, format!("{hour:02}"));
            time.literal(":");
            time.push(Minute, format!("{minute:02}"));
            time.literal(":");
            time.push(Second, format!("{second:02}"));
        }
    }
    let separator = match layout {
        Layout::UnitedStates | Layout::Britain | Layout::German => ", ",
        Layout::French | Layout::Japanese => " ",
    };
    Ok(match kind {
        DateLocaleKind::DateTime => {
            date.literal(separator);
            date.append(time);
            date
        }
        DateLocaleKind::Date => date,
        DateLocaleKind::Time => time,
    })
}

/// A name's width (`"long"`, `"short"`, `"narrow"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TextWidth {
    Long,
    Short,
    Narrow,
}

/// A number's width (`"numeric"`, `"2-digit"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Digits {
    Numeric,
    TwoDigit,
}

/// The `month` option: digits or a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MonthStyle {
    Digits(Digits),
    Text(TextWidth),
}

/// `dateStyle` / `timeStyle`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FormatStyle {
    Full,
    Long,
    Medium,
    Short,
}

/// The Intl.DateTimeFormat components the engine lays out (en-US, the UTC
/// time zone).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DateComponents {
    pub(super) weekday: Option<TextWidth>,
    pub(super) year: Option<Digits>,
    pub(super) month: Option<MonthStyle>,
    pub(super) day: Option<Digits>,
    pub(super) hour: Option<Digits>,
    pub(super) minute: Option<Digits>,
    pub(super) second: Option<Digits>,
    /// The twelve-hour clock (en-US's; `hour12: false` or `h23` clears it).
    pub(super) hour12: bool,
    pub(super) time_zone_name: Option<TextWidth>,
}

const MONTH_NAMES: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];
const WEEKDAY_NAMES: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];

fn named(name: &str, width: TextWidth) -> String {
    match width {
        TextWidth::Long => name.to_string(),
        TextWidth::Short => name.chars().take(3).collect(),
        TextWidth::Narrow => name.chars().take(1).collect(),
    }
}

fn number(value: i64, digits: Digits) -> String {
    match digits {
        Digits::Numeric => value.to_string(),
        Digits::TwoDigit => format!("{:02}", value.rem_euclid(100)),
    }
}

/// Day of the week of `fields`, 0 for Sunday (days from the civil date,
/// 1970-01-01 being a Thursday).
fn weekday_index(fields: &DateFields) -> usize {
    let month = i64::from(fields.month) + 1;
    let year = fields.year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let shifted_month = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(fields.day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    (days + 4).rem_euclid(7) as usize
}

/// ICU's `y`: the year of the era (1 BC is year 1).
fn era_year(fields: &DateFields) -> i64 {
    if fields.year <= 0 {
        1 - fields.year
    } else {
        fields.year
    }
}

/// The ` UTC` / ` Coordinated Universal Time` a `timeZoneName` adds.
fn push_time_zone_name(parts: &mut DateParts, name: Option<TextWidth>) {
    let Some(width) = name else {
        return;
    };
    parts.literal(" ");
    parts.push(
        PartType::TimeZoneName,
        match width {
            TextWidth::Long => "Coordinated Universal Time",
            _ => "UTC",
        },
    );
}

fn en_us_only(locale: Option<&str>) -> Result<(), String> {
    match layout(locale)? {
        Layout::UnitedStates => Ok(()),
        _ => Err(format!(
            "date and time options for locale {:?} (en-US only)",
            locale.unwrap_or("en-US")
        )),
    }
}

/// Format `fields` with `dateStyle` / `timeStyle` (en-US), as typed pieces.
pub(super) fn format_date_styles_parts(
    fields: DateFields,
    locale: Option<&str>,
    date_style: Option<FormatStyle>,
    time_style: Option<FormatStyle>,
    hour12: bool,
) -> Result<DateParts, String> {
    use PartType::{Day, Month, Weekday, Year};
    en_us_only(locale)?;
    let year = era_year(&fields);
    let month = MONTH_NAMES[fields.month as usize % 12];
    let date = date_style.map(|style| {
        let mut date = DateParts::default();
        match style {
            FormatStyle::Full => {
                date.push(Weekday, WEEKDAY_NAMES[weekday_index(&fields)]);
                date.literal(", ");
                date.push(Month, month);
                date.literal(" ");
                date.push(Day, fields.day.to_string());
                date.literal(", ");
                date.push(Year, year.to_string());
            }
            FormatStyle::Long => {
                date.push(Month, month);
                date.literal(" ");
                date.push(Day, fields.day.to_string());
                date.literal(", ");
                date.push(Year, year.to_string());
            }
            FormatStyle::Medium => {
                date.push(Month, named(month, TextWidth::Short));
                date.literal(" ");
                date.push(Day, fields.day.to_string());
                date.literal(", ");
                date.push(Year, year.to_string());
            }
            FormatStyle::Short => {
                date.push(Month, (fields.month + 1).to_string());
                date.literal("/");
                date.push(Day, fields.day.to_string());
                date.literal("/");
                date.push(Year, number(year, Digits::TwoDigit));
            }
        }
        date
    });
    let time = time_style.map(|style| {
        let second = !matches!(style, FormatStyle::Short);
        let zone = match style {
            FormatStyle::Full => Some(TextWidth::Long),
            FormatStyle::Long => Some(TextWidth::Short),
            _ => None,
        };
        let mut time = clock(
            &fields,
            Some(Digits::Numeric),
            Some(Digits::TwoDigit),
            second.then_some(Digits::TwoDigit),
            hour12,
        );
        push_time_zone_name(&mut time, zone);
        time
    });
    Ok(match (date, time) {
        (Some(mut date), Some(time)) => {
            date.literal(
                if matches!(date_style, Some(FormatStyle::Full | FormatStyle::Long)) {
                    " at "
                } else {
                    ", "
                },
            );
            date.append(time);
            date
        }
        (Some(date), None) => date,
        (None, Some(time)) => time,
        (None, None) => DateParts::default(),
    })
}

/// `hour`, `minute` and `second` as en-US lays them out.
fn clock(
    fields: &DateFields,
    hour: Option<Digits>,
    minute: Option<Digits>,
    second: Option<Digits>,
    hour12: bool,
) -> DateParts {
    let mut out = DateParts::default();
    match hour {
        Some(width) if hour12 => {
            let twelve = match fields.hour % 12 {
                0 => 12,
                other => other,
            };
            out.push(PartType::Hour, number(i64::from(twelve), width));
        }
        // A 24-hour hour is always two digits in en-US ("00:07", "15").
        Some(_) => out.push(PartType::Hour, format!("{:02}", fields.hour)),
        None => {}
    }
    if minute.is_some() {
        if hour.is_some() {
            out.literal(":");
            out.push(PartType::Minute, format!("{:02}", fields.minute));
        } else if second.is_some() {
            out.push(PartType::Minute, format!("{:02}", fields.minute));
        } else {
            // ICU's lone minute is unpadded.
            out.push(PartType::Minute, fields.minute.to_string());
        }
    }
    if second.is_some() {
        if minute.is_some() {
            out.literal(":");
            out.push(PartType::Second, format!("{:02}", fields.second));
        } else {
            out.push(PartType::Second, fields.second.to_string());
        }
    }
    if hour.is_some() && hour12 {
        out.literal(DAY_PERIOD_SEPARATOR);
        out.push(
            PartType::DayPeriod,
            if fields.hour < 12 { "AM" } else { "PM" },
        );
    }
    out
}

/// Format `fields` with Intl.DateTimeFormat components (en-US) as typed
/// pieces, or name the combination the engine does not lay out.
pub(super) fn format_date_components_parts(
    fields: DateFields,
    locale: Option<&str>,
    components: &DateComponents,
) -> Result<DateParts, String> {
    use PartType::{Day, Month, Weekday, Year};
    en_us_only(locale)?;
    let year = components
        .year
        .map(|width| number(era_year(&fields), width));
    let day = components
        .day
        .map(|width| number(i64::from(fields.day), width));
    let month_text = matches!(components.month, Some(MonthStyle::Text(_)));
    let month = components.month.map(|style| match style {
        MonthStyle::Digits(width) => number(i64::from(fields.month) + 1, width),
        MonthStyle::Text(width) => named(MONTH_NAMES[fields.month as usize % 12], width),
    });
    let mut core = DateParts::default();
    match (month, day, year) {
        (Some(month), Some(day), Some(year)) if month_text => {
            core.push(Month, month);
            core.literal(" ");
            core.push(Day, day);
            core.literal(", ");
            core.push(Year, year);
        }
        (Some(month), Some(day), None) if month_text => {
            core.push(Month, month);
            core.literal(" ");
            core.push(Day, day);
        }
        (Some(month), None, Some(year)) if month_text => {
            core.push(Month, month);
            core.literal(" ");
            core.push(Year, year);
        }
        (Some(month), Some(day), Some(year)) => {
            core.push(Month, month);
            core.literal("/");
            core.push(Day, day);
            core.literal("/");
            core.push(Year, year);
        }
        (Some(month), Some(day), None) => {
            core.push(Month, month);
            core.literal("/");
            core.push(Day, day);
        }
        (Some(month), None, Some(year)) => {
            core.push(Month, month);
            core.literal("/");
            core.push(Year, year);
        }
        (Some(month), None, None) => core.push(Month, month),
        (None, Some(day), None) => core.push(Day, day),
        (None, None, Some(year)) => core.push(Year, year),
        (None, None, None) => {}
        (None, Some(_), Some(_)) => {
            return Err("a day and year without a month".to_string());
        }
    }
    let mut date = DateParts::default();
    if let Some(width) = components.weekday {
        date.push(Weekday, named(WEEKDAY_NAMES[weekday_index(&fields)], width));
        if !core.is_empty() {
            date.literal(", ");
        }
    }
    let has_core = !core.is_empty();
    date.append(core);
    let has_time =
        components.hour.is_some() || components.minute.is_some() || components.second.is_some();
    if components.second.is_some() && components.minute.is_none() && components.hour.is_some() {
        return Err("an hour and second without a minute".to_string());
    }
    let time = has_time.then(|| {
        let mut time = clock(
            &fields,
            components.hour,
            components.minute,
            components.second,
            components.hour12,
        );
        push_time_zone_name(&mut time, components.time_zone_name);
        time
    });
    Ok(match time {
        Some(time) if !date.is_empty() => {
            let glue = if !has_core {
                " "
            } else if matches!(components.month, Some(MonthStyle::Text(TextWidth::Long))) {
                " at "
            } else {
                ", "
            };
            date.literal(glue);
            date.append(time);
            date
        }
        Some(time) => time,
        None => date,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHRISTMAS: DateFields = DateFields {
        year: 2020,
        month: 11,
        day: 25,
        hour: 15,
        minute: 30,
        second: 5,
    };
    const EARLY: DateFields = DateFields {
        year: 2021,
        month: 0,
        day: 3,
        hour: 0,
        minute: 7,
        second: 9,
    };

    fn all(fields: DateFields, locale: Option<&str>) -> [String; 3] {
        [
            DateLocaleKind::DateTime,
            DateLocaleKind::Date,
            DateLocaleKind::Time,
        ]
        .map(|kind| format_date_locale(fields, locale, kind).expect("format"))
    }

    #[test]
    fn regions_with_another_layout_are_refused() {
        // Node v22.2.0, TZ=UTC (bd-9vouw.462): fr-BE and en-PH share their
        // language's layout; fr-CA (`2021-01-03 00 h 07 min 09 s`), fr-CH
        // (`03.01.2021`) and a locale with an extension do not.
        assert_eq!(all(EARLY, Some("fr-BE")), all(EARLY, Some("fr-FR")));
        assert_eq!(all(EARLY, Some("en-PH")), all(EARLY, Some("en-US")));
        assert_eq!(all(EARLY, Some("de-CH")), all(EARLY, Some("de-DE")));
        for locale in ["fr-CA", "fr-CH", "en-AU", "ja-US", "en-US-u-hc-h23"] {
            assert!(
                format_date_locale(EARLY, Some(locale), DateLocaleKind::Date).is_err(),
                "{locale} must be refused"
            );
        }
    }

    #[test]
    fn layouts_match_node_with_utc() {
        // Node v22.2.0, TZ=UTC.
        assert_eq!(
            all(CHRISTMAS, None),
            ["12/25/2020, 3:30:05 PM", "12/25/2020", "3:30:05 PM"]
        );
        assert_eq!(
            all(EARLY, Some("en-US")),
            ["1/3/2021, 12:07:09 AM", "1/3/2021", "12:07:09 AM"]
        );
        assert_eq!(
            all(EARLY, Some("en-GB")),
            ["03/01/2021, 00:07:09", "03/01/2021", "00:07:09"]
        );
        assert_eq!(
            all(EARLY, Some("de-DE")),
            ["3.1.2021, 00:07:09", "3.1.2021", "00:07:09"]
        );
        assert_eq!(
            all(EARLY, Some("ja-JP")),
            ["2021/1/3 0:07:09", "2021/1/3", "0:07:09"]
        );
        assert_eq!(
            all(CHRISTMAS, Some("fr-FR")),
            ["25/12/2020 15:30:05", "25/12/2020", "15:30:05"]
        );
        let noon = DateFields {
            hour: 12,
            minute: 0,
            second: 0,
            ..CHRISTMAS
        };
        assert_eq!(
            format_date_locale(noon, Some("en"), DateLocaleKind::Time),
            Ok("12:00:00 PM".to_string())
        );
        let before_era = DateFields {
            year: -5,
            month: 0,
            day: 1,
            ..CHRISTMAS
        };
        assert_eq!(
            format_date_locale(before_era, Some("en-US"), DateLocaleKind::Date),
            Ok("1/1/6".to_string())
        );
    }

    #[test]
    fn other_locales_are_refused() {
        assert!(format_date_locale(CHRISTMAS, Some("en-CA"), DateLocaleKind::Date).is_err());
        assert!(format_date_locale(CHRISTMAS, Some("es-ES"), DateLocaleKind::Date).is_err());
    }
}
