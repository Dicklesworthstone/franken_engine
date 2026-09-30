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

fn layout(locale: Option<&str>) -> Result<Layout, String> {
    let tag = locale.unwrap_or("en-US");
    let lower = tag.to_ascii_lowercase().replace('_', "-");
    let language = lower.split('-').next().unwrap_or("");
    match (language, lower.as_str()) {
        (_, "en" | "en-us") => Ok(Layout::UnitedStates),
        (_, "en-gb") => Ok(Layout::Britain),
        ("de", _) => Ok(Layout::German),
        ("fr", _) => Ok(Layout::French),
        ("ja", _) => Ok(Layout::Japanese),
        _ => Err(format!(
            "locale {tag:?} (formatted date locales: en-US, en-GB, de, fr, ja)"
        )),
    }
}

/// Format `fields` for `locale`, or name what the engine does not format.
pub(super) fn format_date_locale(
    fields: DateFields,
    locale: Option<&str>,
    kind: DateLocaleKind,
) -> Result<String, String> {
    let layout = layout(locale)?;
    // ICU's `y` is the year of the era: 1 BC is year 1.
    let year = if fields.year <= 0 {
        1 - fields.year
    } else {
        fields.year
    };
    let (month, day) = (fields.month + 1, fields.day);
    let (hour, minute, second) = (fields.hour, fields.minute, fields.second);
    let date = match layout {
        Layout::UnitedStates => format!("{month}/{day}/{year}"),
        Layout::Britain | Layout::French => format!("{day:02}/{month:02}/{year}"),
        Layout::German => format!("{day}.{month}.{year}"),
        Layout::Japanese => format!("{year}/{month}/{day}"),
    };
    let time = match layout {
        Layout::UnitedStates => {
            let period = if hour < 12 { "AM" } else { "PM" };
            let twelve = match hour % 12 {
                0 => 12,
                other => other,
            };
            format!("{twelve}:{minute:02}:{second:02} {period}")
        }
        Layout::Japanese => format!("{hour}:{minute:02}:{second:02}"),
        _ => format!("{hour:02}:{minute:02}:{second:02}"),
    };
    let separator = match layout {
        Layout::UnitedStates | Layout::Britain | Layout::German => ", ",
        Layout::French | Layout::Japanese => " ",
    };
    Ok(match kind {
        DateLocaleKind::DateTime => format!("{date}{separator}{time}"),
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

fn time_zone_suffix(name: Option<TextWidth>) -> &'static str {
    match name {
        None => "",
        Some(TextWidth::Long) => " Coordinated Universal Time",
        Some(_) => " UTC",
    }
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

/// Format `fields` with `dateStyle` / `timeStyle` (en-US).
pub(super) fn format_date_styles(
    fields: DateFields,
    locale: Option<&str>,
    date_style: Option<FormatStyle>,
    time_style: Option<FormatStyle>,
    hour12: bool,
) -> Result<String, String> {
    en_us_only(locale)?;
    let year = era_year(&fields);
    let month = MONTH_NAMES[fields.month as usize % 12];
    let date = date_style.map(|style| match style {
        FormatStyle::Full => format!(
            "{}, {month} {}, {year}",
            WEEKDAY_NAMES[weekday_index(&fields)],
            fields.day
        ),
        FormatStyle::Long => format!("{month} {}, {year}", fields.day),
        FormatStyle::Medium => format!("{} {}, {year}", named(month, TextWidth::Short), fields.day),
        FormatStyle::Short => format!(
            "{}/{}/{}",
            fields.month + 1,
            fields.day,
            number(year, Digits::TwoDigit)
        ),
    });
    let time = time_style.map(|style| {
        let second = !matches!(style, FormatStyle::Short);
        let zone = match style {
            FormatStyle::Full => Some(TextWidth::Long),
            FormatStyle::Long => Some(TextWidth::Short),
            _ => None,
        };
        clock(
            &fields,
            Some(Digits::Numeric),
            Some(Digits::TwoDigit),
            second.then_some(Digits::TwoDigit),
            hour12,
        ) + time_zone_suffix(zone)
    });
    Ok(match (date, time) {
        (Some(date), Some(time)) => {
            let glue = if matches!(date_style, Some(FormatStyle::Full | FormatStyle::Long)) {
                " at "
            } else {
                ", "
            };
            format!("{date}{glue}{time}")
        }
        (Some(date), None) => date,
        (None, Some(time)) => time,
        (None, None) => String::new(),
    })
}

/// `hour`, `minute` and `second` as en-US lays them out.
fn clock(
    fields: &DateFields,
    hour: Option<Digits>,
    minute: Option<Digits>,
    second: Option<Digits>,
    hour12: bool,
) -> String {
    let mut out = match hour {
        Some(width) if hour12 => {
            let twelve = match fields.hour % 12 {
                0 => 12,
                other => other,
            };
            number(i64::from(twelve), width)
        }
        // A 24-hour hour is always two digits in en-US ("00:07", "15").
        Some(_) => format!("{:02}", fields.hour),
        None => String::new(),
    };
    if minute.is_some() {
        if hour.is_some() {
            out.push_str(&format!(":{:02}", fields.minute));
        } else if second.is_some() {
            out.push_str(&format!("{:02}", fields.minute));
        } else {
            // ICU's lone minute is unpadded.
            out.push_str(&fields.minute.to_string());
        }
    }
    if second.is_some() {
        if minute.is_some() {
            out.push_str(&format!(":{:02}", fields.second));
        } else {
            out.push_str(&fields.second.to_string());
        }
    }
    if hour.is_some() && hour12 {
        out.push_str(if fields.hour < 12 { " AM" } else { " PM" });
    }
    out
}

/// Format `fields` with Intl.DateTimeFormat components (en-US), or name
/// the combination the engine does not lay out.
pub(super) fn format_date_components(
    fields: DateFields,
    locale: Option<&str>,
    components: &DateComponents,
) -> Result<String, String> {
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
    let core = match (month, day, year) {
        (Some(month), Some(day), Some(year)) if month_text => {
            Some(format!("{month} {day}, {year}"))
        }
        (Some(month), Some(day), None) if month_text => Some(format!("{month} {day}")),
        (Some(month), None, Some(year)) if month_text => Some(format!("{month} {year}")),
        (Some(month), Some(day), Some(year)) => Some(format!("{month}/{day}/{year}")),
        (Some(month), Some(day), None) => Some(format!("{month}/{day}")),
        (Some(month), None, Some(year)) => Some(format!("{month}/{year}")),
        (Some(month), None, None) => Some(month),
        (None, Some(day), None) => Some(day),
        (None, None, Some(year)) => Some(year),
        (None, None, None) => None,
        (None, Some(_), Some(_)) => {
            return Err("a day and year without a month".to_string());
        }
    };
    let weekday = components
        .weekday
        .map(|width| named(WEEKDAY_NAMES[weekday_index(&fields)], width));
    let date = match (weekday, &core) {
        (Some(weekday), Some(core)) => Some(format!("{weekday}, {core}")),
        (Some(weekday), None) => Some(weekday),
        (None, Some(core)) => Some(core.clone()),
        (None, None) => None,
    };
    let has_time =
        components.hour.is_some() || components.minute.is_some() || components.second.is_some();
    if components.second.is_some() && components.minute.is_none() && components.hour.is_some() {
        return Err("an hour and second without a minute".to_string());
    }
    let time = has_time.then(|| {
        clock(
            &fields,
            components.hour,
            components.minute,
            components.second,
            components.hour12,
        ) + time_zone_suffix(components.time_zone_name)
    });
    Ok(match (date, time) {
        (Some(date), Some(time)) => {
            let glue = if core.is_none() {
                " "
            } else if matches!(components.month, Some(MonthStyle::Text(TextWidth::Long))) {
                " at "
            } else {
                ", "
            };
            format!("{date}{glue}{time}")
        }
        (Some(date), None) => date,
        (None, Some(time)) => time,
        (None, None) => String::new(),
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
