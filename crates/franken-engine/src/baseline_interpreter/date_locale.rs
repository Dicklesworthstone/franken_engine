//! `Date.prototype.toLocaleString` / `toLocaleDateString` /
//! `toLocaleTimeString` formatting (ECMA-402 subset).
//!
//! The engine is hermetic: local time is UTC, so these format the UTC
//! fields, as Node does with `TZ=UTC`. Without ICU it knows the default
//! numeric layouts of a few locales (en-US, en-GB, de, fr, ja) and no
//! component options (`{ month: 'long' }` and the like); anything else is a
//! typed refusal, never a string that differs from Node's.

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
