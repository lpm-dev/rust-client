//! A point in time, as lpm stores and prints it.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::format_description::well_known::Rfc3339;
pub use time::{Date, Duration, Month};
use time::{OffsetDateTime, UtcOffset};

/// A point in time from the year 0 to the year 9999, kept in UTC.
///
/// Its text forms are the ones lpm's files and JSON output already have, so
/// what an earlier release wrote reads back, and what this one writes an
/// earlier release reads. It has no `Display`: each place that prints one
/// says which form it prints.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(OffsetDateTime);

/// Why text isn't a [`Timestamp`].
#[derive(Debug)]
pub enum ParseError {
    NotRfc3339(time::error::Parse),
    Separator,
    OutOfRange,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRfc3339(error) => error.fmt(f),
            Self::Separator => f.write_str("the date and the time aren't separated by `T`"),
            Self::OutOfRange => f.write_str("the point in time is outside the years 0 to 9999"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Reads a `YYYY-MM-DD` calendar date.
pub fn parse_date(text: &str) -> Option<Date> {
    let mut parts = text.splitn(3, '-');
    let year = parts.next()?.parse().ok()?;
    let month = Month::try_from(parts.next()?.parse::<u8>().ok()?).ok()?;
    let day = parts.next()?.parse().ok()?;
    Date::from_calendar_date(year, month, day).ok()
}

/// How many digits of a second's fraction a text form has.
#[derive(Clone, Copy)]
enum Fraction {
    /// None, three, six or nine, whichever is the fewest that loses nothing.
    Shortest,
    Milliseconds,
    None,
}

impl Timestamp {
    pub fn now() -> Self {
        Self(OffsetDateTime::now_utc())
    }

    fn in_range(datetime: OffsetDateTime) -> Option<Self> {
        let utc = datetime.checked_to_offset(UtcOffset::UTC)?;
        (0..=9999).contains(&utc.year()).then_some(Self(utc))
    }

    fn from_unix_nanoseconds(nanoseconds: i128) -> Option<Self> {
        OffsetDateTime::from_unix_timestamp_nanos(nanoseconds)
            .ok()
            .and_then(Self::in_range)
    }

    /// Returns `None` for a point in time outside the years 0 to 9999.
    pub fn from_unix_seconds(seconds: i64) -> Option<Self> {
        Self::from_unix_nanoseconds(i128::from(seconds) * 1_000_000_000)
    }

    /// Returns `None` for a point in time outside the years 0 to 9999.
    pub fn from_unix_milliseconds(milliseconds: i64) -> Option<Self> {
        Self::from_unix_nanoseconds(i128::from(milliseconds) * 1_000_000)
    }

    /// Returns midnight UTC at the start of `date`, or `None` for a date
    /// before the year 0.
    pub fn at_start_of(date: Date) -> Option<Self> {
        Self::in_range(date.midnight().assume_utc())
    }

    /// Returns `None` when the result is outside the years 0 to 9999,
    /// where `+` panics.
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        self.0.checked_add(duration).and_then(Self::in_range)
    }

    /// Returns `None` when the result is outside the years 0 to 9999,
    /// where `-` panics.
    pub fn checked_sub(self, duration: Duration) -> Option<Self> {
        self.0.checked_sub(duration).and_then(Self::in_range)
    }

    pub fn unix_seconds(self) -> i64 {
        self.0.unix_timestamp()
    }

    pub fn unix_nanoseconds(self) -> i128 {
        self.0.unix_timestamp_nanos()
    }

    /// Returns the UTC calendar date, whose `Display` is `YYYY-MM-DD`.
    pub fn date(self) -> Date {
        self.0.date()
    }

    /// Returns this point in time on a clock `offset` from UTC, or on a
    /// UTC clock where that one would leave the years `time` holds.
    pub fn at_offset(self, offset: UtcOffset) -> OffsetDateTime {
        self.0.checked_to_offset(offset).unwrap_or(self.0)
    }

    /// Reads RFC 3339 text with any offset. Between the date and the time
    /// it takes `T`, `t` or a space, and nothing else.
    ///
    /// A leap second, `23:59:60` at the end of a UTC month, reads as the
    /// last nanosecond before the next minute.
    pub fn parse_rfc3339(text: &str) -> Result<Self, ParseError> {
        let parsed = OffsetDateTime::parse(text, &Rfc3339).map_err(ParseError::NotRfc3339)?;
        // `time` takes any character there.
        if !matches!(text.as_bytes().get(10), Some(b'T' | b't' | b' ')) {
            return Err(ParseError::Separator);
        }
        Self::in_range(parsed).ok_or(ParseError::OutOfRange)
    }

    /// Formats as `2026-01-02T03:04:05.678+00:00`: the fraction is as short
    /// as loses nothing, and the offset is written out.
    pub fn to_rfc3339(self) -> String {
        self.text(Fraction::Shortest, "+00:00")
    }

    /// Formats as `2026-01-02T03:04:05.678Z`, always with milliseconds.
    pub fn to_rfc3339_milliseconds(self) -> String {
        self.text(Fraction::Milliseconds, "Z")
    }

    /// Formats as `2026-01-02T03:04:05Z`, without a fraction.
    pub fn to_rfc3339_seconds(self) -> String {
        self.text(Fraction::None, "Z")
    }

    /// Formats as `2026-01-02 03:04:05.678 UTC`, for a message a person
    /// reads.
    pub fn to_plain_utc(self) -> String {
        let mut text = String::with_capacity(34);
        self.write(&mut text, ' ', Fraction::Shortest, " UTC")
            .expect("writing to a String doesn't fail");
        text
    }

    fn text(self, fraction: Fraction, offset: &str) -> String {
        let mut text = String::with_capacity(35);
        self.write(&mut text, 'T', fraction, offset)
            .expect("writing to a String doesn't fail");
        text
    }

    fn write(
        self,
        out: &mut impl fmt::Write,
        before_the_time: char,
        fraction: Fraction,
        offset: &str,
    ) -> fmt::Result {
        let at = self.0;
        write!(
            out,
            "{:04}-{:02}-{:02}{before_the_time}{:02}:{:02}:{:02}",
            at.year(),
            u8::from(at.month()),
            at.day(),
            at.hour(),
            at.minute(),
            at.second()
        )?;
        let nanoseconds = at.nanosecond();
        match fraction {
            Fraction::None => {}
            Fraction::Milliseconds => write!(out, ".{:03}", nanoseconds / 1_000_000)?,
            Fraction::Shortest if nanoseconds == 0 => {}
            Fraction::Shortest if nanoseconds.is_multiple_of(1_000_000) => {
                write!(out, ".{:03}", nanoseconds / 1_000_000)?;
            }
            Fraction::Shortest if nanoseconds.is_multiple_of(1_000) => {
                write!(out, ".{:06}", nanoseconds / 1_000)?;
            }
            Fraction::Shortest => write!(out, ".{nanoseconds:09}")?,
        }
        out.write_str(offset)
    }
}

/// The form is `2026-01-02T03:04:05.678Z`, which is also how a timestamp is
/// serialized.
impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write(f, 'T', Fraction::Shortest, "Z")
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("{self:?}"))
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = std::borrow::Cow::<str>::deserialize(deserializer)?;
        Self::parse_rfc3339(&text).map_err(serde::de::Error::custom)
    }
}

/// A system time outside the years 0 to 9999 becomes the first or the last
/// point a timestamp holds, so that one read from a file's metadata keeps
/// its order among the others.
impl From<std::time::SystemTime> for Timestamp {
    fn from(system_time: std::time::SystemTime) -> Self {
        let nanoseconds = |duration: std::time::Duration| {
            i128::try_from(duration.as_nanos()).unwrap_or(i128::MAX)
        };
        let (since_epoch, nearest) = match system_time.duration_since(std::time::UNIX_EPOCH) {
            Ok(after) => (nanoseconds(after), LAST_UNIX_NANOSECOND),
            Err(before) => (-nanoseconds(before.duration()), FIRST_UNIX_NANOSECOND),
        };
        Self::from_unix_nanoseconds(since_epoch)
            .or_else(|| Self::from_unix_nanoseconds(nearest))
            .expect("the years 0 to 9999 are held")
    }
}

/// 0000-01-01T00:00:00Z.
const FIRST_UNIX_NANOSECOND: i128 = -62_167_219_200 * 1_000_000_000;
/// 9999-12-31T23:59:59.999999999Z.
const LAST_UNIX_NANOSECOND: i128 = 253_402_300_799 * 1_000_000_000 + 999_999_999;

impl From<Timestamp> for std::time::SystemTime {
    fn from(timestamp: Timestamp) -> Self {
        timestamp.0.into()
    }
}

impl std::str::FromStr for Timestamp {
    type Err = ParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse_rfc3339(text)
    }
}

impl std::ops::Add<Duration> for Timestamp {
    type Output = Self;

    fn add(self, duration: Duration) -> Self {
        self.checked_add(duration)
            .expect("a point in time within the years 0 to 9999")
    }
}

impl std::ops::Sub<Duration> for Timestamp {
    type Output = Self;

    fn sub(self, duration: Duration) -> Self {
        self.checked_sub(duration)
            .expect("a point in time within the years 0 to 9999")
    }
}

impl std::ops::Sub for Timestamp {
    type Output = Duration;

    fn sub(self, earlier: Self) -> Duration {
        self.0 - earlier.0
    }
}

#[cfg(test)]
mod tests {
    use super::{Duration, Timestamp};

    fn at(seconds: i64, nanoseconds: i64) -> Timestamp {
        Timestamp::from_unix_seconds(seconds).unwrap() + Duration::nanoseconds(nanoseconds)
    }

    /// 2026-01-02T03:04:05Z.
    const SECONDS: i64 = 1_767_323_045;

    #[test]
    fn the_shortest_fraction_has_none_three_six_or_nine_digits() {
        let forms = [0, 678_000_000, 678_900_000, 678_901_200, 678_901_234]
            .map(|nanoseconds| at(SECONDS, nanoseconds).to_rfc3339());

        assert_eq!(
            forms,
            [
                "2026-01-02T03:04:05+00:00",
                "2026-01-02T03:04:05.678+00:00",
                "2026-01-02T03:04:05.678900+00:00",
                "2026-01-02T03:04:05.678901200+00:00",
                "2026-01-02T03:04:05.678901234+00:00",
            ]
        );
    }

    #[test]
    fn the_fixed_forms_cut_the_fraction_and_end_in_z() {
        let late = at(SECONDS, 999_999_999);
        let whole = at(SECONDS, 0);

        assert_eq!(late.to_rfc3339_milliseconds(), "2026-01-02T03:04:05.999Z");
        assert_eq!(whole.to_rfc3339_milliseconds(), "2026-01-02T03:04:05.000Z");
        assert_eq!(late.to_rfc3339_seconds(), "2026-01-02T03:04:05Z");
        assert_eq!(late.to_plain_utc(), "2026-01-02 03:04:05.999999999 UTC");
        assert_eq!(whole.to_plain_utc(), "2026-01-02 03:04:05 UTC");
    }

    #[test]
    fn a_timestamp_is_serialized_with_z_and_the_shortest_fraction() {
        let stored = [0, 5_000_000, 5_000]
            .map(|nanoseconds| serde_json::to_string(&at(SECONDS, nanoseconds)).unwrap());

        assert_eq!(
            stored,
            [
                "\"2026-01-02T03:04:05Z\"",
                "\"2026-01-02T03:04:05.005Z\"",
                "\"2026-01-02T03:04:05.000005Z\"",
            ]
        );
        assert_eq!(
            format!("{:?}", at(SECONDS, 5_000_000)),
            "2026-01-02T03:04:05.005Z"
        );
    }

    #[test]
    fn every_form_an_earlier_release_wrote_reads_back_as_the_same_point() {
        let expected = at(SECONDS, 678_000_000);

        for text in [
            "2026-01-02T03:04:05.678Z",
            "2026-01-02T03:04:05.678+00:00",
            "2026-01-02T03:04:05.678000000Z",
            "2026-01-02T05:04:05.678+02:00",
            "2026-01-02t03:04:05.678z",
            "2026-01-02 03:04:05.678Z",
        ] {
            assert_eq!(
                Timestamp::parse_rfc3339(text).ok(),
                Some(expected),
                "{text}"
            );
            let quoted = format!("\"{text}\"");
            assert_eq!(
                serde_json::from_str::<Timestamp>(&quoted).ok(),
                Some(expected),
                "{text}"
            );
        }
    }

    #[test]
    fn text_that_is_not_a_point_in_time_is_refused() {
        for text in [
            "",
            "2026-01-02",
            "2026-01-02T03:04:05",
            "2026-13-02T03:04:05Z",
            "2026-01-02_03:04:05Z",
            "2026-01-02T03:04:05+0000",
            "yesterday",
        ] {
            assert!(Timestamp::parse_rfc3339(text).is_err(), "{text}");
        }
    }

    #[test]
    fn a_point_outside_the_years_it_holds_is_refused_and_never_panics() {
        for text in ["9999-12-31T23:59:59-01:00", "0000-01-01T00:00:00+01:00"] {
            let refused = Timestamp::parse_rfc3339(text).expect_err(text);
            assert!(matches!(refused, super::ParseError::OutOfRange), "{text}");
        }
        let first = Timestamp::parse_rfc3339("0000-01-01T00:00:00Z").unwrap();
        let last = Timestamp::parse_rfc3339("9999-12-31T23:59:59.999999999Z").unwrap();

        assert_eq!(first.to_rfc3339_seconds(), "0000-01-01T00:00:00Z");
        assert_eq!(first.checked_sub(Duration::nanoseconds(1)), None);
        assert_eq!(last.checked_add(Duration::nanoseconds(1)), None);
        assert_eq!(Timestamp::from_unix_seconds(i64::MIN), None);
        assert_eq!(Timestamp::from_unix_seconds(-62_167_219_201), None);
        assert_eq!(Timestamp::from_unix_milliseconds(i64::MAX), None);
        assert_eq!(
            format!("{:?}", at(-62_135_596_800, 0)),
            "0001-01-01T00:00:00Z"
        );
    }

    #[test]
    fn a_system_time_it_cannot_hold_becomes_the_nearest_it_can() {
        let far = std::time::Duration::from_secs(400_000_000_000);
        let after = Timestamp::from(std::time::UNIX_EPOCH + far);
        let known = Timestamp::from(std::time::UNIX_EPOCH + std::time::Duration::from_secs(5));

        assert_eq!(format!("{after:?}"), "9999-12-31T23:59:59.999999999Z");
        assert_eq!(known.unix_seconds(), 5);
        if let Some(early) = std::time::UNIX_EPOCH.checked_sub(far) {
            assert_eq!(
                format!("{:?}", Timestamp::from(early)),
                "0000-01-01T00:00:00Z"
            );
        }
    }

    #[test]
    fn a_leap_second_reads_as_the_end_of_its_minute() {
        let leap = Timestamp::parse_rfc3339("2016-12-31T23:59:60Z").unwrap();

        assert_eq!(format!("{leap:?}"), "2016-12-31T23:59:59.999999999Z");
        assert!(Timestamp::parse_rfc3339("2016-06-15T12:30:60Z").is_err());
    }

    #[test]
    fn an_optional_timestamp_may_be_missing_from_what_is_read() {
        #[derive(serde::Deserialize)]
        struct Stored {
            at: Option<Timestamp>,
        }

        let missing: Stored = serde_json::from_str("{}").unwrap();
        let null: Stored = serde_json::from_str(r#"{"at":null}"#).unwrap();

        assert_eq!(missing.at, None);
        assert_eq!(null.at, None);
    }

    #[test]
    fn a_calendar_date_reads_back_from_how_it_is_printed() {
        let date = at(SECONDS, 0).date();

        assert_eq!(super::parse_date(&date.to_string()), Some(date));
        assert_eq!(super::parse_date("2026-1-2"), Some(date));
        assert_eq!(super::parse_date("2026-02-30"), None);
        assert_eq!(super::parse_date("2026-01"), None);
        assert_eq!(super::parse_date("2026-01-02T03:04:05Z"), None);
    }

    #[test]
    fn timestamps_order_and_differ_by_the_time_between_them() {
        let earlier = at(SECONDS, 0);
        let later = earlier + Duration::hours(2);

        assert!(earlier < later);
        assert_eq!(later - earlier, Duration::hours(2));
        assert_eq!(later - Duration::hours(2), earlier);
        assert_eq!(later.unix_seconds(), SECONDS + 7_200);
        assert_eq!(earlier.checked_add(Duration::hours(2)), Some(later));
        assert_eq!(
            earlier.checked_add(Duration::days(i64::from(u32::MAX))),
            None
        );
        assert_eq!(earlier.date().to_string(), "2026-01-02");
        assert_eq!(
            Timestamp::from_unix_milliseconds(SECONDS * 1_000 + 5).map(Timestamp::unix_nanoseconds),
            Some(i128::from(SECONDS) * 1_000_000_000 + 5_000_000)
        );
    }
}
