//! ISO 8601 policy (spec section 3).
//!
//! * Storage: RFC 3339 UTC with exactly six fractional digits and `Z`.
//! * Display: extended format with explicit offset in the configured zone.
//! * Durations: ISO 8601 durations (`PT1H23M4.5S`, `P7D`).
//! * Intervals: `start/end`, `start/duration`, `duration/end`; `now` is the only extension.
//!
//! Everything else is rejected, and errors always carry an example of the correct form.

use jiff::{tz::TimeZone, Span, Timestamp, Zoned};
use std::fmt;
use std::sync::OnceLock;

pub const DEFAULT_ZONE: &str = "UTC";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TimeError {
    #[error("invalid ISO 8601 date-time {0:?}; expected e.g. 2026-09-23T08:14:02Z or 2026-09-23T10:14:02+02:00")]
    DateTime(String),
    #[error("invalid ISO 8601 duration {0:?}; expected e.g. PT8H, P7D or PT1H30M")]
    Duration(String),
    #[error("invalid ISO 8601 interval {0:?}; expected e.g. P7D/now, 2026-09-01T00:00Z/PT6H or 2026-09-01T00:00:00Z/2026-09-02T00:00:00Z")]
    Interval(String),
    #[error("interval end is before its start: {0}")]
    Reversed(String),
    #[error("unknown time zone {0:?}")]
    Zone(String),
}

/// Current time truncated to microseconds.
pub fn now() -> Timestamp {
    truncate_micros(Timestamp::now())
}

pub fn truncate_micros(ts: Timestamp) -> Timestamp {
    let ns = ts.as_nanosecond();
    Timestamp::from_nanosecond(ns - ns.rem_euclid(1000)).expect("in range")
}

/// Storage format: `2026-09-23T08:14:02.113245Z`.
pub fn fmt_utc(ts: Timestamp) -> String {
    let ts = truncate_micros(ts);
    ts.strftime("%Y-%m-%dT%H:%M:%S.%6fZ").to_string()
}

/// Seconds-precision UTC, used where microseconds are noise (config files, git messages).
pub fn fmt_utc_secs(ts: Timestamp) -> String {
    ts.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Filename basic format: `20260923T081402Z`.
pub fn fmt_basic(ts: Timestamp) -> String {
    ts.strftime("%Y%m%dT%H%M%SZ").to_string()
}

/// `YYYY/MM/DD` date directory (UTC).
pub fn date_dir(ts: Timestamp) -> String {
    ts.strftime("%Y/%m/%d").to_string()
}

fn zone_cache() -> &'static std::sync::Mutex<Vec<(String, TimeZone)>> {
    static C: OnceLock<std::sync::Mutex<Vec<(String, TimeZone)>>> = OnceLock::new();
    C.get_or_init(Default::default)
}

pub fn zone(name: &str) -> Result<TimeZone, TimeError> {
    if name == "UTC" || name == "Z" {
        return Ok(TimeZone::UTC);
    }
    let mut c = zone_cache().lock().unwrap();
    if let Some((_, tz)) = c.iter().find(|(n, _)| n == name) {
        return Ok(tz.clone());
    }
    let tz = TimeZone::get(name).map_err(|_| TimeError::Zone(name.into()))?;
    c.push((name.into(), tz.clone()));
    Ok(tz)
}

/// Display format: `2026-09-23T10:14:02+02:00` in the given zone, or `…Z` when `utc`.
pub fn fmt_display(ts: Timestamp, zone_name: &str, utc: bool) -> String {
    if utc {
        return fmt_utc_secs(ts);
    }
    match zone(zone_name) {
        Ok(tz) => ts.to_zoned(tz).strftime("%Y-%m-%dT%H:%M:%S%:z").to_string(),
        Err(_) => fmt_utc_secs(ts),
    }
}

/// Display with fractional seconds (milliseconds) for event listings.
pub fn fmt_display_ms(ts: Timestamp, zone_name: &str, utc: bool) -> String {
    if utc {
        return ts.strftime("%Y-%m-%dT%H:%M:%S.%3fZ").to_string();
    }
    match zone(zone_name) {
        Ok(tz) => ts.to_zoned(tz).strftime("%Y-%m-%dT%H:%M:%S.%3f%:z").to_string(),
        Err(_) => ts.strftime("%Y-%m-%dT%H:%M:%S.%3fZ").to_string(),
    }
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Strict ISO 8601 extended date-time with mandatory zone designator.
/// Accepts `YYYY-MM-DDTHH:MM[:SS[.f+]](Z|±HH:MM)` and the literal `now`.
pub fn parse_datetime(s: &str) -> Result<Timestamp, TimeError> {
    parse_datetime_at(s, now())
}

pub fn parse_datetime_at(s: &str, now: Timestamp) -> Result<Timestamp, TimeError> {
    let err = || TimeError::DateTime(s.to_string());
    if s == "now" {
        return Ok(now);
    }
    let b = s.as_bytes();
    if b.len() < 17 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' {
        return Err(err());
    }
    if !all_digits(&s[0..4]) || !all_digits(&s[5..7]) || !all_digits(&s[8..10]) || !all_digits(&s[11..13]) || !all_digits(&s[14..16]) {
        return Err(err());
    }
    let mut rest = &s[16..];
    let mut secs = "00";
    let mut frac = "";
    if let Some(r) = rest.strip_prefix(':') {
        if r.len() < 2 || !all_digits(&r[..2]) {
            return Err(err());
        }
        secs = &r[..2];
        rest = &r[2..];
        if let Some(r) = rest.strip_prefix('.') {
            let n = r.bytes().take_while(|c| c.is_ascii_digit()).count();
            if n == 0 || n > 9 {
                return Err(err());
            }
            frac = &r[..n];
            rest = &r[n..];
        }
    }
    let offset = if rest == "Z" {
        "Z".to_string()
    } else if rest.len() == 6 && (rest.starts_with('+') || rest.starts_with('-')) && &rest[3..4] == ":" && all_digits(&rest[1..3]) && all_digits(&rest[4..6]) {
        rest.to_string()
    } else {
        return Err(err());
    };
    let norm = if frac.is_empty() {
        format!("{}:{}{}", &s[..16], secs, offset)
    } else {
        format!("{}:{}.{}{}", &s[..16], secs, frac, offset)
    };
    norm.parse::<Timestamp>().map(truncate_micros).map_err(|_| err())
}

/// An ISO 8601 duration. Years and months are calendar units; everything else is exact.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IsoDuration {
    pub years: u32,
    pub months: u32,
    pub weeks: u32,
    pub days: u32,
    pub hours: u64,
    pub minutes: u64,
    /// Seconds including fraction, in nanoseconds.
    pub nanos: u64,
}

impl IsoDuration {
    pub fn parse(s: &str) -> Result<Self, TimeError> {
        let err = || TimeError::Duration(s.to_string());
        let body = s.strip_prefix('P').ok_or_else(err)?;
        if body.is_empty() {
            return Err(err());
        }
        let (date, time) = match body.split_once('T') {
            Some((d, t)) => {
                if t.is_empty() {
                    return Err(err());
                }
                (d, Some(t))
            }
            None => (body, None),
        };
        let mut d = IsoDuration::default();
        let mut any = false;
        // Date part: designators must appear in order Y M W D.
        let mut order = 0;
        let mut num = String::new();
        for c in date.chars() {
            if c.is_ascii_digit() {
                num.push(c);
                continue;
            }
            let rank = match c {
                'Y' => 1,
                'M' => 2,
                'W' => 3,
                'D' => 4,
                _ => return Err(err()),
            };
            if num.is_empty() || rank <= order || num.len() > 9 {
                return Err(err());
            }
            order = rank;
            let v: u32 = num.parse().map_err(|_| err())?;
            match c {
                'Y' => d.years = v,
                'M' => d.months = v,
                'W' => d.weeks = v,
                _ => d.days = v,
            }
            any = true;
            num.clear();
        }
        if !num.is_empty() {
            return Err(err());
        }
        if let Some(t) = time {
            let mut order = 0;
            let mut tany = false;
            for c in t.chars() {
                if c.is_ascii_digit() || c == '.' || c == ',' {
                    num.push(if c == ',' { '.' } else { c });
                    continue;
                }
                let rank = match c {
                    'H' => 1,
                    'M' => 2,
                    'S' => 3,
                    _ => return Err(err()),
                };
                if num.is_empty() || rank <= order || num.len() > 18 {
                    return Err(err());
                }
                order = rank;
                if c == 'S' {
                    let (i, f) = num.split_once('.').unwrap_or((&num, ""));
                    if !all_digits(i) || (num.contains('.') && (!all_digits(f) || f.len() > 9)) {
                        return Err(err());
                    }
                    let whole: u64 = i.parse().map_err(|_| err())?;
                    let mut frac = f.to_string();
                    while frac.len() < 9 {
                        frac.push('0');
                    }
                    let fr: u64 = frac.parse().map_err(|_| err())?;
                    d.nanos = whole.checked_mul(1_000_000_000).and_then(|x| x.checked_add(fr)).ok_or_else(err)?;
                } else {
                    if !all_digits(&num) {
                        return Err(err());
                    }
                    let v: u64 = num.parse().map_err(|_| err())?;
                    if c == 'H' {
                        d.hours = v
                    } else {
                        d.minutes = v
                    }
                }
                tany = true;
                num.clear();
            }
            if !num.is_empty() || !tany {
                return Err(err());
            }
            any = true;
        }
        if !any {
            return Err(err());
        }
        Ok(d)
    }

    pub fn is_calendar(&self) -> bool {
        self.years != 0 || self.months != 0
    }

    /// Exact length, if the duration has no calendar components.
    pub fn exact(&self) -> Option<std::time::Duration> {
        if self.is_calendar() {
            return None;
        }
        let secs = (self.weeks as u64 * 7 + self.days as u64) * 86400 + self.hours * 3600 + self.minutes * 60;
        Some(std::time::Duration::from_secs(secs) + std::time::Duration::from_nanos(self.nanos))
    }

    pub fn span(&self) -> Span {
        Span::new()
            .years(self.years as i64)
            .months(self.months as i64)
            .weeks(self.weeks as i64)
            .days(self.days as i64)
            .hours(self.hours as i64)
            .minutes(self.minutes as i64)
            .nanoseconds(self.nanos as i64)
    }

    /// `ts - self`, calendar units applied in UTC.
    pub fn before(&self, ts: Timestamp) -> Timestamp {
        let z: Zoned = ts.to_zoned(TimeZone::UTC);
        z.checked_sub(self.span()).map(|z| z.timestamp()).unwrap_or(Timestamp::MIN)
    }

    /// `ts + self`, calendar units applied in UTC.
    pub fn after(&self, ts: Timestamp) -> Timestamp {
        let z: Zoned = ts.to_zoned(TimeZone::UTC);
        z.checked_add(self.span()).map(|z| z.timestamp()).unwrap_or(Timestamp::MAX)
    }
}

impl fmt::Display for IsoDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::from("P");
        if self.years > 0 {
            s += &format!("{}Y", self.years);
        }
        if self.months > 0 {
            s += &format!("{}M", self.months);
        }
        if self.weeks > 0 {
            s += &format!("{}W", self.weeks);
        }
        if self.days > 0 {
            s += &format!("{}D", self.days);
        }
        if self.hours > 0 || self.minutes > 0 || self.nanos > 0 {
            s.push('T');
            if self.hours > 0 {
                s += &format!("{}H", self.hours);
            }
            if self.minutes > 0 {
                s += &format!("{}M", self.minutes);
            }
            if self.nanos > 0 {
                s += &fmt_secs(self.nanos);
                s.push('S');
            }
        }
        if s == "P" {
            s = "PT0S".into();
        }
        f.write_str(&s)
    }
}

impl std::str::FromStr for IsoDuration {
    type Err = TimeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        IsoDuration::parse(s)
    }
}

impl serde::Serialize for IsoDuration {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for IsoDuration {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        IsoDuration::parse(&s).map_err(serde::de::Error::custom)
    }
}

fn fmt_secs(nanos: u64) -> String {
    let whole = nanos / 1_000_000_000;
    let frac = nanos % 1_000_000_000;
    if frac == 0 {
        whole.to_string()
    } else {
        let f = format!("{:09}", frac);
        format!("{}.{}", whole, f.trim_end_matches('0'))
    }
}

/// Format an elapsed duration as `PT1H23M4.5S` (hours may exceed 24; microsecond precision).
pub fn fmt_duration(d: std::time::Duration) -> String {
    let micros = d.as_micros() as u64;
    let total_secs = micros / 1_000_000;
    let h = total_secs / 3600;
    let m = (total_secs % 3600) / 60;
    let s_nanos = (micros % 60_000_000) * 1000;
    let mut s = String::from("PT");
    if h > 0 {
        s += &format!("{}H", h);
    }
    if m > 0 {
        s += &format!("{}M", m);
    }
    if s_nanos > 0 || (h == 0 && m == 0) {
        s += &fmt_secs(s_nanos);
        s.push('S');
    }
    s
}

/// Same as [`fmt_duration`] but rounded to milliseconds, for human tables.
pub fn fmt_duration_ms(d: std::time::Duration) -> String {
    fmt_duration(std::time::Duration::from_millis(d.as_millis() as u64))
}

/// A closed-open interval `[start, end)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interval {
    pub start: Timestamp,
    pub end: Timestamp,
}

impl Interval {
    pub fn parse(s: &str) -> Result<Self, TimeError> {
        Self::parse_at(s, now())
    }

    pub fn parse_at(s: &str, now: Timestamp) -> Result<Self, TimeError> {
        let err = || TimeError::Interval(s.to_string());
        let (a, b) = s.split_once('/').ok_or_else(err)?;
        let a_dur = a.starts_with('P');
        let b_dur = b.starts_with('P');
        let iv = match (a_dur, b_dur) {
            (true, true) => return Err(err()),
            (false, false) => Interval {
                start: parse_datetime_at(a, now).map_err(|_| err())?,
                end: parse_datetime_at(b, now).map_err(|_| err())?,
            },
            (false, true) => {
                let start = parse_datetime_at(a, now).map_err(|_| err())?;
                let d = IsoDuration::parse(b).map_err(|_| err())?;
                Interval { start, end: d.after(start) }
            }
            (true, false) => {
                let end = parse_datetime_at(b, now).map_err(|_| err())?;
                let d = IsoDuration::parse(a).map_err(|_| err())?;
                Interval { start: d.before(end), end }
            }
        };
        if iv.end < iv.start {
            return Err(TimeError::Reversed(s.to_string()));
        }
        Ok(iv)
    }

    /// Interval ending now of the given length (`--since P7D`).
    pub fn since(d: &IsoDuration) -> Self {
        let n = now();
        Interval { start: d.before(n), end: n }
    }

    pub fn contains(&self, ts: Timestamp) -> bool {
        ts >= self.start && ts < self.end
    }

    /// Whether `[a, b]` overlaps this interval.
    pub fn overlaps(&self, a: Timestamp, b: Timestamp) -> bool {
        a < self.end && b >= self.start
    }
}

impl fmt::Display for Interval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", fmt_utc_secs(self.start), fmt_utc_secs(self.end))
    }
}

/// Validator used by tests and doctor: is `s` one of our ISO forms?
pub fn is_iso_datetime(s: &str) -> bool {
    parse_datetime_at(s, Timestamp::UNIX_EPOCH).is_ok() && s != "now"
}

/// Monotonic clock in nanoseconds (CLOCK_MONOTONIC).
pub fn monotonic_ns() -> u64 {
    let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) };
    t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
}

/// Event clock: header wall time plus monotonic offset, so clock steps can't reorder events.
#[derive(Clone, Copy, Debug)]
pub struct EventClock {
    pub wall: Timestamp,
    pub mono: u64,
}

impl EventClock {
    pub fn start() -> Self {
        EventClock { wall: now(), mono: monotonic_ns() }
    }
    pub fn now(&self) -> Timestamp {
        let delta = monotonic_ns().saturating_sub(self.mono);
        let ns = self.wall.as_nanosecond() + delta as i128;
        truncate_micros(Timestamp::from_nanosecond(ns).unwrap_or(self.wall))
    }
    pub fn elapsed(&self) -> std::time::Duration {
        std::time::Duration::from_nanos(monotonic_ns().saturating_sub(self.mono))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    #[test]
    fn storage_format() {
        let t = ts("2026-09-23T08:14:02.113245678Z");
        assert_eq!(fmt_utc(t), "2026-09-23T08:14:02.113245Z");
        assert_eq!(fmt_utc(ts("2026-09-23T08:14:02Z")), "2026-09-23T08:14:02.000000Z");
        assert_eq!(fmt_basic(t), "20260923T081402Z");
        assert_eq!(date_dir(t), "2026/09/23");
    }

    #[test]
    fn display_format() {
        let t = ts("2026-09-23T08:14:02Z");
        assert_eq!(fmt_display(t, "Europe/Prague", false), "2026-09-23T10:14:02+02:00");
        assert_eq!(fmt_display(ts("2026-01-23T08:14:02Z"), "Europe/Prague", false), "2026-01-23T09:14:02+01:00");
        assert_eq!(fmt_display(t, "Europe/Prague", true), "2026-09-23T08:14:02Z");
    }

    #[test]
    fn datetime_strict() {
        assert!(parse_datetime("2026-09-23T08:14:02Z").is_ok());
        assert!(parse_datetime("2026-09-23T08:14Z").is_ok());
        assert!(parse_datetime("2026-09-23T10:14:02+02:00").is_ok());
        assert!(parse_datetime("2026-09-23T08:14:02.5Z").is_ok());
        assert_eq!(parse_datetime("2026-09-23T10:14:02+02:00").unwrap(), ts("2026-09-23T08:14:02Z"));
        for bad in [
            "2026-09-23", "2026-09-23 08:14:02Z", "2026-09-23T08:14:02", "23.9.2026", "2026-09-23T8:14Z",
            "2026-09-23T08:14:02+0200", "yesterday", "2026-13-01T00:00Z", "2026-09-23T08:14:02.Z", "",
            "7d", "1695456842",
        ] {
            assert!(parse_datetime(bad).is_err(), "{bad} should be rejected");
        }
        let e = parse_datetime("7d").unwrap_err().to_string();
        assert!(e.contains("2026-09-23T08:14:02Z"), "error shows example: {e}");
    }

    #[test]
    fn durations() {
        let d = IsoDuration::parse("PT1H23M4.5S").unwrap();
        assert_eq!(d.exact().unwrap(), std::time::Duration::from_millis(4_984_500));
        assert_eq!(d.to_string(), "PT1H23M4.5S");
        assert_eq!(IsoDuration::parse("P7D").unwrap().to_string(), "P7D");
        assert_eq!(IsoDuration::parse("P1Y2M3W4DT5H6M7S").unwrap().to_string(), "P1Y2M3W4DT5H6M7S");
        assert_eq!(IsoDuration::parse("PT0.005S").unwrap().exact().unwrap(), std::time::Duration::from_millis(5));
        assert_eq!(IsoDuration::parse("PT0,5S").unwrap().exact().unwrap(), std::time::Duration::from_millis(500));
        for bad in ["7d", "P", "PT", "P1H", "PT1D", "P1DT", "1D", "p7d", "P7d", "PT1M1H", "P1.5D", "PT1.S", "-P1D", "P 1D", "PT1H1H"] {
            assert!(IsoDuration::parse(bad).is_err(), "{bad} should be rejected");
        }
        assert!(IsoDuration::parse("P1M").unwrap().is_calendar());
    }

    #[test]
    fn fmt_elapsed() {
        use std::time::Duration;
        assert_eq!(fmt_duration(Duration::from_millis(4_984_500)), "PT1H23M4.5S");
        assert_eq!(fmt_duration(Duration::ZERO), "PT0S");
        assert_eq!(fmt_duration(Duration::from_secs(3600)), "PT1H");
        assert_eq!(fmt_duration(Duration::from_secs(90000)), "PT25H");
        assert_eq!(fmt_duration(Duration::from_micros(1)), "PT0.000001S");
        assert_eq!(fmt_duration_ms(Duration::from_micros(1_234_567)), "PT1.234S");
    }

    #[test]
    fn intervals() {
        let now = ts("2026-09-23T12:00:00Z");
        let i = Interval::parse_at("P1D/now", now).unwrap();
        assert_eq!(i.start, ts("2026-09-22T12:00:00Z"));
        assert_eq!(i.end, now);
        let i = Interval::parse_at("2026-09-01T00:00Z/PT6H", now).unwrap();
        assert_eq!(i.end, ts("2026-09-01T06:00:00Z"));
        let i = Interval::parse_at("2026-09-01T00:00:00Z/2026-09-02T00:00:00Z", now).unwrap();
        assert!(i.contains(ts("2026-09-01T12:00:00Z")));
        assert!(!i.contains(ts("2026-09-02T00:00:00Z")));
        let i = Interval::parse_at("P1M/2026-03-31T00:00:00Z", now).unwrap();
        assert_eq!(i.start, ts("2026-02-28T00:00:00Z"));
        for bad in ["P1D", "P1D/P2D", "yesterday/now", "2026-09-02T00:00Z/2026-09-01T00:00Z", "7d/now", "P1D/"] {
            assert!(Interval::parse_at(bad, now).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn event_clock_monotone() {
        let c = EventClock::start();
        let a = c.now();
        let b = c.now();
        assert!(b >= a);
    }
}
