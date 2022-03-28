use std::{
    io::{self, Error, ErrorKind},
    time::SystemTime,
};

use chrono::{DateTime, NaiveDateTime, SecondsFormat, TimeZone, Utc};
use serde::{self, Deserialize, Deserializer};

/// ref. https://serde.rs/custom-date-format.html
pub mod serde_format {
    use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(dt: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // ref. https://docs.rs/chrono/0.4.19/chrono/struct.DateTime.html#method.to_rfc3339_opts
        serializer.serialize_str(&dt.to_rfc3339_opts(SecondsFormat::Millis, true))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        // ref. https://docs.rs/chrono/0.4.19/chrono/struct.DateTime.html#method.parse_from_rfc3339
        match DateTime::parse_from_rfc3339(&s).map_err(serde::de::Error::custom) {
            Ok(dt) => Ok(Utc.from_utc_datetime(&dt.naive_utc())),
            Err(e) => Err(e),
        }
    }
}

fn datefmt<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    // ref. https://docs.rs/chrono/0.4.19/chrono/struct.DateTime.html#method.parse_from_rfc3339
    match DateTime::parse_from_rfc3339(&s).map_err(serde::de::Error::custom) {
        Ok(dt) => Ok(Utc.from_utc_datetime(&dt.naive_utc())),
        Err(e) => Err(e),
    }
}

pub fn format_date<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct Wrapper(#[serde(deserialize_with = "datefmt")] DateTime<Utc>);
    let v = Option::deserialize(deserializer)?;
    Ok(v.map(|Wrapper(a)| a))
}

pub fn now_str() -> io::Result<String> {
    let now = SystemTime::now();
    let now_unix = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("unexpected None duration_since")
        .as_secs();
    let native_dt = NaiveDateTime::from_timestamp(now_unix as i64, 0);
    let now_utc = DateTime::<Utc>::from_utc(native_dt, Utc);
    Ok(now_utc.to_rfc3339_opts(SecondsFormat::Millis, true))
}

pub fn to_str(now_unix: u64) -> io::Result<String> {
    let native_dt = NaiveDateTime::from_timestamp(now_unix as i64, 0);
    let now_utc = DateTime::<Utc>::from_utc(native_dt, Utc);
    Ok(now_utc.to_rfc3339_opts(SecondsFormat::Millis, true))
}

pub fn parse(s: &str) -> io::Result<DateTime<Utc>> {
    match DateTime::parse_from_rfc3339(s) {
        Ok(dt) => Ok(Utc.from_utc_datetime(&dt.naive_utc())),
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("failed to parse {} ({})", s, e),
            ));
        }
    }
}

/// RUST_LOG=debug cargo test --package avalanche-ops --lib -- utils::rfc3339::test_parse --exact --show-output
#[test]
fn test_parse() {
    let _ = env_logger::builder().is_test(true).try_init();
    use log::info;

    let dt = Utc.ymd(2018, 1, 26).and_hms_micro(18, 30, 9, 453_000);
    let s = "2018-01-26T18:30:09.453Z";
    let parsed = parse(s).unwrap();
    assert_eq!(dt, parsed);

    let parsed = parse(&(now_str().unwrap())).unwrap();
    info!("{:?}", parsed);
}
