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
