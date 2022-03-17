use std::io::{self, Error, ErrorKind};

use crate::utils::prefix;
use num_bigint::BigInt;

/// Parses the big.Int encoded in hex.
/// "0x52B7D2DCC80CD2E4000000" is "100000000000000000000000000" (100,000,000 AVAX).
/// "0x5f5e100" or "0x5F5E100" is "100000000".
/// "0x1312D00" is "20000000".
/// ref. https://www.rapidtables.com/convert/number/hex-to-decimal.html
pub fn from_hex(s: &str) -> io::Result<BigInt> {
    let sb = prefix::strip_0x(s).as_bytes();

    // ref. https://docs.rs/num-bigint/latest/num_bigint/struct.BigInt.html
    let b = match BigInt::parse_bytes(sb, 16) {
        Some(v) => v,
        None => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("failed to parse hex big int {} (parse returned None)", s),
            ));
        }
    };
    Ok(b)
}

/// ref. https://doc.rust-lang.org/nightly/core/fmt/trait.UpperHex.html
pub fn to_upper_hex(v: &BigInt) -> String {
    format!("{:#X}", v)
}

/// ref. https://doc.rust-lang.org/nightly/core/fmt/trait.LowerHex.html
pub fn to_lower_hex(v: &BigInt) -> String {
    format!("{:#x}", v)
}

#[test]
fn test_hex() {
    use num_bigint::ToBigInt;

    let big_num = BigInt::default();
    assert_eq!(from_hex("0x0").unwrap(), big_num);

    let big_num = ToBigInt::to_bigint(&100000000000000000000000000_i128).unwrap();
    assert_eq!(from_hex("0x52B7D2DCC80CD2E4000000").unwrap(), big_num);
    assert_eq!(to_upper_hex(&big_num), "0x52B7D2DCC80CD2E4000000",);

    let big_num = ToBigInt::to_bigint(&100000000_i128).unwrap();
    assert_eq!(from_hex("0x5F5E100").unwrap(), big_num);
    assert_eq!(to_lower_hex(&big_num), "0x5f5e100",);
    assert_eq!(to_upper_hex(&big_num), "0x5F5E100",);

    let big_num = ToBigInt::to_bigint(&20000000_i128).unwrap();
    assert_eq!(from_hex("0x1312D00").unwrap(), big_num);
    assert_eq!(to_lower_hex(&big_num), "0x1312d00",);
    assert_eq!(to_upper_hex(&big_num), "0x1312D00",);
}

pub mod serde_hex_format {
    use crate::utils::big_int;
    use num_bigint::BigInt;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bi: &BigInt, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // ref. https://docs.rs/chrono/0.4.19/chrono/struct.DateTime.html#method.to_rfc3339_opts
        serializer.serialize_str(&big_int::to_lower_hex(bi))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BigInt, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        // ref. https://docs.rs/chrono/0.4.19/chrono/struct.DateTime.html#method.parse_from_rfc3339
        match big_int::from_hex(&s).map_err(serde::de::Error::custom) {
            Ok(dt) => Ok(dt),
            Err(e) => Err(e),
        }
    }
}
