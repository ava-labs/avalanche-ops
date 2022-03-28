use std::cmp;

const DELIMITER: f64 = 1000_f64;
const UNITS: &[&str] = &["B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];

/// Converts the number of bytes to a human-readable string.
/// ref. https://github.com/banyan/rust-pretty-bytes/blob/master/src/converter.rs
pub fn bytes(n: f64) -> String {
    let sign = if n.is_sign_positive() { "" } else { "-" };
    let n = n.abs();
    if n < 1_f64 {
        return format!("{}{} {}", sign, n, "B");
    }
    let exp = cmp::min(
        (n.ln() / DELIMITER.ln()).floor() as i32,
        (UNITS.len() - 1) as i32,
    );
    let bytes = format!("{:.2}", n / DELIMITER.powi(exp))
        .parse::<f64>()
        .unwrap()
        * 1_f64;
    let unit = UNITS[exp as usize];
    format!("{}{} {}", sign, bytes, unit)
}

#[test]
fn test_humanize_bytes() {
    assert!(bytes(100000.0) == "100 kB");
    assert!(bytes(490652508160.0) == "490.65 GB");
    assert!(bytes(252868079616.0) == "252.87 GB");
    assert!(bytes(227876253696.0) == "227.88 GB");
}
