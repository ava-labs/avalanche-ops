use std::{env, io};

use rand::seq::SliceRandom;

/// Generates a random string of length "n".
pub fn string(n: usize) -> String {
    let ret = WORDS.choose(&mut rand::thread_rng()).unwrap();
    let mut picked = String::from(ret.to_owned());
    let length = picked.len();

    if length == n {
        return picked;
    }

    if length < n {
        let remaining = n - length;
        for _ in 0..remaining {
            let c = CHARS.choose(&mut rand::thread_rng()).unwrap();
            picked.push_str(c.to_string().as_str());
        }
        return picked;
    }

    picked.truncate(n);
    picked
}

static CHARS: &[char] = &[
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
    'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
];

static WORDS: &[&str] = &[
    "avalanche",
    "avax",
    "awesome",
    "frosty",
    "green",
    "hawaii",
    "impressive",
    "mochi",
    "moon",
    "newyork",
    "ocean",
    "slush",
    "snowflake",
    "snowman",
    "snowstorm",
    "space",
    "sparkle",
    "splendid",
    "summer",
    "sunny",
    "sunrise",
    "surf",
    "uponly",
    "watermelon",
    "weallgonnamakeit",
    "wgmi",
];

#[test]
fn test_string() {
    let _ = env_logger::builder().is_test(true).try_init();
    use log::info;

    let word1 = string(100);
    let word2 = string(100);

    assert_eq!(word1.len(), 100);
    assert_eq!(word2.len(), 100);
    assert_ne!(word1, word2);

    info!("word1: {:?}", word1);
    info!("word2: {:?}", word2);
}

/// Returns a file path randomly generated in tmp directory.
/// The file does not exist yet.
pub fn tmp_path(n: usize) -> io::Result<String> {
    let tmp_dir = env::temp_dir();
    let tmp_file_path = tmp_dir.join(string(n));
    let tmp_file_path = tmp_file_path.as_os_str().to_str().unwrap();
    Ok(String::from(tmp_file_path))
}

#[test]
fn test_temp_path() {
    let _ = env_logger::builder().is_test(true).try_init();
    use log::info;

    let p1 = tmp_path(10).unwrap();
    let p2 = tmp_path(10).unwrap();
    assert_ne!(p1, p2);

    info!("p1: {:?}", p1);
    info!("p2: {:?}", p2);
}
