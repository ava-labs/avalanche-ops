extern crate avalanche_ops;
use avalanche_ops::compress;

fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let contents = "i-abcedfg-NodeID-29HTAG5cfN2fw79A67Jd5zY9drcT51EBG-1.2.3.4";
    println!("contents: {} {}", contents, contents.len());

    let compressed = compress::to_zstd(contents.as_bytes(), None).unwrap();
    println!("compressed: {}", compressed.len());

    let compressed_base58 = compress::to_zstd_base58(contents.as_bytes(), None).unwrap();
    println!(
        "compressed_base58: {:#?} {}",
        compressed_base58,
        compressed_base58.len()
    );

    let compressed_decompressed = compress::from_zstd(&compressed).unwrap();
    assert_eq!(contents.as_bytes(), compressed_decompressed);
    println!(
        "compressed_decompressed: {}",
        String::from_utf8(compressed_decompressed).unwrap()
    );
}
