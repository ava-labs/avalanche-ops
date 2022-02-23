extern crate avalanche_ops;
use avalanche_ops::compress;

fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let contents = "i-abcedfg-NodeID-29HTAG5cfN2fw79A67Jd5zY9drcT51EBG-1.2.3.4";
    println!("contents: {} {}", contents, contents.len());

    let compressed = compress::pack(contents.as_bytes(), compress::Encoder::Zstd(3)).unwrap();
    println!("compressed: {}", compressed.len());

    let compressed_base58 =
        compress::pack(contents.as_bytes(), compress::Encoder::ZstdBase58(3)).unwrap();
    println!(
        "compressed_base58: {:#?} {}",
        compressed_base58,
        compressed_base58.len()
    );

    let compressed_decompressed = compress::unpack(&compressed, compress::Decoder::Zstd).unwrap();
    assert_eq!(contents.as_bytes(), compressed_decompressed);
    println!(
        "compressed_decompressed: {}",
        String::from_utf8(compressed_decompressed).unwrap()
    );
}
