extern crate avalanche_ops;
use avalanche_ops::compress;

fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let contents = "i-abcedfg-NodeID-29HTAG5cfN2fw79A67Jd5zY9drcT51EBG-1.2.3.4";

    let packed = compress::pack(contents.as_bytes(), compress::Encoder::Zstd(3)).unwrap();
    println!("packed: {}", packed.len());

    let unpacked = compress::unpack(&packed, compress::Decoder::Zstd).unwrap();
    assert_eq!(contents.as_bytes(), unpacked);
    println!("unpacked: {}", String::from_utf8(unpacked).unwrap());

    let cb58 = compress::pack(contents.as_bytes(), compress::Encoder::ZstdBase58(3)).unwrap();
    let cb58 = String::from_utf8(cb58).unwrap();
    println!("cb58: {} {}", cb58, cb58.len());

    // compress::pack_directory(
    //     "/tmp/mainnet",
    //     "data.tar.zstd",
    //     compress::DirEncoder::TarZstd(3),
    // )
    // .unwrap();
    // compress::unpack_directory("/tmp/db.tar.gz", "data", compress::DirDecoder::TarGzip).unwrap();
}
