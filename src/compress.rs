use std::{
    fs::{self, File},
    io::{self, Cursor, Error, ErrorKind, Write},
};

use log::info;
use zstd::stream;

pub fn to_zstd(contents: &[u8], level: Option<i32>) -> io::Result<Vec<u8>> {
    let lvl = level.unwrap_or(3);

    let size = contents.len() as f64;
    info!(
        "compressing to zstd (current size {})",
        crate::humanize::bytes(size),
    );

    let compressed = stream::encode_all(Cursor::new(contents), lvl)?;
    let size = compressed.len() as f64;
    info!(
        "compressed to zstd (new size {})",
        crate::humanize::bytes(size),
    );

    Ok(compressed)
}

pub fn from_zstd(contents: &[u8]) -> io::Result<Vec<u8>> {
    let size = contents.len() as f64;
    info!(
        "decompressing zstd (current size {})",
        crate::humanize::bytes(size),
    );

    let decompressed = stream::decode_all(Cursor::new(contents))?;
    let size = decompressed.len() as f64;
    info!(
        "decompressed zstd (new size {})",
        crate::humanize::bytes(size),
    );

    Ok(decompressed)
}

pub fn to_zstd_base58(contents: &[u8], level: Option<i32>) -> io::Result<String> {
    let compressed = to_zstd(contents, level)?;
    Ok(bs58::encode(compressed).into_string())
}

pub fn from_zstd_base58(contents: String) -> io::Result<Vec<u8>> {
    let contents_decoded = match bs58::decode(contents).into_vec() {
        Ok(v) => v,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("failed bs58::decode {}", e),
            ));
        }
    };
    from_zstd(&contents_decoded)
}

/// Compresses the contents in "src_path" using "Zstandard" compression
/// and saves it to "dst_path". Note that even if "dst_path" already exists,
/// it truncates (overwrites).
pub fn to_zstd_file(src_path: &str, dst_path: &str, level: Option<i32>) -> io::Result<()> {
    let lvl = level.unwrap_or(3);

    let meta = fs::metadata(src_path)?;
    let size = meta.len() as f64;

    info!(
        "compressing '{}' to '{}' (current size {})",
        src_path,
        dst_path,
        crate::humanize::bytes(size),
    );

    let contents = fs::read(src_path)?;
    let compressed = stream::encode_all(Cursor::new(&contents[..]), lvl)?;
    let mut f = File::create(dst_path)?;
    f.write_all(&compressed[..])?;

    let meta = fs::metadata(dst_path)?;
    let size = meta.len() as f64;
    info!(
        "compressed '{}' to '{}' (new size {})",
        src_path,
        dst_path,
        crate::humanize::bytes(size),
    );

    Ok(())
}

/// Decompresses the contents in "src_path" using "Zstandard" and saves it
/// to "dst_path". Note that even if "dst_path" already exists, it truncates
/// (overwrites).
pub fn from_zstd_file(src_path: &str, dst_path: &str) -> io::Result<()> {
    let meta = fs::metadata(src_path)?;
    let size = meta.len() as f64;

    info!(
        "decompressing '{}' to '{}' (current size {})",
        src_path,
        dst_path,
        crate::humanize::bytes(size),
    );

    let contents = fs::read(src_path)?;
    let decompressed = stream::decode_all(Cursor::new(&contents[..]))?;
    let mut f = File::create(dst_path)?;
    f.write_all(&decompressed[..])?;

    let meta = fs::metadata(dst_path)?;
    let size = meta.len() as f64;
    info!(
        "decompressed '{}' to '{}' (new size {})",
        src_path,
        dst_path,
        crate::humanize::bytes(size),
    );

    Ok(())
}

#[test]
fn test_compress() {
    let _ = env_logger::builder().is_test(true).try_init();
    use std::{fs, io::Write};

    let contents = crate::random::string(10);
    let contents_compressed = to_zstd(&contents.as_bytes(), None).unwrap();
    let contents_compressed_decompressed = from_zstd(&contents_compressed).unwrap();
    assert_eq!(contents.as_bytes(), contents_compressed_decompressed);
    info!("contents_compressed: {:#?}", contents_compressed);
    let contents_compressed_base64 = to_zstd_base58(&contents.as_bytes(), None).unwrap();
    let contents_compressed_base64_decompressed =
        from_zstd_base58(contents_compressed_base64.clone()).unwrap();
    assert_eq!(contents.as_bytes(), contents_compressed_base64_decompressed);
    info!(
        "contents_compressed_base64: {:#?}",
        contents_compressed_base64
    );

    let contents = crate::random::string(4000);
    let mut f1 = tempfile::NamedTempFile::new().unwrap();
    let ret = f1.write_all(contents.as_bytes());
    assert!(ret.is_ok());
    let p1 = f1.path().to_str().unwrap();

    let tmp_dir = tempfile::tempdir().unwrap();

    let p2 = tmp_dir.path().join(crate::random::string(20));
    let p2 = p2.as_os_str().to_str().unwrap();

    let p3 = tmp_dir.path().join(crate::random::string(20));
    let p3 = p3.as_os_str().to_str().unwrap();

    let ret = to_zstd_file(p1, p2, None);
    assert!(ret.is_ok());

    // compressed file should be smaller
    let meta1 = fs::metadata(p1).unwrap();
    let meta2 = fs::metadata(p2).unwrap();
    assert!(meta1.len() > meta2.len());

    let ret = from_zstd_file(p2, p3);
    assert!(ret.is_ok());

    // decompressed file should be same as original
    let contents1 = fs::read(p1).unwrap();
    let contents3 = fs::read(p3).unwrap();
    assert_eq!(contents1, contents3);
}
