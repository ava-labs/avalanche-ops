use std::{
    fs::{self, File},
    io::{self, Cursor, Write},
};

use log::info;
use zstd::stream;

pub fn compress_zstd(filename: &str, dst_path: &str, level: Option<i32>) -> io::Result<()> {
    let lvl = level.unwrap_or(3);

    let meta = fs::metadata(filename)?;
    let size = meta.len() as f64;

    info!(
        "compressing {} to {} (level {}, original size {})",
        filename,
        dst_path,
        lvl,
        crate::humanize::bytes(size),
    );

    let contents = fs::read(filename)?;
    let compressed = stream::encode_all(Cursor::new(&contents[..]), lvl)?;
    let mut f = File::create(dst_path)?;
    f.write_all(&compressed[..])?;

    let meta = fs::metadata(dst_path)?;
    let size = meta.len() as f64;
    info!(
        "compressed {} to {} (new size {})",
        filename,
        dst_path,
        crate::humanize::bytes(size),
    );

    Ok(())
}

pub fn decompress_zstd(filename: &str, dst_path: &str) -> io::Result<()> {
    let meta = fs::metadata(filename)?;
    let size = meta.len() as f64;

    info!(
        "decompressing {} to {} (original size {})",
        filename,
        dst_path,
        crate::humanize::bytes(size),
    );

    let contents = fs::read(filename)?;
    let decompressed = stream::decode_all(Cursor::new(&contents[..]))?;
    let mut f = File::create(dst_path)?;
    f.write_all(&decompressed[..])?;

    let meta = fs::metadata(dst_path)?;
    let size = meta.len() as f64;
    info!(
        "decompressed {} to {} (new size {})",
        filename,
        dst_path,
        crate::humanize::bytes(size),
    );

    Ok(())
}

#[test]
fn test_compress() {
    let _ = env_logger::builder().is_test(true).try_init();
    use std::{fs, io::Write};

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

    let ret = compress_zstd(p1, p2, None);
    assert!(ret.is_ok());

    // compressed file should be smaller
    let meta1 = fs::metadata(p1).unwrap();
    let meta2 = fs::metadata(p2).unwrap();
    assert!(meta1.len() > meta2.len());

    let ret = decompress_zstd(p2, p3);
    assert!(ret.is_ok());

    // decompressed file should be same as original
    let contents1 = fs::read(p1).unwrap();
    let contents3 = fs::read(p3).unwrap();
    assert_eq!(contents1, contents3);
}
