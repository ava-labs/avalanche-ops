use std::{
    env,
    fs::{self, File},
    io::{self, BufReader, Cursor, Error, ErrorKind, Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use flate2::bufread::{GzDecoder, GzEncoder};
use flate2::Compression;
use fs_extra;
use log::info;
use path_clean::PathClean;
use tar::{Archive, Builder};
use walkdir::{DirEntry, WalkDir};
use zip::{write::FileOptions, ZipArchive, ZipWriter};
use zstd;

use crate::{humanize, random};

/// Represents the compression encoding algorithm.
pub enum Encoder {
    /// Encodes with "Zstandard" compression.
    Zstd(i32),
    /// Encodes with "Zstandard" compression and apply base58.
    ZstdBase58(i32),
    /// Encodes with "Gzip" compression.
    Gzip,
}

impl Encoder {
    pub fn id(&self) -> String {
        match self {
            Encoder::Zstd(level) => format!("zstd (level {})", level),
            Encoder::ZstdBase58(level) => format!("zstd-base58 (level {})", level),
            Encoder::Gzip => String::from("gzip"),
        }
    }
}

/// Represents the compression decoding algorithm.
pub enum Decoder {
    Zstd,
    ZstdBase58,
    Gzip,
}

impl Decoder {
    pub fn id(&self) -> String {
        match self {
            Decoder::Zstd => String::from("zstd"),
            Decoder::ZstdBase58 => String::from("zstd-base58"),
            Decoder::Gzip => String::from("gzip"),
        }
    }
}

pub fn pack(d: &[u8], enc: Encoder) -> io::Result<Vec<u8>> {
    let size = d.len() as f64;
    info!(
        "packing with {} (current size {})",
        enc.id(),
        humanize::bytes(size),
    );

    let packed = match enc {
        Encoder::Zstd(lvl) => zstd::stream::encode_all(Cursor::new(d), lvl)?,
        Encoder::ZstdBase58(lvl) => {
            let encoded = zstd::stream::encode_all(Cursor::new(d), lvl)?;
            bs58::encode(encoded).into_vec()
        }
        Encoder::Gzip => {
            let mut gz = GzEncoder::new(Cursor::new(d), Compression::default());
            let mut encoded = Vec::new();
            gz.read_to_end(&mut encoded)?;
            encoded
        }
    };

    let size = packed.len() as f64;
    info!(
        "packed to {} (new size {})",
        enc.id(),
        humanize::bytes(size),
    );

    Ok(packed)
}

pub fn unpack(d: &[u8], dec: Decoder) -> io::Result<Vec<u8>> {
    let size = d.len() as f64;
    info!(
        "unpacking with {} (current size {})",
        dec.id(),
        humanize::bytes(size),
    );

    let unpacked = match dec {
        Decoder::Zstd => zstd::stream::decode_all(Cursor::new(d))?,
        Decoder::ZstdBase58 => {
            let d_decoded = match bs58::decode(d).into_vec() {
                Ok(v) => v,
                Err(e) => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("failed bs58::decode {}", e),
                    ));
                }
            };
            zstd::stream::decode_all(Cursor::new(d_decoded))?
        }
        Decoder::Gzip => {
            let mut gz = GzDecoder::new(Cursor::new(d));
            let mut decoded = Vec::new();
            gz.read_to_end(&mut decoded)?;
            decoded
        }
    };

    let size = unpacked.len() as f64;
    info!(
        "unpacked to {} (new size {})",
        dec.id(),
        humanize::bytes(size),
    );

    Ok(unpacked)
}

/// Compresses the contents in "src_path" using compression algorithms
/// and saves it to "dst_path". Note that even if "dst_path" already exists,
/// it truncates (overwrites).
pub fn pack_file(src_path: &str, dst_path: &str, enc: Encoder) -> io::Result<()> {
    let meta = fs::metadata(src_path)?;
    let size = meta.len() as f64;
    info!(
        "packing file '{}' to '{}' with {} (current size {})",
        src_path,
        dst_path,
        enc.id(),
        humanize::bytes(size),
    );

    match enc {
        Encoder::Zstd(lvl) => {
            // reading the entire file at once may cause OOM...
            // let d = fs::read(src_path)?;
            // let compressed = zstd::stream::encode_all(Cursor::new(&d[..]), lvl)?;

            let mut f1 = File::open(src_path)?;
            let f2 = File::create(dst_path)?;

            let mut enc = zstd::Encoder::new(f2, lvl)?;

            // reads from reader (f1) and writes to writer "enc"
            io::copy(&mut f1, &mut enc)?;
            enc.finish()?;
        }
        Encoder::ZstdBase58(lvl) => {
            // reading the entire file at once may cause OOM...
            let d = fs::read(src_path)?;
            let encoded = pack(&d, Encoder::ZstdBase58(lvl))?;
            let mut f = File::create(dst_path)?;
            f.write_all(&encoded[..])?;
        }
        Encoder::Gzip => {
            let f = File::open(src_path)?;
            let d = BufReader::new(f);

            let mut gz = GzEncoder::new(d, Compression::default());
            let mut compressed = Vec::new();
            gz.read_to_end(&mut compressed)?;

            let mut f = File::create(dst_path)?;
            f.write_all(&compressed[..])?;
        }
    };

    let meta = fs::metadata(dst_path)?;
    let size = meta.len() as f64;
    info!(
        "packed file '{}' to '{}' with {} (new size {})",
        src_path,
        dst_path,
        enc.id(),
        humanize::bytes(size),
    );

    Ok(())
}

/// Decompresses the contents in "src_path" using compression algorithms
/// and saves it to "dst_path". Note that even if "dst_path" already exists,
/// it truncates (overwrites).
pub fn unpack_file(src_path: &str, dst_path: &str, dec: Decoder) -> io::Result<()> {
    let meta = fs::metadata(src_path)?;
    let size = meta.len() as f64;
    info!(
        "unpacking file '{}' to '{}' with {} (current size {})",
        src_path,
        dst_path,
        dec.id(),
        humanize::bytes(size),
    );

    match dec {
        Decoder::Zstd => {
            // reading the entire file at once may cause OOM...
            // let d = fs::read(src_path)?;
            // let decoded = zstd::stream::decode_all(Cursor::new(&d[..]))?;

            let f = File::open(src_path)?;
            let d = BufReader::new(f);

            let mut dec = zstd::Decoder::new(d)?;
            let mut decoded = Vec::new();
            dec.read_to_end(&mut decoded)?;

            let mut f = File::create(dst_path)?;
            f.write_all(&decoded[..])?;
        }
        Decoder::ZstdBase58 => {
            // reading the entire file at once may cause OOM...
            let d = fs::read(src_path)?;
            let decoded = unpack(&d, Decoder::ZstdBase58)?;
            let mut f = File::create(dst_path)?;
            f.write_all(&decoded[..])?;
        }
        Decoder::Gzip => {
            let f = File::open(src_path)?;
            let d = BufReader::new(f);

            let mut gz = GzDecoder::new(d);
            let mut decoded = Vec::new();
            gz.read_to_end(&mut decoded)?;

            let mut f = File::create(dst_path)?;
            f.write_all(&decoded[..])?;
        }
    };

    let meta = fs::metadata(dst_path)?;
    let size = meta.len() as f64;
    info!(
        "unpacked file '{}' to '{}' with {} (new size {})",
        src_path,
        dst_path,
        dec.id(),
        humanize::bytes(size),
    );

    Ok(())
}

#[test]
fn test_pack_zstd() {
    let _ = env_logger::builder().is_test(true).try_init();

    let contents = random::string(10);
    let contents_compressed = pack(&contents.as_bytes(), Encoder::Zstd(3)).unwrap();
    let contents_compressed_decompressed = unpack(&contents_compressed, Decoder::Zstd).unwrap();
    assert_eq!(contents.as_bytes(), contents_compressed_decompressed);
    let contents_compressed_base58 = pack(&contents.as_bytes(), Encoder::ZstdBase58(3)).unwrap();
    let contents_compressed_base58_decompressed =
        unpack(&contents_compressed_base58, Decoder::ZstdBase58).unwrap();
    assert_eq!(contents.as_bytes(), contents_compressed_base58_decompressed);
    info!(
        "contents_compressed_base58: {}",
        String::from_utf8(contents_compressed_base58).unwrap()
    );

    let contents = random::string(4000);
    let mut f1 = tempfile::NamedTempFile::new().unwrap();
    let ret = f1.write_all(contents.as_bytes());
    assert!(ret.is_ok());
    let p1 = f1.path().to_str().unwrap();

    let tmp_dir = tempfile::tempdir().unwrap();

    let p2 = tmp_dir.path().join(random::string(20));
    let p2 = p2.as_os_str().to_str().unwrap();

    let p3 = tmp_dir.path().join(random::string(20));
    let p3 = p3.as_os_str().to_str().unwrap();

    let ret = pack_file(p1, p2, Encoder::Zstd(3));
    assert!(ret.is_ok());

    // compressed file should be smaller
    let meta1 = fs::metadata(p1).unwrap();
    let meta2 = fs::metadata(p2).unwrap();
    assert!(meta1.len() > meta2.len());

    let ret = unpack_file(p2, p3, Decoder::Zstd);
    assert!(ret.is_ok());

    // decompressed file should be same as original
    let contents1 = fs::read(p1).unwrap();
    let contents3 = fs::read(p3).unwrap();
    assert_eq!(contents1, contents3);
}

#[test]
fn test_pack_gzip() {
    let _ = env_logger::builder().is_test(true).try_init();

    let contents = random::string(10);
    let contents_compressed = pack(&contents.as_bytes(), Encoder::Gzip).unwrap();
    let contents_compressed_decompressed = unpack(&contents_compressed, Decoder::Gzip).unwrap();
    assert_eq!(contents.as_bytes(), contents_compressed_decompressed);

    let contents = random::string(4000);
    let mut f1 = tempfile::NamedTempFile::new().unwrap();
    let ret = f1.write_all(contents.as_bytes());
    assert!(ret.is_ok());
    let p1 = f1.path().to_str().unwrap();

    let tmp_dir = tempfile::tempdir().unwrap();

    let p2 = tmp_dir.path().join(random::string(20));
    let p2 = p2.as_os_str().to_str().unwrap();

    let p3 = tmp_dir.path().join(random::string(20));
    let p3 = p3.as_os_str().to_str().unwrap();

    let ret = pack_file(p1, p2, Encoder::Gzip);
    assert!(ret.is_ok());

    // compressed file should be smaller
    let meta1 = fs::metadata(p1).unwrap();
    let meta2 = fs::metadata(p2).unwrap();
    assert!(meta1.len() > meta2.len());

    let ret = unpack_file(p2, p3, Decoder::Gzip);
    assert!(ret.is_ok());

    // decompressed file should be same as original
    let contents1 = fs::read(p1).unwrap();
    let contents3 = fs::read(p3).unwrap();
    assert_eq!(contents1, contents3);
}

/// Represents the compression encoding algorithm for directory.
pub enum DirEncoder {
    /// Archives the directory with "zip" and
    /// encodes with "Zstandard" compression.
    ZipZstd(i32),
    /// Archives the directory with "tar" and
    /// encodes with "Zstandard" compression.
    TarZstd(i32),
    /// Archives the directory with "zip" and
    /// and encodes with "Gzip" compression.
    ZipGzip,
    /// Archives the directory with "tar" and
    /// and encodes with "Gzip" compression.
    TarGzip,
}

impl DirEncoder {
    pub fn id(&self) -> String {
        match self {
            DirEncoder::ZipZstd(level) => format!("zip-zstd (level {})", level),
            DirEncoder::TarZstd(level) => format!("tar-zstd (level {})", level),
            DirEncoder::ZipGzip => String::from("zip-gzip"),
            DirEncoder::TarGzip => String::from("tar-gzip"),
        }
    }
    pub fn ext(&self) -> &str {
        match self {
            DirEncoder::ZipZstd(_) => ".zip.zstd",
            DirEncoder::TarZstd(_) => ".tar.zstd",
            DirEncoder::ZipGzip => ".zip.gz",
            DirEncoder::TarGzip => ".tar.gz",
        }
    }
}

/// Represents the compression decoding algorithm for directory.
pub enum DirDecoder {
    ZipZstd,
    TarZstd,
    ZipGzip,
    TarGzip,
}

impl DirDecoder {
    pub fn id(&self) -> String {
        match self {
            DirDecoder::ZipZstd => String::from("zip-zstd"),
            DirDecoder::TarZstd => String::from("tar-zstd"),
            DirDecoder::ZipGzip => String::from("zip-gzip"),
            DirDecoder::TarGzip => String::from("tar-gzip"),
        }
    }
    pub fn ext(&self) -> &str {
        match self {
            DirDecoder::ZipZstd => ".zip.zstd",
            DirDecoder::TarZstd => ".tar.zstd",
            DirDecoder::ZipGzip => ".zip.gz",
            DirDecoder::TarGzip => ".tar.gz",
        }
    }
}

/// Archives the source directory "src_dir_path" with archival method and compression
/// and saves to "dst_path". If "dst_path" exists, it overwrites.
pub fn pack_directory(src_dir_path: &str, dst_path: &str, enc: DirEncoder) -> io::Result<()> {
    let size = match fs_extra::dir::get_size(src_dir_path) {
        Ok(v) => v,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("failed get_size {} for directory {}", e, src_dir_path),
            ));
        }
    };
    let size = size as f64;
    info!(
        "packing directory with {} from '{}' (original size {}) to '{}'",
        enc.id(),
        src_dir_path,
        humanize::bytes(size),
        dst_path
    );

    match enc {
        DirEncoder::ZipZstd(lvl) => {
            let options = FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored)
                .unix_permissions(0o755);
            let zip_path = random::tmp_path(10, Some(".zip"))?;
            let zip_file = File::create(&zip_path)?;
            let mut zip = ZipWriter::new(zip_file);

            let mut buffer = Vec::new();
            let src_dir = Path::new(src_dir_path);
            let src_dir_full_path = absolute_path(src_dir)?;
            for entry in WalkDir::new(src_dir_path).into_iter() {
                let entry = match entry {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(Error::new(
                            ErrorKind::Other,
                            format!("failed walk dir {} ({})", src_dir_path, e),
                        ));
                    }
                };

                let full_path = absolute_path(entry.path())?;
                // relative path from source directory
                // e.g., "text/a/b/c.txt" for absolute path "/tmp/text/a/b/c.txt"
                let rel_path = match full_path.strip_prefix(&src_dir_full_path) {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(Error::new(
                            ErrorKind::Other,
                            format!("failed strip_prefix on {:?} ({})", full_path, e),
                        ));
                    }
                };

                if is_dir(&entry) {
                    // only if not root
                    // ref. https://github.com/zip-rs/zip/blob/master/examples/write_dir.rs
                    if !rel_path.as_os_str().is_empty() {
                        let dir_name = rel_path.as_os_str().to_str().unwrap();
                        info!("adding directory {}", dir_name);
                        zip.add_directory(dir_name, options)?;
                    }
                    continue;
                }

                let file_name = rel_path.as_os_str().to_str().unwrap();
                info!("adding file {}", file_name);
                zip.start_file(file_name, options)?;
                let mut f = File::open(full_path)?;
                f.read_to_end(&mut buffer)?;
                zip.write_all(&*buffer)?;
                buffer.clear();
            }

            zip.finish()?;
            info!("wrote zip file {}", zip_path);
            pack_file(&zip_path, dst_path, Encoder::Zstd(lvl))?;
        }
        DirEncoder::TarZstd(lvl) => {
            let tar_path = random::tmp_path(10, Some(".tar"))?;
            let tar_file = File::create(&tar_path)?;
            let mut tar = Builder::new(tar_file);
            let src_dir = Path::new(src_dir_path);
            let src_dir_full_path = absolute_path(src_dir)?;
            for entry in WalkDir::new(src_dir_path).into_iter() {
                let entry = match entry {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(Error::new(
                            ErrorKind::Other,
                            format!("failed walk dir {} ({})", src_dir_path, e),
                        ));
                    }
                };

                let full_path = absolute_path(entry.path())?;
                // relative path from source directory
                // e.g., "text/a/b/c.txt" for absolute path "/tmp/text/a/b/c.txt"
                let rel_path = match full_path.strip_prefix(&src_dir_full_path) {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(Error::new(
                            ErrorKind::Other,
                            format!("failed strip_prefix on {:?} ({})", full_path, e),
                        ));
                    }
                };

                if is_dir(&entry) {
                    continue;
                }

                let file_name = rel_path.as_os_str().to_str().unwrap();
                info!("adding file {}", file_name);
                let mut f = File::open(&full_path)?;
                tar.append_file(&file_name, &mut f)?;
            }

            info!("wrote tar file {}", tar_path);
            pack_file(&tar_path, dst_path, Encoder::Zstd(lvl))?;
        }
        DirEncoder::ZipGzip => {
            let options = FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored)
                .unix_permissions(0o755);
            let zip_path = random::tmp_path(10, Some(".zip"))?;
            let zip_file = File::create(&zip_path)?;
            let mut zip = ZipWriter::new(zip_file);

            let mut buffer = Vec::new();
            let src_dir = Path::new(src_dir_path);
            let src_dir_full_path = absolute_path(src_dir)?;
            for entry in WalkDir::new(src_dir_path).into_iter() {
                let entry = match entry {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(Error::new(
                            ErrorKind::Other,
                            format!("failed walk dir {} ({})", src_dir_path, e),
                        ));
                    }
                };

                let full_path = absolute_path(entry.path())?;
                // relative path from source directory
                // e.g., "text/a/b/c.txt" for absolute path "/tmp/text/a/b/c.txt"
                let rel_path = match full_path.strip_prefix(&src_dir_full_path) {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(Error::new(
                            ErrorKind::Other,
                            format!("failed strip_prefix on {:?} ({})", full_path, e),
                        ));
                    }
                };

                if is_dir(&entry) {
                    // only if not root
                    // ref. https://github.com/zip-rs/zip/blob/master/examples/write_dir.rs
                    if !rel_path.as_os_str().is_empty() {
                        let dir_name = rel_path.as_os_str().to_str().unwrap();
                        info!("adding directory {}", dir_name);
                        zip.add_directory(dir_name, options)?;
                    }
                    continue;
                }

                let file_name = rel_path.as_os_str().to_str().unwrap();
                info!("adding file {}", file_name);
                zip.start_file(file_name, options)?;
                let mut f = File::open(full_path)?;
                f.read_to_end(&mut buffer)?;
                zip.write_all(&*buffer)?;
                buffer.clear();
            }

            zip.finish()?;
            info!("wrote zip file {}", zip_path);
            pack_file(&zip_path, dst_path, Encoder::Gzip)?;
        }
        DirEncoder::TarGzip => {
            // e.g.,
            // tar -czvf db.tar.gz mainnet/
            // -c to create a new archive
            // -z to enable "--gzip" mode
            // -v to enable verbose mode
            // -f to specify the file
            let tar_path = random::tmp_path(10, Some(".tar"))?;
            let tar_file = File::create(&tar_path)?;
            let mut tar = Builder::new(tar_file);
            let src_dir = Path::new(src_dir_path);
            let src_dir_full_path = absolute_path(src_dir)?;
            for entry in WalkDir::new(src_dir_path).into_iter() {
                let entry = match entry {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(Error::new(
                            ErrorKind::Other,
                            format!("failed walk dir {} ({})", src_dir_path, e),
                        ));
                    }
                };

                let full_path = absolute_path(entry.path())?;
                // relative path from source directory
                // e.g., "text/a/b/c.txt" for absolute path "/tmp/text/a/b/c.txt"
                let rel_path = match full_path.strip_prefix(&src_dir_full_path) {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(Error::new(
                            ErrorKind::Other,
                            format!("failed strip_prefix on {:?} ({})", full_path, e),
                        ));
                    }
                };

                if is_dir(&entry) {
                    continue;
                }

                let file_name = rel_path.as_os_str().to_str().unwrap();
                info!("adding file {}", file_name);
                let mut f = File::open(&full_path)?;
                tar.append_file(&file_name, &mut f)?;
            }

            info!("wrote tar file {}", tar_path);
            pack_file(&tar_path, dst_path, Encoder::Gzip)?;
        }
    }

    let meta = fs::metadata(dst_path)?;
    let size = meta.len() as f64;
    info!(
        "packed directory with {} from '{}' to '{}' (new size {})",
        enc.id(),
        src_dir_path,
        dst_path,
        humanize::bytes(size)
    );
    Ok(())
}

/// Un-archives the file with compression and archival method
/// to the destination directory "dst_dir_path".
pub fn unpack_directory(
    src_archive_path: &str,
    dst_dir_path: &str,
    dec: DirDecoder,
) -> io::Result<()> {
    let meta = fs::metadata(src_archive_path)?;
    let size = meta.len() as f64;
    info!(
        "unpacking directory with {} from '{}' (original size {}) to '{}'",
        dec.id(),
        src_archive_path,
        humanize::bytes(size),
        dst_dir_path
    );
    fs::create_dir_all(dst_dir_path)?;
    let dst_dir_path = Path::new(dst_dir_path);

    match dec {
        DirDecoder::ZipZstd => {
            let zip_path = random::tmp_path(10, Some(".zip"))?;
            unpack_file(src_archive_path, &zip_path, Decoder::Zstd)?;

            let zip_file = File::open(&zip_path)?;
            let mut zip = match ZipArchive::new(zip_file) {
                Ok(v) => v,
                Err(e) => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("failed ZipArchive::new on {} ({})", zip_path, e),
                    ));
                }
            };
            info!("opened zip file {}", zip_path);

            for i in 0..zip.len() {
                let mut f = match zip.by_index(i) {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(Error::new(
                            ErrorKind::Other,
                            format!("failed zip.by_index ({})", e),
                        ));
                    }
                };
                let output_path = match f.enclosed_name() {
                    Some(p) => p.to_owned(),
                    None => continue,
                };
                let output_path = dst_dir_path.join(output_path);

                let is_dir = (*f.name()).ends_with('/');
                if is_dir {
                    info!("extracting directory {}", output_path.display());
                    fs::create_dir_all(&output_path)?;
                } else {
                    info!("extracting file {}", output_path.display());
                    if let Some(p) = output_path.parent() {
                        if !p.exists() {
                            fs::create_dir_all(&p)?;
                        }
                    }
                    let mut f2 = File::create(&output_path)?;
                    io::copy(&mut f, &mut f2)?;
                }

                fs::set_permissions(&output_path, PermissionsExt::from_mode(0o444))?;
            }
        }
        DirDecoder::TarZstd => {
            let tar_path = random::tmp_path(10, Some(".tar"))?;
            unpack_file(src_archive_path, &tar_path, Decoder::Zstd)?;

            let tar_file = File::open(&tar_path)?;
            let mut tar = Archive::new(tar_file);
            let entries = tar.entries()?;
            info!("opened tar file {}", tar_path);

            for file in entries {
                let mut f = file?;
                let output_path = f.path()?;
                let output_path = dst_dir_path.join(output_path);
                info!("extracting file {}", output_path.display());
                if let Some(p) = output_path.parent() {
                    if !p.exists() {
                        fs::create_dir_all(&p)?;
                    }
                }
                let mut f2 = File::create(&output_path)?;
                io::copy(&mut f, &mut f2)?;
                fs::set_permissions(&output_path, PermissionsExt::from_mode(0o444))?;
            }
        }
        DirDecoder::ZipGzip => {
            let zip_path = random::tmp_path(10, Some(".zip"))?;
            unpack_file(src_archive_path, &zip_path, Decoder::Gzip)?;

            let zip_file = File::open(&zip_path)?;
            let mut zip = match ZipArchive::new(zip_file) {
                Ok(v) => v,
                Err(e) => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("failed ZipArchive::new on {} ({})", zip_path, e),
                    ));
                }
            };
            info!("opened zip file {}", zip_path);

            for i in 0..zip.len() {
                let mut f = match zip.by_index(i) {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(Error::new(
                            ErrorKind::Other,
                            format!("failed zip.by_index ({})", e),
                        ));
                    }
                };
                let output_path = match f.enclosed_name() {
                    Some(p) => p.to_owned(),
                    None => continue,
                };
                let output_path = dst_dir_path.join(output_path);

                let is_dir = (*f.name()).ends_with('/');
                if is_dir {
                    info!("extracting directory {}", output_path.display());
                    fs::create_dir_all(&output_path)?;
                } else {
                    info!("extracting file {}", output_path.display());
                    if let Some(p) = output_path.parent() {
                        if !p.exists() {
                            fs::create_dir_all(&p)?;
                        }
                    }
                    let mut f2 = File::create(&output_path)?;
                    io::copy(&mut f, &mut f2)?;
                }

                fs::set_permissions(&output_path, PermissionsExt::from_mode(0o444))?;
            }
        }
        DirDecoder::TarGzip => {
            let tar_path = random::tmp_path(10, Some(".tar"))?;
            unpack_file(src_archive_path, &tar_path, Decoder::Gzip)?;

            let tar_file = File::open(&tar_path)?;
            let mut tar = Archive::new(tar_file);
            let entries = tar.entries()?;
            info!("opened tar file {}", tar_path);

            for file in entries {
                let mut f = file?;
                let output_path = f.path()?;
                let output_path = dst_dir_path.join(output_path);
                info!("extracting file {}", output_path.display());
                if let Some(p) = output_path.parent() {
                    if !p.exists() {
                        fs::create_dir_all(&p)?;
                    }
                }
                let mut f2 = File::create(&output_path)?;
                io::copy(&mut f, &mut f2)?;
                fs::set_permissions(&output_path, PermissionsExt::from_mode(0o444))?;
            }
        }
    }

    let size = match fs_extra::dir::get_size(dst_dir_path) {
        Ok(v) => v,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "failed get_size {} for directory {}",
                    e,
                    dst_dir_path.display()
                ),
            ));
        }
    };
    let size = size as f64;
    info!(
        "unpacked directory with {} from '{}' to '{}' (new size {})",
        dec.id(),
        src_archive_path,
        dst_dir_path.display(),
        humanize::bytes(size)
    );
    Ok(())
}

fn is_dir(entry: &DirEntry) -> bool {
    entry.file_type().is_dir()
}

fn absolute_path(path: impl AsRef<Path>) -> io::Result<PathBuf> {
    let p = path.as_ref();

    let ap = if p.is_absolute() {
        p.to_path_buf()
    } else {
        env::current_dir()?.join(p)
    }
    .clean();

    Ok(ap)
}

#[test]
fn test_pack_directory_zip_zstd() {
    let _ = env_logger::builder().is_test(true).try_init();

    let src_dir_path = env::temp_dir().join(random::string(10));
    fs::create_dir_all(&src_dir_path).unwrap();
    info!("created {}", src_dir_path.display());
    for _i in 0..10 {
        let p = src_dir_path.join(random::string(10));
        let mut f = File::create(&p).unwrap();
        f.write_all(random::string(1000).as_bytes()).unwrap();
    }
    info!("wrote to {}", src_dir_path.display());

    let zip_path = random::tmp_path(10, Some(".zip")).unwrap();
    pack_directory(
        src_dir_path.as_os_str().to_str().unwrap(),
        &zip_path,
        DirEncoder::ZipZstd(3),
    )
    .unwrap();
    let dst_dir_path2 = env::temp_dir().join(random::string(10));
    let dst_dir_path2 = dst_dir_path2.as_os_str().to_str().unwrap();
    unpack_directory(&zip_path, dst_dir_path2, DirDecoder::ZipZstd).unwrap();

    let tar_path = random::tmp_path(10, Some(".tar")).unwrap();
    pack_directory(
        src_dir_path.as_os_str().to_str().unwrap(),
        &tar_path,
        DirEncoder::TarZstd(3),
    )
    .unwrap();
    let dst_dir_path2 = env::temp_dir().join(random::string(10));
    let dst_dir_path2 = dst_dir_path2.as_os_str().to_str().unwrap();
    unpack_directory(&tar_path, dst_dir_path2, DirDecoder::TarZstd).unwrap();
}

#[test]
fn test_pack_directory_zip_gzip() {
    let _ = env_logger::builder().is_test(true).try_init();

    let src_dir_path = env::temp_dir().join(random::string(10));
    fs::create_dir_all(&src_dir_path).unwrap();
    info!("created {}", src_dir_path.display());
    for _i in 0..10 {
        let p = src_dir_path.join(random::string(10));
        let mut f = File::create(&p).unwrap();
        f.write_all(random::string(1000).as_bytes()).unwrap();
    }
    info!("wrote to {}", src_dir_path.display());

    let zip_path = random::tmp_path(10, Some(".zip")).unwrap();
    pack_directory(
        src_dir_path.as_os_str().to_str().unwrap(),
        &zip_path,
        DirEncoder::ZipZstd(3),
    )
    .unwrap();
    let dst_dir_path2 = env::temp_dir().join(random::string(10));
    let dst_dir_path2 = dst_dir_path2.as_os_str().to_str().unwrap();
    unpack_directory(&zip_path, dst_dir_path2, DirDecoder::ZipZstd).unwrap();

    let tar_path = random::tmp_path(10, Some(".tar")).unwrap();
    pack_directory(
        src_dir_path.as_os_str().to_str().unwrap(),
        &tar_path,
        DirEncoder::TarGzip,
    )
    .unwrap();
    let dst_dir_path2 = env::temp_dir().join(random::string(10));
    let dst_dir_path2 = dst_dir_path2.as_os_str().to_str().unwrap();
    unpack_directory(&tar_path, dst_dir_path2, DirDecoder::TarGzip).unwrap();
}
