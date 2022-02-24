use std::{
    env, fmt,
    fs::{self, File},
    io::{self, BufReader, Cursor, Error, ErrorKind, Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use flate2::{
    bufread::{GzDecoder, GzEncoder},
    Compression,
};
use fs_extra;
use log::info;
use path_clean::PathClean;
use tar::{Archive, Builder};
use walkdir::{DirEntry, WalkDir};
use zip::{write::FileOptions, ZipArchive, ZipWriter};
use zstd;

use crate::{humanize, random};

#[derive(Eq, PartialEq, Clone)]
/// Represents the compression encoding algorithm.
pub enum Encoder {
    /// Encodes with "Zstandard" compression.
    Zstd(i32),
    /// Encodes with "Zstandard" compression and apply base58.
    ZstdBase58(i32),
    /// Encodes with "Gzip" compression.
    Gzip,
}

impl fmt::Display for Encoder {
    /// The last integer is the zstd compression level.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Encoder::Zstd(level) => write!(f, "zstd{}", level),
            Encoder::ZstdBase58(level) => {
                write!(f, "zstd-base58{}", level)
            }
            Encoder::Gzip => write!(f, "gzip"),
        }
    }
}

impl Encoder {
    pub fn id(&self) -> &str {
        match self {
            Encoder::Zstd(1) => "zstd1",
            Encoder::Zstd(2) => "zstd2",
            Encoder::Zstd(3) => "zstd3",
            Encoder::ZstdBase58(1) => "zstd1-base58",
            Encoder::ZstdBase58(2) => "zstd2-base58",
            Encoder::ZstdBase58(3) => "zstd3-base58",
            Encoder::Gzip => "gzip",
            _ => "unknown",
        }
    }
    pub fn new(id: &str) -> io::Result<Self> {
        match id {
            "zstd1" => Ok(Encoder::Zstd(1)),
            "zstd2" => Ok(Encoder::Zstd(2)),
            "zstd3" => Ok(Encoder::Zstd(3)),
            "zstd1-base58" => Ok(Encoder::ZstdBase58(1)),
            "zstd2-base58" => Ok(Encoder::ZstdBase58(2)),
            "zstd3-base58" => Ok(Encoder::ZstdBase58(3)),
            "gzip" => Ok(Encoder::Gzip),
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("unknown id {}", id),
                ));
            }
        }
    }
    pub fn ext(&self) -> &str {
        match self {
            Encoder::Zstd(_) => ".zstd",
            Encoder::ZstdBase58(_) => ".zstd.base58",
            Encoder::Gzip => ".gz",
        }
    }
}

#[derive(Clone)]
/// Represents the compression decoding algorithm.
pub enum Decoder {
    Zstd,
    ZstdBase58,
    Gzip,
}

impl fmt::Display for Decoder {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Decoder::Zstd => write!(f, "zstd"),
            Decoder::ZstdBase58 => write!(f, "zstd-base58"),
            Decoder::Gzip => write!(f, "gzip"),
        }
    }
}

impl Decoder {
    pub fn id(&self) -> &str {
        match self {
            Decoder::Zstd => "zstd",
            Decoder::ZstdBase58 => "zstd-base58",
            Decoder::Gzip => "gzip",
        }
    }
    pub fn new(id: &str) -> io::Result<Self> {
        match id {
            "zstd" => Ok(Decoder::Zstd),
            "zstd-base58" => Ok(Decoder::ZstdBase58),
            "gzip" => Ok(Decoder::Gzip),
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("unknown id {}", id),
                ));
            }
        }
    }
}

pub fn pack(d: &[u8], enc: Encoder) -> io::Result<Vec<u8>> {
    let size_before = d.len() as f64;
    info!(
        "packing (algorithm {}, current size {})",
        enc.to_string(),
        humanize::bytes(size_before),
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

    let size_after = packed.len() as f64;
    info!(
        "packed to {} (before {}, new size {})",
        enc.to_string(),
        humanize::bytes(size_before),
        humanize::bytes(size_after),
    );
    Ok(packed)
}

pub fn unpack(d: &[u8], dec: Decoder) -> io::Result<Vec<u8>> {
    let size_before = d.len() as f64;
    info!(
        "unpacking (algorithm {}, current size {})",
        dec.to_string(),
        humanize::bytes(size_before),
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

    let size_after = unpacked.len() as f64;
    info!(
        "unpacked to {} (before {}, new size {})",
        dec.to_string(),
        humanize::bytes(size_before),
        humanize::bytes(size_after),
    );
    Ok(unpacked)
}

/// Compresses the contents in "src_path" using compression algorithms
/// and saves it to "dst_path". Note that even if "dst_path" already exists,
/// it truncates (overwrites).
pub fn pack_file(src_path: &str, dst_path: &str, enc: Encoder) -> io::Result<()> {
    let meta = fs::metadata(src_path)?;
    let size_before = meta.len() as f64;
    info!(
        "packing file '{}' to '{}' (algorithm {}, current size {})",
        src_path,
        dst_path,
        enc.to_string(),
        humanize::bytes(size_before),
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
    let size_after = meta.len() as f64;
    info!(
        "packed file '{}' to '{}' (algorithm {}, before {}, new size {})",
        src_path,
        dst_path,
        enc.to_string(),
        humanize::bytes(size_before),
        humanize::bytes(size_after),
    );
    Ok(())
}

/// Decompresses the contents in "src_path" using compression algorithms
/// and saves it to "dst_path". Note that even if "dst_path" already exists,
/// it truncates (overwrites).
pub fn unpack_file(src_path: &str, dst_path: &str, dec: Decoder) -> io::Result<()> {
    let meta = fs::metadata(src_path)?;
    let size_before = meta.len() as f64;
    info!(
        "unpacking file '{}' to '{}' (algorithm {}, current size {})",
        src_path,
        dst_path,
        dec.to_string(),
        humanize::bytes(size_before),
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
    let size_after = meta.len() as f64;
    info!(
        "unpacked file '{}' to '{}' (algorithm {}, before {}, new size {})",
        src_path,
        dst_path,
        dec.to_string(),
        humanize::bytes(size_before),
        humanize::bytes(size_after),
    );
    Ok(())
}

#[derive(Clone)]
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

impl fmt::Display for DirEncoder {
    /// The last integer is the zstd compression level.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DirEncoder::ZipZstd(level) => write!(f, "zip-zstd{}", level),
            DirEncoder::TarZstd(level) => write!(f, "tar-zstd{}", level),
            DirEncoder::ZipGzip => write!(f, "zip-gzip"),
            DirEncoder::TarGzip => write!(f, "tar-gzip"),
        }
    }
}

impl DirEncoder {
    pub fn id(&self) -> &str {
        match self {
            DirEncoder::ZipZstd(1) => "zip-zstd1",
            DirEncoder::ZipZstd(2) => "zip-zstd2",
            DirEncoder::ZipZstd(3) => "zip-zstd3",
            DirEncoder::TarZstd(1) => "tar-zstd1",
            DirEncoder::TarZstd(2) => "tar-zstd2",
            DirEncoder::TarZstd(3) => "tar-zstd3",
            DirEncoder::ZipGzip => "zip-gzip",
            DirEncoder::TarGzip => "tar-gzip",
            _ => "unknown",
        }
    }
    pub fn new(id: &str) -> io::Result<Self> {
        match id {
            "zip-zstd1" => Ok(DirEncoder::ZipZstd(1)),
            "zip-zstd2" => Ok(DirEncoder::ZipZstd(2)),
            "zip-zstd3" => Ok(DirEncoder::ZipZstd(3)),
            "tar-zstd1" => Ok(DirEncoder::TarZstd(1)),
            "tar-zstd2" => Ok(DirEncoder::TarZstd(2)),
            "tar-zstd3" => Ok(DirEncoder::TarZstd(3)),
            "zip-gzip" => Ok(DirEncoder::ZipGzip),
            "tar-gzip" => Ok(DirEncoder::TarGzip),
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("unknown id {}", id),
                ));
            }
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

#[derive(Clone)]
/// Represents the compression decoding algorithm for directory.
pub enum DirDecoder {
    ZipZstd,
    TarZstd,
    ZipGzip,
    TarGzip,
}

impl fmt::Display for DirDecoder {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DirDecoder::ZipZstd => write!(f, "zip-zstd"),
            DirDecoder::TarZstd => write!(f, "tar-zstd"),
            DirDecoder::ZipGzip => write!(f, "zip-gzip"),
            DirDecoder::TarGzip => write!(f, "tar-gzip"),
        }
    }
}

impl DirDecoder {
    pub fn id(&self) -> &str {
        match self {
            DirDecoder::ZipZstd => "zip-zstd",
            DirDecoder::TarZstd => "tar-zstd",
            DirDecoder::ZipGzip => "zip-gzip",
            DirDecoder::TarGzip => "tar-gzip",
        }
    }
    pub fn new(id: &str) -> io::Result<Self> {
        match id {
            "zip-zstd" => Ok(DirDecoder::ZipZstd),
            "tar-zstd" => Ok(DirDecoder::TarZstd),
            "zip-gzip" => Ok(DirDecoder::ZipGzip),
            "tar-gzip" => Ok(DirDecoder::TarGzip),
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("unknown id {}", id),
                ));
            }
        }
    }
    pub fn new_from_ext(ext: &str) -> io::Result<Self> {
        if ext.ends_with(DirDecoder::ZipZstd.ext()) {
            Ok(DirDecoder::ZipZstd)
        } else if ext.ends_with(DirDecoder::TarZstd.ext()) {
            Ok(DirDecoder::TarZstd)
        } else if ext.ends_with(DirDecoder::ZipGzip.ext()) {
            Ok(DirDecoder::ZipGzip)
        } else if ext.ends_with(DirDecoder::TarGzip.ext()) {
            Ok(DirDecoder::TarGzip)
        } else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("unknown ext {}", ext),
            ));
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
    let size_before = size as f64;
    info!(
        "packing directory from '{}' to '{}' (algorithm {}, current size {})",
        src_dir_path,
        dst_path,
        enc.to_string(),
        humanize::bytes(size_before),
    );

    let archive_path = random::tmp_path(10, None)?;
    let archive_file = File::create(&archive_path)?;
    match enc {
        DirEncoder::ZipZstd(lvl) => {
            let mut zip = ZipWriter::new(archive_file);

            let mut buffer = Vec::new();
            let src_dir = Path::new(src_dir_path);
            let src_dir_full_path = absolute_path(src_dir)?;

            let options = FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored)
                .unix_permissions(0o755);
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
            pack_file(&archive_path, dst_path, Encoder::Zstd(lvl))?;
        }
        DirEncoder::TarZstd(lvl) => {
            let mut tar = Builder::new(archive_file);
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
            pack_file(&archive_path, dst_path, Encoder::Zstd(lvl))?;
        }
        DirEncoder::ZipGzip => {
            let mut zip = ZipWriter::new(archive_file);

            let mut buffer = Vec::new();
            let src_dir = Path::new(src_dir_path);
            let src_dir_full_path = absolute_path(src_dir)?;

            let options = FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored)
                .unix_permissions(0o755);
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
            pack_file(&archive_path, dst_path, Encoder::Gzip)?;
        }
        DirEncoder::TarGzip => {
            // e.g.,
            // tar -czvf db.tar.gz mainnet/
            // -c to create a new archive
            // -z to enable "--gzip" mode
            // -v to enable verbose mode
            // -f to specify the file
            let mut tar = Builder::new(archive_file);
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
            pack_file(&archive_path, dst_path, Encoder::Gzip)?;
        }
    }

    let meta = fs::metadata(dst_path)?;
    let size_after = meta.len() as f64;
    info!(
        "packed directory from '{}' to '{}' (algorithm {}, before {}, new size {})",
        src_dir_path,
        dst_path,
        enc.to_string(),
        humanize::bytes(size_before),
        humanize::bytes(size_after),
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
    let size_before = meta.len() as f64;
    info!(
        "unpacking directory from '{}' to '{}' (algorithm {}, current size {})",
        src_archive_path,
        dst_dir_path,
        dec.to_string(),
        humanize::bytes(size_before),
    );
    fs::create_dir_all(dst_dir_path)?;
    let _dst_dir_path = Path::new(dst_dir_path);

    let unpacked_path = random::tmp_path(10, None)?;
    match dec {
        DirDecoder::ZipZstd => {
            unpack_file(src_archive_path, &unpacked_path, Decoder::Zstd)?;

            let zip_file = File::open(&unpacked_path)?;
            let mut zip = match ZipArchive::new(zip_file) {
                Ok(v) => v,
                Err(e) => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("failed ZipArchive::new on {} ({})", unpacked_path, e),
                    ));
                }
            };
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
                let output_path = _dst_dir_path.join(output_path);

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
            unpack_file(src_archive_path, &unpacked_path, Decoder::Zstd)?;

            let tar_file = File::open(&unpacked_path)?;
            let mut tar = Archive::new(tar_file);
            let entries = tar.entries()?;
            for file in entries {
                let mut f = file?;
                let output_path = f.path()?;
                let output_path = _dst_dir_path.join(output_path);
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
            unpack_file(src_archive_path, &unpacked_path, Decoder::Gzip)?;

            let zip_file = File::open(&unpacked_path)?;
            let mut zip = match ZipArchive::new(zip_file) {
                Ok(v) => v,
                Err(e) => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("failed ZipArchive::new on {} ({})", unpacked_path, e),
                    ));
                }
            };
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
                let output_path = _dst_dir_path.join(output_path);

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
            unpack_file(src_archive_path, &unpacked_path, Decoder::Gzip)?;

            let tar_file = File::open(&unpacked_path)?;
            let mut tar = Archive::new(tar_file);
            let entries = tar.entries()?;
            for file in entries {
                let mut f = file?;
                let output_path = f.path()?;
                let output_path = _dst_dir_path.join(output_path);
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

    let size = match fs_extra::dir::get_size(_dst_dir_path) {
        Ok(v) => v,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "failed get_size {} for directory {}",
                    e,
                    _dst_dir_path.display()
                ),
            ));
        }
    };
    let size_after = size as f64;
    info!(
        "unpacked directory from '{}' to '{}' (algorithm {}, before {}, new size {})",
        src_archive_path,
        dst_dir_path,
        dec.to_string(),
        humanize::bytes(size_before),
        humanize::bytes(size_after),
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
fn test_pack_unpack() {
    let _ = env_logger::builder().is_test(true).try_init();

    let contents = random::string(1024 * 10);

    let encs = vec![
        "zstd1",
        "zstd2",
        "zstd3",
        "zstd1-base58",
        "zstd2-base58",
        "zstd3-base58",
        "gzip",
    ];
    let decs = vec![
        "zstd",
        "zstd",
        "zstd",
        "zstd-base58",
        "zstd-base58",
        "zstd-base58",
        "gzip",
    ];
    for (i, _) in encs.iter().enumerate() {
        let packed = pack(&contents.as_bytes(), Encoder::new(encs[i]).unwrap()).unwrap();

        // compressed should be smaller
        if !encs[i].contains("base58") {
            assert!(contents.len() > packed.len());
        }

        let unpacked = unpack(&packed, Decoder::new(decs[i]).unwrap()).unwrap();

        // decompressed should be same as original
        assert_eq!(contents.as_bytes(), unpacked);
    }

    let mut orig_file = tempfile::NamedTempFile::new().unwrap();
    orig_file.write_all(contents.as_bytes()).unwrap();
    let orig_path = orig_file.path().to_str().unwrap();
    let orig_meta = fs::metadata(orig_path).unwrap();
    for (i, _) in encs.iter().enumerate() {
        let packed = tempfile::NamedTempFile::new().unwrap();
        let packed_path = packed.path().to_str().unwrap();
        pack_file(&orig_path, packed_path, Encoder::new(encs[i]).unwrap()).unwrap();

        // compressed file should be smaller
        if !encs[i].contains("base58") {
            let meta_packed = fs::metadata(packed_path).unwrap();
            assert!(orig_meta.len() > meta_packed.len());
        }

        let unpacked = tempfile::NamedTempFile::new().unwrap();
        let unpacked_path = unpacked.path().to_str().unwrap();
        unpack_file(packed_path, unpacked_path, Decoder::new(decs[i]).unwrap()).unwrap();

        // decompressed file should be same as original
        let contents_unpacked = fs::read(unpacked_path).unwrap();
        assert_eq!(contents.as_bytes(), contents_unpacked);
    }

    let src_dir_path = env::temp_dir().join(random::string(10));
    fs::create_dir_all(&src_dir_path).unwrap();
    let _src_dir_path = src_dir_path.to_str().unwrap();
    for _i in 0..20 {
        let p = src_dir_path.join(random::string(10));
        let mut f = File::create(&p).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
    }
    info!("created {}", src_dir_path.display());
    let src_dir_size = fs_extra::dir::get_size(src_dir_path.clone()).unwrap();

    let encs = vec![
        "zip-zstd1",
        "zip-zstd2",
        "zip-zstd3",
        "tar-zstd1",
        "tar-zstd2",
        "tar-zstd3",
        "zip-gzip",
        "tar-gzip",
    ];
    let decs = vec![
        "zip-zstd", // decoder has no zstd level
        "zip-zstd", // decoder has no zstd level
        "zip-zstd", // decoder has no zstd level
        "tar-zstd", // decoder has no zstd level
        "tar-zstd", // decoder has no zstd level
        "tar-zstd", // decoder has no zstd level
        "zip-gzip", // gzip has no level
        "tar-gzip", // gzip has no level
    ];
    for (i, _) in encs.iter().enumerate() {
        let packed = tempfile::NamedTempFile::new().unwrap();
        let packed_path = packed.path().to_str().unwrap();
        pack_directory(
            _src_dir_path,
            packed_path,
            DirEncoder::new(encs[i]).unwrap(),
        )
        .unwrap();

        // archived/compressed file should be smaller
        let meta_packed = fs::metadata(packed_path).unwrap();
        assert!(src_dir_size > meta_packed.len());

        let unpacked_path = env::temp_dir().join(random::string(10));
        let unpacked_path = unpacked_path.as_os_str().to_str().unwrap();
        unpack_directory(
            packed_path,
            unpacked_path,
            DirDecoder::new(decs[i]).unwrap(),
        )
        .unwrap();
        fs::remove_dir_all(unpacked_path).unwrap();
    }
    fs::remove_dir_all(_src_dir_path).unwrap();
}
