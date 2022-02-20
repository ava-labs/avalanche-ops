use std::{
    env,
    fs::{self, File},
    io::{self, Cursor, Error, ErrorKind, Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use fs_extra::dir::get_size;
use log::info;
use path_clean::PathClean;
use tar::{Archive, Builder};
use walkdir::{DirEntry, WalkDir};
use zip::{write::FileOptions, ZipArchive, ZipWriter};
use zstd::stream;

use crate::{humanize, random};

pub fn to_zstd(d: &[u8], level: Option<i32>) -> io::Result<Vec<u8>> {
    let lvl = level.unwrap_or(3);

    let size = d.len() as f64;
    info!(
        "compressing to zstd (current size {})",
        humanize::bytes(size),
    );

    let compressed = stream::encode_all(Cursor::new(d), lvl)?;
    let size = compressed.len() as f64;
    info!("compressed to zstd (new size {})", humanize::bytes(size),);

    Ok(compressed)
}

pub fn from_zstd(d: &[u8]) -> io::Result<Vec<u8>> {
    let size = d.len() as f64;
    info!(
        "decompressing zstd (current size {})",
        humanize::bytes(size),
    );

    let decompressed = stream::decode_all(Cursor::new(d))?;
    let size = decompressed.len() as f64;
    info!("decompressed zstd (new size {})", humanize::bytes(size),);

    Ok(decompressed)
}

pub fn to_zstd_base58(d: &[u8], level: Option<i32>) -> io::Result<String> {
    let compressed = to_zstd(d, level)?;
    Ok(bs58::encode(compressed).into_string())
}

pub fn from_zstd_base58(d: String) -> io::Result<Vec<u8>> {
    let d_decoded = match bs58::decode(d).into_vec() {
        Ok(v) => v,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("failed bs58::decode {}", e),
            ));
        }
    };
    from_zstd(&d_decoded)
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
        humanize::bytes(size),
    );

    let d = fs::read(src_path)?;
    let compressed = stream::encode_all(Cursor::new(&d[..]), lvl)?;
    let mut f = File::create(dst_path)?;
    f.write_all(&compressed[..])?;

    let meta = fs::metadata(dst_path)?;
    let size = meta.len() as f64;
    info!(
        "compressed '{}' to '{}' (new size {})",
        src_path,
        dst_path,
        humanize::bytes(size),
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
        humanize::bytes(size),
    );

    let d = fs::read(src_path)?;
    let decompressed = stream::decode_all(Cursor::new(&d[..]))?;
    let mut f = File::create(dst_path)?;
    f.write_all(&decompressed[..])?;

    let meta = fs::metadata(dst_path)?;
    let size = meta.len() as f64;
    info!(
        "decompressed '{}' to '{}' (new size {})",
        src_path,
        dst_path,
        humanize::bytes(size),
    );

    Ok(())
}

#[test]
fn test_compress() {
    let _ = env_logger::builder().is_test(true).try_init();

    let contents = random::string(10);
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

/// Archives the source directory "src_dir_path" with zip and zstd compression
/// and saves to "dst_path". If "dst_path" exists, it overwrites.
pub fn to_zip_zstd(src_dir_path: &str, dst_path: &str, level: Option<i32>) -> io::Result<()> {
    let size = match get_size(src_dir_path) {
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
        "start to_zip_zstd directory '{}' (original size {}) to '{}'",
        src_dir_path,
        humanize::bytes(size),
        dst_path
    );

    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o755);
    let zip_path = random::tmp_path(10)?;
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
    to_zstd_file(&zip_path, dst_path, level)?;

    let meta = fs::metadata(dst_path)?;
    let size = meta.len() as f64;
    info!(
        "done to_zip_zstd '{}' to '{}' (final zipped, compressed size {})",
        src_dir_path,
        dst_path,
        humanize::bytes(size)
    );
    Ok(())
}

/// Archives the source directory "src_dir_path" with tar and zstd compression
/// and saves to "dst_path". If "dst_path" exists, it overwrites.
pub fn to_tar_zstd(src_dir_path: &str, dst_path: &str, level: Option<i32>) -> io::Result<()> {
    let size = match get_size(src_dir_path) {
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
        "start to_tar_zstd directory '{}' (original size {}) to '{}'",
        src_dir_path,
        humanize::bytes(size),
        dst_path
    );

    let tar_path = random::tmp_path(10)?;
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
    to_zstd_file(&tar_path, dst_path, level)?;

    let meta = fs::metadata(dst_path)?;
    let size = meta.len() as f64;
    info!(
        "done to_tar_zstd '{}' to '{}' (final tar-ed, compressed size {})",
        src_dir_path,
        dst_path,
        humanize::bytes(size)
    );
    Ok(())
}

/// Un-archives the zip file with "zstd" and unpack them to the destination
/// directory "dst_dir_path".
pub fn from_zip_zstd(src_archive_path: &str, dst_dir_path: &str) -> io::Result<()> {
    let meta = fs::metadata(src_archive_path)?;
    let size = meta.len() as f64;
    info!(
        "start from_zip_zstd archive '{}' (original size {}) to '{}'",
        src_archive_path,
        humanize::bytes(size),
        dst_dir_path
    );
    fs::create_dir_all(dst_dir_path)?;
    let dst_dir_path = Path::new(dst_dir_path);

    let zip_path = random::tmp_path(10)?;
    from_zstd_file(src_archive_path, &zip_path)?;

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

    let size = match get_size(dst_dir_path) {
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
        "done from_zip_zstd '{}' to '{}' (final decompressed, unzipped size {})",
        src_archive_path,
        dst_dir_path.display(),
        humanize::bytes(size)
    );
    Ok(())
}

/// Un-archives the tar file with "zstd" and unpack them to the destination
/// directory "dst_dir_path".
pub fn from_tar_zstd(src_archive_path: &str, dst_dir_path: &str) -> io::Result<()> {
    let meta = fs::metadata(src_archive_path)?;
    let size = meta.len() as f64;
    info!(
        "start from_tar_zstd archive '{}' (original size {}) to '{}'",
        src_archive_path,
        humanize::bytes(size),
        dst_dir_path
    );
    fs::create_dir_all(dst_dir_path)?;
    let dst_dir_path = Path::new(dst_dir_path);

    let tar_path = random::tmp_path(10)?;
    from_zstd_file(src_archive_path, &tar_path)?;

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

    let size = match get_size(dst_dir_path) {
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
        "done from_tar_zstd '{}' to '{}' (final decompressed, un-tar-ed size {})",
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
fn test_archive() {
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

    let zip_path = random::tmp_path(10).unwrap();
    to_zip_zstd(src_dir_path.as_os_str().to_str().unwrap(), &zip_path, None).unwrap();
    let dst_dir_path2 = env::temp_dir().join(random::string(10));
    let dst_dir_path2 = dst_dir_path2.as_os_str().to_str().unwrap();
    from_zip_zstd(&zip_path, dst_dir_path2).unwrap();

    let tar_path = random::tmp_path(10).unwrap();
    to_tar_zstd(src_dir_path.as_os_str().to_str().unwrap(), &tar_path, None).unwrap();
    let dst_dir_path2 = env::temp_dir().join(random::string(10));
    let dst_dir_path2 = dst_dir_path2.as_os_str().to_str().unwrap();
    from_tar_zstd(&tar_path, dst_dir_path2).unwrap();
}
