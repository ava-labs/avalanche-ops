use std::{
    env, fmt,
    fs::{self, File},
    io::{self, copy, Cursor, Error, ErrorKind},
    os::unix::fs::PermissionsExt,
};

use reqwest::ClientBuilder;
use serde::{Deserialize, Serialize};
use tokio::time::{sleep, Duration};

/// Downloads the latest from the github release page.
pub async fn download_latest(
    arch: Option<Arch>,
    os: Option<Os>,
    target_file_path: &str,
) -> io::Result<()> {
    download(arch, os, None, target_file_path).await
}

pub const DEFAULT_TAG_NAME: &str = "latest";

/// Downloads the official binaries from the GitHub release page.
/// Returns the path to the binary path.
///
/// Leave "release_tag" none to download the latest.
///
/// Leave "arch" and "os" empty to auto-detect from its local system.
/// "arch" must be either "amd64" or "arm64".
/// "os" must be either "macos", "linux", or "win".
/// ref. https://github.com/ava-labs/avalanche-ops/releases
pub async fn download(
    arch: Option<Arch>,
    os: Option<Os>,
    release_tag: Option<String>,
    target_file_path: &str,
) -> io::Result<()> {
    // e.g., "v0.0.45"
    let tag_name = if let Some(v) = release_tag {
        v
    } else {
        log::info!("fetching the latest git tags");
        let mut release_info = ReleaseResponse::default();
        for round in 0..20 {
            let info = match crate::github::fetch_latest_release("ava-labs", "avalanche-ops").await
            {
                Ok(v) => v,
                Err(e) => {
                    log::warn!(
                        "failed fetch_latest_release {} -- retrying {}...",
                        e,
                        round + 1
                    );
                    sleep(Duration::from_secs((round + 1) * 5)).await;
                    continue;
                }
            };

            release_info = info;
            if release_info.tag_name.is_some() {
                break;
            }

            log::warn!("release_info.tag_name is None -- retrying {}...", round + 1);
            sleep(Duration::from_secs((round + 1) * 5)).await;
        }

        if release_info.tag_name.is_none() {
            log::warn!("release_info.tag_name not found -- defaults to {DEFAULT_TAG_NAME}");
            release_info.tag_name = Some(DEFAULT_TAG_NAME.to_string());
        }

        if release_info.prerelease {
            log::warn!(
                "latest release '{}' is prerelease, falling back to default tag name '{}'",
                release_info.tag_name.unwrap(),
                DEFAULT_TAG_NAME
            );
            DEFAULT_TAG_NAME.to_string()
        } else {
            release_info.tag_name.unwrap()
        }
    };

    // ref. https://github.com/ava-labs/avalanche-ops/releases
    log::info!(
        "detecting arch and platform for the release version tag {}",
        tag_name
    );
    let arch = {
        if arch.is_none() {
            match env::consts::ARCH {
                "x86_64" => String::from("x86_64"),
                "aarch64" => String::from("aarch64"),
                _ => String::from(""),
            }
        } else {
            let arch = arch.unwrap();
            arch.to_string()
        }
    };

    // TODO: handle Apple arm64 when the official binary is available
    // ref. https://github.com/ava-labs/avalanche-ops/releases
    let (file_name, fallback_file) = {
        if os.is_none() {
            if cfg!(target_os = "macos") {
                (format!("avalanche-config.{arch}-apple-darwin"), None)
            } else if cfg!(unix) {
                (format!("avalanche-config.{arch}-unknown-linux-gnu"), None)
            } else {
                (String::new(), None)
            }
        } else {
            let os = os.unwrap();
            match os {
                Os::MacOs => (format!("avalanche-config.{arch}-apple-darwin"), None),
                Os::Linux => (format!("avalanche-config.{arch}-unknown-linux-gnu"), None),
                Os::Ubuntu2004 => (
                    format!("avalanche-config.{arch}-ubuntu20.04-linux-gnu"),
                    Some(format!("avalanche-config.{arch}-unknown-linux-gnu")),
                ),
            }
        }
    };
    if file_name.is_empty() {
        return Err(Error::new(
            ErrorKind::Other,
            format!("unknown platform '{}'", env::consts::OS),
        ));
    }

    log::info!("downloading latest '{}'", file_name);
    let download_url = format!(
        "https://github.com/ava-labs/avalanche-ops/releases/download/{tag_name}/{file_name}",
    );
    let tmp_file_path = random_manager::tmp_path(10, None)?;
    match download_file(&download_url, &tmp_file_path).await {
        Ok(_) => {}
        Err(e) => {
            log::warn!("failed to download {:?}", e);
            if let Some(fallback) = fallback_file {
                let download_url = format!(
                    "https://github.com/ava-labs/avalanche-ops/releases/download/{tag_name}/{fallback}",
                );
                log::warn!("falling back to {download_url}");
                download_file(&download_url, &tmp_file_path).await?;
            } else {
                return Err(e);
            }
        }
    }

    {
        let f = File::open(&tmp_file_path)?;
        f.set_permissions(PermissionsExt::from_mode(0o777))?;
    }
    log::info!("copying {tmp_file_path} to {target_file_path}");
    fs::copy(&tmp_file_path, &target_file_path)?;
    fs::remove_file(&tmp_file_path)?;

    Ok(())
}

/// ref. https://github.com/ava-labs/avalanche-ops/releases
/// ref. https://api.github.com/repos/ava-labs/avalanche-ops/releases/latest
pub async fn fetch_latest_release(org: &str, repo: &str) -> io::Result<ReleaseResponse> {
    let ep = format!(
        "https://api.github.com/repos/{}/{}/releases/latest",
        org, repo
    );
    log::info!("fetching {}", ep);

    let cli = ClientBuilder::new()
        .user_agent(env!("CARGO_PKG_NAME"))
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(15))
        .connection_verbose(true)
        .build()
        .map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed ClientBuilder build {}", e),
            )
        })?;
    let resp =
        cli.get(&ep).send().await.map_err(|e| {
            Error::new(ErrorKind::Other, format!("failed ClientBuilder send {}", e))
        })?;
    let out = resp
        .bytes()
        .await
        .map_err(|e| Error::new(ErrorKind::Other, format!("failed ClientBuilder send {}", e)))?;
    let out: Vec<u8> = out.into();

    let resp: ReleaseResponse = match serde_json::from_slice(&out) {
        Ok(p) => p,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("failed to decode {}", e),
            ));
        }
    };
    Ok(resp)
}

/// ref. https://api.github.com/repos/ava-labs/avalanche-ops/releases/latest
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ReleaseResponse {
    /// Sometimes empty for github API consistency issue.
    pub tag_name: Option<String>,
    /// Sometimes empty for github API consistency issue.
    pub assets: Option<Vec<Asset>>,

    #[serde(default)]
    pub prerelease: bool,
}

impl Default for ReleaseResponse {
    fn default() -> Self {
        Self::default()
    }
}

impl ReleaseResponse {
    pub fn default() -> Self {
        Self {
            tag_name: None,
            assets: None,
            prerelease: false,
        }
    }
}

/// ref. https://api.github.com/repos/ava-labs/avalanche-ops/releases/latest
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Asset {
    pub name: String,
    pub browser_download_url: String,
}

/// Represents the release "arch".
#[derive(Eq, PartialEq, Clone)]
pub enum Arch {
    Amd64,
    Arm64,
}

/// ref. https://doc.rust-lang.org/std/string/trait.ToString.html
/// ref. https://doc.rust-lang.org/std/fmt/trait.Display.html
/// Use "Self.to_string()" to directly invoke this
impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Arch::Amd64 => write!(f, "amd64"),
            Arch::Arm64 => write!(f, "arm64"),
        }
    }
}

impl Arch {
    pub fn new(arch: &str) -> io::Result<Self> {
        match arch {
            "amd64" => Ok(Arch::Amd64),
            "arm64" => Ok(Arch::Arm64),
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("unknown arch {}", arch),
            )),
        }
    }
}

/// Represents the release "os".
#[derive(Eq, PartialEq, Clone)]
pub enum Os {
    MacOs,
    Linux,
    Ubuntu2004,
}

/// ref. https://doc.rust-lang.org/std/string/trait.ToString.html
/// ref. https://doc.rust-lang.org/std/fmt/trait.Display.html
/// Use "Self.to_string()" to directly invoke this
impl fmt::Display for Os {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Os::MacOs => write!(f, "macos"),
            Os::Linux => write!(f, "linux"),
            Os::Ubuntu2004 => write!(f, "ubuntu20.04"),
        }
    }
}

impl Os {
    pub fn new(os: &str) -> io::Result<Self> {
        match os {
            "macos" => Ok(Os::MacOs),
            "linux" => Ok(Os::Linux),
            "ubuntu20.04" => Ok(Os::Ubuntu2004),
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("unknown os {}", os),
            )),
        }
    }
}

/// Downloads a file to the "file_path".
pub async fn download_file(ep: &str, file_path: &str) -> io::Result<()> {
    log::info!("downloading the file via {}", ep);
    let resp = reqwest::get(ep)
        .await
        .map_err(|e| Error::new(ErrorKind::Other, format!("failed reqwest::get {}", e)))?;

    let mut content = Cursor::new(
        resp.bytes()
            .await
            .map_err(|e| Error::new(ErrorKind::Other, format!("failed bytes {}", e)))?,
    );

    let mut f = File::create(file_path)?;
    copy(&mut content, &mut f)?;

    Ok(())
}
