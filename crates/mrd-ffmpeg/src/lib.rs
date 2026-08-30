use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
};
use thiserror::Error;

const WINDOWS_RELEASE_ESSENTIALS_ARCHIVE_URL: &str =
    "https://www.gyan.dev/ffmpeg/builds/ffmpeg-release-essentials.zip";
const WINDOWS_RELEASE_ESSENTIALS_SHA256_URL: &str =
    "https://www.gyan.dev/ffmpeg/builds/ffmpeg-release-essentials.zip.sha256";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfmpegPlatform {
    Windows,
    Macos,
    Linux,
    Unknown,
}

impl FfmpegPlatform {
    pub fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::Macos
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else {
            Self::Unknown
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FfmpegDownloadSettings {
    #[serde(default)]
    pub archive_url: String,
    #[serde(default)]
    pub sha256_url: Option<String>,
    #[serde(default)]
    pub require_sha256: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FfmpegSettings {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_channel")]
    pub channel: String,
    #[serde(default)]
    pub install_dir: Option<PathBuf>,
    #[serde(default)]
    pub ffmpeg_path: Option<PathBuf>,
    #[serde(default)]
    pub ffprobe_path: Option<PathBuf>,
    #[serde(default = "default_download_settings")]
    pub download: FfmpegDownloadSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FfmpegProbeResult {
    pub available: bool,
    pub ffmpeg_path: Option<PathBuf>,
    pub ffprobe_path: Option<PathBuf>,
    pub ffmpeg_version: Option<String>,
    pub ffprobe_version: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FfmpegInstallResult {
    pub install_dir: PathBuf,
    pub probe: FfmpegProbeResult,
    pub archive_sha256: Option<String>,
}

#[derive(Debug, Error)]
pub enum FfmpegError {
    #[error("FFmpeg optional tooling is disabled")]
    Disabled,
    #[error("managed FFmpeg download is not configured for this platform")]
    DownloadNotConfigured,
    #[error("FFmpeg install directory is not configured")]
    InstallDirMissing,
    #[error("FFmpeg checksum is required but no SHA256 source was configured")]
    ChecksumMissing,
    #[error("invalid SHA256 metadata")]
    InvalidSha256,
    #[error("FFmpeg archive checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },
    #[error("FFmpeg network request failed: {0}")]
    Request(String),
    #[error("FFmpeg file operation failed for {path}: {message}")]
    File { path: PathBuf, message: String },
    #[error("FFmpeg archive extraction failed: {0}")]
    Archive(String),
    #[error("FFmpeg archive did not contain {0}")]
    ExecutableMissing(&'static str),
    #[error("installed FFmpeg probe failed: {0}")]
    Probe(String),
}

impl FfmpegSettings {
    pub fn golden_for_platform(platform: FfmpegPlatform) -> Self {
        match platform {
            FfmpegPlatform::Windows => Self {
                enabled: true,
                channel: default_channel(),
                install_dir: Some(default_managed_install_dir_for_channel(&default_channel())),
                ffmpeg_path: None,
                ffprobe_path: None,
                download: FfmpegDownloadSettings {
                    archive_url: WINDOWS_RELEASE_ESSENTIALS_ARCHIVE_URL.to_string(),
                    sha256_url: Some(WINDOWS_RELEASE_ESSENTIALS_SHA256_URL.to_string()),
                    require_sha256: true,
                },
            },
            _ => Self {
                enabled: true,
                channel: "system".to_string(),
                install_dir: None,
                ffmpeg_path: None,
                ffprobe_path: None,
                download: FfmpegDownloadSettings {
                    archive_url: String::new(),
                    sha256_url: None,
                    require_sha256: false,
                },
            },
        }
    }
}

impl Default for FfmpegSettings {
    fn default() -> Self {
        golden_settings()
    }
}

pub fn golden_settings() -> FfmpegSettings {
    FfmpegSettings::golden_for_platform(FfmpegPlatform::current())
}

pub fn probe_ffmpeg(settings: &FfmpegSettings) -> FfmpegProbeResult {
    if !settings.enabled {
        return unavailable("FFmpeg optional tooling is disabled in settings.");
    }

    let ffmpeg = resolve_tool(
        "ffmpeg",
        settings.ffmpeg_path.as_deref(),
        settings.install_dir.as_deref(),
    );
    let ffprobe = resolve_tool(
        "ffprobe",
        settings.ffprobe_path.as_deref(),
        settings.install_dir.as_deref(),
    );

    let Some(ffmpeg_path) = ffmpeg else {
        return unavailable("ffmpeg executable was not found in configured paths or PATH.");
    };
    let Some(ffprobe_path) = ffprobe else {
        return unavailable("ffprobe executable was not found in configured paths or PATH.");
    };

    let ffmpeg_version = match probe_tool_version(&ffmpeg_path) {
        Ok(version) => version,
        Err(error) => return unavailable(format!("ffmpeg probe failed: {error}")),
    };
    let ffprobe_version = match probe_tool_version(&ffprobe_path) {
        Ok(version) => version,
        Err(error) => return unavailable(format!("ffprobe probe failed: {error}")),
    };

    FfmpegProbeResult {
        available: true,
        ffmpeg_path: Some(ffmpeg_path),
        ffprobe_path: Some(ffprobe_path),
        ffmpeg_version: Some(ffmpeg_version),
        ffprobe_version: Some(ffprobe_version),
        reason: None,
    }
}

pub async fn download_ffmpeg(
    settings: &FfmpegSettings,
) -> Result<FfmpegInstallResult, FfmpegError> {
    if !settings.enabled {
        return Err(FfmpegError::Disabled);
    }
    if settings.download.archive_url.trim().is_empty() {
        return Err(FfmpegError::DownloadNotConfigured);
    }
    let install_dir = settings
        .install_dir
        .clone()
        .ok_or(FfmpegError::InstallDirMissing)?;

    let expected_sha256 = if settings.download.require_sha256 {
        let sha256_url = settings
            .download
            .sha256_url
            .as_deref()
            .ok_or(FfmpegError::ChecksumMissing)?;
        let body = reqwest::get(sha256_url)
            .await
            .map_err(|error| FfmpegError::Request(error.to_string()))?
            .error_for_status()
            .map_err(|error| FfmpegError::Request(error.to_string()))?
            .text()
            .await
            .map_err(|error| FfmpegError::Request(error.to_string()))?;
        Some(parse_sha256(&body)?)
    } else {
        None
    };

    let archive_bytes = reqwest::get(&settings.download.archive_url)
        .await
        .map_err(|error| FfmpegError::Request(error.to_string()))?
        .error_for_status()
        .map_err(|error| FfmpegError::Request(error.to_string()))?
        .bytes()
        .await
        .map_err(|error| FfmpegError::Request(error.to_string()))?;
    let archive_path = unique_temp_path("mrd-ffmpeg-download", "zip");
    fs::write(&archive_path, &archive_bytes).map_err(|error| FfmpegError::File {
        path: archive_path.clone(),
        message: error.to_string(),
    })?;

    let result = install_ffmpeg_archive(&archive_path, &install_dir, expected_sha256.as_deref());
    let _ = fs::remove_file(&archive_path);
    result
}

pub fn install_ffmpeg_archive(
    archive_path: &Path,
    install_dir: &Path,
    expected_sha256: Option<&str>,
) -> Result<FfmpegInstallResult, FfmpegError> {
    let archive_sha256 = if let Some(expected) = expected_sha256 {
        verify_sha256(archive_path, expected)?;
        Some(expected.to_ascii_lowercase())
    } else {
        None
    };

    let parent = install_dir
        .parent()
        .ok_or_else(|| FfmpegError::File {
            path: install_dir.to_path_buf(),
            message: "install directory has no parent".to_string(),
        })?
        .to_path_buf();
    fs::create_dir_all(&parent).map_err(|error| FfmpegError::File {
        path: parent.clone(),
        message: error.to_string(),
    })?;
    let staging_dir = parent.join(format!(
        ".{}-tmp-{}",
        install_dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("ffmpeg"),
        now_nanos()
    ));
    fs::create_dir_all(&staging_dir).map_err(|error| FfmpegError::File {
        path: staging_dir.clone(),
        message: error.to_string(),
    })?;

    if let Err(error) = extract_zip_archive(archive_path, &staging_dir)
        .and_then(|_| promote_extracted_ffmpeg(&staging_dir, install_dir))
    {
        let _ = fs::remove_dir_all(&staging_dir);
        return Err(error);
    }

    let settings = FfmpegSettings {
        install_dir: Some(install_dir.to_path_buf()),
        ..FfmpegSettings::golden_for_platform(FfmpegPlatform::current())
    };
    let probe = probe_ffmpeg(&settings);
    if !probe.available {
        return Err(FfmpegError::Probe(
            probe
                .reason
                .clone()
                .unwrap_or_else(|| "installed tools were unavailable".to_string()),
        ));
    }

    Ok(FfmpegInstallResult {
        install_dir: install_dir.to_path_buf(),
        probe,
        archive_sha256,
    })
}

pub fn parse_sha256(raw: &str) -> Result<String, FfmpegError> {
    raw.split_whitespace()
        .find(|token| token.len() == 64 && token.chars().all(|ch| ch.is_ascii_hexdigit()))
        .map(|token| token.to_ascii_lowercase())
        .ok_or(FfmpegError::InvalidSha256)
}

pub fn verify_sha256(path: &Path, expected: &str) -> Result<(), FfmpegError> {
    let expected = parse_sha256(expected)?;
    let mut file = fs::File::open(path).map_err(|error| FfmpegError::File {
        path: path.to_path_buf(),
        message: error.to_string(),
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| FfmpegError::File {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual = format!("{:x}", hasher.finalize());
    if actual == expected {
        Ok(())
    } else {
        Err(FfmpegError::ChecksumMismatch { expected, actual })
    }
}

pub fn default_managed_install_dir_for_channel(channel: &str) -> PathBuf {
    if let Ok(appdata) = std::env::var("APPDATA") {
        return PathBuf::from(appdata)
            .join("mini-remote-desktop")
            .join("tools")
            .join("ffmpeg")
            .join(channel);
    }

    std::env::temp_dir()
        .join("mini-remote-desktop")
        .join("tools")
        .join("ffmpeg")
        .join(channel)
}

fn default_enabled() -> bool {
    true
}

fn default_channel() -> String {
    "release-essentials".to_string()
}

fn default_download_settings() -> FfmpegDownloadSettings {
    FfmpegSettings::golden_for_platform(FfmpegPlatform::current()).download
}

fn extract_zip_archive(archive_path: &Path, destination: &Path) -> Result<(), FfmpegError> {
    let file = fs::File::open(archive_path).map_err(|error| FfmpegError::File {
        path: archive_path.to_path_buf(),
        message: error.to_string(),
    })?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|error| FfmpegError::Archive(error.to_string()))?;

    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| FfmpegError::Archive(error.to_string()))?;
        let Some(enclosed_name) = entry.enclosed_name() else {
            continue;
        };
        let output_path = destination.join(enclosed_name);
        if entry.is_dir() {
            fs::create_dir_all(&output_path).map_err(|error| FfmpegError::File {
                path: output_path.clone(),
                message: error.to_string(),
            })?;
            continue;
        }
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent).map_err(|error| FfmpegError::File {
                path: parent.to_path_buf(),
                message: error.to_string(),
            })?;
        }
        let mut output = fs::File::create(&output_path).map_err(|error| FfmpegError::File {
            path: output_path.clone(),
            message: error.to_string(),
        })?;
        std::io::copy(&mut entry, &mut output).map_err(|error| FfmpegError::File {
            path: output_path.clone(),
            message: error.to_string(),
        })?;
        output.flush().map_err(|error| FfmpegError::File {
            path: output_path.clone(),
            message: error.to_string(),
        })?;
        #[cfg(unix)]
        if let Some(mode) = entry.unix_mode() {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&output_path, fs::Permissions::from_mode(mode)).map_err(
                |error| FfmpegError::File {
                    path: output_path.clone(),
                    message: error.to_string(),
                },
            )?;
        }
    }
    Ok(())
}

fn promote_extracted_ffmpeg(staging_dir: &Path, install_dir: &Path) -> Result<(), FfmpegError> {
    let ffmpeg = find_tool_recursive(staging_dir, "ffmpeg")
        .ok_or(FfmpegError::ExecutableMissing("ffmpeg"))?;
    let _ffprobe = find_tool_recursive(staging_dir, "ffprobe")
        .ok_or(FfmpegError::ExecutableMissing("ffprobe"))?;
    let root = install_root_for_tool(&ffmpeg)?;

    if install_dir.exists() {
        fs::remove_dir_all(install_dir).map_err(|error| FfmpegError::File {
            path: install_dir.to_path_buf(),
            message: error.to_string(),
        })?;
    }
    fs::rename(&root, install_dir).map_err(|error| FfmpegError::File {
        path: install_dir.to_path_buf(),
        message: error.to_string(),
    })?;
    if staging_dir.exists() {
        let _ = fs::remove_dir_all(staging_dir);
    }
    Ok(())
}

fn find_tool_recursive(root: &Path, tool: &str) -> Option<PathBuf> {
    let names = tool_file_names(tool);
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| names.iter().any(|candidate| candidate == name))
            {
                return Some(path);
            }
        }
    }
    None
}

fn install_root_for_tool(tool_path: &Path) -> Result<PathBuf, FfmpegError> {
    let parent = tool_path.parent().ok_or_else(|| FfmpegError::File {
        path: tool_path.to_path_buf(),
        message: "tool path has no parent".to_string(),
    })?;
    if parent
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("bin"))
    {
        return parent
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| FfmpegError::File {
                path: tool_path.to_path_buf(),
                message: "bin directory has no parent".to_string(),
            });
    }
    Ok(parent.to_path_buf())
}

fn unique_temp_path(prefix: &str, extension: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{prefix}-{}.{}", now_nanos(), extension))
}

fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

fn unavailable(reason: impl Into<String>) -> FfmpegProbeResult {
    FfmpegProbeResult {
        available: false,
        ffmpeg_path: None,
        ffprobe_path: None,
        ffmpeg_version: None,
        ffprobe_version: None,
        reason: Some(reason.into()),
    }
}

fn resolve_tool(
    tool: &str,
    explicit_path: Option<&Path>,
    install_dir: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(path) = explicit_path {
        return path.is_file().then(|| path.to_path_buf());
    }

    if let Some(install_dir) = install_dir {
        for candidate in install_dir_candidates(install_dir, tool) {
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        if install_dir.exists() {
            return None;
        }
    }

    path_candidates(tool)
        .into_iter()
        .find(|candidate| candidate.is_file())
}

fn install_dir_candidates(install_dir: &Path, tool: &str) -> Vec<PathBuf> {
    tool_file_names(tool)
        .into_iter()
        .flat_map(|file_name| {
            [
                install_dir.join("bin").join(&file_name),
                install_dir.join(file_name),
            ]
        })
        .collect()
}

fn path_candidates(tool: &str) -> Vec<PathBuf> {
    let Some(path_env) = std::env::var_os("PATH") else {
        return Vec::new();
    };

    std::env::split_paths(&path_env)
        .flat_map(|dir| {
            tool_file_names(tool)
                .into_iter()
                .map(move |file_name| dir.join(file_name))
        })
        .collect()
}

fn tool_file_names(tool: &str) -> Vec<String> {
    if cfg!(windows) {
        vec![
            format!("{tool}.exe"),
            format!("{tool}.cmd"),
            format!("{tool}.bat"),
            tool.to_string(),
        ]
    } else {
        vec![tool.to_string()]
    }
}

fn probe_tool_version(path: &Path) -> Result<String, String> {
    let output = Command::new(path)
        .arg("-version")
        .output()
        .map_err(|error| format!("failed to run {}: {error}", path.display()))?;

    if !output.status.success() {
        return Err(format!(
            "{} exited with status {}",
            path.display(),
            output.status
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let version = stdout
        .lines()
        .chain(stderr.lines())
        .find(|line| !line.trim().is_empty())
        .map(str::trim)
        .unwrap_or("version output was empty")
        .to_string();
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_settings_use_windows_release_essentials_source() {
        let settings = FfmpegSettings::golden_for_platform(FfmpegPlatform::Windows);

        assert!(settings.enabled);
        assert_eq!(settings.channel, "release-essentials");
        assert!(settings
            .download
            .archive_url
            .ends_with("/ffmpeg-release-essentials.zip"));
        assert!(settings
            .download
            .sha256_url
            .as_deref()
            .unwrap()
            .ends_with(".zip.sha256"));
        assert!(settings.download.require_sha256);
    }

    #[test]
    fn non_windows_golden_settings_probe_without_managed_download() {
        let settings = FfmpegSettings::golden_for_platform(FfmpegPlatform::Linux);

        assert!(settings.enabled);
        assert!(settings.download.archive_url.is_empty());
        assert!(settings.download.sha256_url.is_none());
    }

    #[test]
    fn probe_succeeds_with_fake_tools_in_configured_directory() {
        let dir = unique_temp_dir("mrd-ffmpeg-probe-ok");
        write_fake_tool(&dir, "ffmpeg");
        write_fake_tool(&dir, "ffprobe");

        let mut settings = FfmpegSettings::golden_for_platform(FfmpegPlatform::Windows);
        settings.install_dir = Some(dir.clone());

        let result = probe_ffmpeg(&settings);

        assert!(result.available, "{result:?}");
        assert_eq!(
            result.ffmpeg_path.as_deref(),
            Some(dir.join(exe_name("ffmpeg")).as_path())
        );
        assert_eq!(
            result.ffprobe_path.as_deref(),
            Some(dir.join(exe_name("ffprobe")).as_path())
        );
    }

    #[test]
    fn probe_fails_when_ffprobe_is_missing() {
        let dir = unique_temp_dir("mrd-ffmpeg-probe-missing");
        write_fake_tool(&dir, "ffmpeg");

        let mut settings = FfmpegSettings::golden_for_platform(FfmpegPlatform::Windows);
        settings.install_dir = Some(dir);

        let result = probe_ffmpeg(&settings);

        assert!(!result.available);
        assert!(result.reason.unwrap().contains("ffprobe"));
    }

    #[test]
    fn parses_plain_and_filename_sha256_formats() {
        let plain = parse_sha256("a".repeat(64).as_str()).expect("plain hash");
        let named =
            parse_sha256(format!("{}  ffmpeg-release-essentials.zip", "b".repeat(64)).as_str())
                .expect("named hash");

        assert_eq!(plain, "a".repeat(64));
        assert_eq!(named, "b".repeat(64));
    }

    #[test]
    fn checksum_mismatch_is_reported() {
        let path = unique_temp_dir("mrd-ffmpeg-hash").join("archive.zip");
        std::fs::write(&path, b"not the expected content").expect("write archive");

        let error = verify_sha256(&path, &"0".repeat(64)).unwrap_err();

        assert!(error.to_string().contains("checksum mismatch"));
    }

    #[test]
    fn install_archive_extracts_tools_and_probe_succeeds() {
        let root = unique_temp_dir("mrd-ffmpeg-install");
        let archive_path = root.join("ffmpeg.zip");
        write_fake_ffmpeg_archive(&archive_path);
        let expected_sha256 = file_sha256(&archive_path);
        let install_dir = root.join("managed-ffmpeg");

        let result = install_ffmpeg_archive(&archive_path, &install_dir, Some(&expected_sha256))
            .expect("install archive");

        assert!(result.probe.available);
        assert_eq!(
            result.archive_sha256.as_deref(),
            Some(expected_sha256.as_str())
        );
        assert!(install_dir.join("bin").join(exe_name("ffmpeg")).is_file());
        assert!(install_dir.join("bin").join(exe_name("ffprobe")).is_file());
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "{prefix}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn write_fake_tool(dir: &std::path::Path, name: &str) {
        let path = dir.join(exe_name(name));
        #[cfg(windows)]
        {
            std::fs::write(
                &path,
                format!("@echo off\r\necho {name} version test\r\nexit /b 0\r\n"),
            )
            .expect("write fake tool");
        }

        #[cfg(not(windows))]
        {
            std::fs::write(
                &path,
                format!("#!/bin/sh\necho \"{name} version test\"\nexit 0\n"),
            )
            .expect("write fake tool");
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(&path)
                .expect("fake tool metadata")
                .permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&path, permissions).expect("chmod fake tool");
        }
    }

    fn write_fake_ffmpeg_archive(path: &std::path::Path) {
        let file = std::fs::File::create(path).expect("create fake archive");
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default().unix_permissions(0o755);
        for tool in ["ffmpeg", "ffprobe"] {
            zip.start_file(
                format!("ffmpeg-release-essentials/bin/{}", exe_name(tool)),
                options,
            )
            .expect("start zip file");
            let script = if cfg!(windows) {
                format!("@echo off\r\necho {tool} version test\r\nexit /b 0\r\n")
            } else {
                format!("#!/bin/sh\necho \"{tool} version test\"\nexit 0\n")
            };
            zip.write_all(script.as_bytes()).expect("write zip file");
        }
        zip.finish().expect("finish fake archive");
    }

    fn file_sha256(path: &std::path::Path) -> String {
        let bytes = std::fs::read(path).expect("read file");
        format!("{:x}", Sha256::digest(&bytes))
    }

    fn exe_name(name: &str) -> String {
        if cfg!(windows) {
            format!("{name}.cmd")
        } else {
            name.to_string()
        }
    }
}
