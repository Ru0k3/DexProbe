use std::fs;
use std::io::Cursor;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use zip::ZipArchive;

use crate::config;
use crate::core::error::ScanError;
use crate::core::logger;

static SCAN_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy)]
pub struct ArchiveLimits {
    pub max_entry_count: usize,
    pub max_entry_bytes: u64,
    pub max_total_extracted_bytes: u64,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_entry_count: config::MAX_ENTRY_COUNT,
            max_entry_bytes: config::MAX_ENTRY_BYTES,
            max_total_extracted_bytes: config::MAX_TOTAL_EXTRACTED_BYTES,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ArchiveEntry {
    pub name: String,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub is_symlink: bool,
}

#[derive(Debug)]
pub struct ApkArchive {
    path: PathBuf,
    entries: Vec<ArchiveEntry>,
    limits: ArchiveLimits,
}

impl ApkArchive {
    pub fn open(path: &Path, limits: ArchiveLimits) -> std::result::Result<Self, ScanError> {
        let file = fs::File::open(path)?;
        let mut archive = ZipArchive::new(file)
            .map_err(|error| ScanError::MalformedArchive(error.to_string()))?;
        if archive.len() > limits.max_entry_count {
            return Err(ScanError::ArchiveLimit(format!(
                "entry count {} exceeds {}",
                archive.len(),
                limits.max_entry_count
            )));
        }
        let mut entries = Vec::with_capacity(archive.len());
        let mut total = 0u64;
        for index in 0..archive.len() {
            let entry = archive
                .by_index(index)
                .map_err(|error| ScanError::MalformedArchive(error.to_string()))?;
            let name = entry.name().to_string();
            validate_entry_name(&name)?;
            let uncompressed_size = entry.size();
            if uncompressed_size > limits.max_entry_bytes {
                return Err(ScanError::ArchiveLimit(format!(
                    "{name} is {} bytes",
                    uncompressed_size
                )));
            }
            total = total.saturating_add(uncompressed_size);
            if total > limits.max_total_extracted_bytes {
                return Err(ScanError::ArchiveLimit(format!(
                    "total uncompressed size exceeds {} bytes",
                    limits.max_total_extracted_bytes
                )));
            }
            let is_symlink = entry
                .unix_mode()
                .map(|mode| (mode & 0o170000) == 0o120000)
                .unwrap_or(false);
            if is_symlink {
                return Err(ScanError::ArchiveLimit(format!("symlink entry: {name}")));
            }
            entries.push(ArchiveEntry {
                name,
                compressed_size: entry.compressed_size(),
                uncompressed_size,
                is_symlink,
            });
        }
        Ok(Self {
            path: path.to_path_buf(),
            entries,
            limits,
        })
    }

    pub fn entries(&self) -> &[ArchiveEntry] {
        &self.entries
    }

    pub fn limits(&self) -> ArchiveLimits {
        self.limits
    }

    pub fn read_entry_bounded(&self, name: &str) -> std::result::Result<Vec<u8>, ScanError> {
        let file = fs::File::open(&self.path)?;
        let mut archive = ZipArchive::new(file)
            .map_err(|error| ScanError::MalformedArchive(error.to_string()))?;
        let mut entry = archive
            .by_name(name)
            .map_err(|error| ScanError::MalformedArchive(error.to_string()))?;
        if entry.size() > self.limits.max_entry_bytes {
            return Err(ScanError::ArchiveLimit(name.to_string()));
        }
        let mut bytes = Vec::new();
        let mut limited = (&mut entry).take(self.limits.max_entry_bytes + 1);
        limited.read_to_end(&mut bytes)?;
        if bytes.len() as u64 > self.limits.max_entry_bytes {
            return Err(ScanError::ArchiveLimit(name.to_string()));
        }
        Ok(bytes)
    }

    pub fn extract_entry_bounded(
        &self,
        name: &str,
        destination: &Path,
    ) -> std::result::Result<u64, ScanError> {
        let bytes = self.read_entry_bounded(name)?;
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(destination, &bytes)?;
        Ok(bytes.len() as u64)
    }
}

fn validate_entry_name(name: &str) -> std::result::Result<(), ScanError> {
    let path = Path::new(name);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(ScanError::ArchiveLimit(format!(
            "unsafe archive path: {name}"
        )));
    }
    Ok(())
}

#[derive(Debug)]
pub struct TempTreeGuard {
    path: PathBuf,
}

impl Drop for TempTreeGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(Debug)]
pub struct UnpackedApk {
    pub apk_path: PathBuf,
    pub metadata: Metadata,
    pub files: Vec<String>,
    pub temp_dir: Option<PathBuf>,
    pub manifest: Option<PathBuf>,
    pub dex_files: Vec<PathBuf>,
    pub res_files: Vec<PathBuf>,
    pub decoded_manifest: Option<DecodedManifest>,
    _temp_guard: TempTreeGuard,
}

impl UnpackedApk {
    pub fn package(&self) -> &str {
        self.metadata.package.as_deref().unwrap_or("unknown")
    }

    pub fn apk_name(&self) -> &str {
        self.apk_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown.apk")
    }

    pub fn raw(&self, internal_path: &str) -> Result<Option<Vec<u8>>> {
        let archive = ApkArchive::open(&self.apk_path, ArchiveLimits::default())
            .map_err(|error| anyhow::anyhow!(error))?;
        match archive.read_entry_bounded(internal_path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(ScanError::MalformedArchive(_)) => Ok(None),
            Err(error) => Err(anyhow::anyhow!(error)),
        }
    }
}

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct Metadata {
    pub package: Option<String>,
    pub version_name: Option<String>,
    pub version_code: Option<String>,
    pub min_sdk: Option<String>,
    pub target_sdk: Option<String>,
    pub max_sdk: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ManifestComponent {
    pub name: String,
    pub exported: Option<bool>,
    pub permission: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct DecodedManifest {
    pub package: Option<String>,
    pub version_name: Option<String>,
    pub version_code: Option<String>,
    pub min_sdk: Option<String>,
    pub target_sdk: Option<String>,
    pub max_sdk: Option<String>,
    pub debuggable: Option<bool>,
    pub allow_backup: Option<bool>,
    pub uses_cleartext_traffic: Option<bool>,
    pub network_security_config: Option<String>,
    pub permissions: Vec<String>,
    pub activities: Vec<ManifestComponent>,
    pub services: Vec<ManifestComponent>,
    pub receivers: Vec<ManifestComponent>,
    pub providers: Vec<ManifestComponent>,
}

pub fn open_apk(apk_path: impl Into<PathBuf>, verbose: bool) -> Result<UnpackedApk> {
    let apk_path = fs::canonicalize(apk_path.into())?;
    if !apk_path.is_file() {
        anyhow::bail!(
            "APK file not found or is not a file: {}",
            apk_path.display()
        );
    }
    if apk_path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
        != Some("apk")
    {
        anyhow::bail!("expected a .apk file: {}", apk_path.display());
    }
    let archive = ApkArchive::open(&apk_path, ArchiveLimits::default())
        .map_err(|error| anyhow::anyhow!(error))?;
    logger::section(&format!("APK UNPACKER — {}", apk_path.display()), 54);

    let files = archive
        .entries()
        .iter()
        .map(|entry| entry.name.clone())
        .collect::<Vec<_>>();
    if verbose {
        for entry in &files {
            println!("  {entry}");
        }
    }
    let temp_dir = make_temp_dir(&apk_path)?;
    let guard = TempTreeGuard {
        path: temp_dir.clone(),
    };
    let mut unpacked = UnpackedApk {
        apk_path,
        metadata: Metadata::default(),
        files,
        temp_dir: Some(temp_dir),
        manifest: None,
        dex_files: Vec::new(),
        res_files: Vec::new(),
        decoded_manifest: None,
        _temp_guard: guard,
    };
    let raw_manifest = archive
        .read_entry_bounded("AndroidManifest.xml")
        .map_err(|error| anyhow::anyhow!(error))?;
    let decoded_manifest = decode_manifest(&raw_manifest)
        .map_err(|error| anyhow::anyhow!(ScanError::ManifestDecode(error.to_string())))?;
    unpacked.metadata = Metadata {
        package: decoded_manifest.package.clone(),
        version_name: decoded_manifest.version_name.clone(),
        version_code: decoded_manifest.version_code.clone(),
        min_sdk: decoded_manifest.min_sdk.clone(),
        target_sdk: decoded_manifest.target_sdk.clone(),
        max_sdk: decoded_manifest.max_sdk.clone(),
    };
    unpacked.decoded_manifest = Some(decoded_manifest);
    unpacked.manifest = extract_entry(&archive, &mut unpacked, "AndroidManifest.xml", "manifest")?;
    unpacked.dex_files = extract_matching(
        &archive,
        &mut unpacked,
        |name| name.ends_with(".dex"),
        "dex",
    )?;
    unpacked.res_files = extract_matching(
        &archive,
        &mut unpacked,
        |name| name.starts_with("res/") || name.starts_with("assets/"),
        "resources",
    )?;
    logger::ok(&format!(
        "Unpack complete — {} files, {} DEX, {} resources.",
        unpacked.files.len(),
        unpacked.dex_files.len(),
        unpacked.res_files.len()
    ));
    Ok(unpacked)
}

fn decode_manifest(raw: &[u8]) -> Result<DecodedManifest> {
    let mut cursor = Cursor::new(raw);
    let chunk = apk::res::Chunk::parse(&mut cursor)
        .map_err(|error| anyhow::anyhow!("binary AXML parse failed: {error}"))?;
    let mut strings = Vec::new();
    collect_string_pool(&chunk, &mut strings);
    let mut manifest = DecodedManifest::default();
    walk_manifest(&chunk, &strings, &mut manifest);
    if manifest.package.is_none() {
        anyhow::bail!("manifest element was not decoded");
    }
    Ok(manifest)
}

fn collect_string_pool(chunk: &apk::res::Chunk, strings: &mut Vec<String>) {
    match chunk {
        apk::res::Chunk::StringPool(pool, _) => *strings = pool.clone(),
        apk::res::Chunk::Xml(children) | apk::res::Chunk::Table(_, children) => {
            for child in children {
                collect_string_pool(child, strings);
            }
        }
        _ => {}
    }
}

fn walk_manifest(chunk: &apk::res::Chunk, strings: &[String], manifest: &mut DecodedManifest) {
    match chunk {
        apk::res::Chunk::Xml(children) | apk::res::Chunk::Table(_, children) => {
            for child in children {
                walk_manifest(child, strings, manifest);
            }
        }
        apk::res::Chunk::XmlStartElement(_, element, attributes) => {
            let name = string_at(strings, element.name).unwrap_or_default();
            let attrs = attributes
                .iter()
                .filter_map(|attribute| {
                    Some((
                        string_at(strings, attribute.name)?,
                        attribute_value(strings, attribute),
                    ))
                })
                .collect::<std::collections::HashMap<_, _>>();
            match name.as_str() {
                "manifest" => {
                    manifest.package = attrs.get("package").cloned();
                    manifest.version_name = attrs.get("versionName").cloned();
                    manifest.version_code = attrs.get("versionCode").cloned();
                }
                "uses-sdk" => {
                    manifest.min_sdk = attrs.get("minSdkVersion").cloned();
                    manifest.target_sdk = attrs.get("targetSdkVersion").cloned();
                    manifest.max_sdk = attrs.get("maxSdkVersion").cloned();
                }
                "uses-permission" => {
                    if let Some(permission) = attrs.get("name") {
                        manifest.permissions.push(permission.clone());
                    }
                }
                "application" => {
                    manifest.debuggable = attrs.get("debuggable").and_then(|v| v.parse().ok());
                    manifest.allow_backup = attrs.get("allowBackup").and_then(|v| v.parse().ok());
                    manifest.uses_cleartext_traffic = attrs
                        .get("usesCleartextTraffic")
                        .and_then(|v| v.parse().ok());
                    manifest.network_security_config = attrs.get("networkSecurityConfig").cloned();
                }
                "activity" => manifest.activities.push(component_from(&attrs)),
                "service" => manifest.services.push(component_from(&attrs)),
                "receiver" => manifest.receivers.push(component_from(&attrs)),
                "provider" => manifest.providers.push(component_from(&attrs)),
                _ => {}
            }
        }
        _ => {}
    }
}

fn component_from(attrs: &std::collections::HashMap<String, String>) -> ManifestComponent {
    ManifestComponent {
        name: attrs.get("name").cloned().unwrap_or_default(),
        exported: attrs.get("exported").and_then(|value| value.parse().ok()),
        permission: attrs.get("permission").cloned(),
    }
}

fn string_at(strings: &[String], index: i32) -> Option<String> {
    strings.get(usize::try_from(index).ok()?).cloned()
}

fn attribute_value(strings: &[String], attribute: &apk::res::ResXmlAttribute) -> String {
    if attribute.raw_value >= 0
        && let Some(value) = string_at(strings, attribute.raw_value)
    {
        return value;
    }
    if attribute.typed_value.data_type == apk::res::ResValueType::IntBoolean as u8 {
        return (attribute.typed_value.data != 0).to_string();
    }
    attribute.typed_value.data.to_string()
}

pub fn cleanup(unpacked: &mut UnpackedApk) {
    if let Some(temp_dir) = unpacked.temp_dir.take() {
        if let Err(error) = fs::remove_dir_all(&temp_dir) {
            logger::warn(&format!("Could not remove {}: {error}", temp_dir.display()));
            unpacked.temp_dir = Some(temp_dir);
        } else {
            logger::ok("Temp directory deleted.");
        }
    }
}

fn make_temp_dir(path: &Path) -> Result<PathBuf> {
    let scan_id = format!(
        "{}-{}-{}",
        path.file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("apk"),
        std::process::id(),
        SCAN_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let base = std::env::temp_dir().join(format!("dexprobe-{scan_id}"));
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&base)?;
    Ok(base)
}

fn extract_entry(
    archive: &ApkArchive,
    unpacked: &mut UnpackedApk,
    name: &str,
    subdir: &str,
) -> Result<Option<PathBuf>> {
    if !archive.entries().iter().any(|entry| entry.name == name) {
        logger::warn(&format!("{name} not found"));
        return Ok(None);
    }
    let destination = unpacked.temp_dir.as_ref().unwrap().join(subdir).join(name);
    archive
        .extract_entry_bounded(name, &destination)
        .map_err(|error| anyhow::anyhow!(error))?;
    Ok(Some(destination))
}

fn extract_matching<F>(
    archive: &ApkArchive,
    unpacked: &mut UnpackedApk,
    predicate: F,
    subdir: &str,
) -> Result<Vec<PathBuf>>
where
    F: Fn(&str) -> bool,
{
    let mut paths = Vec::new();
    for name in archive
        .entries()
        .iter()
        .map(|entry| entry.name.as_str())
        .filter(|name| predicate(name))
    {
        let destination = unpacked.temp_dir.as_ref().unwrap().join(subdir).join(name);
        archive
            .extract_entry_bounded(name, &destination)
            .map_err(|error| anyhow::anyhow!(error))?;
        paths.push(destination);
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::{ApkArchive, ArchiveLimits, ScanError, open_apk};
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_apk(name: &str, entries: &[(&str, &[u8])]) -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("dexprobe-{name}-{id}.apk"));
        let file = fs::File::create(&path).expect("create fixture");
        let mut writer = ZipWriter::new(file);
        for (entry, bytes) in entries {
            writer
                .start_file(*entry, SimpleFileOptions::default())
                .expect("start entry");
            writer.write_all(bytes).expect("write entry");
        }
        writer.finish().expect("finish fixture");
        path
    }

    #[test]
    fn rejects_traversal_entries() {
        let path = temp_apk("traversal", &[("../escape", b"bad")]);
        let result = ApkArchive::open(&path, ArchiveLimits::default());
        fs::remove_file(path).expect("remove fixture");
        assert!(matches!(result, Err(ScanError::ArchiveLimit(_))));
    }

    #[test]
    fn enforces_entry_limit_before_reading() {
        let path = temp_apk("oversized", &[("payload", b"123456789")]);
        let result = ApkArchive::open(
            &path,
            ArchiveLimits {
                max_entry_count: 10,
                max_entry_bytes: 4,
                max_total_extracted_bytes: 10,
            },
        );
        fs::remove_file(path).expect("remove fixture");
        assert!(matches!(result, Err(ScanError::ArchiveLimit(_))));
    }

    #[test]
    fn rejects_manifest_that_is_not_binary_axml() {
        let path = temp_apk("bad-manifest", &[("AndroidManifest.xml", b"not axml")]);
        let result = open_apk(&path, false);
        fs::remove_file(path).expect("remove fixture");
        let error = result.expect_err("malformed manifest must fail");
        assert!(error.to_string().contains("manifest decode failed"));
    }

    #[test]
    fn creates_private_unique_temp_directories() {
        let first = super::make_temp_dir(Path::new("sample.apk")).expect("create temp dir");
        let second = super::make_temp_dir(Path::new("sample.apk")).expect("create temp dir");
        assert_ne!(first, second);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&first).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        fs::remove_dir_all(first).unwrap();
        fs::remove_dir_all(second).unwrap();
    }
}
