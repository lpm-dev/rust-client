use lpm_common::{LpmError, LpmRoot};
use lpm_extractor::verify_and_extract;
use lpm_runtime::platform::Platform;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const ENGINE_SCHEMA_VERSION: u32 = 1;
const ENGINE_SIDECAR_FILE_NAME: &str = ".lpm-engine.json";
const MAX_ENGINE_DOWNLOAD_SIZE: usize = 150 * 1024 * 1024;
const TSGO_VERSION: &str = "7.0.0-dev.20260525.1";

#[derive(Debug, Clone, Copy)]
struct EnginePlatformAsset {
    platform: &'static str,
    tarball_url: &'static str,
    tarball_integrity: &'static str,
    entry_rel_path: &'static str,
}

#[derive(Debug, Clone)]
struct ResolvedEngineAsset {
    tarball_url: String,
    tarball_integrity: String,
    entry_rel_path: String,
}

#[derive(Debug, Clone)]
pub struct EngineDef {
    pub name: &'static str,
    pub latest_version: &'static str,
    assets: &'static [EnginePlatformAsset],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EngineSidecar {
    schema_version: u32,
    engine_name: String,
    version: String,
    platform: String,
    entry_rel_path: String,
    tarball_url: String,
    tarball_integrity: String,
    tarball_sha256: String,
    layout_sha256: String,
    verified_at_unix: u64,
}

impl EngineSidecar {
    fn new(
        engine_name: impl Into<String>,
        version: impl Into<String>,
        platform: impl Into<String>,
        entry_rel_path: impl Into<String>,
        tarball_url: impl Into<String>,
        tarball_integrity: impl Into<String>,
        tarball_sha256: impl Into<String>,
        layout_sha256: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: ENGINE_SCHEMA_VERSION,
            engine_name: engine_name.into(),
            version: version.into(),
            platform: platform.into(),
            entry_rel_path: entry_rel_path.into(),
            tarball_url: tarball_url.into(),
            tarball_integrity: tarball_integrity.into(),
            tarball_sha256: tarball_sha256.into(),
            layout_sha256: layout_sha256.into(),
            verified_at_unix: now_unix(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum EngineReuseDecision {
    Hit,
    Miss(EngineMissReason),
}

#[derive(Debug, PartialEq, Eq)]
enum EngineMissReason {
    SidecarMissing,
    SidecarMalformed,
    SchemaMismatch,
    IdentityMismatch,
    PlatformMismatch,
    EntryMissing,
    LayoutHashMismatch,
}

static TSGO_ASSETS: &[EnginePlatformAsset] = &[
    EnginePlatformAsset {
        platform: "darwin-arm64",
        tarball_url: "https://registry.npmjs.org/@typescript/native-preview-darwin-arm64/-/native-preview-darwin-arm64-7.0.0-dev.20260525.1.tgz",
        tarball_integrity: "sha512-x0ClBYc6xQDLXvpRn/zg6SViX/r1F8LXHyfSHmKx4ieiaZiVvGsEww/qzdHind+Y62MIUN3e/XfDFrpRxWDv0g==",
        entry_rel_path: "lib/tsgo",
    },
    EnginePlatformAsset {
        platform: "darwin-x64",
        tarball_url: "https://registry.npmjs.org/@typescript/native-preview-darwin-x64/-/native-preview-darwin-x64-7.0.0-dev.20260525.1.tgz",
        tarball_integrity: "sha512-CSHbx6HfM+xXqceGFtG4kcqqoQ5xjT1BHO0bqLfLeQtKlMlze59dIV2DbOb5Aj6wm2ACTKU4K9aurJDdHARx1g==",
        entry_rel_path: "lib/tsgo",
    },
    EnginePlatformAsset {
        platform: "linux-x64",
        tarball_url: "https://registry.npmjs.org/@typescript/native-preview-linux-x64/-/native-preview-linux-x64-7.0.0-dev.20260525.1.tgz",
        tarball_integrity: "sha512-GhC0kXeYxn55Rk3klmWET/Y033AHeMzLBMO58yP7R8m5ZdGiBisejDZnvttzczYJtgT42LNOtVmbtsG/+R8XWw==",
        entry_rel_path: "lib/tsgo",
    },
    EnginePlatformAsset {
        platform: "linux-arm",
        tarball_url: "https://registry.npmjs.org/@typescript/native-preview-linux-arm/-/native-preview-linux-arm-7.0.0-dev.20260525.1.tgz",
        tarball_integrity: "sha512-hY2EVAaGc1bsaxthJiNUbzn6ESkMSLBiWRCNhQl8XdhDWew8KhKCjw4DHe0lAYSdxLJBe6fCPpcFjDnoSowBxA==",
        entry_rel_path: "lib/tsgo",
    },
    EnginePlatformAsset {
        platform: "linux-arm64",
        tarball_url: "https://registry.npmjs.org/@typescript/native-preview-linux-arm64/-/native-preview-linux-arm64-7.0.0-dev.20260525.1.tgz",
        tarball_integrity: "sha512-0DFKd3EuZ/Z0/mB114mATrlRxQUo7rcpXYgd5CJN7y1dbIgkavbjVamzzJKt3s42tkJGfdys83w6aIHDu6fykw==",
        entry_rel_path: "lib/tsgo",
    },
    EnginePlatformAsset {
        platform: "win-x64",
        tarball_url: "https://registry.npmjs.org/@typescript/native-preview-win32-x64/-/native-preview-win32-x64-7.0.0-dev.20260525.1.tgz",
        tarball_integrity: "sha512-xJCdFz9smVQVpXYW0vZZJsM0GIANPqSt8eMDRYfDY6M/BcXNXYOAt7tsxnSRyYWnFf9Ci7wKNRZaihZrDJ2m6A==",
        entry_rel_path: "lib/tsgo.exe",
    },
    EnginePlatformAsset {
        platform: "win-arm64",
        tarball_url: "https://registry.npmjs.org/@typescript/native-preview-win32-arm64/-/native-preview-win32-arm64-7.0.0-dev.20260525.1.tgz",
        tarball_integrity: "sha512-L2+bsx73FyuEzLNgybtIxhnT9lYYAh9rTRFWZ4wZlJg44DGstjgz4FBKVHBO/cm3Hz7YNWeJESrB9ROUNbffPg==",
        entry_rel_path: "lib/tsgo.exe",
    },
];

static ENGINES: &[EngineDef] = &[EngineDef {
    name: "tsgo",
    latest_version: TSGO_VERSION,
    assets: TSGO_ASSETS,
}];

pub async fn ensure_engine(
    engine_name: &str,
    pinned_version: Option<&str>,
    quiet: bool,
) -> Result<PathBuf, LpmError> {
    let def = get_engine(engine_name)
        .ok_or_else(|| LpmError::Engine(format!("unknown engine: '{engine_name}'")))?;
    let version = resolve_engine_version(def, pinned_version)?;
    let platform = Platform::current()?;
    let platform_str = platform.to_string();
    let asset = resolve_engine_asset(def, &platform_str)?;
    let entry_path = engine_entry_path(def.name, &version, &platform_str, &asset.entry_rel_path)?;
    let sidecar_path = engine_sidecar_path(def.name, &version, &platform_str)?;
    let platform_dir = engine_platform_dir(def.name, &version, &platform_str)?;

    if matches!(
        validate_for_reuse(
            &sidecar_path,
            &platform_dir,
            def.name,
            &version,
            &platform_str,
            &asset.entry_rel_path,
        ),
        EngineReuseDecision::Hit,
    ) {
        return Ok(entry_path);
    }

    let lock_path = engine_install_lock_path(def.name, &version)?;
    let engine_name_owned = def.name.to_string();
    let version_owned = version.clone();
    let platform_owned = platform_str.clone();
    lpm_common::with_exclusive_lock_async(lock_path, async move {
        install_under_lock(
            &engine_name_owned,
            &version_owned,
            &platform_owned,
            asset,
            quiet,
        )
        .await
    })
    .await
}

pub fn get_engine(name: &str) -> Option<&'static EngineDef> {
    ENGINES.iter().find(|engine| engine.name == name)
}

fn resolve_engine_version(def: &EngineDef, pinned_version: Option<&str>) -> Result<String, LpmError> {
    match pinned_version {
        None => Ok(def.latest_version.to_string()),
        Some(version) if version == def.latest_version => Ok(version.to_string()),
        Some(version) => Err(LpmError::Engine(format!(
            "managed engine '{}' only supports the bundled version {} today; requested {}",
            def.name, def.latest_version, version,
        ))),
    }
}

fn resolve_engine_asset(def: &EngineDef, platform: &str) -> Result<ResolvedEngineAsset, LpmError> {
    let asset = def
        .assets
        .iter()
        .find(|asset| asset.platform == platform)
        .ok_or_else(|| {
            LpmError::Engine(format!(
                "engine '{}' has no install for platform {}",
                def.name, platform
            ))
        })?;
    Ok(ResolvedEngineAsset {
        tarball_url: asset.tarball_url.to_string(),
        tarball_integrity: asset.tarball_integrity.to_string(),
        entry_rel_path: asset.entry_rel_path.to_string(),
    })
}

async fn install_under_lock(
    engine_name: &str,
    version: &str,
    platform: &str,
    asset: ResolvedEngineAsset,
    quiet: bool,
) -> Result<PathBuf, LpmError> {
    let engines_root = engines_dir()?;
    install_under_lock_at(&engines_root, engine_name, version, platform, asset, quiet).await
}

async fn install_under_lock_at(
    engines_root: &Path,
    engine_name: &str,
    version: &str,
    platform: &str,
    asset: ResolvedEngineAsset,
    quiet: bool,
) -> Result<PathBuf, LpmError> {
    let platform_dir = engine_platform_dir_at(engines_root, engine_name, version, platform)?;
    let sidecar_path = engine_sidecar_path_at(engines_root, engine_name, version, platform)?;
    let entry_path = engine_entry_path_at(
        engines_root,
        engine_name,
        version,
        platform,
        &asset.entry_rel_path,
    )?;

    if matches!(
        validate_for_reuse(
            &sidecar_path,
            &platform_dir,
            engine_name,
            version,
            platform,
            &asset.entry_rel_path,
        ),
        EngineReuseDecision::Hit,
    ) {
        return Ok(entry_path);
    }

    if !quiet {
        eprintln!(
            "  Engine '{}' not installed. Downloading {} v{} ({})...",
            engine_name, engine_name, version, platform,
        );
    }

    let bytes = download_tarball(&asset.tarball_url).await?;
    lpm_extractor::verify_integrity(&bytes, &asset.tarball_integrity)?;

    let tarball_sha256 = compute_sha256(&bytes);
    let version_dir = engine_version_dir_at(engines_root, engine_name, version)?;
    std::fs::create_dir_all(&version_dir)?;

    if platform_dir.exists() {
        std::fs::remove_dir_all(&platform_dir).map_err(|e| {
            LpmError::Engine(format!(
                "failed to clear invalid cached engine '{}' at {}: {e}",
                engine_name,
                platform_dir.display(),
            ))
        })?;
    }

    let stage_dir = version_dir.join(format!(".{platform}.{}.stage", std::process::id()));
    let _ = std::fs::remove_dir_all(&stage_dir);
    std::fs::create_dir_all(&stage_dir)?;

    if let Err(error) = verify_and_extract(&bytes, &asset.tarball_integrity, &stage_dir) {
        let _ = std::fs::remove_dir_all(&stage_dir);
        return Err(error);
    }

    let staged_entry = stage_dir.join(&asset.entry_rel_path);
    if !staged_entry.is_file() {
        let _ = std::fs::remove_dir_all(&stage_dir);
        return Err(LpmError::Engine(format!(
            "engine '{}' extracted without expected entry {}",
            engine_name, asset.entry_rel_path,
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged_entry, std::fs::Permissions::from_mode(0o755))?;
    }

    let layout_sha256 = hash_directory_tree(&stage_dir)?;
    std::fs::rename(&stage_dir, &platform_dir).map_err(|e| {
        let _ = std::fs::remove_dir_all(&stage_dir);
        LpmError::Engine(format!(
            "failed to finalize engine '{}' install: {e}",
            engine_name,
        ))
    })?;

    let sidecar = EngineSidecar::new(
        engine_name,
        version,
        platform,
        &asset.entry_rel_path,
        &asset.tarball_url,
        &asset.tarball_integrity,
        tarball_sha256,
        layout_sha256,
    );
    if let Err(error) = write_sidecar_atomic(&sidecar_path, &sidecar) {
        let _ = std::fs::remove_dir_all(&platform_dir);
        return Err(error);
    }

    Ok(entry_path)
}

async fn download_tarball(url: &str) -> Result<Vec<u8>, LpmError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| LpmError::Network(format!("failed to create HTTP client: {e}")))?;

    let resp = client
        .get(url)
        .header("User-Agent", "lpm-cli")
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("failed to download engine tarball: {e}")))?;

    if !resp.status().is_success() {
        return Err(LpmError::Http {
            status: resp.status().as_u16(),
            message: format!("failed to download engine tarball from {url}"),
        });
    }

    if let Some(content_length) = resp.content_length()
        && content_length as usize > MAX_ENGINE_DOWNLOAD_SIZE
    {
        return Err(LpmError::Engine(format!(
            "engine download size ({} bytes) exceeds maximum allowed size ({} bytes)",
            content_length, MAX_ENGINE_DOWNLOAD_SIZE,
        )));
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| LpmError::Network(format!("failed to read engine tarball: {e}")))?;

    if bytes.len() > MAX_ENGINE_DOWNLOAD_SIZE {
        return Err(LpmError::Engine(format!(
            "engine download size ({} bytes) exceeds maximum allowed size ({} bytes)",
            bytes.len(), MAX_ENGINE_DOWNLOAD_SIZE,
        )));
    }

    Ok(bytes.to_vec())
}

fn validate_for_reuse(
    sidecar_path: &Path,
    install_dir: &Path,
    requested_engine: &str,
    requested_version: &str,
    current_platform: &str,
    expected_entry_rel_path: &str,
) -> EngineReuseDecision {
    let sidecar = match read_sidecar(sidecar_path) {
        Ok(sidecar) => sidecar,
        Err(reason) => return EngineReuseDecision::Miss(reason),
    };

    if sidecar.schema_version != ENGINE_SCHEMA_VERSION {
        return EngineReuseDecision::Miss(EngineMissReason::SchemaMismatch);
    }
    if sidecar.engine_name != requested_engine || sidecar.version != requested_version {
        return EngineReuseDecision::Miss(EngineMissReason::IdentityMismatch);
    }
    if sidecar.platform != current_platform {
        return EngineReuseDecision::Miss(EngineMissReason::PlatformMismatch);
    }
    if sidecar.entry_rel_path != expected_entry_rel_path {
        return EngineReuseDecision::Miss(EngineMissReason::IdentityMismatch);
    }
    if !install_dir.join(expected_entry_rel_path).is_file() {
        return EngineReuseDecision::Miss(EngineMissReason::EntryMissing);
    }
    match hash_directory_tree(install_dir) {
        Ok(observed) if observed == sidecar.layout_sha256 => EngineReuseDecision::Hit,
        Ok(_) => EngineReuseDecision::Miss(EngineMissReason::LayoutHashMismatch),
        Err(_) => EngineReuseDecision::Miss(EngineMissReason::LayoutHashMismatch),
    }
}

fn read_sidecar(sidecar_path: &Path) -> Result<EngineSidecar, EngineMissReason> {
    let bytes = match std::fs::read(sidecar_path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(EngineMissReason::SidecarMissing);
        }
        Err(_) => return Err(EngineMissReason::SidecarMalformed),
    };
    serde_json::from_slice(&bytes).map_err(|_| EngineMissReason::SidecarMalformed)
}

fn write_sidecar_atomic(sidecar_path: &Path, sidecar: &EngineSidecar) -> Result<(), LpmError> {
    if let Some(parent) = sidecar_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(sidecar)
        .map_err(|e| LpmError::Engine(format!("failed to serialize engine sidecar: {e}")))?;
    let tmp = sidecar_path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp, json.as_bytes())
        .map_err(|e| LpmError::Engine(format!("failed to write engine sidecar tmp: {e}")))?;
    std::fs::rename(&tmp, sidecar_path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        LpmError::Engine(format!("failed to finalize engine sidecar: {e}"))
    })?;
    Ok(())
}

fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

fn hash_directory_tree(root: &Path) -> Result<String, LpmError> {
    let mut rel_files = Vec::new();
    collect_files(root, root, &mut rel_files)?;
    rel_files.sort();

    let mut hasher = Sha256::new();
    for rel in rel_files {
        hasher.update(normalize_rel_path(&rel).as_bytes());
        hasher.update([0]);
        hash_file_into(&root.join(&rel), &mut hasher)?;
        hasher.update([0]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn collect_files(root: &Path, current: &Path, rel_files: &mut Vec<PathBuf>) -> Result<(), LpmError> {
    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_files(root, &path, rel_files)?;
            continue;
        }

        let rel = path
            .strip_prefix(root)
            .map_err(|e| LpmError::Engine(format!("failed to derive engine relative path: {e}")))?
            .to_path_buf();
        if rel == PathBuf::from(ENGINE_SIDECAR_FILE_NAME) {
            continue;
        }
        rel_files.push(rel);
    }
    Ok(())
}

fn hash_file_into(path: &Path, hasher: &mut Sha256) -> Result<(), LpmError> {
    use std::io::Read;

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        let target = std::fs::read_link(path)?;
        hasher.update(b"symlink");
        hasher.update(normalize_rel_path(&target).as_bytes());
        return Ok(());
    }

    let mut file = std::fs::File::open(path)?;
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(())
}

fn normalize_rel_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn validate_engine_version(version: &str) -> Result<(), LpmError> {
    if version.is_empty() {
        return Err(LpmError::Engine("engine version must not be empty".into()));
    }
    if version.contains("..") {
        return Err(LpmError::Engine(format!(
            "engine version contains forbidden sequence '..': {version}"
        )));
    }
    if !version
        .chars()
        .all(|ch| ch.is_alphanumeric() || ch == '.' || ch == '-' || ch == '_')
    {
        return Err(LpmError::Engine(format!(
            "engine version contains invalid characters: {version}"
        )));
    }
    Ok(())
}

fn validate_platform(platform: &str) -> Result<(), LpmError> {
    if platform.is_empty() {
        return Err(LpmError::Engine("platform must not be empty".into()));
    }
    if platform.contains("..") || platform.contains('/') || platform.contains('\\') {
        return Err(LpmError::Engine(format!(
            "platform contains forbidden characters: {platform}"
        )));
    }
    if !platform.chars().all(|ch| ch.is_alphanumeric() || ch == '-') {
        return Err(LpmError::Engine(format!(
            "platform contains invalid characters: {platform}"
        )));
    }
    Ok(())
}

fn engines_dir() -> Result<PathBuf, LpmError> {
    let root = LpmRoot::from_env()
        .map_err(|e| LpmError::Engine(format!("could not determine LPM home: {e}")))?;
    Ok(root.engines_root())
}

fn engine_version_dir_at(
    engines_root: &Path,
    engine_name: &str,
    version: &str,
) -> Result<PathBuf, LpmError> {
    validate_engine_version(version)?;
    Ok(engines_root.join(engine_name).join(version))
}

fn engine_platform_dir(engine_name: &str, version: &str, platform: &str) -> Result<PathBuf, LpmError> {
    let engines_root = engines_dir()?;
    engine_platform_dir_at(&engines_root, engine_name, version, platform)
}

fn engine_platform_dir_at(
    engines_root: &Path,
    engine_name: &str,
    version: &str,
    platform: &str,
) -> Result<PathBuf, LpmError> {
    validate_engine_version(version)?;
    validate_platform(platform)?;
    Ok(engine_version_dir_at(engines_root, engine_name, version)?.join(platform))
}

fn engine_sidecar_path(engine_name: &str, version: &str, platform: &str) -> Result<PathBuf, LpmError> {
    let engines_root = engines_dir()?;
    engine_sidecar_path_at(&engines_root, engine_name, version, platform)
}

fn engine_sidecar_path_at(
    engines_root: &Path,
    engine_name: &str,
    version: &str,
    platform: &str,
) -> Result<PathBuf, LpmError> {
    Ok(engine_platform_dir_at(engines_root, engine_name, version, platform)?
        .join(ENGINE_SIDECAR_FILE_NAME))
}

fn engine_entry_path(
    engine_name: &str,
    version: &str,
    platform: &str,
    entry_rel_path: &str,
) -> Result<PathBuf, LpmError> {
    let engines_root = engines_dir()?;
    engine_entry_path_at(&engines_root, engine_name, version, platform, entry_rel_path)
}

fn engine_entry_path_at(
    engines_root: &Path,
    engine_name: &str,
    version: &str,
    platform: &str,
    entry_rel_path: &str,
) -> Result<PathBuf, LpmError> {
    Ok(engine_platform_dir_at(engines_root, engine_name, version, platform)?.join(entry_rel_path))
}

fn engine_install_lock_path(engine_name: &str, version: &str) -> Result<PathBuf, LpmError> {
    let engines_root = engines_dir()?;
    Ok(engine_version_dir_at(&engines_root, engine_name, version)?.join(".install.lock"))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn create_test_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            for (name, content) in files {
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                let tar_path = format!("package/{name}");
                builder
                    .append_data(&mut header, &tar_path, &content[..])
                    .unwrap();
            }
            builder.finish().unwrap();
        }

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap()
    }

    fn install_fake_engine(root: &Path, entry_rel_path: &str) -> PathBuf {
        let install_dir = root.join("tsgo").join("1.0.0").join("darwin-arm64");
        let entry_path = install_dir.join(entry_rel_path);
        std::fs::create_dir_all(entry_path.parent().unwrap()).unwrap();
        std::fs::write(&entry_path, b"engine-bytes").unwrap();
        std::fs::write(install_dir.join("lib/lib.d.ts"), b"declare const x: string;").unwrap();

        let layout_sha256 = hash_directory_tree(&install_dir).unwrap();
        let sidecar = EngineSidecar::new(
            "tsgo",
            "1.0.0",
            "darwin-arm64",
            entry_rel_path,
            "https://example.test/native-preview.tgz",
            "sha512-test",
            "tarball-sha",
            layout_sha256,
        );
        write_sidecar_atomic(&install_dir.join(ENGINE_SIDECAR_FILE_NAME), &sidecar).unwrap();
        entry_path
    }

    #[test]
    fn validate_for_reuse_detects_tampered_layout_file() {
        let dir = tempfile::tempdir().unwrap();
        let install_dir = dir.path().join("tsgo").join("1.0.0").join("darwin-arm64");
        let entry_path = install_fake_engine(dir.path(), "lib/tsgo");
        std::fs::write(install_dir.join("lib/lib.d.ts"), b"tampered").unwrap();

        let decision = validate_for_reuse(
            &install_dir.join(ENGINE_SIDECAR_FILE_NAME),
            &install_dir,
            "tsgo",
            "1.0.0",
            "darwin-arm64",
            "lib/tsgo",
        );
        assert_eq!(decision, EngineReuseDecision::Miss(EngineMissReason::LayoutHashMismatch));
        assert!(entry_path.exists());
    }

    #[tokio::test]
    async fn install_under_lock_downloads_and_extracts_layout() {
        let tarball = create_test_tarball(&[
            ("lib/tsgo", b"#!/bin/sh\nexit 0\n"),
            ("lib/lib.d.ts", b"declare const x: string;\n"),
        ]);
        let integrity = lpm_common::Integrity::from_bytes(
            lpm_common::integrity::HashAlgorithm::Sha512,
            &tarball,
        )
        .to_string();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/tsgo.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball.clone()))
            .mount(&server)
            .await;

        let home = tempfile::tempdir().unwrap();
        let engines_root = home.path().join("engines");
        let result = install_under_lock_at(
            &engines_root,
            "tsgo",
            "1.0.0",
            "darwin-arm64",
            ResolvedEngineAsset {
                tarball_url: format!("{}/tsgo.tgz", server.uri()),
                tarball_integrity: integrity,
                entry_rel_path: "lib/tsgo".into(),
            },
            true,
        )
        .await
        .unwrap();

        assert!(result.exists());
        assert!(home
            .path()
            .join("engines/tsgo/1.0.0/darwin-arm64/lib/lib.d.ts")
            .exists());
        assert!(home
            .path()
            .join("engines/tsgo/1.0.0/darwin-arm64/.lpm-engine.json")
            .exists());
    }

    #[test]
    fn resolve_engine_version_rejects_unbundled_pin() {
        let error = resolve_engine_version(get_engine("tsgo").unwrap(), Some("1.0.0"))
            .unwrap_err();
        assert!(error.to_string().contains("only supports the bundled version"));
    }
}