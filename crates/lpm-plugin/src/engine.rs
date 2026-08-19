use lpm_common::{LpmError, LpmRoot};
use lpm_extractor::verify_and_extract;
use lpm_runtime::platform::Platform;
use lpm_semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const ENGINE_SCHEMA_VERSION: u32 = 2;
const ENGINE_SIDECAR_FILE_NAME: &str = ".lpm-engine.json";
const ENGINE_VERSION_CACHE_FILE_NAME: &str = ".version-cache.json";
const MAX_ENGINE_DOWNLOAD_SIZE: usize = 150 * 1024 * 1024;
const MANAGED_ENGINE_TOOL_NAMES: &[&str] = &["rolldown"];
const MANAGED_TOOL_NPM_REGISTRY_ENV: &str = "LPM_MANAGED_TOOL_NPM_REGISTRY";
const ROLLDOWN_VERSION: &str = "1.2.4";
const ROLLDOWN_ROOT_TARBALL_URL: &str = "https://registry.npmjs.org/rolldown/-/rolldown-1.2.4.tgz";
const ROLLDOWN_ROOT_TARBALL_INTEGRITY: &str = "sha512-rSr7irW0K7QRWzjdJXqZowkcRdDtjRduh43rBltnVKd0VFq839l1lJoDvGJb6gl7+4rTTCrPWu+YfujUL8Ug7w==";
const ROLLDOWN_PLUGINUTILS_TARBALL_URL: &str =
    "https://registry.npmjs.org/@rolldown/pluginutils/-/pluginutils-1.0.1.tgz";
const ROLLDOWN_PLUGINUTILS_TARBALL_INTEGRITY: &str = "sha512-2j9bGt5Jh8hj+vPtgzPtl72j0yRxHAyumoo6TNfAjsLB04UtpSvPbPcDcBMxz7n+9CYB0c1GxQFxYRg2jimqGw==";
const OXC_TYPES_TARBALL_URL: &str =
    "https://registry.npmjs.org/@oxc-project/types/-/types-0.144.0.tgz";
const OXC_TYPES_TARBALL_INTEGRITY: &str = "sha512-nuhZIOLuI6TFQ32I/WnUx+SCPY7SdSKwgnFHydAuoS1+Z4BRcaP+RRJmGzl9lw+0OFF7UmaESf7KQRXaNLHypg==";
const TSGO_VERSION: &str = "7.0.0-dev.20260707.2";

#[derive(Debug, Clone, Copy)]
struct EngineInstallAsset {
    install_subdir: &'static str,
    tarball_url: &'static str,
    tarball_integrity: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct EnginePlatformAsset {
    platform: &'static str,
    entry_rel_path: &'static str,
    packages: &'static [EngineInstallAsset],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ResolvedEngineInstallAsset {
    install_subdir: String,
    tarball_url: String,
    tarball_integrity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ResolvedEngineAsset {
    entry_rel_path: String,
    packages: Vec<ResolvedEngineInstallAsset>,
}

#[derive(Debug, Clone)]
pub struct EngineDef {
    pub name: &'static str,
    pub latest_version: &'static str,
    assets: &'static [EnginePlatformAsset],
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct EngineVersionCache {
    #[serde(default)]
    engines: HashMap<String, CachedEngine>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct CachedEngine {
    #[serde(default)]
    selected: HashMap<String, String>,
    #[serde(default)]
    assets: HashMap<String, HashMap<String, ResolvedEngineAsset>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineInstallEvent {
    ResolvingLatest { engine: String },
    Downloading { engine: String, version: String },
    VerifiedIntegrity { engine: String, version: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EngineSidecarPackage {
    install_subdir: String,
    tarball_url: String,
    tarball_integrity: String,
    tarball_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EngineSidecar {
    schema_version: u32,
    engine_name: String,
    version: String,
    platform: String,
    entry_rel_path: String,
    #[serde(default)]
    packages: Vec<EngineSidecarPackage>,
    layout_sha256: String,
    verified_at_unix: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct NpmVersionMetadata {
    version: String,
    dist: NpmDist,
    #[serde(default)]
    dependencies: HashMap<String, String>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
struct NpmDist {
    tarball: String,
    integrity: String,
}

#[derive(Debug, Deserialize)]
struct NpmPackument {
    versions: HashMap<String, NpmVersionMetadata>,
}

impl EngineSidecar {
    fn new(
        engine_name: impl Into<String>,
        version: impl Into<String>,
        platform: impl Into<String>,
        entry_rel_path: impl Into<String>,
        packages: Vec<EngineSidecarPackage>,
        layout_sha256: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: ENGINE_SCHEMA_VERSION,
            engine_name: engine_name.into(),
            version: version.into(),
            platform: platform.into(),
            entry_rel_path: entry_rel_path.into(),
            packages,
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
        entry_rel_path: "lib/tsgo",
        packages: &[EngineInstallAsset {
            install_subdir: "",
            tarball_url: "https://registry.npmjs.org/@typescript/native-preview-darwin-arm64/-/native-preview-darwin-arm64-7.0.0-dev.20260707.2.tgz",
            tarball_integrity: "sha512-wny2pgKjGbiZtnOIHVa3tXC1UfDqxNEFzyPGmiqybedG8hipG2Nfp0l5UxbaKCjkLacUpH/W5bP2hBOMVhCOzg==",
        }],
    },
    EnginePlatformAsset {
        platform: "darwin-x64",
        entry_rel_path: "lib/tsgo",
        packages: &[EngineInstallAsset {
            install_subdir: "",
            tarball_url: "https://registry.npmjs.org/@typescript/native-preview-darwin-x64/-/native-preview-darwin-x64-7.0.0-dev.20260707.2.tgz",
            tarball_integrity: "sha512-Afc7M5zOwo+GpfcYwz5Z8HMB2tPVsui7nNIqEuuFB73MPdVqNn/Wmpe4tP4MRri0AtJnJknoHBaTJ/VDAp/Jhw==",
        }],
    },
    EnginePlatformAsset {
        platform: "linux-x64",
        entry_rel_path: "lib/tsgo",
        packages: &[EngineInstallAsset {
            install_subdir: "",
            tarball_url: "https://registry.npmjs.org/@typescript/native-preview-linux-x64/-/native-preview-linux-x64-7.0.0-dev.20260707.2.tgz",
            tarball_integrity: "sha512-du0dzi6y97Po5vDNdPJTyyijHCpaS22JLRnKZEJXBDaO9gCIymOv/5QQokFRuOlQm0bWl3i9PF4OVdGP6uAOQA==",
        }],
    },
    EnginePlatformAsset {
        platform: "linux-arm",
        entry_rel_path: "lib/tsgo",
        packages: &[EngineInstallAsset {
            install_subdir: "",
            tarball_url: "https://registry.npmjs.org/@typescript/native-preview-linux-arm/-/native-preview-linux-arm-7.0.0-dev.20260707.2.tgz",
            tarball_integrity: "sha512-hJm/UOqZTr9FHmR7uNm8VGX4oKtfWk0Jem0zPeJFNC8ckGUfSBueyiEYMZB+XmRc1aG4x1E46y3CplP4CLHvGQ==",
        }],
    },
    EnginePlatformAsset {
        platform: "linux-arm64",
        entry_rel_path: "lib/tsgo",
        packages: &[EngineInstallAsset {
            install_subdir: "",
            tarball_url: "https://registry.npmjs.org/@typescript/native-preview-linux-arm64/-/native-preview-linux-arm64-7.0.0-dev.20260707.2.tgz",
            tarball_integrity: "sha512-iITBa2WjjTI5N9t5l7Z4KoOSI+2zBlhbvFzsD/f8qX8QoKjz/Y4DPyBDgezYi8nkqjjksbgSOJ3/ykzhwrB9cg==",
        }],
    },
    EnginePlatformAsset {
        platform: "win-x64",
        entry_rel_path: "lib/tsgo.exe",
        packages: &[EngineInstallAsset {
            install_subdir: "",
            tarball_url: "https://registry.npmjs.org/@typescript/native-preview-win32-x64/-/native-preview-win32-x64-7.0.0-dev.20260707.2.tgz",
            tarball_integrity: "sha512-DL4u27stv0fo71sVhOzHSwE+YMZsbBijVI+kg5dLDLilSH79WFTJ8RSQ46vJrCMt+Gjlv/JOZP1PuLJDfioYeQ==",
        }],
    },
    EnginePlatformAsset {
        platform: "win-arm64",
        entry_rel_path: "lib/tsgo.exe",
        packages: &[EngineInstallAsset {
            install_subdir: "",
            tarball_url: "https://registry.npmjs.org/@typescript/native-preview-win32-arm64/-/native-preview-win32-arm64-7.0.0-dev.20260707.2.tgz",
            tarball_integrity: "sha512-SsAwfhyHJ1akgBc+99z4+hwdbHsdWaKB8EwCNIMA6JfSLMeUjffrYvxu+vfMyxVtOVOz7RrRXRoiDiu4a2sCtg==",
        }],
    },
];

static ROLLDOWN_ASSETS: &[EnginePlatformAsset] = &[
    EnginePlatformAsset {
        platform: "darwin-arm64",
        entry_rel_path: "bin/cli.mjs",
        packages: &[
            EngineInstallAsset {
                install_subdir: "",
                tarball_url: ROLLDOWN_ROOT_TARBALL_URL,
                tarball_integrity: ROLLDOWN_ROOT_TARBALL_INTEGRITY,
            },
            EngineInstallAsset {
                install_subdir: "node_modules/@rolldown/pluginutils",
                tarball_url: ROLLDOWN_PLUGINUTILS_TARBALL_URL,
                tarball_integrity: ROLLDOWN_PLUGINUTILS_TARBALL_INTEGRITY,
            },
            EngineInstallAsset {
                install_subdir: "node_modules/@oxc-project/types",
                tarball_url: OXC_TYPES_TARBALL_URL,
                tarball_integrity: OXC_TYPES_TARBALL_INTEGRITY,
            },
            EngineInstallAsset {
                install_subdir: "node_modules/@rolldown/binding-darwin-arm64",
                tarball_url: "https://registry.npmjs.org/@rolldown/binding-darwin-arm64/-/binding-darwin-arm64-1.2.4.tgz",
                tarball_integrity: "sha512-Dc5mPD8F5F/FS8i01syd7FTF6yB2fVthH/TRkjwJkzUK6EpoxHtqvZQP5Zwq80/5z19TWYHIg1KOHboCgVx/aQ==",
            },
        ],
    },
    EnginePlatformAsset {
        platform: "darwin-x64",
        entry_rel_path: "bin/cli.mjs",
        packages: &[
            EngineInstallAsset {
                install_subdir: "",
                tarball_url: ROLLDOWN_ROOT_TARBALL_URL,
                tarball_integrity: ROLLDOWN_ROOT_TARBALL_INTEGRITY,
            },
            EngineInstallAsset {
                install_subdir: "node_modules/@rolldown/pluginutils",
                tarball_url: ROLLDOWN_PLUGINUTILS_TARBALL_URL,
                tarball_integrity: ROLLDOWN_PLUGINUTILS_TARBALL_INTEGRITY,
            },
            EngineInstallAsset {
                install_subdir: "node_modules/@oxc-project/types",
                tarball_url: OXC_TYPES_TARBALL_URL,
                tarball_integrity: OXC_TYPES_TARBALL_INTEGRITY,
            },
            EngineInstallAsset {
                install_subdir: "node_modules/@rolldown/binding-darwin-x64",
                tarball_url: "https://registry.npmjs.org/@rolldown/binding-darwin-x64/-/binding-darwin-x64-1.2.4.tgz",
                tarball_integrity: "sha512-fpDm4oBo6SqLvWUYCmFhdde3U9KH2fRNNMeAnAPAIwxRL345xutL0EtEUcuoxsoazdJGv/MuDBQHlCDrtbvqOg==",
            },
        ],
    },
    EnginePlatformAsset {
        platform: "linux-x64",
        entry_rel_path: "bin/cli.mjs",
        packages: &[
            EngineInstallAsset {
                install_subdir: "",
                tarball_url: ROLLDOWN_ROOT_TARBALL_URL,
                tarball_integrity: ROLLDOWN_ROOT_TARBALL_INTEGRITY,
            },
            EngineInstallAsset {
                install_subdir: "node_modules/@rolldown/pluginutils",
                tarball_url: ROLLDOWN_PLUGINUTILS_TARBALL_URL,
                tarball_integrity: ROLLDOWN_PLUGINUTILS_TARBALL_INTEGRITY,
            },
            EngineInstallAsset {
                install_subdir: "node_modules/@oxc-project/types",
                tarball_url: OXC_TYPES_TARBALL_URL,
                tarball_integrity: OXC_TYPES_TARBALL_INTEGRITY,
            },
            EngineInstallAsset {
                install_subdir: "node_modules/@rolldown/binding-linux-x64-gnu",
                tarball_url: "https://registry.npmjs.org/@rolldown/binding-linux-x64-gnu/-/binding-linux-x64-gnu-1.2.4.tgz",
                tarball_integrity: "sha512-4/GyVjmhR+Tc6HLJvwc1sOhPqAZtySiSMesOZyX6JQ5XBxoTDEMKQzvo07NIK6nTon/SivlZqvhzvuVBNQhObQ==",
            },
        ],
    },
    EnginePlatformAsset {
        platform: "linux-arm64",
        entry_rel_path: "bin/cli.mjs",
        packages: &[
            EngineInstallAsset {
                install_subdir: "",
                tarball_url: ROLLDOWN_ROOT_TARBALL_URL,
                tarball_integrity: ROLLDOWN_ROOT_TARBALL_INTEGRITY,
            },
            EngineInstallAsset {
                install_subdir: "node_modules/@rolldown/pluginutils",
                tarball_url: ROLLDOWN_PLUGINUTILS_TARBALL_URL,
                tarball_integrity: ROLLDOWN_PLUGINUTILS_TARBALL_INTEGRITY,
            },
            EngineInstallAsset {
                install_subdir: "node_modules/@oxc-project/types",
                tarball_url: OXC_TYPES_TARBALL_URL,
                tarball_integrity: OXC_TYPES_TARBALL_INTEGRITY,
            },
            EngineInstallAsset {
                install_subdir: "node_modules/@rolldown/binding-linux-arm64-gnu",
                tarball_url: "https://registry.npmjs.org/@rolldown/binding-linux-arm64-gnu/-/binding-linux-arm64-gnu-1.2.4.tgz",
                tarball_integrity: "sha512-tIP06BeD9EqvECBrPZ+sqdPlYrT+aYaAiu1wYziVx5elRK/ftm33JxVDy2bXGbr6J0CrtirCkR87/X5a2euEng==",
            },
        ],
    },
    EnginePlatformAsset {
        platform: "win-x64",
        entry_rel_path: "bin/cli.mjs",
        packages: &[
            EngineInstallAsset {
                install_subdir: "",
                tarball_url: ROLLDOWN_ROOT_TARBALL_URL,
                tarball_integrity: ROLLDOWN_ROOT_TARBALL_INTEGRITY,
            },
            EngineInstallAsset {
                install_subdir: "node_modules/@rolldown/pluginutils",
                tarball_url: ROLLDOWN_PLUGINUTILS_TARBALL_URL,
                tarball_integrity: ROLLDOWN_PLUGINUTILS_TARBALL_INTEGRITY,
            },
            EngineInstallAsset {
                install_subdir: "node_modules/@oxc-project/types",
                tarball_url: OXC_TYPES_TARBALL_URL,
                tarball_integrity: OXC_TYPES_TARBALL_INTEGRITY,
            },
            EngineInstallAsset {
                install_subdir: "node_modules/@rolldown/binding-win32-x64-msvc",
                tarball_url: "https://registry.npmjs.org/@rolldown/binding-win32-x64-msvc/-/binding-win32-x64-msvc-1.2.4.tgz",
                tarball_integrity: "sha512-UwSDJOg3dqCAejWdxclJjCsh3Qq4vLYMDxmyHqo1btz3stK2VqgwNd3mm5tuIwzSlGIQ/1H9Hr+Zn09mrezNqQ==",
            },
        ],
    },
    EnginePlatformAsset {
        platform: "win-arm64",
        entry_rel_path: "bin/cli.mjs",
        packages: &[
            EngineInstallAsset {
                install_subdir: "",
                tarball_url: ROLLDOWN_ROOT_TARBALL_URL,
                tarball_integrity: ROLLDOWN_ROOT_TARBALL_INTEGRITY,
            },
            EngineInstallAsset {
                install_subdir: "node_modules/@rolldown/pluginutils",
                tarball_url: ROLLDOWN_PLUGINUTILS_TARBALL_URL,
                tarball_integrity: ROLLDOWN_PLUGINUTILS_TARBALL_INTEGRITY,
            },
            EngineInstallAsset {
                install_subdir: "node_modules/@oxc-project/types",
                tarball_url: OXC_TYPES_TARBALL_URL,
                tarball_integrity: OXC_TYPES_TARBALL_INTEGRITY,
            },
            EngineInstallAsset {
                install_subdir: "node_modules/@rolldown/binding-win32-arm64-msvc",
                tarball_url: "https://registry.npmjs.org/@rolldown/binding-win32-arm64-msvc/-/binding-win32-arm64-msvc-1.2.4.tgz",
                tarball_integrity: "sha512-AWLi0uBRYh6QlE7OKhiz+phZC0qwtij2QZmhmOdsLdFn64m7oMpooE9ICE3lhm9xMb4SpDo2WbHcxX1iFLFtqw==",
            },
        ],
    },
];

static ENGINES: &[EngineDef] = &[
    EngineDef {
        name: "tsgo",
        latest_version: TSGO_VERSION,
        assets: TSGO_ASSETS,
    },
    EngineDef {
        name: "rolldown",
        latest_version: ROLLDOWN_VERSION,
        assets: ROLLDOWN_ASSETS,
    },
];

pub async fn ensure_engine(
    engine_name: &str,
    pinned_version: Option<&str>,
    quiet: bool,
) -> Result<PathBuf, LpmError> {
    let def = get_engine(engine_name)
        .ok_or_else(|| LpmError::Engine(format!("unknown engine: '{engine_name}'")))?;
    let platform = Platform::current()?;
    let platform_str = platform.to_string();
    let version = resolve_engine_version(def, pinned_version, &platform_str)?;
    let asset = resolve_engine_asset(def, &version, &platform_str)?;
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
            &asset.packages,
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

pub fn user_facing_engine_tool_names() -> &'static [&'static str] {
    MANAGED_ENGINE_TOOL_NAMES
}

pub fn resolve_engine_version_for_current_platform(
    engine_name: &str,
    pinned_version: Option<&str>,
) -> Result<String, LpmError> {
    let def = get_engine(engine_name)
        .ok_or_else(|| LpmError::Engine(format!("unknown engine: '{engine_name}'")))?;
    let platform = Platform::current()?.to_string();
    resolve_engine_version(def, pinned_version, &platform)
}

pub fn get_latest_engine_version(engine_name: &str) -> Result<String, LpmError> {
    let def = get_engine(engine_name)
        .ok_or_else(|| LpmError::Engine(format!("unknown engine: '{engine_name}'")))?;
    let platform = Platform::current()?.to_string();
    Ok(read_cached_engine_selected(def.name, &platform)
        .filter(|cached| crate::versions::is_newer_semver(cached, def.latest_version))
        .unwrap_or_else(|| def.latest_version.to_string()))
}

pub fn list_installed_versions(engine_name: &str) -> Result<Vec<String>, LpmError> {
    let dir = engines_dir()?.join(engine_name);
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut versions = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        if entry.path().is_dir() {
            versions.push(entry.file_name().to_string_lossy().to_string());
        }
    }
    versions.sort_by(|a, b| compare_semver_like(a, b));
    Ok(versions)
}

pub fn remove_version(engine_name: &str, version: &str) -> Result<bool, LpmError> {
    let dir = engine_version_dir(engine_name, version)?;
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn remove_all(engine_name: &str) -> Result<usize, LpmError> {
    let dir = engines_dir()?.join(engine_name);
    if !dir.exists() {
        return Ok(0);
    }

    let versions = list_installed_versions(engine_name)?;
    let count = versions.len();
    std::fs::remove_dir_all(&dir)?;
    Ok(count)
}

fn resolve_engine_version(
    def: &EngineDef,
    pinned_version: Option<&str>,
    platform: &str,
) -> Result<String, LpmError> {
    match pinned_version {
        None => Ok(get_latest_engine_version_for_platform(def, platform)),
        Some(version) if version == def.latest_version => Ok(version.to_string()),
        Some(version) if cached_engine_asset(def.name, version, platform).is_some() => {
            Ok(version.to_string())
        }
        Some(version) => Err(LpmError::Engine(format!(
            "tools.{} is pinned to {}, but that version is not approved for {}. \
             Run `lpm plugin update {}` to approve a verified version, or remove the pin to use {}.",
            def.name, version, platform, def.name, def.latest_version,
        ))),
    }
}

fn resolve_engine_asset(
    def: &EngineDef,
    version: &str,
    platform: &str,
) -> Result<ResolvedEngineAsset, LpmError> {
    if version != def.latest_version {
        return cached_engine_asset(def.name, version, platform).ok_or_else(|| {
            LpmError::Engine(format!(
                "engine '{}' version {} is approved without an install graph for {}; run `lpm plugin update {}` again",
                def.name, version, platform, def.name,
            ))
        });
    }

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
        entry_rel_path: asset.entry_rel_path.to_string(),
        packages: asset
            .packages
            .iter()
            .map(|package| ResolvedEngineInstallAsset {
                install_subdir: package.install_subdir.to_string(),
                tarball_url: package.tarball_url.to_string(),
                tarball_integrity: package.tarball_integrity.to_string(),
            })
            .collect(),
    })
}

fn compare_semver_like(a: &str, b: &str) -> std::cmp::Ordering {
    match (Version::parse(a), Version::parse(b)) {
        (Ok(a), Ok(b)) => a.cmp(&b),
        _ => a.cmp(b),
    }
}

fn get_latest_engine_version_for_platform(def: &EngineDef, platform: &str) -> String {
    read_cached_engine_selected(def.name, platform)
        .filter(|cached| crate::versions::is_newer_semver(cached, def.latest_version))
        .unwrap_or_else(|| def.latest_version.to_string())
}

fn read_cached_engine_selected(engine_name: &str, platform: &str) -> Option<String> {
    let cache = read_engine_version_cache().ok()?;
    cache
        .engines
        .get(engine_name)?
        .selected
        .get(platform)
        .cloned()
}

fn cached_engine_asset(
    engine_name: &str,
    version: &str,
    platform: &str,
) -> Option<ResolvedEngineAsset> {
    let cache = read_engine_version_cache().ok()?;
    cache
        .engines
        .get(engine_name)?
        .assets
        .get(version)?
        .get(platform)
        .cloned()
}

fn approve_engine_version(
    engine_name: &str,
    version: &str,
    platform: &str,
    asset: &ResolvedEngineAsset,
) -> Result<(), LpmError> {
    let cache_path = engine_version_cache_path()?;
    let mut cache = read_engine_version_cache_at(&cache_path).unwrap_or_default();
    let entry = cache.engines.entry(engine_name.to_string()).or_default();
    entry
        .selected
        .insert(platform.to_string(), version.to_string());
    entry
        .assets
        .entry(version.to_string())
        .or_default()
        .insert(platform.to_string(), asset.clone());

    if let Some(parent) = cache_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(&cache)
        .map_err(|e| LpmError::Engine(format!("failed to serialize engine version cache: {e}")))?;
    lpm_common::write_file_atomic_with_options(
        &cache_path,
        json.as_bytes(),
        lpm_common::AtomicWriteOptions::new().unix_mode(0o600),
    )
    .map_err(|e| LpmError::Engine(format!("failed to write engine version cache: {e}")))?;
    Ok(())
}

fn read_engine_version_cache() -> Result<EngineVersionCache, LpmError> {
    read_engine_version_cache_at(&engine_version_cache_path()?)
}

fn read_engine_version_cache_at(path: &Path) -> Result<EngineVersionCache, LpmError> {
    let content = std::fs::read_to_string(path)?;
    serde_json::from_str(&content)
        .map_err(|e| LpmError::Engine(format!("failed to parse engine version cache: {e}")))
}

fn engine_version_cache_path() -> Result<PathBuf, LpmError> {
    Ok(engines_dir()?.join(ENGINE_VERSION_CACHE_FILE_NAME))
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
            &asset.packages,
        ),
        EngineReuseDecision::Hit,
    ) {
        return Ok(entry_path);
    }

    if !quiet {
        eprintln!(
            "  Managed tool '{}' not installed. Downloading {} v{} ({})...",
            engine_name, engine_name, version, platform,
        );
    }

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

    let mut sidecar_packages = Vec::with_capacity(asset.packages.len());

    for package in &asset.packages {
        let bytes = download_tarball(&package.tarball_url).await?;
        lpm_extractor::verify_integrity(&bytes, &package.tarball_integrity)?;

        sidecar_packages.push(EngineSidecarPackage {
            install_subdir: package.install_subdir.clone(),
            tarball_url: package.tarball_url.clone(),
            tarball_integrity: package.tarball_integrity.clone(),
            tarball_sha256: compute_sha256(&bytes),
        });

        let extract_root = install_root_for_stage(&stage_dir, &package.install_subdir)?;
        std::fs::create_dir_all(&extract_root)?;

        if let Err(error) = verify_and_extract(&bytes, &package.tarball_integrity, &extract_root) {
            let _ = std::fs::remove_dir_all(&stage_dir);
            return Err(error);
        }
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
        sidecar_packages,
        layout_sha256,
    );
    if let Err(error) = write_sidecar_atomic(&sidecar_path, &sidecar) {
        let _ = std::fs::remove_dir_all(&platform_dir);
        return Err(error);
    }

    Ok(entry_path)
}

async fn download_tarball(url: &str) -> Result<Vec<u8>, LpmError> {
    validate_fetch_url(url, "engine tarball")?;

    let client = lpm_http::client_builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| LpmError::Network(format!("failed to create HTTP client: {e}")))?;

    let resp = client
        .get(url)
        .header("User-Agent", "lpm-cli")
        .send()
        .await
        .map_err(|e| {
            LpmError::Network(format!(
                "failed to download engine tarball: {}",
                lpm_http::display_error(&e)
            ))
        })?;

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
            bytes.len(),
            MAX_ENGINE_DOWNLOAD_SIZE,
        )));
    }

    Ok(bytes.to_vec())
}

pub async fn peek_latest_engine_version(engine_name: &str) -> Result<String, String> {
    match engine_name {
        "rolldown" => {
            let client = npm_client().map_err(|e| e.to_string())?;
            let base = managed_tool_npm_registry_base().map_err(|e| e.to_string())?;
            let metadata = fetch_npm_version_metadata(&client, &base, "rolldown", "latest")
                .await
                .map_err(|e| e.to_string())?;
            Ok(metadata.version)
        }
        _ => Err(format!(
            "managed engine '{engine_name}' is not exposed through `lpm plugin update`"
        )),
    }
}

pub async fn update_engine_with_observer(
    engine_name: &str,
    observer: &mut (dyn FnMut(EngineInstallEvent) + Send),
) -> Result<String, LpmError> {
    update_engine_with_optional_observer(engine_name, Some(observer)).await
}

pub async fn update_engine(engine_name: &str) -> Result<String, LpmError> {
    update_engine_with_optional_observer(engine_name, None).await
}

async fn update_engine_with_optional_observer(
    engine_name: &str,
    observer: Option<&mut (dyn FnMut(EngineInstallEvent) + Send)>,
) -> Result<String, LpmError> {
    let def = get_engine(engine_name)
        .ok_or_else(|| LpmError::Engine(format!("unknown engine: '{engine_name}'")))?;
    if !MANAGED_ENGINE_TOOL_NAMES.contains(&def.name) {
        return Err(LpmError::Engine(format!(
            "managed engine '{}' is internal and is not updated through `lpm plugin update`",
            def.name
        )));
    }

    let lock_path = engine_update_lock_path(def.name)?;
    lpm_common::with_exclusive_lock_async(lock_path, run_engine_update_under_lock(def, observer))
        .await
}

async fn run_engine_update_under_lock(
    def: &'static EngineDef,
    mut observer: Option<&mut (dyn FnMut(EngineInstallEvent) + Send)>,
) -> Result<String, LpmError> {
    emit_engine_install_event(
        &mut observer,
        EngineInstallEvent::ResolvingLatest {
            engine: def.name.to_string(),
        },
    );

    let platform = Platform::current()?;
    let platform_str = platform.to_string();
    let (latest_version, fetched_asset) = match def.name {
        "rolldown" => fetch_latest_rolldown_asset_for_platform(&platform_str).await?,
        _ => {
            return Err(LpmError::Engine(format!(
                "managed engine '{}' is not user-updatable",
                def.name
            )));
        }
    };

    let (target_version, asset) =
        if crate::versions::is_newer_semver(&latest_version, def.latest_version) {
            (latest_version, fetched_asset)
        } else {
            (
                def.latest_version.to_string(),
                resolve_engine_asset(def, def.latest_version, &platform_str)?,
            )
        };

    emit_engine_install_event(
        &mut observer,
        EngineInstallEvent::Downloading {
            engine: def.name.to_string(),
            version: target_version.clone(),
        },
    );
    install_under_lock(
        def.name,
        &target_version,
        &platform_str,
        asset.clone(),
        true,
    )
    .await?;
    emit_engine_install_event(
        &mut observer,
        EngineInstallEvent::VerifiedIntegrity {
            engine: def.name.to_string(),
            version: target_version.clone(),
        },
    );
    approve_engine_version(def.name, &target_version, &platform_str, &asset)?;
    Ok(target_version)
}

fn emit_engine_install_event(
    observer: &mut Option<&mut (dyn FnMut(EngineInstallEvent) + Send)>,
    event: EngineInstallEvent,
) {
    if let Some(observer) = observer.as_deref_mut() {
        observer(event);
    }
}

async fn fetch_latest_rolldown_asset_for_platform(
    platform: &str,
) -> Result<(String, ResolvedEngineAsset), LpmError> {
    let client = npm_client()?;
    let base = managed_tool_npm_registry_base()?;
    let root = fetch_npm_version_metadata(&client, &base, "rolldown", "latest").await?;

    let pluginutils_req = root
        .dependencies
        .get("@rolldown/pluginutils")
        .ok_or_else(|| {
            LpmError::Engine("rolldown metadata is missing @rolldown/pluginutils".into())
        })?;
    let oxc_types_req = root.dependencies.get("@oxc-project/types").ok_or_else(|| {
        LpmError::Engine("rolldown metadata is missing @oxc-project/types".into())
    })?;
    let binding_package = rolldown_binding_package_for_platform(platform)?;
    let binding_req = root
        .optional_dependencies
        .get(binding_package)
        .ok_or_else(|| {
            LpmError::Engine(format!(
                "rolldown metadata is missing {binding_package} for {platform}"
            ))
        })?;

    let pluginutils =
        resolve_npm_dependency_metadata(&client, &base, "@rolldown/pluginutils", pluginutils_req)
            .await?;
    let oxc_types =
        resolve_npm_dependency_metadata(&client, &base, "@oxc-project/types", oxc_types_req)
            .await?;
    let binding =
        resolve_npm_dependency_metadata(&client, &base, binding_package, binding_req).await?;

    let packages = vec![
        npm_package_asset("", &root)?,
        npm_package_asset("node_modules/@rolldown/pluginutils", &pluginutils)?,
        npm_package_asset("node_modules/@oxc-project/types", &oxc_types)?,
        npm_package_asset(&format!("node_modules/{binding_package}"), &binding)?,
    ];

    Ok((
        root.version.clone(),
        ResolvedEngineAsset {
            entry_rel_path: "bin/cli.mjs".into(),
            packages,
        },
    ))
}

fn npm_package_asset(
    install_subdir: &str,
    metadata: &NpmVersionMetadata,
) -> Result<ResolvedEngineInstallAsset, LpmError> {
    if metadata.dist.integrity.is_empty() {
        return Err(LpmError::Engine(format!(
            "npm metadata for version {} is missing dist.integrity",
            metadata.version
        )));
    }
    validate_fetch_url(&metadata.dist.tarball, "npm tarball")?;
    Ok(ResolvedEngineInstallAsset {
        install_subdir: install_subdir.to_string(),
        tarball_url: metadata.dist.tarball.clone(),
        tarball_integrity: metadata.dist.integrity.clone(),
    })
}

fn npm_client() -> Result<reqwest::Client, LpmError> {
    lpm_http::client_builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| LpmError::Network(format!("failed to create npm HTTP client: {e}")))
}

fn managed_tool_npm_registry_base() -> Result<String, LpmError> {
    let raw = std::env::var(MANAGED_TOOL_NPM_REGISTRY_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| lpm_common::NPM_REGISTRY_URL.to_string());
    validate_fetch_url(&raw, "npm registry")?;
    Ok(raw.trim_end_matches('/').to_string())
}

async fn fetch_npm_version_metadata(
    client: &reqwest::Client,
    base: &str,
    package: &str,
    version: &str,
) -> Result<NpmVersionMetadata, LpmError> {
    let url = format!("{}/{}/{}", base, encode_npm_package_path(package), version);
    fetch_json(client, &url, "npm version metadata").await
}

async fn fetch_npm_packument(
    client: &reqwest::Client,
    base: &str,
    package: &str,
) -> Result<NpmPackument, LpmError> {
    let url = format!("{}/{}", base, encode_npm_package_path(package));
    fetch_json(client, &url, "npm package metadata").await
}

async fn resolve_npm_dependency_metadata(
    client: &reqwest::Client,
    base: &str,
    package: &str,
    requirement: &str,
) -> Result<NpmVersionMetadata, LpmError> {
    let trimmed = requirement.trim();
    let exact = trimmed.strip_prefix('=').unwrap_or(trimmed);
    if Version::parse(exact).is_ok() {
        return fetch_npm_version_metadata(client, base, package, exact).await;
    }

    let req = VersionReq::parse(trimmed).map_err(|e| {
        LpmError::Engine(format!(
            "failed to parse npm dependency range {package}@{trimmed}: {e}"
        ))
    })?;
    let packument = fetch_npm_packument(client, base, package).await?;
    let mut best: Option<(Version, String)> = None;
    for version in packument.versions.keys() {
        let Ok(parsed) = Version::parse(version) else {
            continue;
        };
        if !req.matches(&parsed) {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|(best_version, _)| parsed > *best_version)
        {
            best = Some((parsed, version.clone()));
        }
    }

    let (_, version_key) = best.ok_or_else(|| {
        LpmError::Engine(format!(
            "no npm version of {package} satisfies required range {trimmed}"
        ))
    })?;
    packument
        .versions
        .get(&version_key)
        .cloned()
        .ok_or_else(|| {
            LpmError::Engine(format!(
                "resolved npm version {package}@{version_key} disappeared from metadata"
            ))
        })
}

async fn fetch_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    context: &str,
) -> Result<T, LpmError> {
    validate_fetch_url(url, context)?;
    let resp = client
        .get(url)
        .header("User-Agent", "lpm-cli")
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| {
            LpmError::Network(format!(
                "failed to fetch {context}: {}",
                lpm_http::display_error(&e)
            ))
        })?;
    if !resp.status().is_success() {
        return Err(LpmError::Http {
            status: resp.status().as_u16(),
            message: format!("failed to fetch {context} from {url}"),
        });
    }
    resp.json()
        .await
        .map_err(|e| LpmError::Network(format!("failed to parse {context}: {e}")))
}

fn encode_npm_package_path(name: &str) -> String {
    name.replace('@', "%40").replace('/', "%2f")
}

fn rolldown_binding_package_for_platform(platform: &str) -> Result<&'static str, LpmError> {
    match platform {
        "darwin-arm64" => Ok("@rolldown/binding-darwin-arm64"),
        "darwin-x64" => Ok("@rolldown/binding-darwin-x64"),
        "linux-arm" => Ok("@rolldown/binding-linux-arm-gnueabihf"),
        "linux-arm64" => Ok("@rolldown/binding-linux-arm64-gnu"),
        "linux-x64" => Ok("@rolldown/binding-linux-x64-gnu"),
        "win-arm64" => Ok("@rolldown/binding-win32-arm64-msvc"),
        "win-x64" => Ok("@rolldown/binding-win32-x64-msvc"),
        _ => Err(LpmError::Engine(format!(
            "rolldown has no npm binding package for platform {platform}"
        ))),
    }
}

fn validate_fetch_url(url: &str, context: &str) -> Result<(), LpmError> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| LpmError::Engine(format!("invalid {context} URL {url}: {e}")))?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if parsed.host_str().is_some_and(lpm_common::is_loopback_host) => Ok(()),
        scheme => Err(LpmError::Engine(format!(
            "refusing {context} URL {url}: scheme {scheme:?} is not allowed"
        ))),
    }
}

fn validate_for_reuse(
    sidecar_path: &Path,
    install_dir: &Path,
    requested_engine: &str,
    requested_version: &str,
    current_platform: &str,
    expected_entry_rel_path: &str,
    expected_packages: &[ResolvedEngineInstallAsset],
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
    if sidecar.packages.len() != expected_packages.len() {
        return EngineReuseDecision::Miss(EngineMissReason::IdentityMismatch);
    }
    if sidecar
        .packages
        .iter()
        .zip(expected_packages)
        .any(|(observed, expected)| {
            observed.install_subdir != expected.install_subdir
                || observed.tarball_url != expected.tarball_url
                || observed.tarball_integrity != expected.tarball_integrity
        })
    {
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
    lpm_common::write_file_atomic_with_options(
        sidecar_path,
        json.as_bytes(),
        lpm_common::AtomicWriteOptions::new().unix_mode(0o600),
    )
    .map_err(|e| LpmError::Engine(format!("failed to write engine sidecar: {e}")))?;
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

fn collect_files(
    root: &Path,
    current: &Path,
    rel_files: &mut Vec<PathBuf>,
) -> Result<(), LpmError> {
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
        if rel.as_path() == Path::new(ENGINE_SIDECAR_FILE_NAME) {
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

fn install_root_for_stage(stage_dir: &Path, install_subdir: &str) -> Result<PathBuf, LpmError> {
    if install_subdir.is_empty() {
        return Ok(stage_dir.to_path_buf());
    }

    let rel = Path::new(install_subdir);
    if rel.is_absolute() {
        return Err(LpmError::Engine(format!(
            "engine install subdir must be relative: {install_subdir}"
        )));
    }

    for component in rel.components() {
        match component {
            std::path::Component::CurDir | std::path::Component::Normal(_) => {}
            _ => {
                return Err(LpmError::Engine(format!(
                    "engine install subdir contains invalid component: {install_subdir}"
                )));
            }
        }
    }

    Ok(stage_dir.join(rel))
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

fn engine_version_dir(engine_name: &str, version: &str) -> Result<PathBuf, LpmError> {
    let engines_root = engines_dir()?;
    engine_version_dir_at(&engines_root, engine_name, version)
}

fn engine_platform_dir(
    engine_name: &str,
    version: &str,
    platform: &str,
) -> Result<PathBuf, LpmError> {
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

fn engine_sidecar_path(
    engine_name: &str,
    version: &str,
    platform: &str,
) -> Result<PathBuf, LpmError> {
    let engines_root = engines_dir()?;
    engine_sidecar_path_at(&engines_root, engine_name, version, platform)
}

fn engine_sidecar_path_at(
    engines_root: &Path,
    engine_name: &str,
    version: &str,
    platform: &str,
) -> Result<PathBuf, LpmError> {
    Ok(
        engine_platform_dir_at(engines_root, engine_name, version, platform)?
            .join(ENGINE_SIDECAR_FILE_NAME),
    )
}

fn engine_entry_path(
    engine_name: &str,
    version: &str,
    platform: &str,
    entry_rel_path: &str,
) -> Result<PathBuf, LpmError> {
    let engines_root = engines_dir()?;
    engine_entry_path_at(
        &engines_root,
        engine_name,
        version,
        platform,
        entry_rel_path,
    )
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

fn engine_update_lock_path(engine_name: &str) -> Result<PathBuf, LpmError> {
    Ok(engines_dir()?.join(engine_name).join(".update.lock"))
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
        std::fs::write(
            install_dir.join("lib/lib.d.ts"),
            b"declare const x: string;",
        )
        .unwrap();

        let layout_sha256 = hash_directory_tree(&install_dir).unwrap();
        let sidecar = EngineSidecar::new(
            "tsgo",
            "1.0.0",
            "darwin-arm64",
            entry_rel_path,
            vec![EngineSidecarPackage {
                install_subdir: "".into(),
                tarball_url: "https://example.test/native-preview.tgz".into(),
                tarball_integrity: "sha512-test".into(),
                tarball_sha256: "tarball-sha".into(),
            }],
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
            &[ResolvedEngineInstallAsset {
                install_subdir: "".into(),
                tarball_url: "https://example.test/native-preview.tgz".into(),
                tarball_integrity: "sha512-test".into(),
            }],
        );
        assert_eq!(
            decision,
            EngineReuseDecision::Miss(EngineMissReason::LayoutHashMismatch)
        );
        assert!(entry_path.exists());
    }

    #[test]
    fn validate_for_reuse_detects_engine_package_definition_drift() {
        let dir = tempfile::tempdir().unwrap();
        let install_dir = dir.path().join("tsgo").join("1.0.0").join("darwin-arm64");
        install_fake_engine(dir.path(), "lib/tsgo");

        let decision = validate_for_reuse(
            &install_dir.join(ENGINE_SIDECAR_FILE_NAME),
            &install_dir,
            "tsgo",
            "1.0.0",
            "darwin-arm64",
            "lib/tsgo",
            &[ResolvedEngineInstallAsset {
                install_subdir: "".into(),
                tarball_url: "https://example.test/other-native-preview.tgz".into(),
                tarball_integrity: "sha512-test".into(),
            }],
        );

        assert_eq!(
            decision,
            EngineReuseDecision::Miss(EngineMissReason::IdentityMismatch)
        );
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
                entry_rel_path: "lib/tsgo".into(),
                packages: vec![ResolvedEngineInstallAsset {
                    install_subdir: "".into(),
                    tarball_url: format!("{}/tsgo.tgz", server.uri()),
                    tarball_integrity: integrity,
                }],
            },
            true,
        )
        .await
        .unwrap();

        assert!(result.exists());
        assert!(
            home.path()
                .join("engines/tsgo/1.0.0/darwin-arm64/lib/lib.d.ts")
                .exists()
        );
        assert!(
            home.path()
                .join("engines/tsgo/1.0.0/darwin-arm64/.lpm-engine.json")
                .exists()
        );
    }

    #[tokio::test]
    async fn install_under_lock_supports_nested_engine_packages() {
        let rolldown_tarball = create_test_tarball(&[
            ("bin/cli.mjs", b"#!/usr/bin/env node\n"),
            ("package.json", br#"{"name":"rolldown","version":"1.0.2"}"#),
        ]);
        let binding_tarball = create_test_tarball(&[
            (
                "package.json",
                br#"{"name":"@rolldown/binding-darwin-arm64","version":"1.0.2"}"#,
            ),
            ("rolldown-binding.darwin-arm64.node", b"binding-bytes"),
        ]);
        let rolldown_integrity = lpm_common::Integrity::from_bytes(
            lpm_common::integrity::HashAlgorithm::Sha512,
            &rolldown_tarball,
        )
        .to_string();
        let binding_integrity = lpm_common::Integrity::from_bytes(
            lpm_common::integrity::HashAlgorithm::Sha512,
            &binding_tarball,
        )
        .to_string();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rolldown.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(rolldown_tarball.clone()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/binding.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(binding_tarball.clone()))
            .mount(&server)
            .await;

        let home = tempfile::tempdir().unwrap();
        let engines_root = home.path().join("engines");
        let result = install_under_lock_at(
            &engines_root,
            "rolldown",
            "1.0.2",
            "darwin-arm64",
            ResolvedEngineAsset {
                entry_rel_path: "bin/cli.mjs".into(),
                packages: vec![
                    ResolvedEngineInstallAsset {
                        install_subdir: "".into(),
                        tarball_url: format!("{}/rolldown.tgz", server.uri()),
                        tarball_integrity: rolldown_integrity,
                    },
                    ResolvedEngineInstallAsset {
                        install_subdir: "node_modules/@rolldown/binding-darwin-arm64".into(),
                        tarball_url: format!("{}/binding.tgz", server.uri()),
                        tarball_integrity: binding_integrity,
                    },
                ],
            },
            true,
        )
        .await
        .unwrap();

        assert!(result.exists());
        assert!(
            home.path()
                .join("engines/rolldown/1.0.2/darwin-arm64/bin/cli.mjs")
                .exists()
        );
        assert!(home
            .path()
            .join(
                "engines/rolldown/1.0.2/darwin-arm64/node_modules/@rolldown/binding-darwin-arm64/package.json"
            )
            .exists());
    }

    #[test]
    fn resolve_engine_version_rejects_unbundled_pin() {
        let error =
            resolve_engine_version(get_engine("tsgo").unwrap(), Some("1.0.0"), "darwin-arm64")
                .unwrap_err();
        assert!(error.to_string().contains("not approved"));
    }
}
