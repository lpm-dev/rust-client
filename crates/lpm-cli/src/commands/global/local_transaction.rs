use super::{LocalLinkPackage, UnlinkSummary, linked_source_path};
use crate::directory_transaction::{
    DirectoryIdentity, create_private_directory, directory_identity, discard_private_directory,
    open_directory_for_publication, open_directory_shared, publish_entry_noreplace,
};
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
use cap_std::fs::Dir;
use lpm_common::{GlobalStateDirectories, LpmError, LpmRoot};
use lpm_global::{AliasEntry, GlobalManifest, PackageEntry, PackageSource, Shim};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::ffi::OsStr;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};

const JOURNAL: &str = "local-link-transaction.json";
const FILE_CAP: u64 = 64 * 1024;
const PROVENANCE: &str = ".lpm-link-provenance.json";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    name: String,
    value: Value,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "kebab-case")]
enum Value {
    Symlink(PathBuf),
    File(String),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    finished: bool,
    unlink: bool,
    package: String,
    entry: PackageEntry,
    aliases: BTreeMap<String, AliasEntry>,
    wrapper_identity: Option<DirectoryIdentity>,
    archive: String,
    archive_identity: DirectoryIdentity,
    wrapper: Vec<Artifact>,
    global: Vec<Artifact>,
}

fn invalid(message: impl Into<String>) -> LpmError {
    LpmError::Script(message.into())
}

fn sync(directory: &Dir) -> io::Result<()> {
    #[cfg(unix)]
    directory.open(".")?.sync_all()?;
    #[cfg(not(unix))]
    let _ = directory;
    Ok(())
}

fn read_value(directory: &Dir, name: &str) -> Result<Option<Value>, LpmError> {
    let metadata = match directory.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    #[cfg(unix)]
    if metadata.is_symlink() {
        return Ok(Some(Value::Symlink(directory.read_link_contents(name)?)));
    }
    if !metadata.is_file() || metadata.len() > FILE_CAP {
        return Err(invalid(format!(
            "refusing unexpected local-link artifact '{name}'"
        )));
    }
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = directory.open_with(name, &options)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("local-link artifact changed during inspection"));
    }
    let mut text = String::new();
    file.take(FILE_CAP + 1).read_to_string(&mut text)?;
    if text.len() as u64 > FILE_CAP {
        return Err(invalid("local-link artifact exceeds the size limit"));
    }
    Ok(Some(Value::File(text)))
}

fn artifacts(shim: &Shim) -> Result<Vec<Artifact>, LpmError> {
    lpm_global::shim::validate_command_name(&shim.command_name)?;
    #[cfg(unix)]
    {
        Ok(vec![Artifact {
            name: shim.command_name.clone(),
            value: Value::Symlink(shim.target.clone()),
        }])
    }
    #[cfg(windows)]
    {
        Ok(lpm_global::shim::windows_shim_contents(shim)?
            .into_iter()
            .map(|(name, value)| Artifact {
                name,
                value: Value::File(value),
            })
            .collect())
    }
}

pub(super) fn validate_bins(bins: &[super::LocalLinkBin]) -> Result<(), LpmError> {
    let mut output = Vec::new();
    for bin in bins {
        output.extend(artifacts(&Shim {
            command_name: bin.command_name.clone(),
            target: bin.target.clone(),
        })?);
    }
    validate_artifacts(&output)?;
    if provenance_bytes(&output)?.len() as u64 > FILE_CAP {
        return Err(invalid(
            "local-link command inventory exceeds the size limit",
        ));
    }
    Ok(())
}

fn validate_artifacts(artifacts: &[Artifact]) -> Result<(), LpmError> {
    let mut names = HashSet::with_capacity(artifacts.len());
    for artifact in artifacts {
        lpm_global::shim::validate_command_name(&artifact.name)?;
        let name = if cfg!(any(target_os = "macos", windows)) {
            artifact.name.to_ascii_lowercase()
        } else {
            artifact.name.clone()
        };
        if !names.insert(name) {
            return Err(invalid(
                "local package declares overlapping command artifacts",
            ));
        }
    }
    Ok(())
}

fn global_artifacts(
    root: &LpmRoot,
    package: &str,
    entry: &PackageEntry,
    aliases: &BTreeMap<String, AliasEntry>,
) -> Result<Vec<Artifact>, LpmError> {
    wrapper_leaf(entry)?;
    let install_bin = root
        .global_root()
        .join(&entry.root)
        .join("node_modules/.bin");
    let mut result = Vec::new();
    for name in &entry.commands {
        result.extend(artifacts(&Shim {
            command_name: name.clone(),
            target: install_bin.join(name),
        })?);
    }
    for (name, alias) in aliases {
        lpm_global::shim::validate_command_name(&alias.bin)?;
        if alias.package != package || !entry.commands.contains(&alias.bin) {
            return Err(invalid("invalid local-link alias owner or target"));
        }
        result.extend(artifacts(&Shim {
            command_name: name.clone(),
            target: install_bin.join(&alias.bin),
        })?);
    }
    validate_artifacts(&result)?;
    Ok(result)
}

fn provenance_bytes(wrapper: &[Artifact]) -> Result<Vec<u8>, LpmError> {
    serde_json::to_vec(wrapper).map_err(|error| invalid(error.to_string()))
}

fn provenance_integrity(bytes: &[u8]) -> String {
    format!("local-link-sha256-{}", hex::encode(Sha256::digest(bytes)))
}

fn read_bytes(directory: &Dir, name: &str, cap: u64) -> Result<Option<Vec<u8>>, LpmError> {
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = match directory.open_with(name, &options) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > cap {
        return Err(invalid(format!("invalid local-link state file '{name}'")));
    }
    let mut bytes = Vec::new();
    file.take(cap + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(invalid("local-link state exceeds the size limit"));
    }
    Ok(Some(bytes))
}

fn read_manifest(directory: &Dir) -> Result<GlobalManifest, LpmError> {
    let Some(bytes) = read_bytes(
        directory,
        lpm_global::MANIFEST_FILENAME,
        lpm_common::STATE_FILE_SIZE_CAP_BYTES,
    )?
    else {
        return Ok(GlobalManifest::default());
    };
    lpm_global::manifest::parse_manifest(&bytes)
}

fn require_missing(directory: &Dir, artifacts: &[Artifact]) -> Result<(), LpmError> {
    for artifact in artifacts {
        if directory.symlink_metadata(&artifact.name).is_ok() {
            return Err(invalid(format!(
                "command artifact '{}' already exists; move it before linking",
                artifact.name
            )));
        }
        match directory.symlink_metadata(&artifact.name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(invalid("command artifact changed during inspection")),
        }
    }
    Ok(())
}

fn require_owned(directory: &Dir, artifacts: &[Artifact]) -> Result<(), LpmError> {
    for artifact in artifacts {
        if read_value(directory, &artifact.name)?.is_some_and(|value| value != artifact.value) {
            return Err(invalid(format!(
                "command artifact '{}' changed; move it before unlinking",
                artifact.name
            )));
        }
    }
    Ok(())
}

fn publish(
    directory: &Dir,
    archive: &Dir,
    artifact: &Artifact,
    staged: &str,
) -> Result<(), LpmError> {
    #[cfg(unix)]
    if let Value::Symlink(target) = &artifact.value {
        directory.symlink_contents(target, &artifact.name)?;
        sync(directory)?;
        return Ok(());
    }
    let Value::File(text) = &artifact.value else {
        return Err(invalid("invalid local-link artifact for this platform"));
    };
    let mut options = cap_std::fs::OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    let mut file = archive.open_with(staged, &options)?;
    pause("after-global-link-stage-created");
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    drop(file);
    publish_entry_noreplace(
        archive,
        OsStr::new(staged),
        directory,
        OsStr::new(&artifact.name),
    )?;
    sync(directory)?;
    sync(archive)?;
    Ok(())
}

fn write_journal(directory: &Dir, journal: &Journal) -> Result<(), LpmError> {
    let bytes = serde_json::to_vec(journal).map_err(|error| invalid(error.to_string()))?;
    if bytes.len() as u64 > lpm_common::STATE_FILE_SIZE_CAP_BYTES {
        return Err(invalid("local-link transaction exceeds the size limit"));
    }
    lpm_common::write_file_atomic_in_dir_with(directory, OsStr::new(JOURNAL), |file| {
        file.write_all(&bytes)?;
        file.sync_all()
    })?;
    sync(directory)?;
    Ok(())
}

fn write_manifest(directory: &Dir, manifest: &GlobalManifest) -> Result<(), LpmError> {
    let text = toml::to_string_pretty(manifest).map_err(|error| invalid(error.to_string()))?;
    lpm_common::write_file_atomic_in_dir_with(
        directory,
        OsStr::new(lpm_global::MANIFEST_FILENAME),
        |file| {
            file.write_all(text.as_bytes())?;
            file.sync_all()
        },
    )?;
    sync(directory)?;
    Ok(())
}

fn wrapper_bin(wrapper: &Dir, create: bool) -> Result<Dir, LpmError> {
    if create {
        wrapper.create_dir("node_modules")?;
        sync(wrapper)?;
    }
    let modules = open_directory_shared(wrapper, OsStr::new("node_modules"))?;
    if create {
        modules.create_dir(".bin")?;
        sync(&modules)?;
    }
    Ok(open_directory_shared(&modules, OsStr::new(".bin"))?)
}

fn wrapper_leaf(entry: &PackageEntry) -> Result<&OsStr, LpmError> {
    lpm_global::validated_local_link_root_relative(Path::new("/"), &entry.root).map_err(invalid)?;
    Path::new(&entry.root)
        .file_name()
        .ok_or_else(|| invalid("local-link root has no name"))
}

fn pause(stage: &str) {
    crate::install_recovery::test_pause(stage);
}

pub(super) fn link(
    root: &LpmRoot,
    link: &mut LocalLinkPackage,
    manifest: &mut GlobalManifest,
) -> Result<(), LpmError> {
    let dirs = GlobalStateDirectories::open_or_create(root)?;
    let (leaf, wrapper_dir) = create_private_directory(dirs.links(), "link")?;
    let mut archive_slot = None;
    let result = (|| {
        sync(dirs.links())?;
        link.root_relative = format!("links/{}", leaf.to_string_lossy());
        let mut wrapper = Vec::new();
        for bin in &link.bins {
            wrapper.extend(artifacts(&Shim {
                command_name: bin.command_name.clone(),
                target: bin.target.clone(),
            })?);
        }
        validate_artifacts(&wrapper)?;
        let provenance = provenance_bytes(&wrapper)?;
        let entry = PackageEntry {
            saved_spec: format!("link:{}", link.source_dir.display()),
            resolved: link.version.clone(),
            integrity: provenance_integrity(&provenance),
            source: PackageSource::LocalLink,
            installed_at: chrono::Utc::now(),
            root: link.root_relative.clone(),
            commands: link
                .bins
                .iter()
                .map(|bin| bin.command_name.clone())
                .collect(),
        };
        let aliases = BTreeMap::new();
        let global = global_artifacts(root, &link.name, &entry, &aliases)?;
        require_missing(dirs.bin(), &global)?;
        archive_slot = Some(create_private_directory(dirs.global(), "local-link")?);
        let (archive_name, archive_dir) = archive_slot
            .as_ref()
            .ok_or_else(|| invalid("local-link archive was not created"))?;
        let journal = Journal {
            version: 1,
            finished: false,
            unlink: false,
            package: link.name.clone(),
            entry: entry.clone(),
            aliases,
            wrapper_identity: Some(directory_identity(&wrapper_dir)?),
            archive: archive_name.to_string_lossy().into_owned(),
            archive_identity: directory_identity(archive_dir)?,
            wrapper,
            global,
        };
        write_journal(dirs.global(), &journal)?;
        pause("after-global-link-journal");
        lpm_common::write_file_atomic_in_dir_with(&wrapper_dir, OsStr::new(PROVENANCE), |file| {
            file.write_all(&provenance)?;
            file.sync_all()
        })?;
        sync(&wrapper_dir)?;
        let bin = wrapper_bin(&wrapper_dir, true)?;
        for (index, artifact) in journal.wrapper.iter().enumerate() {
            publish(
                &bin,
                archive_dir,
                artifact,
                &format!("publish-wrapper-{index}"),
            )?;
        }
        for (index, artifact) in journal.global.iter().enumerate() {
            publish(
                dirs.bin(),
                archive_dir,
                artifact,
                &format!("publish-global-{index}"),
            )?;
        }
        pause("after-global-link-shims");
        manifest.packages.insert(link.name.clone(), entry);
        write_manifest(dirs.global(), manifest)?;
        pause("after-global-link-manifest");
        Ok::<_, LpmError>(())
    })();
    let journal_missing = matches!(dirs.global().symlink_metadata(JOURNAL), Err(error) if error.kind() == io::ErrorKind::NotFound);
    if journal_missing {
        // Until the journal exists, both allocations contain no user files.
        let cleanup = discard_private_directory(wrapper_dir).and_then(|()| sync(dirs.links()));
        if let Some((_, archive)) = archive_slot {
            discard_private_directory(archive)?;
            sync(dirs.global())?;
        }
        return result.and(cleanup.map_err(LpmError::from));
    }
    drop(archive_slot);
    drop(wrapper_dir);
    result.and(recover_locked(root))
}

pub(super) fn unlink(
    root: &LpmRoot,
    package: &str,
    manifest: &mut GlobalManifest,
    entry: PackageEntry,
) -> Result<UnlinkSummary, LpmError> {
    let dirs = GlobalStateDirectories::open_or_create(root)?;
    let leaf = wrapper_leaf(&entry)?;
    let wrapper_dir = match open_directory_shared(dirs.links(), leaf) {
        Ok(directory) => Some(directory),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let aliases: BTreeMap<_, _> = manifest
        .aliases
        .iter()
        .filter(|(_, owner)| owner.package == package)
        .map(|(name, owner)| (name.clone(), owner.clone()))
        .collect();
    let global = global_artifacts(root, package, &entry, &aliases)?;
    require_owned(dirs.bin(), &global)?;
    // Older links have no immutable record of their wrapper contents.
    let preserve_wrapper = entry.integrity == "local-link";
    let mut wrapper = Vec::new();
    let mut wrapper_identity = None;
    if let Some(directory) = wrapper_dir.as_ref().filter(|_| !preserve_wrapper) {
        let bytes = read_bytes(directory, PROVENANCE, lpm_common::STATE_FILE_SIZE_CAP_BYTES)?
            .ok_or_else(|| invalid("local-link provenance is missing; preserving command files"))?;
        if provenance_integrity(&bytes) != entry.integrity {
            return Err(invalid(
                "local-link provenance changed; preserving command files",
            ));
        }
        wrapper = serde_json::from_slice(&bytes)
            .map_err(|error| invalid(format!("invalid local-link provenance: {error}")))?;
        validate_artifacts(&wrapper)?;
        let bin = wrapper_bin(directory, false)?;
        require_owned(&bin, &wrapper)?;
        wrapper_identity = Some(directory_identity(directory)?);
    }
    let (archive_name, archive_dir) = create_private_directory(dirs.global(), "local-link")?;
    let journal = Journal {
        version: 1,
        finished: false,
        unlink: true,
        package: package.into(),
        entry: entry.clone(),
        aliases,
        wrapper_identity,
        archive: archive_name.to_string_lossy().into_owned(),
        archive_identity: directory_identity(&archive_dir)?,
        wrapper,
        global,
    };
    if let Err(error) = write_journal(dirs.global(), &journal) {
        if matches!(dirs.global().symlink_metadata(JOURNAL), Err(error) if error.kind() == io::ErrorKind::NotFound)
        {
            discard_private_directory(archive_dir)?;
            sync(dirs.global())?;
        }
        return Err(error);
    }
    manifest.packages.remove(package);
    manifest.aliases.retain(|_, owner| owner.package != package);
    let result = write_manifest(dirs.global(), manifest);
    if result.is_ok() {
        pause("after-global-unlink-manifest");
    }
    drop(wrapper_dir);
    drop(archive_dir);
    let recovery = recover_locked(root);
    result.and(recovery)?;
    Ok(UnlinkSummary {
        package: package.into(),
        version: entry.resolved.clone(),
        linked_path: linked_source_path(&entry).map(str::to_string),
        commands: entry.commands,
        retained_wrapper: root
            .global_root()
            .join(&entry.root)
            .exists()
            .then(|| root.global_root().join(&entry.root)),
    })
}

pub(crate) fn pending(root: &LpmRoot) -> Result<bool, LpmError> {
    match std::fs::symlink_metadata(root.global_root().join(JOURNAL)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn recover(root: &LpmRoot) -> Result<(), LpmError> {
    if !pending(root)? {
        return Ok(());
    }
    lpm_common::with_exclusive_lock(root.global_tx_lock(), || recover_locked(root))
}

pub(super) fn recover_locked(root: &LpmRoot) -> Result<(), LpmError> {
    if !pending(root)? {
        return Ok(());
    }
    let dirs = GlobalStateDirectories::open_or_create(root)?;
    let bytes = read_bytes(
        dirs.global(),
        JOURNAL,
        lpm_common::STATE_FILE_SIZE_CAP_BYTES,
    )?
    .ok_or_else(|| invalid("local-link recovery journal disappeared"))?;
    let mut journal: Journal = serde_json::from_slice(&bytes)
        .map_err(|error| invalid(format!("invalid local-link recovery journal: {error}")))?;
    validate(root, &journal)?;
    if journal.finished {
        return finish_cleanup(&dirs, &journal);
    }
    let manifest = read_manifest(dirs.global())?;
    let same_root = |other: &str| {
        if cfg!(any(target_os = "macos", windows)) {
            other.eq_ignore_ascii_case(&journal.entry.root)
        } else {
            other == journal.entry.root
        }
    };
    let names: Vec<_> = journal
        .entry
        .commands
        .iter()
        .chain(journal.aliases.keys())
        .cloned()
        .collect();
    if manifest
        .packages
        .iter()
        .any(|(name, entry)| name != &journal.package && same_root(&entry.root))
        || !lpm_global::find_command_collisions(&manifest, &journal.package, &names).is_empty()
        || manifest.pending.iter().any(|(name, entry)| {
            name == &journal.package
                || same_root(&entry.root)
                || entry.commands.iter().any(|command| {
                    names.iter().any(|name| {
                        if cfg!(any(target_os = "macos", windows)) {
                            name.eq_ignore_ascii_case(command)
                        } else {
                            name == command
                        }
                    })
                })
        })
    {
        return Err(invalid(
            "local-link recovery conflicts with another manifest owner; preserving its commands",
        ));
    }
    let row = manifest.packages.get(&journal.package);
    let aliases: BTreeMap<_, _> = manifest
        .aliases
        .iter()
        .filter(|(_, owner)| owner.package == journal.package)
        .map(|(name, owner)| (name.clone(), owner.clone()))
        .collect();
    let installed = row == Some(&journal.entry) && aliases == journal.aliases;
    let absent = row.is_none() && aliases.is_empty();
    if !installed && !absent {
        return Err(invalid(
            "local-link state changed during recovery; preserving the pending transaction",
        ));
    }
    let archive = open_directory_shared(dirs.global(), OsStr::new(&journal.archive))?;
    if directory_identity(&archive)? != journal.archive_identity {
        return Err(invalid("local-link recovery archive changed"));
    }
    let remove_outputs = if journal.unlink { absent } else { !installed };
    if remove_outputs {
        if let Some(expected) = &journal.wrapper_identity {
            match open_directory_shared(dirs.links(), wrapper_leaf(&journal.entry)?) {
                Ok(wrapper) if &directory_identity(&wrapper)? != expected => {
                    return Err(invalid("local-link wrapper changed during recovery"));
                }
                Ok(wrapper) => {
                    let expected_bytes = provenance_bytes(&journal.wrapper)?;
                    match read_bytes(&wrapper, PROVENANCE, FILE_CAP)? {
                        Some(bytes) if bytes == expected_bytes => {}
                        Some(_) => {
                            return Err(invalid(
                                "local-link wrapper provenance changed during recovery",
                            ));
                        }
                        None => {
                            let mut published = journal.global.iter().any(|artifact| {
                                dirs.bin().symlink_metadata(&artifact.name).is_ok()
                            });
                            if let Ok(bin) = wrapper_bin(&wrapper, false) {
                                published |= journal
                                    .wrapper
                                    .iter()
                                    .any(|artifact| bin.symlink_metadata(&artifact.name).is_ok());
                            }
                            if published {
                                return Err(invalid(
                                    "local-link wrapper provenance is missing; preserving command files",
                                ));
                            }
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        for (index, artifact) in journal.global.iter().enumerate() {
            remove_owned(dirs.bin(), &archive, artifact, &format!("global-{index}"))?;
        }
        let leaf = wrapper_leaf(&journal.entry)?;
        if let Some(expected_identity) = &journal.wrapper_identity {
            match open_directory_shared(dirs.links(), leaf) {
                Ok(wrapper) => {
                    if &directory_identity(&wrapper)? != expected_identity {
                        return Err(invalid("local-link wrapper changed during recovery"));
                    }
                    match wrapper_bin(&wrapper, false) {
                        Ok(bin) => {
                            for (index, artifact) in journal.wrapper.iter().enumerate() {
                                remove_owned(
                                    &bin,
                                    &archive,
                                    artifact,
                                    &format!("wrapper-{index}"),
                                )?;
                            }
                            drop(bin);
                        }
                        Err(LpmError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error),
                    }
                    if let Ok(modules) = open_directory_shared(&wrapper, OsStr::new("node_modules"))
                    {
                        remove_empty(&modules, OsStr::new(".bin"))?;
                        drop(modules);
                        remove_empty(&wrapper, OsStr::new("node_modules"))?;
                    }
                    let provenance = String::from_utf8(provenance_bytes(&journal.wrapper)?)
                        .map_err(|error| invalid(error.to_string()))?;
                    remove_owned(
                        &wrapper,
                        &archive,
                        &Artifact {
                            name: PROVENANCE.into(),
                            value: Value::File(provenance),
                        },
                        "provenance",
                    )?;
                    drop(wrapper);
                    remove_empty(dirs.links(), leaf)?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    drop(archive);
    journal.finished = true;
    write_journal(dirs.global(), &journal)?;
    pause("after-global-link-cleanup");
    finish_cleanup(&dirs, &journal)
}

fn finish_cleanup(dirs: &GlobalStateDirectories, journal: &Journal) -> Result<(), LpmError> {
    match open_directory_shared(dirs.global(), OsStr::new(&journal.archive)) {
        Ok(archive) => {
            if directory_identity(&archive)? != journal.archive_identity {
                return Err(invalid("local-link recovery archive changed"));
            }
            let expected: BTreeMap<String, &Artifact> = journal
                .wrapper
                .iter()
                .enumerate()
                .map(|(index, artifact)| (format!("publish-wrapper-{index}"), artifact))
                .chain(
                    journal
                        .global
                        .iter()
                        .enumerate()
                        .map(|(index, artifact)| (format!("publish-global-{index}"), artifact)),
                )
                .collect();
            for entry in archive.entries()? {
                let name = entry?.file_name();
                let name = name
                    .to_str()
                    .ok_or_else(|| invalid("invalid local-link staging filename"))?;
                let artifact = expected.get(name).ok_or_else(|| {
                    invalid("local-link recovery archive retains an unrecorded artifact")
                })?;
                let bytes = read_bytes(&archive, name, FILE_CAP)?
                    .ok_or_else(|| invalid("local-link staging artifact disappeared"))?;
                if !valid_staging_bytes(&artifact.value, &bytes) {
                    return Err(invalid(
                        "local-link staging artifact changed; preserving it",
                    ));
                }
                archive.remove_file(name)?;
            }
            sync(&archive)?;
            drop(archive);
            remove_empty(dirs.global(), OsStr::new(&journal.archive))?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    dirs.global().remove_file(JOURNAL)?;
    sync(dirs.global())?;
    Ok(())
}

fn validate(root: &LpmRoot, journal: &Journal) -> Result<(), LpmError> {
    if journal.version != 1 || journal.entry.source != PackageSource::LocalLink {
        return Err(invalid("unsupported local-link recovery journal"));
    }
    wrapper_leaf(&journal.entry)?;
    let path = Path::new(&journal.archive);
    if !journal.archive.starts_with(".lpm-local-link-")
        || path.components().count() != 1
        || !matches!(
            path.components().next(),
            Some(std::path::Component::Normal(_))
        )
    {
        return Err(invalid("invalid local-link recovery archive"));
    }
    if global_artifacts(root, &journal.package, &journal.entry, &journal.aliases)? != journal.global
    {
        return Err(invalid(
            "local-link journal commands do not match their recorded owner",
        ));
    }
    validate_artifacts(&journal.wrapper)?;
    if journal.wrapper_identity.is_some() {
        if provenance_integrity(&provenance_bytes(&journal.wrapper)?) != journal.entry.integrity {
            return Err(invalid(
                "local-link journal provenance does not match its owner",
            ));
        }
        let expected: HashSet<_> = journal
            .entry
            .commands
            .iter()
            .flat_map(|name| lpm_global::expected_artifacts(Path::new(""), name))
            .collect();
        let actual: HashSet<_> = journal
            .wrapper
            .iter()
            .map(|artifact| PathBuf::from(&artifact.name))
            .collect();
        if expected != actual {
            return Err(invalid(
                "local-link journal wrapper commands do not match their owner",
            ));
        }
    } else if !journal.unlink || !journal.wrapper.is_empty() {
        return Err(invalid("local-link journal has no wrapper identity"));
    }
    for artifact in journal.global.iter().chain(&journal.wrapper) {
        lpm_global::shim::validate_command_name(&artifact.name)?;
        match &artifact.value {
            Value::File(text) if text.len() as u64 > FILE_CAP => {
                return Err(invalid("oversized local-link artifact"));
            }
            Value::Symlink(path) if !path.is_absolute() => {
                return Err(invalid("relative local-link recovery target"));
            }
            _ => {}
        }
    }
    Ok(())
}

fn remove_owned(
    directory: &Dir,
    archive: &Dir,
    artifact: &Artifact,
    staged: &str,
) -> Result<(), LpmError> {
    if read_value(archive, staged)?.is_none() {
        if read_value(directory, &artifact.name)?.is_none() {
            return Ok(());
        }
        publish_entry_noreplace(
            directory,
            OsStr::new(&artifact.name),
            archive,
            OsStr::new(staged),
        )?;
        sync(directory)?;
        sync(archive)?;
    }
    if read_value(archive, staged)? != Some(artifact.value.clone()) {
        publish_entry_noreplace(
            archive,
            OsStr::new(staged),
            directory,
            OsStr::new(&artifact.name),
        )?;
        sync(directory)?;
        sync(archive)?;
        return Err(invalid(format!(
            "local-link artifact '{}' changed; preserved it during recovery",
            artifact.name
        )));
    }
    archive.remove_file(staged)?;
    sync(archive)?;
    Ok(())
}

fn remove_empty(parent: &Dir, name: &OsStr) -> Result<(), LpmError> {
    let directory = match open_directory_for_publication(parent, name) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if directory.entries()?.next().transpose()?.is_none() {
        discard_private_directory(directory)?;
        sync(parent)?;
    }
    Ok(())
}

fn valid_staging_bytes(expected: &Value, actual: &[u8]) -> bool {
    matches!(expected, Value::File(text) if text.as_bytes().starts_with(actual))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_staging_accepts_only_prefixes_of_the_recorded_template() {
        let expected = Value::File("node '工具' ".into());
        let Value::File(text) = &expected else {
            unreachable!()
        };
        for end in 0..=text.len() {
            assert!(valid_staging_bytes(&expected, &text.as_bytes()[..end]));
        }
        assert!(!valid_staging_bytes(&expected, b"user data"));
        assert!(!valid_staging_bytes(&expected, b"node 'other' "));
        assert!(!valid_staging_bytes(
            &expected,
            "node '工具' extra".as_bytes()
        ));
        assert!(!valid_staging_bytes(
            &Value::Symlink(PathBuf::from("/tool")),
            b""
        ));
    }
}
