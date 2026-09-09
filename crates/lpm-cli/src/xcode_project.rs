//! Xcode project detection and pbxproj editing for LPM local package linking.
//!
//! Handles:
//! - Finding .xcodeproj in a directory tree (walking up like find_package_swift)
//! - Reading and editing project.pbxproj to add local Swift package references
//! - Generating random 24-char hex object IDs
//! - Atomic writes with backup for safety

use lpm_common::LpmError;
use rand::Rng;
use std::path::{Path, PathBuf};

/// Result of linking a local package to an Xcode project.
pub struct XcodeLinkResult {
    pub package_ref_added: bool,
    pub _already_linked: bool,
    pub target_name: String,
}

fn read_pbxproj(path: &Path) -> Result<String, LpmError> {
    let metadata = path.symlink_metadata().map_err(|error| {
        LpmError::Registry(format!("failed to inspect project.pbxproj: {error}"))
    })?;
    if lpm_common::is_symlink_or_junction(&metadata) || !metadata.is_file() {
        return Err(LpmError::Registry(format!(
            "refusing project.pbxproj that is not a regular file: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 {
            return Err(LpmError::Registry(format!(
                "refusing hard-linked project.pbxproj: {}",
                path.display()
            )));
        }
    }
    lpm_common::read_text_file_capped(path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
        .map_err(|error| LpmError::Registry(format!("failed to read project.pbxproj: {error}")))
}

/// Walk up from `dir` to find a `.xcodeproj` directory.
/// Stops if `Package.swift` is found first (that means SPM project, not Xcode app).
/// Returns the path to the `.xcodeproj` directory.
pub fn find_xcodeproj(dir: &Path) -> Result<Option<PathBuf>, LpmError> {
    let mut current = dir.to_path_buf();
    loop {
        // If Package.swift exists here, this is an SPM project — stop looking for xcodeproj
        if current.join("Package.swift").exists() {
            return Ok(None);
        }

        if let Some(project) = find_xcodeproj_in_directory(&current)? {
            return Ok(Some(project));
        }

        if !current.pop() {
            return Ok(None);
        }
    }
}

pub fn find_xcodeproj_in_directory(directory: &Path) -> Result<Option<PathBuf>, LpmError> {
    let entries = std::fs::read_dir(directory).map_err(|error| {
        LpmError::Registry(format!(
            "failed to inspect Xcode projects in {}: {error}",
            directory.display()
        ))
    })?;
    let mut projects = Vec::new();
    let mut workspaces = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            LpmError::Registry(format!(
                "failed to inspect an Xcode project entry in {}: {error}",
                directory.display()
            ))
        })?;
        let path = entry.path();
        if path.extension() == Some(std::ffi::OsStr::new("xcworkspace")) {
            workspaces.push(path);
            continue;
        }
        if path.extension() != Some(std::ffi::OsStr::new("xcodeproj")) {
            continue;
        }
        let metadata = path.symlink_metadata().map_err(|error| {
            LpmError::Registry(format!(
                "failed to inspect Xcode project {}: {error}",
                path.display()
            ))
        })?;
        if lpm_common::is_symlink_or_junction(&metadata) || !metadata.is_dir() {
            return Err(LpmError::Registry(format!(
                "refusing .xcodeproj that is not a real directory: {}",
                path.display()
            )));
        }
        projects.push(path);
    }
    if projects.is_empty() && !workspaces.is_empty() {
        workspaces.sort();
        for workspace in &workspaces {
            projects.extend(workspace_projects(workspace)?);
        }
        projects.sort();
        projects.dedup();
        if projects.len() > 1
            && workspaces.len() == 1
            && let Some(project) = projects
                .iter()
                .find(|project| project.file_stem() == workspaces[0].file_stem())
        {
            return Ok(Some(project.clone()));
        }
    }
    projects.sort();
    match projects.as_slice() {
        [] => Ok(None),
        [project] => Ok(Some(project.clone())),
        _ => {
            let directory_name = directory.file_name();
            if let Some(project) = projects
                .iter()
                .find(|project| project.file_stem() == directory_name)
            {
                return Ok(Some(project.clone()));
            }
            let names = projects
                .into_iter()
                .filter_map(|project| {
                    project
                        .file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                })
                .collect::<Vec<_>>()
                .join(", ");
            Err(LpmError::Registry(format!(
                "multiple Xcode projects found in {} ({names}); run from the intended project directory or name that project to match the workspace or directory",
                directory.display()
            )))
        }
    }
}

fn workspace_projects(workspace: &Path) -> Result<Vec<PathBuf>, LpmError> {
    let root = workspace
        .parent()
        .ok_or_else(|| LpmError::Registry("Xcode workspace has no parent directory".into()))?;
    let canonical_root = root
        .canonicalize()
        .map_err(|error| LpmError::Registry(error.to_string()))?;
    validate_workspace_path(workspace, &canonical_root)?;
    let file = workspace.join("contents.xcworkspacedata");
    validate_workspace_path(&file, &canonical_root)?;
    let contents = lpm_common::read_text_file_capped(&file, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
        .map_err(|error| LpmError::Registry(format!("Cannot read Xcode workspace: {error}")))?;
    let document = roxmltree::Document::parse(&contents)
        .map_err(|error| LpmError::Registry(format!("Invalid Xcode workspace: {error}")))?;
    let mut projects = Vec::new();
    let mut pending = vec![(document.root_element(), root.to_path_buf(), 0)];
    let mut visited = 0;
    while let Some((node, group, depth)) = pending.pop() {
        visited += 1;
        if visited > 10_000 || depth > 64 {
            return Err(LpmError::Registry(
                "Xcode workspace exceeds the supported size or nesting limit".into(),
            ));
        }
        let location = node.attribute("location");
        let path = match location {
            Some(value) => {
                let (kind, value) = value.split_once(':').unwrap_or(("group", value));
                match kind {
                    "group" => group.join(value),
                    "container" => root.join(value),
                    "absolute" => PathBuf::from(value),
                    "self" if value.is_empty() => group.clone(),
                    _ => {
                        return Err(LpmError::Registry(format!(
                            "Unsupported Xcode workspace location: {kind}"
                        )));
                    }
                }
            }
            None => group.clone(),
        };
        if node.has_tag_name("FileRef")
            && path.extension() == Some(std::ffi::OsStr::new("xcodeproj"))
        {
            validate_workspace_path(&path, &canonical_root)?;
            if !path.is_dir() {
                return Err(LpmError::Registry(
                    "Xcode workspace project is not a directory".into(),
                ));
            }
            projects.push(path);
            continue;
        }
        let next_group = if node.has_tag_name("Group") {
            path
        } else {
            group
        };
        pending.extend(
            node.children()
                .filter(|child| child.is_element())
                .map(|child| (child, next_group.clone(), depth + 1)),
        );
    }
    Ok(projects)
}

fn validate_workspace_path(path: &Path, root: &Path) -> Result<(), LpmError> {
    let canonical = path.canonicalize().map_err(|error| {
        LpmError::Registry(format!(
            "Invalid Xcode workspace path {}: {error}",
            path.display()
        ))
    })?;
    if !canonical.starts_with(root) {
        return Err(LpmError::Registry(format!(
            "Xcode workspace reference leaves its directory: {}; run the install from that project's directory",
            path.display()
        )));
    }
    let mut current = path.to_path_buf();
    loop {
        let metadata = current
            .symlink_metadata()
            .map_err(|error| LpmError::Registry(error.to_string()))?;
        if lpm_common::is_symlink_or_junction(&metadata) {
            return Err(LpmError::Registry(format!(
                "Refusing linked Xcode workspace path: {}",
                current.display()
            )));
        }
        if current.canonicalize().is_ok_and(|value| value == root) || !current.pop() {
            break;
        }
    }
    Ok(())
}

/// Link a local package to the Xcode project by editing project.pbxproj.
///
/// On first call: adds all 6 required pbxproj entries (XCLocalSwiftPackageReference,
/// XCSwiftPackageProductDependency, PBXBuildFile, PBXFrameworksBuildPhase,
/// PBXProject.packageReferences, PBXNativeTarget.packageProductDependencies).
///
/// On subsequent calls: detects existing entries, returns `_already_linked: true`.
pub fn link_local_package(
    xcodeproj_path: &Path,
    product_name: &str,
    local_pkg_rel_path: &str,
) -> Result<XcodeLinkResult, LpmError> {
    let pbxproj = xcodeproj_path.join("project.pbxproj");
    if !pbxproj.exists() {
        return Err(LpmError::Registry(format!(
            "project.pbxproj not found in {}",
            xcodeproj_path.display()
        )));
    }

    let original = read_pbxproj(&pbxproj)?;
    let content = repair_legacy_package_sections(&original, product_name, local_pkg_rel_path)?;
    let project_name = xcodeproj_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("project");

    let existing_ref = find_existing_local_pkg_ref(&content, local_pkg_rel_path);
    let existing_product = find_existing_product_dep(&content, product_name);
    let (target_id, target_name) = find_main_app_target_for_project(&content, project_name)
        .ok_or_else(|| {
            LpmError::Registry(format!(
                "No unambiguous app target found in {project_name}.xcodeproj. \
                 Name one application target '{project_name}' or keep a single app target."
            ))
        })?;

    match (existing_ref, existing_product) {
        (Some(_), Some(_)) => {
            if content != original {
                write_pbxproj_atomic(&pbxproj, &original, &content)?;
            }
            return Ok(XcodeLinkResult {
                package_ref_added: false,
                _already_linked: true,
                target_name,
            });
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(LpmError::Registry(format!(
                "incomplete LPMDependencies link in {project_name}.xcodeproj; restore project.pbxproj.lpm-backup or remove the stale package entries"
            )));
        }
        (None, None) => {}
    }

    let (link_content, frameworks_phase_id) = if let Some(id) =
        find_frameworks_phase(&content, &target_id)
    {
        (content.clone(), id)
    } else {
        let id = generate_object_id();
        let entry = format!(
            "\t\t{id} /* Frameworks */ = {{\n\t\t\tisa = PBXFrameworksBuildPhase;\n\t\t\tbuildActionMask = 2147483647;\n\t\t\tfiles = (\n\t\t\t);\n\t\t\trunOnlyForDeploymentPostprocessing = 0;\n\t\t}};"
        );
        let edited = insert_in_section_or_create(&content, "PBXFrameworksBuildPhase", &entry)?;
        let edited = insert_or_create_array_property(
            &edited,
            &target_id,
            "buildPhases",
            &format!("\t\t\t\t{id} /* Frameworks */,"),
            "isa",
        )?;
        (edited, id)
    };

    // Generate object IDs
    let pkg_ref_id = generate_object_id();
    let product_dep_id = generate_object_id();
    let build_file_id = generate_object_id();

    // Back up pbxproj before first modification
    let backup_path = pbxproj.with_extension("pbxproj.lpm-backup");
    if !backup_path.exists() {
        lpm_common::write_file_atomic(&backup_path, content.as_bytes())
            .map_err(|e| LpmError::Registry(format!("failed to back up project.pbxproj: {e}")))?;
    }

    // Apply all edits
    let edited = insert_full_package_link(
        &link_content,
        local_pkg_rel_path,
        product_name,
        &target_id,
        &frameworks_phase_id,
        &pkg_ref_id,
        &product_dep_id,
        &build_file_id,
    )?;

    // Atomic write
    write_pbxproj_atomic(&pbxproj, &original, &edited)?;

    Ok(XcodeLinkResult {
        package_ref_added: true,
        _already_linked: false,
        target_name,
    })
}

// ── Internal functions ─────────────────────────────────────────────────

/// Generate a random 24-character uppercase hex string for pbxproj object IDs.
fn generate_object_id() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 12] = rng.r#gen();
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Find an existing XCLocalSwiftPackageReference for the given relative path.
fn find_existing_local_pkg_ref(content: &str, relative_path: &str) -> Option<String> {
    // Look for: relativePath = Packages/LPMDependencies;
    let pattern = format!("relativePath = {};", relative_path);
    if !content.contains(&pattern) {
        return None;
    }

    // Extract the object ID from the line above
    for line in content.lines() {
        if line.contains("XCLocalSwiftPackageReference")
            && line.contains(&format!("\"{relative_path}\""))
        {
            return extract_object_id(line);
        }
    }

    // Fallback: find the object block containing the relativePath
    let pattern_pos = content.find(&pattern)?;
    let block_start = content[..pattern_pos].rfind('\n')?;
    let before_block = &content[..block_start];
    let id_line_start = before_block.rfind('\n').map_or(0, |i| i + 1);
    let id_line = &content[id_line_start..block_start];
    extract_object_id(id_line)
}

/// Find an existing XCSwiftPackageProductDependency for the given product name.
fn find_existing_product_dep(content: &str, product_name: &str) -> Option<String> {
    // Look for: productName = LPMDependencies; inside XCSwiftPackageProductDependency
    let in_section = content.contains("XCSwiftPackageProductDependency section");
    if !in_section {
        return None;
    }

    let section_start = content.find("/* Begin XCSwiftPackageProductDependency section */")?;
    let section_end = content.find("/* End XCSwiftPackageProductDependency section */")?;
    let section = &content[section_start..section_end];

    let product_pattern = format!("productName = {};", product_name);
    if !section.contains(&product_pattern) {
        return None;
    }

    // Extract object ID from the entry
    for line in section.lines() {
        if line.contains(&format!("/* {product_name} */")) && line.contains(" = {") {
            return extract_object_id(line);
        }
    }
    None
}

/// Find the main app target (productType = "com.apple.product-type.application").
/// Returns (object_id, target_name).
fn find_app_targets(content: &str) -> Vec<(String, String)> {
    let Some(section_start) = content.find("/* Begin PBXNativeTarget section */") else {
        return Vec::new();
    };
    let Some(section_end) = content.find("/* End PBXNativeTarget section */") else {
        return Vec::new();
    };
    let section = &content[section_start..section_end];
    let mut targets = Vec::new();
    let mut current_id = String::new();
    let mut current_name = String::new();

    for line in section.lines() {
        let trimmed = line.trim();

        // Entry header: ID /* TargetName */ = {
        if trimmed.contains("/* ") && trimmed.ends_with(" = {") && !trimmed.starts_with("/*") {
            if let Some(id) = extract_object_id(trimmed) {
                current_id = id;
            }
            if let Some(name) = extract_comment_name(trimmed) {
                current_name = name;
            }
        }

        // Check product type
        if trimmed.contains("productType")
            && trimmed.contains("com.apple.product-type.application")
            && !current_id.is_empty()
        {
            targets.push((current_id.clone(), current_name.clone()));
        }
    }
    targets
}

fn find_main_app_target_for_project(content: &str, project_name: &str) -> Option<(String, String)> {
    let mut targets = find_app_targets(content);
    if targets.len() == 1 {
        return targets.pop();
    }
    targets
        .into_iter()
        .find(|(_, target_name)| target_name == project_name)
}

/// Find the PBXFrameworksBuildPhase ID referenced by the given target.
fn find_frameworks_phase(content: &str, target_id: &str) -> Option<String> {
    let target = object_block(content, target_id)?;
    let phases = property_value(target, "buildPhases")?;
    phases
        .split(|ch: char| !ch.is_ascii_hexdigit())
        .filter(|value| value.len() == 24)
        .find(|id| {
            object_block(content, id).and_then(|phase| property_value(phase, "isa"))
                == Some("PBXFrameworksBuildPhase")
        })
        .map(str::to_owned)
}

/// Insert all 6 pbxproj entries for a new local package link.
#[allow(clippy::too_many_arguments)]
fn insert_full_package_link(
    content: &str,
    local_pkg_rel_path: &str,
    product_name: &str,
    target_id: &str,
    frameworks_phase_id: &str,
    pkg_ref_id: &str,
    product_dep_id: &str,
    build_file_id: &str,
) -> Result<String, LpmError> {
    let mut result = content.to_string();

    // 1. PBXBuildFile — add entry
    let build_file_entry = format!(
        "\t\t{build_file_id} /* {product_name} in Frameworks */ = \
		 {{isa = PBXBuildFile; productRef = {product_dep_id} /* {product_name} */; }};"
    );
    result = insert_in_section_or_create(&result, "PBXBuildFile", &build_file_entry)?;

    // 2. PBXFrameworksBuildPhase — add build file to the Frameworks phase's files list
    result = insert_in_array_property(
        &result,
        frameworks_phase_id,
        "files",
        &format!("\t\t\t\t{build_file_id} /* {product_name} in Frameworks */,"),
    )?;

    // 3. PBXProject.packageReferences — add package ref
    let project_id = find_project_object_id(&result)
        .ok_or_else(|| LpmError::Registry("Could not find PBXProject object in pbxproj".into()))?;
    result = insert_or_create_array_property(
        &result,
        &project_id,
        "packageReferences",
        &format!(
            "\t\t\t\t{pkg_ref_id} /* XCLocalSwiftPackageReference \"{local_pkg_rel_path}\" */,"
        ),
        "mainGroup",
    )?;

    // 4. PBXNativeTarget.packageProductDependencies — add product dep
    result = insert_or_create_array_property(
        &result,
        target_id,
        "packageProductDependencies",
        &format!("\t\t\t\t{product_dep_id} /* {product_name} */,"),
        "dependencies",
    )?;

    // 5. XCLocalSwiftPackageReference — add section entry
    let pkg_ref_entry = format!(
        "\t\t{pkg_ref_id} /* XCLocalSwiftPackageReference \"{local_pkg_rel_path}\" */ = {{\n\
		 \t\t\tisa = XCLocalSwiftPackageReference;\n\
		 \t\t\trelativePath = {local_pkg_rel_path};\n\
		 \t\t}};"
    );
    result = insert_in_section_or_create(&result, "XCLocalSwiftPackageReference", &pkg_ref_entry)?;

    // 6. XCSwiftPackageProductDependency — add section entry
    let product_dep_entry = format!(
        "\t\t{product_dep_id} /* {product_name} */ = {{\n\
		 \t\t\tisa = XCSwiftPackageProductDependency;\n\
		 \t\t\tproductName = {product_name};\n\
		 \t\t}};"
    );
    result = insert_in_section_or_create(
        &result,
        "XCSwiftPackageProductDependency",
        &product_dep_entry,
    )?;

    Ok(result)
}

/// Insert an entry into an existing pbxproj section (between Begin/End comments).
fn insert_in_section(content: &str, section_name: &str, entry: &str) -> Result<String, LpmError> {
    let end_marker = format!("/* End {} section */", section_name);
    let end_pos = content.find(&end_marker).ok_or_else(|| {
        LpmError::Registry(format!("Could not find {section_name} section in pbxproj"))
    })?;

    let mut result = String::with_capacity(content.len() + entry.len() + 2);
    result.push_str(&content[..end_pos]);
    result.push_str(entry);
    result.push('\n');
    result.push_str(&content[end_pos..]);
    Ok(result)
}

/// Insert an entry into a section, creating the section if it doesn't exist.
fn insert_in_section_or_create(
    content: &str,
    section_name: &str,
    entry: &str,
) -> Result<String, LpmError> {
    let begin_marker = format!("/* Begin {} section */", section_name);

    if content.contains(&begin_marker) {
        return insert_in_section(content, section_name, entry);
    }

    let (_, objects_end) = objects_range(content)?;
    let line_start = if content[..objects_end]
        .rsplit_once('\n')
        .is_some_and(|(_, line)| line.trim().is_empty())
    {
        content[..objects_end]
            .rfind('\n')
            .map_or(objects_end, |index| index + 1)
    } else {
        objects_end
    };

    let section_block = format!(
        "\n/* Begin {section_name} section */\n\
		 {entry}\n\
		 /* End {section_name} section */\n"
    );

    let mut result = String::with_capacity(content.len() + section_block.len());
    result.push_str(&content[..line_start]);
    result.push_str(&section_block);
    result.push_str(&content[line_start..]);
    Ok(result)
}

/// Insert a value into an existing array property of an object.
fn insert_in_array_property(
    content: &str,
    object_id: &str,
    property_name: &str,
    value: &str,
) -> Result<String, LpmError> {
    // Find the object by ID
    let obj_start = object_definition_start(content, object_id).ok_or_else(|| {
        LpmError::Registry(format!("Could not find object {object_id} in pbxproj"))
    })?;

    // Find the property within the object
    let search_from = obj_start;
    let obj_block_end =
        find_block_end(&content[search_from..]).map_or(content.len(), |i| search_from + i);

    let prop_pattern = format!("{property_name} = (");
    let prop_pos = content[search_from..obj_block_end]
        .find(&prop_pattern)
        .map(|i| search_from + i)
        .ok_or_else(|| {
            LpmError::Registry(format!(
                "Could not find '{property_name}' in object {object_id}"
            ))
        })?;

    // Find the closing ) of the array
    let array_start = prop_pos + prop_pattern.len();
    let close_paren = content[array_start..]
        .find(')')
        .map(|i| array_start + i)
        .ok_or_else(|| {
            LpmError::Registry(format!("Could not find closing ')' for '{property_name}'"))
        })?;

    // Insert before the closing )
    let close_line_start = content[..close_paren]
        .rfind('\n')
        .map_or(close_paren, |i| i + 1);

    let mut result = String::with_capacity(content.len() + value.len() + 2);
    result.push_str(&content[..close_line_start]);
    result.push_str(value);
    result.push('\n');
    result.push_str(&content[close_line_start..]);
    Ok(result)
}

/// Insert a value into an array property, creating the property if it doesn't exist.
fn insert_or_create_array_property(
    content: &str,
    object_id: &str,
    property_name: &str,
    value: &str,
    insert_after_property: &str,
) -> Result<String, LpmError> {
    // Try to insert into existing property
    let obj_start = object_definition_start(content, object_id).ok_or_else(|| {
        LpmError::Registry(format!("Could not find object {object_id} in pbxproj"))
    })?;

    let obj_block_end =
        find_block_end(&content[obj_start..]).map_or(content.len(), |i| obj_start + i);

    let prop_pattern = format!("{property_name} = (");
    let has_property = content[obj_start..obj_block_end].contains(&prop_pattern);

    if has_property {
        return insert_in_array_property(content, object_id, property_name, value);
    }

    // Property doesn't exist — create it after insert_after_property
    let after_pattern = format!("{insert_after_property} = ");
    let after_pos = content[obj_start..obj_block_end]
        .find(&after_pattern)
        .map(|i| obj_start + i);

    let insert_pos = if let Some(pos) = after_pos {
        // Find the end of the property (could be a simple value or an array)
        let from_prop = &content[pos..obj_block_end];
        if let Some(array_end) = from_prop.find(");") {
            pos + array_end + 2 // After ");"
        } else if let Some(semi) = from_prop.find(';') {
            pos + semi + 1 // After ";"
        } else {
            pos
        }
    } else {
        // Fallback: insert before the closing }; of the object
        content[obj_start..obj_block_end]
            .rfind("};")
            .map_or(obj_block_end, |i| obj_start + i)
    };

    // Find the end of the current line
    let line_end = content[insert_pos..]
        .find('\n')
        .map_or(insert_pos, |i| insert_pos + i + 1);

    let new_property = format!(
        "\t\t\t{property_name} = (\n\
		 {value}\n\
		 \t\t\t);\n"
    );

    let mut result = String::with_capacity(content.len() + new_property.len());
    result.push_str(&content[..line_end]);
    result.push_str(&new_property);
    result.push_str(&content[line_end..]);
    Ok(result)
}

/// Find the PBXProject object ID (the rootObject).
fn find_project_object_id(content: &str) -> Option<String> {
    for line in content.lines() {
        if line.trim_start().starts_with("rootObject = ") {
            return extract_object_id(line.trim());
        }
    }
    None
}

/// Extract an object ID (24-char hex) from a pbxproj line.
fn extract_object_id(line: &str) -> Option<String> {
    let trimmed = line.trim();
    // ID is the first word — 24 hex chars
    let id = trimmed.split_whitespace().next()?;
    if id.len() == 24 && id.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(id.to_string())
    } else {
        // Try after "= " for rootObject lines
        if let Some(after_eq) = trimmed.split(" = ").nth(1) {
            let id = after_eq.split_whitespace().next()?.trim_end_matches(';');
            if id.len() == 24 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(id.to_string());
            }
        }
        None
    }
}

/// Extract the name from a pbxproj comment: `/* Name */`.
fn extract_comment_name(line: &str) -> Option<String> {
    let start = line.find("/* ")? + 3;
    let end = line[start..].find(" */").map(|i| start + i)?;
    Some(line[start..end].to_string())
}

fn object_definition_start(content: &str, object_id: &str) -> Option<usize> {
    let mut offset = 0;
    for line in content.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if let Some(mut rest) = trimmed.strip_prefix(object_id) {
            rest = rest.trim_start();
            if rest.starts_with("/*") {
                rest = rest.split_once("*/")?.1.trim_start();
            }
            if rest.starts_with("= {") {
                return Some(offset + line.len() - trimmed.len());
            }
        }
        offset += line.len();
    }
    None
}

fn repair_legacy_package_sections(
    content: &str,
    product_name: &str,
    relative_path: &str,
) -> Result<String, LpmError> {
    let mut repaired = content.to_owned();
    for section in [
        "XCLocalSwiftPackageReference",
        "XCSwiftPackageProductDependency",
    ] {
        let (_, objects_end) = objects_range(&repaired)?;
        let begin_marker = format!("/* Begin {section} section */");
        let end_marker = format!("/* End {section} section */");
        let Some(begin) = repaired.find(&begin_marker) else {
            continue;
        };
        if begin < objects_end {
            continue;
        }
        let end = repaired[begin..]
            .find(&end_marker)
            .map(|offset| begin + offset + end_marker.len())
            .ok_or_else(|| LpmError::Registry("Unclosed legacy Swift package section".into()))?;
        let block = &repaired[begin..end];
        let expected = if section == "XCLocalSwiftPackageReference" {
            find_existing_local_pkg_ref(block, relative_path)
        } else {
            find_existing_product_dep(block, product_name)
        };
        if expected.is_none() {
            return Err(LpmError::Registry("Unexpected package objects outside the Xcode objects dictionary; restore the project backup".into()));
        }
        let block = format!("\n{block}\n");
        repaired.replace_range(begin..end, "");
        repaired.insert_str(objects_end, &block);
    }
    Ok(repaired)
}

fn object_block<'a>(content: &'a str, id: &str) -> Option<&'a str> {
    let start = object_definition_start(content, id)?;
    let end = start + find_block_end(&content[start..])?;
    Some(&content[start..end])
}

fn property_value<'a>(block: &'a str, name: &str) -> Option<&'a str> {
    let label = format!("{name} = ");
    let value = block.split_once(&label)?.1.split(';').next()?.trim();
    Some(value.trim_matches('"'))
}

const DEPLOYMENT_PLATFORMS: &[(&str, &str)] = &[
    ("MACOSX_DEPLOYMENT_TARGET", "macOS"),
    ("IPHONEOS_DEPLOYMENT_TARGET", "iOS"),
    ("TVOS_DEPLOYMENT_TARGET", "tvOS"),
    ("WATCHOS_DEPLOYMENT_TARGET", "watchOS"),
    ("XROS_DEPLOYMENT_TARGET", "visionOS"),
];

fn deployment_configurations(
    content: &str,
    object: &str,
) -> std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>> {
    let mut result = std::collections::BTreeMap::new();
    let Some(list) = object_block(content, object)
        .and_then(|block| property_value(block, "buildConfigurationList"))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|id| object_block(content, id))
    else {
        return result;
    };
    let Some(configs) = property_value(list, "buildConfigurations") else {
        return result;
    };
    for id in configs
        .split(|ch: char| !ch.is_ascii_hexdigit())
        .filter(|value| value.len() == 24)
    {
        let Some(config) = object_block(content, id) else {
            continue;
        };
        let Some(name) = property_value(config, "name") else {
            continue;
        };
        let mut settings = std::collections::BTreeMap::new();
        for (key, platform) in DEPLOYMENT_PLATFORMS {
            if let Some(value) =
                property_value(config, key).filter(|value| deployment_version(value).is_some())
            {
                settings.insert((*platform).to_owned(), value.to_owned());
            }
        }
        result.insert(name.to_owned(), settings);
    }
    result
}

pub(crate) fn deployment_version(value: &str) -> Option<Vec<u32>> {
    let parts = value
        .split('.')
        .map(str::parse)
        .collect::<Result<Vec<u32>, _>>()
        .ok()?;
    (parts.len() <= 3 && !parts.is_empty() && parts[0] > 0).then_some(parts)
}

pub(crate) fn deployment_targets(
    project: &Path,
) -> Result<std::collections::BTreeMap<String, String>, LpmError> {
    let content = read_pbxproj(&project.join("project.pbxproj"))?;
    let project_name = project
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    let (target, _) = find_main_app_target_for_project(&content, project_name)
        .ok_or_else(|| LpmError::Registry("No unambiguous Xcode application target".into()))?;
    let project_settings = find_project_object_id(&content)
        .map(|id| deployment_configurations(&content, &id))
        .unwrap_or_default();
    let mut settings = deployment_configurations(&content, &target);
    if settings.is_empty() {
        settings = project_settings.clone();
    }
    let mut result = std::collections::BTreeMap::<String, String>::new();
    for (name, target_settings) in settings {
        let mut merged = project_settings.get(&name).cloned().unwrap_or_default();
        merged.extend(target_settings);
        for (platform, version) in merged {
            let entry = result.entry(platform).or_insert_with(|| version.clone());
            if deployment_version(&version) < deployment_version(entry) {
                *entry = version;
            }
        }
    }
    Ok(result)
}

fn objects_range(content: &str) -> Result<(usize, usize), LpmError> {
    let start = content
        .find("objects = {")
        .map(|index| index + "objects = ".len())
        .ok_or_else(|| LpmError::Registry("Could not find pbxproj objects dictionary".into()))?;
    let end = find_block_end(&content[start..])
        .map(|length| start + length)
        .ok_or_else(|| LpmError::Registry("Unclosed pbxproj objects dictionary".into()))?;
    let close = if content.as_bytes().get(end - 1) == Some(&b';') {
        end - 2
    } else {
        end - 1
    };
    Ok((start, close))
}

/// Find a dictionary's end without treating quoted text or comments as syntax.
fn find_block_end(content: &str) -> Option<usize> {
    let bytes = content.as_bytes();
    let mut index = 0;
    let mut depth = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                index += 1;
                while index < bytes.len() {
                    if bytes[index] == b'\\' {
                        index += 2;
                        continue;
                    }
                    if bytes[index] == b'"' {
                        break;
                    }
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index += 2;
                while index + 1 < bytes.len() && &bytes[index..index + 2] != b"*/" {
                    index += 1;
                }
                index += 1;
            }
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(
                        index
                            + if bytes.get(index + 1) == Some(&b';') {
                                2
                            } else {
                                1
                            },
                    );
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

/// Write pbxproj content atomically.
fn write_pbxproj_atomic(
    pbxproj_path: &Path,
    expected: &str,
    content: &str,
) -> Result<(), LpmError> {
    let current = read_pbxproj(pbxproj_path)?;
    if current != expected {
        return Err(LpmError::Registry(format!(
            "project.pbxproj changed during install: {}",
            pbxproj_path.display()
        )));
    }
    lpm_common::write_file_atomic(pbxproj_path, content)
        .map_err(|e| LpmError::Registry(format!("failed to write pbxproj: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_xcodeproj(directory: &Path, project_name: &str, content: &str) -> PathBuf {
        let xcodeproj = directory.join(format!("{project_name}.xcodeproj"));
        std::fs::create_dir(&xcodeproj).unwrap();
        std::fs::write(xcodeproj.join("project.pbxproj"), content).unwrap();
        xcodeproj
    }

    fn with_second_app_target(content: &str, target_name: &str) -> String {
        let target = content
            .split("/* Begin PBXNativeTarget section */")
            .nth(1)
            .and_then(|section| section.split("/* End PBXNativeTarget section */").next())
            .expect("sample target section")
            .replace("284E0D1F2F5F71880018579D", "111111111111111111111111")
            .replace("MyApp", target_name);
        content.replace(
            "/* End PBXNativeTarget section */",
            &format!("{target}/* End PBXNativeTarget section */"),
        )
    }

    const SAMPLE_PBXPROJ: &str = r#"// !$*UTF8*$!
{
	archiveVersion = 1;
	classes = {
	};
	objectVersion = 77;
	objects = {

/* Begin PBXBuildFile section */
/* End PBXBuildFile section */

/* Begin PBXFileReference section */
		284E0D202F5F71880018579D /* MyApp.app */ = {isa = PBXFileReference; explicitFileType = wrapper.application; includeInIndex = 0; path = MyApp.app; sourceTree = BUILT_PRODUCTS_DIR; };
/* End PBXFileReference section */

/* Begin PBXFrameworksBuildPhase section */
		284E0D1D2F5F71880018579D /* Frameworks */ = {
			isa = PBXFrameworksBuildPhase;
			buildActionMask = 2147483647;
			files = (
			);
			runOnlyForDeploymentPostprocessing = 0;
		};
/* End PBXFrameworksBuildPhase section */

/* Begin PBXGroup section */
		284E0D172F5F71880018579D = {
			isa = PBXGroup;
			children = (
				284E0D212F5F71880018579D /* Products */,
			);
			sourceTree = "<group>";
		};
		284E0D212F5F71880018579D /* Products */ = {
			isa = PBXGroup;
			children = (
				284E0D202F5F71880018579D /* MyApp.app */,
			);
			name = Products;
			sourceTree = "<group>";
		};
/* End PBXGroup section */

/* Begin PBXNativeTarget section */
		284E0D1F2F5F71880018579D /* MyApp */ = {
			isa = PBXNativeTarget;
			buildConfigurationList = 284E0D2B2F5F718A0018579D /* Build configuration list for PBXNativeTarget "MyApp" */;
			buildPhases = (
				284E0D1C2F5F71880018579D /* Sources */,
				284E0D1D2F5F71880018579D /* Frameworks */,
				284E0D1E2F5F71880018579D /* Resources */,
			);
			buildRules = (
			);
			dependencies = (
			);
			name = MyApp;
			productName = MyApp;
			productReference = 284E0D202F5F71880018579D /* MyApp.app */;
			productType = "com.apple.product-type.application";
		};
/* End PBXNativeTarget section */

/* Begin PBXProject section */
		284E0D182F5F71880018579D /* Project object */ = {
			isa = PBXProject;
			attributes = {
				BuildIndependentTargetsInParallel = 1;
			};
			buildConfigurationList = 284E0D1B2F5F71880018579D /* Build configuration list for PBXProject "MyApp" */;
			developmentRegion = en;
			hasScannedForEncodings = 0;
			knownRegions = (
				en,
				Base,
			);
			mainGroup = 284E0D172F5F71880018579D;
			minimizedProjectReferenceProxies = 1;
			preferredProjectObjectVersion = 77;
			productRefGroup = 284E0D212F5F71880018579D /* Products */;
			projectDirPath = "";
			projectRoot = "";
			targets = (
				284E0D1F2F5F71880018579D /* MyApp */,
			);
		};
/* End PBXProject section */

/* Begin PBXResourcesBuildPhase section */
		284E0D1E2F5F71880018579D /* Resources */ = {
			isa = PBXResourcesBuildPhase;
			buildActionMask = 2147483647;
			files = (
			);
			runOnlyForDeploymentPostprocessing = 0;
		};
/* End PBXResourcesBuildPhase section */

/* Begin PBXSourcesBuildPhase section */
		284E0D1C2F5F71880018579D /* Sources */ = {
			isa = PBXSourcesBuildPhase;
			buildActionMask = 2147483647;
			files = (
			);
			runOnlyForDeploymentPostprocessing = 0;
		};
/* End PBXSourcesBuildPhase section */

	};
	rootObject = 284E0D182F5F71880018579D /* Project object */;
}
"#;

    #[test]
    fn new_package_objects_stay_inside_the_objects_dictionary() {
        let result = insert_full_package_link(
            SAMPLE_PBXPROJ,
            "Packages/LPMDependencies",
            "LPMDependencies",
            "284E0D1F2F5F71880018579D",
            "284E0D1D2F5F71880018579D",
            "AAAAAAAAAAAAAAAAAAAAAAAA",
            "BBBBBBBBBBBBBBBBBBBBBBBB",
            "CCCCCCCCCCCCCCCCCCCCCCCC",
        )
        .unwrap();
        let start = result.find("objects = {").unwrap();
        let end = start + find_block_end(&result[start..]).unwrap();
        assert!(
            result
                .find("/* Begin XCLocalSwiftPackageReference section */")
                .unwrap()
                < end
        );
        assert!(
            result
                .find("/* Begin XCSwiftPackageProductDependency section */")
                .unwrap()
                < end
        );
    }

    #[test]
    fn reinstall_repairs_legacy_package_sections_outside_objects() {
        let dir = tempfile::tempdir().unwrap();
        let mut broken = insert_full_package_link(
            SAMPLE_PBXPROJ,
            "Packages/LPMDependencies",
            "LPMDependencies",
            "284E0D1F2F5F71880018579D",
            "284E0D1D2F5F71880018579D",
            "AAAAAAAAAAAAAAAAAAAAAAAA",
            "BBBBBBBBBBBBBBBBBBBBBBBB",
            "CCCCCCCCCCCCCCCCCCCCCCCC",
        )
        .unwrap();
        for section in [
            "XCLocalSwiftPackageReference",
            "XCSwiftPackageProductDependency",
        ] {
            let begin = broken
                .find(&format!("/* Begin {section} section */"))
                .unwrap();
            let marker = format!("/* End {section} section */");
            let end = broken.find(&marker).unwrap() + marker.len();
            let block = broken[begin..end].to_owned();
            broken.replace_range(begin..end, "");
            let root = broken.find("\trootObject").unwrap();
            broken.insert_str(root, &format!("{block}\n"));
        }
        let project = write_xcodeproj(dir.path(), "MyApp", &broken);
        link_local_package(&project, "LPMDependencies", "Packages/LPMDependencies").unwrap();
        let repaired = std::fs::read_to_string(project.join("project.pbxproj")).unwrap();
        let start = repaired.find("objects = {").unwrap();
        let end = start + find_block_end(&repaired[start..]).unwrap();
        assert!(
            repaired
                .find("/* Begin XCLocalSwiftPackageReference section */")
                .unwrap()
                < end
        );
        let before = repaired;
        link_local_package(&project, "LPMDependencies", "Packages/LPMDependencies").unwrap();
        assert_eq!(
            std::fs::read_to_string(project.join("project.pbxproj")).unwrap(),
            before
        );
    }

    #[test]
    fn xcode_link_creates_a_missing_frameworks_phase() {
        let dir = tempfile::tempdir().unwrap();
        let start = SAMPLE_PBXPROJ
            .find("/* Begin PBXFrameworksBuildPhase section */")
            .unwrap();
        let end = SAMPLE_PBXPROJ
            .find("/* End PBXFrameworksBuildPhase section */")
            .unwrap()
            + "/* End PBXFrameworksBuildPhase section */".len();
        let mut content = SAMPLE_PBXPROJ.to_owned();
        content.replace_range(start..end, "");
        content = content.replace("284E0D1D2F5F71880018579D /* Frameworks */,", "");
        let project = write_xcodeproj(dir.path(), "MyApp", &content);
        link_local_package(&project, "LPMDependencies", "Packages/LPMDependencies").unwrap();
        let edited = std::fs::read_to_string(project.join("project.pbxproj")).unwrap();
        assert!(find_frameworks_phase(&edited, "284E0D1F2F5F71880018579D").is_some());
        assert!(edited.contains("isa = PBXFrameworksBuildPhase"));
    }

    #[test]
    fn workspace_discovery_follows_nested_group_project_references() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("Apps/My App");
        std::fs::create_dir_all(&nested).unwrap();
        let project = write_xcodeproj(&nested, "MyApp", SAMPLE_PBXPROJ);
        let workspace = dir.path().join("MyApp.xcworkspace");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::write(workspace.join("contents.xcworkspacedata"), r#"<?xml version="1.0"?><Workspace version="1.0"><Group location="group:Apps"><FileRef location="group:My App/MyApp.xcodeproj"/></Group></Workspace>"#).unwrap();
        assert_eq!(find_xcodeproj(dir.path()).unwrap(), Some(project));
    }

    #[test]
    fn workspace_discovery_rejects_references_outside_the_workspace() {
        let dir = tempfile::tempdir().unwrap();
        write_xcodeproj(dir.path(), "Outside", SAMPLE_PBXPROJ);
        let root = dir.path().join("Workspace");
        let workspace = root.join("App.xcworkspace");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(
            workspace.join("contents.xcworkspacedata"),
            r#"<Workspace><FileRef location="group:../Outside.xcodeproj"/></Workspace>"#,
        )
        .unwrap();
        let error = find_xcodeproj(&root).unwrap_err().to_string();
        assert!(error.contains("leaves its directory"), "{error}");
    }

    #[test]
    fn dictionary_boundary_ignores_braces_in_comments_and_escaped_strings() {
        let content = r#"{ /* } */ value = "quoted \" }"; child = {}; }; trailing"#;
        let end = find_block_end(content).unwrap();
        assert_eq!(&content[end..], " trailing");
    }

    #[test]
    fn generate_object_id_format() {
        let id = generate_object_id();
        assert_eq!(id.len(), 24);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_object_id_is_unique() {
        let a = generate_object_id();
        let b = generate_object_id();
        assert_ne!(a, b);
    }

    #[test]
    fn find_main_app_target_selects_application() {
        let result = find_main_app_target_for_project(SAMPLE_PBXPROJ, "MyApp");
        assert!(result.is_some());
        let (id, name) = result.unwrap();
        assert_eq!(id, "284E0D1F2F5F71880018579D");
        assert_eq!(name, "MyApp");
    }

    #[test]
    fn find_main_app_target_skips_test_targets() {
        let with_test = SAMPLE_PBXPROJ.replace(
            "com.apple.product-type.application",
            "com.apple.product-type.bundle.unit-test",
        );
        let result = find_main_app_target_for_project(&with_test, "MyApp");
        assert!(result.is_none());
    }

    #[test]
    fn main_app_target_prefers_the_project_named_application() {
        let with_two_apps = with_second_app_target(SAMPLE_PBXPROJ, "Secondary");

        let result = find_main_app_target_for_project(&with_two_apps, "MyApp").unwrap();
        assert_eq!(result.0, "284E0D1F2F5F71880018579D");
        assert_eq!(result.1, "MyApp");
    }

    #[test]
    fn xcode_project_discovery_prefers_the_directory_named_project() {
        let directory = tempfile::tempdir().unwrap();
        let project_dir = directory.path().join("MyApp");
        std::fs::create_dir(&project_dir).unwrap();
        std::fs::create_dir(project_dir.join("Other.xcodeproj")).unwrap();
        std::fs::create_dir(project_dir.join("MyApp.xcodeproj")).unwrap();

        assert_eq!(
            find_xcodeproj(&project_dir).unwrap(),
            Some(project_dir.join("MyApp.xcodeproj"))
        );
    }

    #[test]
    fn xcode_project_discovery_rejects_unmatched_ambiguity() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("First.xcodeproj")).unwrap();
        std::fs::create_dir(directory.path().join("Second.xcodeproj")).unwrap();

        let error = find_xcodeproj(directory.path()).unwrap_err();

        assert!(error.to_string().contains("multiple Xcode projects"));
    }

    #[cfg(unix)]
    #[test]
    fn xcode_project_discovery_rejects_a_linked_project_directory() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), directory.path().join("Linked.xcodeproj")).unwrap();

        let error = find_xcodeproj_in_directory(directory.path()).unwrap_err();

        assert!(error.to_string().contains("not a real directory"));
    }

    #[test]
    fn existing_xcode_link_rejects_ambiguous_app_targets() {
        let directory = tempfile::tempdir().unwrap();
        let linked = insert_full_package_link(
            SAMPLE_PBXPROJ,
            "Packages/LPMDependencies",
            "LPMDependencies",
            "284E0D1F2F5F71880018579D",
            "284E0D1D2F5F71880018579D",
            "AAAAAAAAAAAAAAAAAAAAAAAA",
            "BBBBBBBBBBBBBBBBBBBBBBBB",
            "CCCCCCCCCCCCCCCCCCCCCCCC",
        )
        .unwrap();
        let ambiguous = with_second_app_target(&linked, "Secondary");
        let xcodeproj = write_xcodeproj(directory.path(), "Unmatched", &ambiguous);

        let error = link_local_package(&xcodeproj, "LPMDependencies", "Packages/LPMDependencies")
            .err()
            .expect("ambiguous app targets must be rejected");

        assert!(error.to_string().contains("No unambiguous app target"));
    }

    #[test]
    fn xcode_link_rejects_partial_preexisting_entries() {
        let directory = tempfile::tempdir().unwrap();
        let linked = insert_full_package_link(
            SAMPLE_PBXPROJ,
            "Packages/LPMDependencies",
            "LPMDependencies",
            "284E0D1F2F5F71880018579D",
            "284E0D1D2F5F71880018579D",
            "AAAAAAAAAAAAAAAAAAAAAAAA",
            "BBBBBBBBBBBBBBBBBBBBBBBB",
            "CCCCCCCCCCCCCCCCCCCCCCCC",
        )
        .unwrap();
        let section_start = linked
            .find("/* Begin XCSwiftPackageProductDependency section */")
            .unwrap();
        let section_end = linked
            .find("/* End XCSwiftPackageProductDependency section */")
            .unwrap()
            + "/* End XCSwiftPackageProductDependency section */".len();
        let partial = format!("{}{}", &linked[..section_start], &linked[section_end..]);
        let xcodeproj = write_xcodeproj(directory.path(), "MyApp", &partial);

        let error = link_local_package(&xcodeproj, "LPMDependencies", "Packages/LPMDependencies")
            .err()
            .expect("partial Xcode links must be rejected");

        assert!(
            error
                .to_string()
                .contains("incomplete LPMDependencies link")
        );
    }

    #[test]
    fn xcode_link_rejects_an_oversized_project_before_parsing() {
        let directory = tempfile::tempdir().unwrap();
        let xcodeproj = directory.path().join("MyApp.xcodeproj");
        std::fs::create_dir(&xcodeproj).unwrap();
        let pbxproj = xcodeproj.join("project.pbxproj");
        let file = std::fs::File::create(&pbxproj).unwrap();
        file.set_len(lpm_common::CONFIG_FILE_SIZE_CAP_BYTES + 1)
            .unwrap();

        let error = link_local_package(&xcodeproj, "LPMDependencies", "Packages/LPMDependencies")
            .err()
            .expect("oversized pbxproj input must be rejected");

        assert!(error.to_string().contains("limit"));
    }

    #[cfg(unix)]
    #[test]
    fn xcode_link_rejects_a_linked_project_file_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let outside = directory.path().join("outside.pbxproj");
        std::fs::write(&outside, SAMPLE_PBXPROJ).unwrap();
        let xcodeproj = directory.path().join("MyApp.xcodeproj");
        std::fs::create_dir(&xcodeproj).unwrap();
        symlink(&outside, xcodeproj.join("project.pbxproj")).unwrap();

        let result = link_local_package(&xcodeproj, "LPMDependencies", "Packages/LPMDependencies");

        assert!(result.is_err());
        assert_eq!(std::fs::read_to_string(outside).unwrap(), SAMPLE_PBXPROJ);
    }

    #[cfg(unix)]
    #[test]
    fn xcode_link_rejects_a_hard_linked_project_file_without_touching_its_peer() {
        let directory = tempfile::tempdir().unwrap();
        let outside = directory.path().join("outside.pbxproj");
        std::fs::write(&outside, SAMPLE_PBXPROJ).unwrap();
        let xcodeproj = directory.path().join("MyApp.xcodeproj");
        std::fs::create_dir(&xcodeproj).unwrap();
        std::fs::hard_link(&outside, xcodeproj.join("project.pbxproj")).unwrap();

        let result = link_local_package(&xcodeproj, "LPMDependencies", "Packages/LPMDependencies");

        assert!(result.is_err());
        assert_eq!(std::fs::read_to_string(outside).unwrap(), SAMPLE_PBXPROJ);
    }

    #[test]
    fn pbxproj_write_rejects_a_concurrent_change() {
        let directory = tempfile::tempdir().unwrap();
        let pbxproj = directory.path().join("project.pbxproj");
        std::fs::write(&pbxproj, "new editor content").unwrap();

        let error = write_pbxproj_atomic(&pbxproj, "previous content", "lpm edit").unwrap_err();

        assert!(error.to_string().contains("changed during install"));
        assert_eq!(
            std::fs::read_to_string(pbxproj).unwrap(),
            "new editor content"
        );
    }

    #[test]
    fn frameworks_phase_lookup_uses_object_type_when_comments_change() {
        let content = SAMPLE_PBXPROJ.replace("/* Frameworks */", "/* Libraries */");
        assert_eq!(
            find_frameworks_phase(&content, "284E0D1F2F5F71880018579D"),
            find_frameworks_phase(SAMPLE_PBXPROJ, "284E0D1F2F5F71880018579D")
        );
    }

    #[test]
    fn find_frameworks_phase_works() {
        let phase = find_frameworks_phase(SAMPLE_PBXPROJ, "284E0D1F2F5F71880018579D");
        assert_eq!(phase, Some("284E0D1D2F5F71880018579D".to_string()));
    }

    #[test]
    fn find_existing_local_pkg_ref_returns_none_when_missing() {
        assert!(find_existing_local_pkg_ref(SAMPLE_PBXPROJ, "Packages/LPMDependencies").is_none());
    }

    #[test]
    fn find_existing_product_dep_returns_none_when_missing() {
        assert!(find_existing_product_dep(SAMPLE_PBXPROJ, "LPMDependencies").is_none());
    }

    #[test]
    fn find_project_object_id_works() {
        let id = find_project_object_id(SAMPLE_PBXPROJ);
        assert_eq!(id, Some("284E0D182F5F71880018579D".to_string()));
    }

    #[test]
    fn insert_full_package_link_adds_all_entries() {
        let result = insert_full_package_link(
            SAMPLE_PBXPROJ,
            "Packages/LPMDependencies",
            "LPMDependencies",
            "284E0D1F2F5F71880018579D",
            "284E0D1D2F5F71880018579D",
            "AAAAAAAAAAAAAAAAAAAAAAAA",
            "BBBBBBBBBBBBBBBBBBBBBBBB",
            "CCCCCCCCCCCCCCCCCCCCCCCC",
        )
        .unwrap();

        // Verify all 6 entries
        assert!(
            result.contains("CCCCCCCCCCCCCCCCCCCCCCCC /* LPMDependencies in Frameworks */"),
            "PBXBuildFile entry missing"
        );
        assert!(
            result.contains("isa = XCLocalSwiftPackageReference"),
            "XCLocalSwiftPackageReference missing"
        );
        assert!(
            result.contains("relativePath = Packages/LPMDependencies"),
            "relativePath missing"
        );
        assert!(
            result.contains("productName = LPMDependencies"),
            "productName missing"
        );
        assert!(
            result.contains("AAAAAAAAAAAAAAAAAAAAAAAA /* XCLocalSwiftPackageReference"),
            "packageReferences entry missing"
        );
        assert!(
            result.contains("BBBBBBBBBBBBBBBBBBBBBBBB /* LPMDependencies */"),
            "packageProductDependencies entry missing"
        );
    }

    #[test]
    fn insert_full_package_link_is_valid_pbxproj() {
        let result = insert_full_package_link(
            SAMPLE_PBXPROJ,
            "Packages/LPMDependencies",
            "LPMDependencies",
            "284E0D1F2F5F71880018579D",
            "284E0D1D2F5F71880018579D",
            "AAAAAAAAAAAAAAAAAAAAAAAA",
            "BBBBBBBBBBBBBBBBBBBBBBBB",
            "CCCCCCCCCCCCCCCCCCCCCCCC",
        )
        .unwrap();

        // Basic structural checks
        assert!(result.starts_with("// !$*UTF8*$!"));
        assert!(result.contains("rootObject = "));
        assert!(result.ends_with("}\n"));

        // After linking, detection should find the entries
        assert!(find_existing_local_pkg_ref(&result, "Packages/LPMDependencies").is_some());
        assert!(find_existing_product_dep(&result, "LPMDependencies").is_some());
    }

    #[test]
    fn extract_object_id_from_line() {
        assert_eq!(
            extract_object_id("284E0D1F2F5F71880018579D /* MyApp */ = {"),
            Some("284E0D1F2F5F71880018579D".to_string())
        );
        assert_eq!(extract_object_id("not an id"), None);
    }

    #[test]
    fn extract_comment_name_works() {
        assert_eq!(
            extract_comment_name("284E0D1F2F5F71880018579D /* MyApp */ = {"),
            Some("MyApp".to_string())
        );
    }
}
