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

/// Walk up from `dir` to find a `.xcodeproj` directory.
/// Stops if `Package.swift` is found first (that means SPM project, not Xcode app).
/// Returns the path to the `.xcodeproj` directory.
pub fn find_xcodeproj(dir: &Path) -> Option<PathBuf> {
	let mut current = dir.to_path_buf();
	loop {
		// If Package.swift exists here, this is an SPM project — stop looking for xcodeproj
		if current.join("Package.swift").exists() {
			return None;
		}

		// Look for .xcodeproj in this directory
		if let Ok(entries) = std::fs::read_dir(&current) {
			for entry in entries.flatten() {
				let path = entry.path();
				if path.is_dir() {
					if let Some(ext) = path.extension() {
						if ext == "xcodeproj" {
							return Some(path);
						}
					}
				}
			}
		}

		if !current.pop() {
			return None;
		}
	}
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

	let content = std::fs::read_to_string(&pbxproj)
		.map_err(|e| LpmError::Registry(format!("failed to read project.pbxproj: {e}")))?;

	// Check if already linked
	let existing_ref = find_existing_local_pkg_ref(&content, local_pkg_rel_path);
	let existing_product = find_existing_product_dep(&content, product_name);

	if existing_ref.is_some() && existing_product.is_some() {
		// Find target name for the result
		let target_name = find_main_app_target(&content)
			.map(|(_, name)| name)
			.unwrap_or_else(|| "Unknown".to_string());

		return Ok(XcodeLinkResult {
			package_ref_added: false,
			_already_linked: true,
			target_name,
		});
	}

	// Find the main app target
	let (target_id, target_name) = find_main_app_target(&content).ok_or_else(|| {
		let proj_name = xcodeproj_path
			.file_stem()
			.and_then(|s| s.to_str())
			.unwrap_or("project");
		LpmError::Registry(format!(
			"No app target found in {proj_name}.xcodeproj. \
			 LPM requires an app target (not a framework or test target)."
		))
	})?;

	// Find the Frameworks build phase for this target
	let frameworks_phase_id = find_frameworks_phase(&content, &target_id).ok_or_else(|| {
		LpmError::Registry(format!(
			"No Frameworks build phase found for target '{target_name}'"
		))
	})?;

	// Generate object IDs
	let pkg_ref_id = generate_object_id();
	let product_dep_id = generate_object_id();
	let build_file_id = generate_object_id();

	// Back up pbxproj before first modification
	let backup_path = pbxproj.with_extension("pbxproj.lpm-backup");
	if !backup_path.exists() {
		std::fs::copy(&pbxproj, &backup_path).map_err(|e| {
			LpmError::Registry(format!("failed to back up project.pbxproj: {e}"))
		})?;
	}

	// Apply all edits
	let edited = insert_full_package_link(
		&content,
		local_pkg_rel_path,
		product_name,
		&target_id,
		&frameworks_phase_id,
		&pkg_ref_id,
		&product_dep_id,
		&build_file_id,
	)?;

	// Atomic write
	write_pbxproj_atomic(&pbxproj, &edited)?;

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
	let id_line_start = before_block.rfind('\n').map(|i| i + 1).unwrap_or(0);
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
fn find_main_app_target(content: &str) -> Option<(String, String)> {
	let section_start =
		content.find("/* Begin PBXNativeTarget section */")?;
	let section_end =
		content.find("/* End PBXNativeTarget section */")?;
	let section = &content[section_start..section_end];

	// Find targets with application product type
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
		if trimmed.contains("productType") && trimmed.contains("com.apple.product-type.application")
		{
			if !current_id.is_empty() {
				return Some((current_id.clone(), current_name.clone()));
			}
		}
	}

	None
}

/// Find the PBXFrameworksBuildPhase ID referenced by the given target.
fn find_frameworks_phase(content: &str, target_id: &str) -> Option<String> {
	// Find the target block
	let target_pattern = format!("{target_id} /*");
	let target_start = content.find(&target_pattern)?;

	// Find buildPhases within this target
	let target_section = &content[target_start..];
	let target_end = find_block_end(target_section)?;
	let target_block = &target_section[..target_end];

	// Find the Frameworks phase ID in buildPhases
	for line in target_block.lines() {
		if line.contains("/* Frameworks */") {
			return extract_object_id(line.trim());
		}
	}
	None
}

/// Insert all 6 pbxproj entries for a new local package link.
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
	result = insert_in_section(&result, "PBXBuildFile", &build_file_entry)?;

	// 2. PBXFrameworksBuildPhase — add build file to the Frameworks phase's files list
	result = insert_in_array_property(
		&result,
		frameworks_phase_id,
		"files",
		&format!("\t\t\t\t{build_file_id} /* {product_name} in Frameworks */,"),
	)?;

	// 3. PBXProject.packageReferences — add package ref
	let project_id = find_project_object_id(&result).ok_or_else(|| {
		LpmError::Registry("Could not find PBXProject object in pbxproj".into())
	})?;
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
	result =
		insert_in_section_or_create(&result, "XCLocalSwiftPackageReference", &pkg_ref_entry)?;

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

	// Section doesn't exist — create it before the closing `};` + `rootObject` line
	let insert_before = content
		.find("\trootObject = ")
		.or_else(|| content.rfind("};"))
		.ok_or_else(|| {
			LpmError::Registry("Could not find insertion point for new pbxproj section".into())
		})?;

	// Find the start of the line
	let line_start = content[..insert_before]
		.rfind('\n')
		.map(|i| i + 1)
		.unwrap_or(insert_before);

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
	let obj_pattern = format!("{object_id} /*");
	let obj_start = content.find(&obj_pattern).ok_or_else(|| {
		LpmError::Registry(format!("Could not find object {object_id} in pbxproj"))
	})?;

	// Find the property within the object
	let search_from = obj_start;
	let obj_block_end = find_block_end(&content[search_from..])
		.map(|i| search_from + i)
		.unwrap_or(content.len());

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
			LpmError::Registry(format!(
				"Could not find closing ')' for '{property_name}'"
			))
		})?;

	// Insert before the closing )
	let close_line_start = content[..close_paren]
		.rfind('\n')
		.map(|i| i + 1)
		.unwrap_or(close_paren);

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
	let obj_pattern = format!("{object_id} /*");
	let obj_start = content.find(&obj_pattern).ok_or_else(|| {
		LpmError::Registry(format!("Could not find object {object_id} in pbxproj"))
	})?;

	let obj_block_end = find_block_end(&content[obj_start..])
		.map(|i| obj_start + i)
		.unwrap_or(content.len());

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
			.map(|i| obj_start + i)
			.unwrap_or(obj_block_end)
	};

	// Find the end of the current line
	let line_end = content[insert_pos..]
		.find('\n')
		.map(|i| insert_pos + i + 1)
		.unwrap_or(insert_pos);

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
			let id = after_eq
				.trim()
				.split_whitespace()
				.next()?
				.trim_end_matches(';');
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

/// Find the end of a `{ ... };` block starting from the first `{`.
fn find_block_end(content: &str) -> Option<usize> {
	let mut depth = 0i32;
	let mut in_string = false;

	for (i, ch) in content.char_indices() {
		match ch {
			'"' if !in_string => in_string = true,
			'"' if in_string => in_string = false,
			'{' if !in_string => depth += 1,
			'}' if !in_string => {
				depth -= 1;
				if depth == 0 {
					// Include the trailing `;` if present
					let rest = &content[i + 1..];
					if rest.starts_with(';') {
						return Some(i + 2);
					}
					return Some(i + 1);
				}
			}
			_ => {}
		}
	}
	None
}

/// Write pbxproj content atomically: write to temp file, then rename.
fn write_pbxproj_atomic(pbxproj_path: &Path, content: &str) -> Result<(), LpmError> {
	let dir = pbxproj_path
		.parent()
		.ok_or_else(|| LpmError::Registry("Invalid pbxproj path".into()))?;

	let tmp_path = dir.join(".project.pbxproj.lpm-tmp");
	std::fs::write(&tmp_path, content)
		.map_err(|e| LpmError::Registry(format!("failed to write temp pbxproj: {e}")))?;

	std::fs::rename(&tmp_path, pbxproj_path)
		.map_err(|e| LpmError::Registry(format!("failed to rename pbxproj: {e}")))?;

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

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
		let result = find_main_app_target(SAMPLE_PBXPROJ);
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
		let result = find_main_app_target(&with_test);
		assert!(result.is_none());
	}

	#[test]
	fn find_frameworks_phase_works() {
		let phase =
			find_frameworks_phase(SAMPLE_PBXPROJ, "284E0D1F2F5F71880018579D");
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
