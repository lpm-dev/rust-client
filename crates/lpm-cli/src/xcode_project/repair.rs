use super::*;

fn references<'a>(content: &'a str, object: &str, property: &str) -> Vec<&'a str> {
    object_block(content, object)
        .and_then(|block| property_value(block, property))
        .unwrap_or("")
        .split(|ch: char| !ch.is_ascii_hexdigit())
        .filter(|value| value.len() == 24)
        .collect()
}

pub(super) fn target_link(
    content: &str,
    target: &str,
    package: &str,
    product: &str,
    name: &str,
    path: &str,
) -> Result<String, LpmError> {
    let mut edited = content.to_owned();
    let project = find_project_object_id(content)
        .ok_or_else(|| LpmError::Registry("Missing Xcode project object".into()))?;
    if !references(&edited, &project, "packageReferences").contains(&package) {
        edited = insert_or_create_array_property(
            &edited,
            &project,
            "packageReferences",
            &format!("\t\t\t\t{package} /* XCLocalSwiftPackageReference \"{path}\" */,"),
            "mainGroup",
        )?;
    }
    // Each target can have its own product object for the same local package.
    let product = references(&edited, target, "packageProductDependencies")
        .into_iter()
        .find(|id| {
            object_block(&edited, id).is_some_and(|block| {
                property_value(block, "productName")
                    .is_some_and(|value| value.trim_matches('"') == name)
                    && property_value(block, "package")
                        .is_none_or(|value| value.starts_with(package))
            })
        })
        .unwrap_or(product)
        .to_owned();
    if !references(&edited, target, "packageProductDependencies").contains(&product.as_str()) {
        edited = insert_or_create_array_property(
            &edited,
            target,
            "packageProductDependencies",
            &format!("\t\t\t\t{product} /* {name} */,"),
            "dependencies",
        )?;
    }
    let phase = if let Some(phase) = find_frameworks_phase(&edited, target) {
        phase
    } else {
        let phase = generate_object_id();
        edited = insert_in_section_or_create(
            &edited,
            "PBXFrameworksBuildPhase",
            &format!(
                "\t\t{phase} /* Frameworks */ = {{\n\t\t\tisa = PBXFrameworksBuildPhase;\n\t\t\tbuildActionMask = 2147483647;\n\t\t\tfiles = (\n\t\t\t);\n\t\t\trunOnlyForDeploymentPostprocessing = 0;\n\t\t}};"
            ),
        )?;
        edited = insert_or_create_array_property(
            &edited,
            target,
            "buildPhases",
            &format!("\t\t\t\t{phase} /* Frameworks */,"),
            "isa",
        )?;
        phase
    };
    if references(&edited, &phase, "files").iter().any(|id| {
        object_block(&edited, id)
            .and_then(|block| property_value(block, "productRef"))
            .is_some_and(|value| value.starts_with(&product))
    }) {
        return Ok(edited);
    }
    let build = generate_object_id();
    edited = insert_in_section_or_create(
        &edited,
        "PBXBuildFile",
        &format!(
            "\t\t{build} /* {name} in Frameworks */ = {{isa = PBXBuildFile; productRef = {product} /* {name} */; }};"
        ),
    )?;
    insert_or_create_array_property(
        &edited,
        &phase,
        "files",
        &format!("\t\t\t\t{build} /* {name} in Frameworks */,"),
        "buildActionMask",
    )
}
