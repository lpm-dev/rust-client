/// Extract and normalize Swift manifest metadata from raw `swift package dump-package` output.
///
/// Transforms raw SPM dump-package JSON into the canonical format expected by the server:
/// - `toolsVersion: { _version: "5.9.0", ... }` → `"5.9.0"`
/// - `platforms[].platformName` → `platforms[].name`
/// - `products[].type: { library: [...] }` → `"library"`
/// - `targets[].dependencies[].byName: ["Foo", null]` → `{ type: "byName", name: "Foo" }`
/// - `dependencies[].sourceControl: [{ identity, location, ... }]` → flat object
pub(super) fn extract_swift_metadata(manifest: &serde_json::Value) -> serde_json::Value {
    let tools_version = manifest
        .get("toolsVersion")
        .and_then(|tv| {
            // Object form: { _version: "5.9.0", ... }
            if let Some(v) = tv.get("_version").and_then(|v| v.as_str()) {
                Some(serde_json::json!(v))
            } else if tv.is_string() {
                // Already a string
                Some(tv.clone())
            } else {
                None
            }
        })
        .unwrap_or(serde_json::Value::Null);

    let platforms = manifest
        .get("platforms")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .map(|p| {
                    serde_json::json!({
                        "name": p.get("platformName")
                            .or_else(|| p.get("name"))
                            .and_then(|v| v.as_str())
                            .unwrap_or_default(),
                        "version": p.get("version")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default(),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let products = manifest
        .get("products")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .map(|p| {
                    let product_type = p.get("type").map_or_else(
                        || "library".into(),
                        |t| {
                            if let Some(obj) = t.as_object() {
                                obj.keys()
                                    .next()
                                    .cloned()
                                    .unwrap_or_else(|| "library".into())
                            } else if let Some(s) = t.as_str() {
                                s.to_string()
                            } else {
                                "library".into()
                            }
                        },
                    );

                    serde_json::json!({
                        "name": p.get("name").and_then(|v| v.as_str()).unwrap_or_default(),
                        "type": product_type,
                        "targets": p.get("targets").cloned().unwrap_or(serde_json::json!([])),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let targets = manifest
        .get("targets")
        .and_then(|t| t.as_array())
        .map(|arr| {
            arr.iter()
                .map(|t| {
                    let deps = t
                        .get("dependencies")
                        .and_then(|d| d.as_array())
                        .map(|deps| {
                            deps.iter()
                                .map(|d| {
                                    // Already extracted: has "type" and "name"
                                    if d.get("type").is_some() && d.get("name").is_some() {
                                        return d.clone();
                                    }
                                    // Raw: { byName: ["Foo", null] }
                                    if let Some(by_name) =
                                        d.get("byName").and_then(|v| v.as_array())
                                    {
                                        return serde_json::json!({
                                            "type": "byName",
                                            "name": by_name.first()
                                                .and_then(|v| v.as_str())
                                                .unwrap_or_default(),
                                        });
                                    }
                                    // Raw: { product: ["Bar", ...] }
                                    if let Some(product) =
                                        d.get("product").and_then(|v| v.as_array())
                                    {
                                        return serde_json::json!({
                                            "type": "product",
                                            "name": product.first()
                                                .and_then(|v| v.as_str())
                                                .unwrap_or_default(),
                                        });
                                    }
                                    d.clone()
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();

                    serde_json::json!({
                        "name": t.get("name").and_then(|v| v.as_str()).unwrap_or_default(),
                        "type": t.get("type").and_then(|v| v.as_str()).unwrap_or("regular"),
                        "dependencies": deps,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let dependencies = manifest
        .get("dependencies")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .map(|dep| {
                    // Already extracted
                    if dep.get("type").is_some()
                        && (dep.get("identity").is_some() || dep.get("name").is_some())
                    {
                        return dep.clone();
                    }
                    // Raw: { sourceControl: [{ identity, location: { remote: [...] }, requirement }] }
                    if let Some(sc_val) = dep.get("sourceControl") {
                        let sc = if let Some(arr) = sc_val.as_array() {
                            arr.first()
                        } else {
                            Some(sc_val)
                        };
                        if let Some(sc) = sc {
                            return serde_json::json!({
                                "type": "sourceControl",
                                "identity": sc.get("identity").and_then(|v| v.as_str()),
                                "location": sc.get("location")
                                    .and_then(|l| l.get("remote"))
                                    .and_then(|r| r.as_array())
                                    .and_then(|a| a.first())
                                    .and_then(|v| v.as_str()),
                                "requirement": sc.get("requirement").cloned(),
                            });
                        }
                    }
                    // Raw: { fileSystem: [{ identity, path }] }
                    if let Some(fs_val) = dep.get("fileSystem") {
                        let fs = if let Some(arr) = fs_val.as_array() {
                            arr.first()
                        } else {
                            Some(fs_val)
                        };
                        if let Some(fs) = fs {
                            return serde_json::json!({
                                "type": "fileSystem",
                                "identity": fs.get("identity").and_then(|v| v.as_str()),
                                "path": fs.get("path").and_then(|v| v.as_str()),
                            });
                        }
                    }
                    dep.clone()
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    serde_json::json!({
        "toolsVersion": tools_version,
        "platforms": platforms,
        "products": products,
        "targets": targets,
        "dependencies": dependencies,
    })
}
