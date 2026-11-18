mod publication;

use crate::commands::install::{
    NpmFirewallMaterializationPackage, begin_prepared_npm_firewall_materialization_preflight,
    prepare_npm_firewall_materialization_preflight, registry_materialization_route_is_public_npm,
};
use crate::commands::registry_reads::{
    RoutedPackageRef, fetch_routed_package_metadata, normalize_package_version_input,
    prepare_routed_read_context,
};
use crate::install_ui;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use std::path::Path;
use std::path::PathBuf;
use std::time::Instant;

pub async fn run(
    client: &RegistryClient,
    project_dir: &Path,
    package: &str,
    version: Option<&str>,
    output_dir: Option<&str>,
    allow_unverified: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let (package, version) = normalize_package_version_input("download", package, version)?;
    let context =
        prepare_routed_read_context(client, project_dir, &[package.to_string()], json_output)?;
    let start = Instant::now();

    if !json_output {
        install_ui::phase_line(install_ui::TerminalLine::new("Resolving ").field(package));
    }

    let (package_ref, metadata) = fetch_routed_package_metadata(&context, package).await?;
    let package_name = metadata.name.clone();

    let version_key = match version {
        Some(spec) => metadata.resolve_version_spec(spec)?,
        None => metadata
            .latest_version_tag()
            .map(str::to_string)
            .ok_or_else(|| LpmError::NotFound(format!("no versions found for {package_name}")))?,
    };

    let ver = metadata.version(&version_key).ok_or_else(|| {
        LpmError::NotFound(format!(
            "version {version_key} not found for {package_name}"
        ))
    })?;

    let tarball_url = ver.tarball_url().ok_or_else(|| {
        LpmError::Registry(format!("no tarball URL for {package_name}@{version_key}"))
    })?;

    let integrity_str = ver.integrity_or_shasum();
    if let Some(sri) = integrity_str.as_ref() {
        lpm_common::integrity::Integrity::parse(sri.as_ref())?;
    } else if !allow_unverified {
        return Err(LpmError::Registry(format!(
            "{package_name}@{version_key}: registry returned no integrity hash; refusing to download an unverified tarball. Use --allow-unverified to extract without verification"
        )));
    }

    let firewall_packages = match &package_ref {
        RoutedPackageRef::Registry(route_name)
            if registry_materialization_route_is_public_npm(
                &context.route_table,
                &context.client,
                route_name,
            ) =>
        {
            vec![NpmFirewallMaterializationPackage::new(
                &package_name,
                &version_key,
                integrity_str.as_deref(),
                metadata.time.get(&version_key).map(String::as_str),
            )]
        }
        _ => Vec::new(),
    };
    let firewall_preflight = prepare_npm_firewall_materialization_preflight(
        project_dir,
        &firewall_packages,
        json_output,
    )?;

    if !json_output {
        let download_message = install_ui::TerminalLine::new("Downloading ")
            .field(&package_name)
            .text("@")
            .field(&version_key);
        install_ui::phase_line(install_ui::with_firewall_badge(
            download_message,
            firewall_preflight.is_active(),
        ));
    }

    let firewall_verdict = begin_prepared_npm_firewall_materialization_preflight(
        &context.client,
        firewall_preflight,
        json_output,
    )
    .await?;

    let downloaded = match integrity_str.as_ref() {
        Some(sri) => {
            context
                .client
                .download_tarball_routed_with_integrity(
                    &context.route_table,
                    &package_ref.route_name(),
                    tarball_url,
                    sri.as_ref(),
                )
                .await?
        }
        None => {
            context
                .client
                .download_tarball_routed(
                    &context.route_table,
                    &package_ref.route_name(),
                    tarball_url,
                )
                .await?
        }
    };
    let firewall_json = firewall_verdict.settle(json_output).await?;
    let size = downloaded.compressed_size;

    let integrity_verified = if let Some(sri) = integrity_str.as_ref() {
        if !json_output {
            install_ui::done_line(
                install_ui::TerminalLine::new("Verified integrity ").field(&short_integrity(sri)),
            );
        }
        true
    } else {
        if !json_output {
            install_ui::warn("No integrity hash available — skipping verification");
        }
        false
    };

    let target_dir = output_dir.map_or_else(|| PathBuf::from("."), PathBuf::from);
    let (target_dir, files) = tokio::task::spawn_blocking(move || {
        let result = publication::extract_and_publish(downloaded.file.path(), &target_dir);
        // Keep the spool reservation until extraction and publication finish.
        drop(downloaded);
        result.map(|files| (target_dir, files))
    })
    .await
    .map_err(|error| LpmError::Registry(format!("download extraction worker failed: {error}")))??;

    let elapsed = start.elapsed();

    if json_output {
        // Resolve to an absolute path now that extraction has created the
        // directory. Fall back to the lexical form if canonicalize fails
        // (e.g., target_dir was deleted out from under us mid-run).
        let absolute_output_dir = target_dir.canonicalize().map_or_else(
            |_| target_dir.display().to_string(),
            |p| p.display().to_string(),
        );
        let mut json = serde_json::json!({
            "success": true,
            "package": package_name,
            "version": version_key,
            "tarball_url": masked_tarball_url(tarball_url),
            "integrity": integrity_str,
            "integrity_verified": integrity_verified,
            "size_bytes": size,
            "output_dir": absolute_output_dir,
            "files_extracted": files.len(),
            "elapsed_secs": (elapsed.as_millis() as f64) / 1000.0,
        });
        if let Some(firewall_json) = firewall_json {
            json["firewall"] = firewall_json;
        }
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        eprintln!(
            "{}",
            crate::install_ui::terminal_line!(
                "    {} {}",
                install_ui::dim(&format!("{:<16}", "output:")),
                install_ui::yellow(&target_dir.display().to_string())
            )
        );
        eprintln!(
            "{}",
            crate::install_ui::terminal_line!(
                "    {} {}",
                install_ui::dim(&format!("{:<16}", "files extracted:")),
                files.len()
            )
        );
        eprintln!(
            "{}",
            crate::install_ui::terminal_line!(
                "    {} {}",
                install_ui::dim(&format!("{:<16}", "size:")),
                lpm_common::format_bytes(size)
            )
        );
        eprintln!();

        // Show extracted files summary
        if files.len() <= 20 {
            for f in &files {
                eprintln!(
                    "{}",
                    crate::install_ui::terminal_line!(
                        "    {}",
                        install_ui::dim(&f.display().to_string())
                    )
                );
            }
        } else {
            for f in files.iter().take(15) {
                eprintln!(
                    "{}",
                    crate::install_ui::terminal_line!(
                        "    {}",
                        install_ui::dim(&f.display().to_string())
                    )
                );
            }
            eprintln!(
                "{}",
                crate::install_ui::terminal_line!(
                    "    {}",
                    install_ui::dim(&format!("… and {} more files", files.len() - 15))
                )
            );
        }

        eprintln!();
        let duration = install_ui::format_duration(elapsed);
        install_ui::done_line(
            install_ui::TerminalLine::new("Done · tarball extracted in ").green(&duration),
        );
    }

    Ok(())
}

fn short_integrity(integrity: &str) -> String {
    const KEEP: usize = 10;
    if integrity.chars().count() <= KEEP * 2 + 3 {
        return integrity.to_string();
    }
    let prefix: String = integrity.chars().take(KEEP).collect();
    let suffix: String = integrity
        .chars()
        .rev()
        .take(KEEP)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{prefix}…{suffix}")
}

/// `url` with any credentials, each query value, and any fragment replaced
/// by `<redacted>`, keeping the query's keys: a registry that signs its
/// download URLs puts the signature in the query.
fn masked_tarball_url(url: &str) -> std::borrow::Cow<'_, str> {
    const MASK: &str = "<redacted>";
    let (before_fragment, fragment) = match url.split_once('#') {
        Some((before, fragment)) => (before, Some(fragment)),
        None => (url, None),
    };
    let (base, query) = match before_fragment.split_once('?') {
        Some((base, query)) => (base, Some(query)),
        None => (before_fragment, None),
    };
    let authority_start = base.find("://").map_or(0, |scheme_end| scheme_end + 3);
    let authority_end = base[authority_start..]
        .find('/')
        .map_or(base.len(), |offset| authority_start + offset);
    let userinfo_end = base[authority_start..authority_end]
        .rfind('@')
        .map(|offset| authority_start + offset);
    if query.is_none() && fragment.is_none() && userinfo_end.is_none() {
        return std::borrow::Cow::Borrowed(url);
    }
    let mut masked = String::with_capacity(url.len());
    match userinfo_end {
        Some(userinfo_end) => {
            masked.push_str(&base[..authority_start]);
            masked.push_str(MASK);
            masked.push_str(&base[userinfo_end..]);
        }
        None => masked.push_str(base),
    }
    if let Some(query) = query {
        masked.push('?');
        let mut pairs = query.split('&').filter(|pair| !pair.is_empty()).peekable();
        while let Some(pair) = pairs.next() {
            match pair.split_once('=') {
                Some((key, _)) => {
                    masked.push_str(key);
                    masked.push('=');
                    masked.push_str(MASK);
                }
                None => masked.push_str(MASK),
            }
            if pairs.peek().is_some() {
                masked.push('&');
            }
        }
    }
    if fragment.is_some_and(|fragment| !fragment.is_empty()) {
        masked.push('#');
        masked.push_str(MASK);
    }
    std::borrow::Cow::Owned(masked)
}

#[cfg(test)]
mod tests {
    use super::masked_tarball_url;

    #[test]
    fn a_tarball_url_without_a_query_is_shown_as_it_is() {
        let url = "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz";
        assert!(matches!(
            masked_tarball_url(url),
            std::borrow::Cow::Borrowed(shown) if shown == url
        ));
    }

    #[test]
    fn a_tarball_url_shows_its_query_keys_but_not_their_values() {
        for (url, shown) in [
            (
                "https://cdn.example/pkg/-/pkg-1.0.0.tgz?X-Amz-Signature=abc&X-Amz-Expires=600",
                "https://cdn.example/pkg/-/pkg-1.0.0.tgz?X-Amz-Signature=<redacted>&X-Amz-Expires=<redacted>",
            ),
            (
                "https://cdn.example/pkg.tgz?token&&sig=a=b",
                "https://cdn.example/pkg.tgz?<redacted>&sig=<redacted>",
            ),
            (
                "https://cdn.example/pkg.tgz?sig=abc#frag?ment",
                "https://cdn.example/pkg.tgz?sig=<redacted>#<redacted>",
            ),
            (
                "https://cdn.example/pkg.tgz#value",
                "https://cdn.example/pkg.tgz#<redacted>",
            ),
            (
                "https://cdn.example/pkg.tgz?",
                "https://cdn.example/pkg.tgz?",
            ),
            (
                "https://user:token@cdn.example/pkg.tgz",
                "https://<redacted>@cdn.example/pkg.tgz",
            ),
            (
                "https://user:token@cdn.example/pkg.tgz?sig=abc",
                "https://<redacted>@cdn.example/pkg.tgz?sig=<redacted>",
            ),
            (
                "https://cdn.example/path@segment/pkg.tgz",
                "https://cdn.example/path@segment/pkg.tgz",
            ),
        ] {
            assert_eq!(masked_tarball_url(url), shown, "{url}");
        }
    }
}
