//! Smart import path rewriting for source-delivered packages.
//!
//! When `lpm add` copies source files into a project, internal imports need
//! to be rewritten from the author's alias to the buyer's alias. Relative
//! imports between installed files are also resolved through the src→dest
//! mapping to keep internal references correct.

use std::collections::{HashMap, HashSet};

/// File extensions to try when resolving import paths.
const EXTENSIONS: &[&str] = &[".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpecifierKind {
    Relative,
    AuthorAlias,
    Bare,
}

fn classify_specifier(specifier: &str, author_alias: Option<&str>) -> SpecifierKind {
    if specifier.starts_with("./")
        || specifier.starts_with("../")
        || specifier == "."
        || specifier == ".."
    {
        return SpecifierKind::Relative;
    }
    // A protocol-relative URL, never a path into the package, even under `/`.
    if specifier.starts_with("//") {
        return SpecifierKind::Bare;
    }
    if let Some(alias) = author_alias
        && specifier.starts_with(alias)
    {
        return SpecifierKind::AuthorAlias;
    }
    SpecifierKind::Bare
}

/// Rewrite imports in a source file using per-file context.
///
/// # Arguments
/// * `content` - The file content
/// * `file_src_path` - The file's path relative to the extraction root (e.g., `"atoms/Icon/Icon.jsx"`)
/// * `file_dest_path` - The file's destination path relative to target dir (e.g., `"atoms/Icon/Icon.jsx"`)
/// * `author_alias` - The alias used by the author (e.g., `"@/"`)
/// * `buyer_alias` - The alias configured in the buyer's project (e.g., `"@/components/"`)
/// * `src_to_dest` - Map from source paths to destination paths
/// * `src_files` - Set of all source file paths
/// * `dest_files` - Set of all destination file paths
///
/// Returns the rewritten content, or None if no changes were made.
#[cfg(test)]
#[expect(
    clippy::too_many_arguments,
    reason = "rewriting requires explicit source, destination, alias, and index context"
)]
pub fn rewrite_imports(
    content: &str,
    file_src_path: &str,
    file_dest_path: &str,
    author_alias: Option<&str>,
    buyer_alias: Option<&str>,
    src_to_dest: &HashMap<String, String>,
    _src_files: &HashSet<String>,
    dest_files: &HashSet<String>,
) -> Option<String> {
    let borrowed_map = src_to_dest
        .iter()
        .map(|(source, destination)| (source.as_str(), destination.as_str()))
        .collect();
    let borrowed_destinations = dest_files.iter().map(String::as_str).collect();
    rewrite_imports_indexed(
        content,
        file_src_path,
        file_dest_path,
        author_alias,
        buyer_alias,
        &borrowed_map,
        &borrowed_destinations,
    )
}

pub fn rewrite_imports_indexed(
    content: &str,
    file_src_path: &str,
    file_dest_path: &str,
    author_alias: Option<&str>,
    buyer_alias: Option<&str>,
    src_to_dest: &HashMap<&str, &str>,
    dest_files: &HashSet<&str>,
) -> Option<String> {
    rewrite_imports_indexed_inner(
        content,
        file_src_path,
        file_dest_path,
        author_alias,
        buyer_alias,
        src_to_dest,
        dest_files,
        None,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "rewriting and import collection share explicit path and alias indexes"
)]
pub fn rewrite_imports_indexed_collecting_bare(
    content: &str,
    file_src_path: &str,
    file_dest_path: &str,
    author_alias: Option<&str>,
    buyer_alias: Option<&str>,
    src_to_dest: &HashMap<&str, &str>,
    dest_files: &HashSet<&str>,
    bare_specifiers: &mut HashSet<String>,
) -> Option<String> {
    rewrite_imports_indexed_inner(
        content,
        file_src_path,
        file_dest_path,
        author_alias,
        buyer_alias,
        src_to_dest,
        dest_files,
        Some(bare_specifiers),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "rewriting and import collection share explicit path and alias indexes"
)]
fn rewrite_imports_indexed_inner(
    content: &str,
    file_src_path: &str,
    file_dest_path: &str,
    author_alias: Option<&str>,
    buyer_alias: Option<&str>,
    src_to_dest: &HashMap<&str, &str>,
    dest_files: &HashSet<&str>,
    mut bare_specifiers: Option<&mut HashSet<String>>,
) -> Option<String> {
    let file_src_path = normalize_separators(file_src_path);
    let file_dest_path = normalize_separators(file_dest_path);
    let file_src_dir = dirname(&file_src_path);
    let file_dest_dir = dirname(&file_dest_path);

    let mut replacements = Vec::new();
    visit_code_specifier_ranges(content, |range| {
        let specifier = &content[range.clone()];
        if classify_specifier(specifier, author_alias) == SpecifierKind::Bare
            && let Some(bare_specifiers) = bare_specifiers.as_deref_mut()
        {
            bare_specifiers.insert(specifier.to_string());
        }
        if let Some(new_specifier) = resolve_and_rewrite(
            specifier,
            &file_src_dir,
            &file_dest_dir,
            author_alias,
            buyer_alias,
            src_to_dest,
            dest_files,
        ) {
            replacements.push((range, new_specifier));
        }
    });
    if replacements.is_empty() {
        return None;
    }

    let extra: usize = replacements
        .iter()
        .map(|(range, replacement)| replacement.len().saturating_sub(range.len()))
        .sum();
    let mut result = String::with_capacity(content.len() + extra);
    let mut copied = 0;
    for (range, replacement) in replacements {
        if range.start < copied {
            continue;
        }
        result.push_str(&content[copied..range.start]);
        result.push_str(&replacement);
        copied = range.end;
    }
    result.push_str(&content[copied..]);
    Some(result)
}

fn normalize_separators(path: &str) -> std::borrow::Cow<'_, str> {
    if path.as_bytes().contains(&b'\\') {
        std::borrow::Cow::Owned(path.replace('\\', "/"))
    } else {
        std::borrow::Cow::Borrowed(path)
    }
}

fn resolve_and_rewrite(
    specifier: &str,
    file_src_dir: &str,
    file_dest_dir: &str,
    author_alias: Option<&str>,
    buyer_alias: Option<&str>,
    src_to_dest: &HashMap<&str, &str>,
    dest_files: &HashSet<&str>,
) -> Option<String> {
    match classify_specifier(specifier, author_alias) {
        SpecifierKind::Relative => {
            // An import that climbs above the source package points into the
            // author's project, whatever it lands on after delivery.
            if leaves_the_root(file_src_dir, specifier) {
                return None;
            }
            let folder = names_a_folder(specifier);
            let resolved_src = normalize_path(&join_path(file_src_dir, specifier));
            if let Some(src_match) = try_resolve_map_key(&resolved_src, folder, src_to_dest)
                && let Some(dest_path) = src_to_dest.get(src_match)
            {
                return compute_new_specifier(
                    dest_path,
                    file_dest_dir,
                    buyer_alias,
                    Some(specifier),
                    dest_files,
                );
            }

            if !leaves_the_root(file_dest_dir, specifier) {
                let resolved_dest = normalize_path(&join_path(file_dest_dir, specifier));
                if let Some(dest_match) = try_resolve_set(&resolved_dest, folder, dest_files) {
                    return compute_new_specifier(
                        dest_match,
                        file_dest_dir,
                        buyer_alias,
                        Some(specifier),
                        dest_files,
                    );
                }
            }

            None
        }

        SpecifierKind::AuthorAlias => {
            let alias = author_alias?;
            let path = specifier.strip_prefix(alias)?;
            // A prefix kept as written, such as `#`, may be followed by `/`.
            let path = path.strip_prefix('/').unwrap_or(path);
            let folder = path.is_empty() || path.ends_with('/');

            if let Some(src_match) = try_resolve_map_key(path, folder, src_to_dest)
                && let Some(dest_path) = src_to_dest.get(src_match)
            {
                return compute_new_specifier(
                    dest_path,
                    file_dest_dir,
                    buyer_alias,
                    None,
                    dest_files,
                );
            }

            if let Some(dest_match) = try_resolve_set(path, folder, dest_files) {
                if buyer_alias == author_alias {
                    return None;
                }
                return compute_new_specifier(
                    dest_match,
                    file_dest_dir,
                    buyer_alias,
                    None,
                    dest_files,
                );
            }

            if buyer_alias != author_alias
                && let Some(b_alias) = buyer_alias
            {
                return Some(format!("{b_alias}{path}"));
            }

            None
        }

        SpecifierKind::Bare => None,
    }
}

/// Collects bare imports using the same lexer and classifier as rewriting.
#[cfg(test)]
pub fn collect_bare_specifiers(content: &str, author_alias: Option<&str>) -> HashSet<String> {
    let mut bare = HashSet::new();
    visit_code_specifier_ranges(content, |range| {
        let specifier = &content[range];
        if classify_specifier(specifier, author_alias) == SpecifierKind::Bare {
            bare.insert(specifier.to_string());
        }
    });

    bare
}

fn visit_code_specifier_ranges(content: &str, mut visit: impl FnMut(std::ops::Range<usize>)) {
    visit_code_ranges(content.as_bytes(), 0, false, &mut visit);
}

fn visit_code_ranges(
    bytes: &[u8],
    mut index: usize,
    stop_at_closing_brace: bool,
    visit: &mut impl FnMut(std::ops::Range<usize>),
) -> usize {
    let mut nested_braces = 0_usize;
    let mut regex_allowed = true;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' | b'"' => {
                index = skip_quoted(bytes, index);
                regex_allowed = false;
            }
            b'`' => {
                index = visit_template_literal(bytes, index, visit);
                regex_allowed = false;
            }
            b'/' if bytes[index..].starts_with(b"//") => {
                index = bytes[index..]
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(bytes.len(), |offset| index + offset + 1);
            }
            b'/' if bytes[index..].starts_with(b"/*") => {
                index = bytes[index + 2..]
                    .windows(2)
                    .position(|window| window == b"*/")
                    .map_or(bytes.len(), |offset| index + offset + 4);
            }
            b'/' if regex_allowed => {
                index = skip_regex(bytes, index);
                regex_allowed = false;
            }
            b'/' => {
                index += 1;
                regex_allowed = true;
            }
            b'{' => {
                nested_braces += 1;
                index += 1;
                regex_allowed = true;
            }
            b'}' if stop_at_closing_brace && nested_braces == 0 => return index + 1,
            b'}' => {
                nested_braces = nested_braces.saturating_sub(1);
                index += 1;
                regex_allowed = false;
            }
            byte if is_identifier_start(byte) => {
                let start = index;
                index += 1;
                while index < bytes.len() && is_identifier_byte(bytes[index]) {
                    index += 1;
                }
                let keyword = &bytes[start..index];
                index = match keyword {
                    b"from" => visit_quoted_after(bytes, index, false, visit),
                    b"import" | b"require" => visit_quoted_after(bytes, index, true, visit),
                    _ => index,
                };
                regex_allowed = keyword_allows_regex(keyword);
            }
            byte if byte.is_ascii_digit() => {
                index += 1;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric()
                        || matches!(bytes[index], b'.' | b'_' | b'$'))
                {
                    index += 1;
                }
                regex_allowed = false;
            }
            b'+' | b'-' if bytes.get(index + 1) == bytes.get(index) => {
                index += 2;
                regex_allowed = false;
            }
            byte => {
                index += 1;
                if !byte.is_ascii_whitespace() {
                    regex_allowed = punctuation_allows_regex(byte);
                }
            }
        }
    }
    bytes.len()
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$')
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$')
}

fn keyword_allows_regex(keyword: &[u8]) -> bool {
    matches!(
        keyword,
        b"return"
            | b"throw"
            | b"case"
            | b"delete"
            | b"void"
            | b"typeof"
            | b"instanceof"
            | b"in"
            | b"of"
            | b"yield"
            | b"await"
            | b"new"
            | b"else"
            | b"do"
    )
}

fn punctuation_allows_regex(byte: u8) -> bool {
    !matches!(byte, b')' | b']' | b'.')
}

fn skip_trivia(bytes: &[u8], mut index: usize) -> usize {
    loop {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if bytes[index..].starts_with(b"//") {
            index = bytes[index..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(bytes.len(), |offset| index + offset + 1);
        } else if bytes[index..].starts_with(b"/*") {
            index = bytes[index + 2..]
                .windows(2)
                .position(|window| window == b"*/")
                .map_or(bytes.len(), |offset| index + offset + 4);
        } else {
            return index;
        }
    }
}

fn visit_quoted_after(
    bytes: &[u8],
    mut index: usize,
    allow_parentheses: bool,
    visit: &mut impl FnMut(std::ops::Range<usize>),
) -> usize {
    index = skip_trivia(bytes, index);
    if allow_parentheses && bytes.get(index) == Some(&b'(') {
        index = skip_trivia(bytes, index + 1);
    }
    let Some(&quote @ (b'\'' | b'"')) = bytes.get(index) else {
        return index.max(1);
    };
    let start = index + 1;
    index = start;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index = (index + 2).min(bytes.len());
        } else if bytes[index] == quote {
            visit(start..index);
            return index + 1;
        } else {
            index += 1;
        }
    }
    bytes.len()
}

fn visit_template_literal(
    bytes: &[u8],
    start: usize,
    visit: &mut impl FnMut(std::ops::Range<usize>),
) -> usize {
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index = (index + 2).min(bytes.len()),
            b'`' => return index + 1,
            b'$' if bytes.get(index + 1) == Some(&b'{') => {
                index = visit_code_ranges(bytes, index + 2, true, visit);
            }
            _ => index += 1,
        }
    }
    bytes.len()
}

fn skip_quoted(bytes: &[u8], start: usize) -> usize {
    let quote = bytes[start];
    let mut index = start + 1;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index = (index + 2).min(bytes.len());
        } else if bytes[index] == quote {
            return index + 1;
        } else {
            index += 1;
        }
    }
    bytes.len()
}

fn skip_regex(bytes: &[u8], start: usize) -> usize {
    let mut index = start + 1;
    let mut in_character_class = false;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index = (index + 2).min(bytes.len()),
            b'[' => {
                in_character_class = true;
                index += 1;
            }
            b']' => {
                in_character_class = false;
                index += 1;
            }
            b'/' if !in_character_class => {
                index += 1;
                while index < bytes.len() && bytes[index].is_ascii_alphabetic() {
                    index += 1;
                }
                return index;
            }
            b'\n' | b'\r' => return index,
            _ => index += 1,
        }
    }
    bytes.len()
}

/// Compute the new import specifier for a resolved internal file.
///
/// With a buyer alias, the alias is the exact prefix of every delivered file,
/// as `lpm add` builds it, and the file's path follows it. Without one, the
/// specifier is relative, or `None` when the original relative import still
/// points at the file.
fn compute_new_specifier(
    resolved_dest_path: &str,
    file_dest_dir: &str,
    buyer_alias: Option<&str>,
    original_relative: Option<&str>,
    dest_files: &HashSet<&str>,
) -> Option<String> {
    let runtime_extension = [".js", ".mjs", ".cjs", ".json"]
        .iter()
        .any(|extension| resolved_dest_path.ends_with(extension));
    let clean_path = if runtime_extension {
        resolved_dest_path.to_string()
    } else {
        import_path_without_extension(resolved_dest_path, dest_files)
    };

    if let Some(alias) = buyer_alias {
        return Some(format!("{alias}{clean_path}"));
    }

    // The original import stays when it still reaches the same file: a folder
    // import through that folder's index, any other through the same path
    // with or without its extension.
    if let Some(original) = original_relative
        && !leaves_the_root(file_dest_dir, original)
    {
        let original_target = normalize_path(&join_path(file_dest_dir, original));
        let unchanged = if names_a_folder(original) {
            try_resolve_set(&original_target, true, dest_files) == Some(resolved_dest_path)
        } else {
            original_target == clean_path
                || (!runtime_extension
                    && import_path_without_extension(&original_target, dest_files) == clean_path)
        };
        if unchanged {
            return None;
        }
    }

    Some(relative_import_specifier(file_dest_dir, &clean_path))
}

fn relative_import_specifier(from_dir: &str, target: &str) -> String {
    let from_parts = || from_dir.split('/').filter(|part| !part.is_empty());
    let target_parts = || target.split('/').filter(|part| !part.is_empty());
    let common = from_parts()
        .zip(target_parts())
        .take_while(|(left, right)| left == right)
        .count();
    let from_count = from_parts().count();
    let mut result = String::with_capacity(from_dir.len() + target.len() + 3);
    for _ in common..from_count {
        result.push_str("../");
    }
    if common == from_count {
        result.push_str("./");
    }
    for (index, part) in target_parts().skip(common).enumerate() {
        if index > 0 {
            result.push('/');
        }
        result.push_str(part);
    }
    result
}

/// Whether a specifier names a folder: `.`, `..`, or one whose last segment is
/// empty, `.` or `..`. LPM CLI resolves a folder only to its index, never to a
/// file of the same name beside it.
fn names_a_folder(specifier: &str) -> bool {
    matches!(specifier.rsplit('/').next(), Some("" | "." | ".."))
}

/// Whether a relative specifier, joined to `dir`, climbs above the package
/// root. Such an import points outside the delivered files, so LPM CLI leaves
/// it as written.
fn leaves_the_root(dir: &str, specifier: &str) -> bool {
    let mut depth = dir
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .count();
    for segment in specifier.split('/') {
        match segment {
            "" | "." => {}
            ".." if depth == 0 => return true,
            ".." => depth -= 1,
            _ => depth += 1,
        }
    }
    false
}

/// LPM CLI's lookup for `candidate`, a path from the package root: the file
/// itself, then with each supported extension, then the folder's index. A
/// `folder` candidate only tries the index, and an empty one is the package
/// root.
fn try_resolve<'a>(
    candidate: &str,
    folder: bool,
    mut lookup: impl FnMut(&str) -> Option<&'a str>,
) -> Option<&'a str> {
    let candidate = candidate.strip_prefix("./").unwrap_or(candidate);
    let candidate = candidate.strip_suffix('/').unwrap_or(candidate);
    let mut scratch = String::with_capacity(candidate.len() + "/index".len() + 4);
    if !folder && !candidate.is_empty() {
        if let Some(path) = lookup(candidate) {
            return Some(path);
        }
        for ext in EXTENSIONS {
            scratch.clear();
            scratch.push_str(candidate);
            scratch.push_str(ext);
            if let Some(path) = lookup(&scratch) {
                return Some(path);
            }
        }
    }

    for ext in EXTENSIONS {
        scratch.clear();
        if !candidate.is_empty() {
            scratch.push_str(candidate);
            scratch.push('/');
        }
        scratch.push_str("index");
        scratch.push_str(ext);
        if let Some(path) = lookup(&scratch) {
            return Some(path);
        }
    }

    None
}

fn try_resolve_map_key<'a>(
    candidate: &str,
    folder: bool,
    files: &HashMap<&'a str, &str>,
) -> Option<&'a str> {
    try_resolve(candidate, folder, |path| {
        files.get_key_value(path).map(|(key, _)| *key)
    })
}

fn try_resolve_set<'a>(candidate: &str, folder: bool, files: &HashSet<&'a str>) -> Option<&'a str> {
    try_resolve(candidate, folder, |path| files.get(path).copied())
}

#[cfg(test)]
fn try_resolve_file(candidate: &str, files: &HashSet<String>) -> Option<String> {
    let borrowed = files.iter().map(String::as_str).collect();
    try_resolve_set(candidate, false, &borrowed).map(str::to_string)
}

/// The import path for a delivered file: without its extension, and without a
/// trailing `/index` unless a file of the folder's name ships beside it, since
/// `a` would then load `a.ts` instead of `a/index.ts`.
/// Files that bundlers or TypeScript also pick for an extensionless import,
/// though LPM CLI doesn't rewrite them.
const SIBLING_ONLY_EXTENSIONS: &[&str] = &[".json", ".d.ts", ".d.mts", ".d.cts"];

fn import_path_without_extension(path: &str, dest_files: &HashSet<&str>) -> String {
    let stripped = strip_import_extension(path);
    let Some(extension) = EXTENSIONS
        .iter()
        .find(|extension| path.ends_with(**extension))
    else {
        return stripped;
    };
    let Some(folder) = path[..path.len() - extension.len()].strip_suffix("/index") else {
        return stripped;
    };
    let mut sibling = String::with_capacity(folder.len() + 6);
    let has_sibling = EXTENSIONS
        .iter()
        .chain(SIBLING_ONLY_EXTENSIONS)
        .any(|extension| {
            sibling.clear();
            sibling.push_str(folder);
            sibling.push_str(extension);
            dest_files.contains(sibling.as_str())
        });
    if has_sibling {
        format!("{folder}/index")
    } else {
        stripped
    }
}

/// Strip file extension for import paths. Also strips /index suffixes.
fn strip_import_extension(path: &str) -> String {
    for ext in EXTENSIONS {
        if let Some(stripped) = path.strip_suffix(ext) {
            return stripped
                .strip_suffix("/index")
                .unwrap_or(stripped)
                .to_string();
        }
    }

    path.to_string()
}

/// Get the directory portion of a path. `"a/b/c.js"` → `"a/b"`, `"c.js"` → `""`.
fn dirname(path: &str) -> String {
    match path.rfind('/') {
        Some(pos) => path[..pos].to_string(),
        None => String::new(),
    }
}

/// Join a base directory and a relative path. Handles `..` and `.` segments.
fn join_path(base: &str, relative: &str) -> String {
    if base.is_empty() {
        return relative.to_string();
    }
    format!("{base}/{relative}")
}

/// Normalize a path by resolving `.` and `..` segments.
fn normalize_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();

    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }

    parts.join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dirname() {
        assert_eq!(dirname("a/b/c.js"), "a/b");
        assert_eq!(dirname("c.js"), "");
        assert_eq!(dirname("a/b"), "a");
    }

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path("a/b/../c"), "a/c");
        assert_eq!(normalize_path("a/./b/c"), "a/b/c");
        assert_eq!(normalize_path("./a/b"), "a/b");
        assert_eq!(normalize_path("a/b/c/../../d"), "a/d");
    }

    #[test]
    fn test_strip_import_extension() {
        assert_eq!(strip_import_extension("foo/bar.js"), "foo/bar");
        assert_eq!(strip_import_extension("foo/bar.tsx"), "foo/bar");
        assert_eq!(strip_import_extension("foo/bar/index.js"), "foo/bar");
        assert_eq!(strip_import_extension("foo/bar"), "foo/bar");
    }

    #[test]
    fn test_try_resolve_file() {
        let mut files = HashSet::new();
        files.insert("lib/utils.js".to_string());
        files.insert("components/Button/index.tsx".to_string());
        files.insert("modern/esm.mts".to_string());
        files.insert("modern/cjs.cts".to_string());

        assert_eq!(
            try_resolve_file("lib/utils", &files),
            Some("lib/utils.js".to_string())
        );
        assert_eq!(
            try_resolve_file("lib/utils.js", &files),
            Some("lib/utils.js".to_string())
        );
        assert_eq!(
            try_resolve_file("components/Button", &files),
            Some("components/Button/index.tsx".to_string())
        );
        assert_eq!(try_resolve_file("missing", &files), None);
        assert_eq!(
            try_resolve_file("modern/esm", &files),
            Some("modern/esm.mts".to_string())
        );
        assert_eq!(
            try_resolve_file("modern/cjs", &files),
            Some("modern/cjs.cts".to_string())
        );
    }

    #[test]
    fn test_relative_import_rewriting() {
        let mut src_to_dest: HashMap<String, String> = HashMap::new();
        src_to_dest.insert("lib/cn.js".to_string(), "lib/cn.js".to_string());
        src_to_dest.insert(
            "atoms/Icon/Icon.jsx".to_string(),
            "atoms/Icon/Icon.jsx".to_string(),
        );

        let src_files: HashSet<String> = src_to_dest.keys().cloned().collect();
        let dest_files: HashSet<String> = src_to_dest.values().cloned().collect();

        let content = r#"import { cn } from "../../lib/cn"
import Icon from "../Icon/Icon"
import React from "react"
"#;

        let result = rewrite_imports(
            content,
            "atoms/Button/Button.jsx",
            "atoms/Button/Button.jsx",
            Some("@/"),
            Some("@/components/"),
            &src_to_dest,
            &src_files,
            &dest_files,
        );

        let rewritten = result.unwrap();
        assert!(rewritten.contains("@/components/lib/cn"));
        assert!(rewritten.contains("@/components/atoms/Icon/Icon"));
        assert!(rewritten.contains("from \"react\""));
    }

    #[test]
    fn test_author_alias_rewriting() {
        let mut src_to_dest: HashMap<String, String> = HashMap::new();
        src_to_dest.insert("lib/utils.js".to_string(), "lib/utils.js".to_string());

        let src_files: HashSet<String> = src_to_dest.keys().cloned().collect();
        let dest_files: HashSet<String> = src_to_dest.values().cloned().collect();

        let content = r#"import { cn } from "@/lib/utils"
"#;

        let result = rewrite_imports(
            content,
            "atoms/Icon/Icon.jsx",
            "atoms/Icon/Icon.jsx",
            Some("@/"),
            Some("@/design-system/"),
            &src_to_dest,
            &src_files,
            &dest_files,
        );

        let rewritten = result.unwrap();
        assert!(rewritten.contains("@/design-system/lib/utils"));
    }

    #[test]
    fn test_no_rewrite_when_no_alias() {
        let src_to_dest: HashMap<String, String> = HashMap::new();
        let src_files: HashSet<String> = HashSet::new();
        let dest_files: HashSet<String> = HashSet::new();

        let content = r#"import React from "react"
"#;

        let result = rewrite_imports(
            content,
            "index.js",
            "index.js",
            None,
            None,
            &src_to_dest,
            &src_files,
            &dest_files,
        );

        assert!(result.is_none());
    }

    #[test]
    fn test_external_imports_unchanged() {
        let mut src_to_dest: HashMap<String, String> = HashMap::new();
        src_to_dest.insert("lib/cn.js".to_string(), "lib/cn.js".to_string());

        let src_files: HashSet<String> = src_to_dest.keys().cloned().collect();
        let dest_files: HashSet<String> = src_to_dest.values().cloned().collect();

        let content = r#"import React from "react"
import { useState } from "react"
import Link from "next/link"
"#;

        let result = rewrite_imports(
            content,
            "atoms/Button.jsx",
            "atoms/Button.jsx",
            Some("@/"),
            Some("@/components/"),
            &src_to_dest,
            &src_files,
            &dest_files,
        );

        assert!(result.is_none());
    }

    #[test]
    fn classify_relative_imports() {
        assert_eq!(
            classify_specifier("./Foo", Some("@/")),
            SpecifierKind::Relative
        );
        assert_eq!(
            classify_specifier("../bar", Some("@/")),
            SpecifierKind::Relative
        );
        assert_eq!(classify_specifier("./Foo", None), SpecifierKind::Relative);
    }

    #[test]
    fn classify_author_alias_only_when_alias_set() {
        assert_eq!(
            classify_specifier("@/lib/utils", Some("@/")),
            SpecifierKind::AuthorAlias
        );
        // No alias configured → @-prefixed becomes Bare (it's a scoped npm pkg).
        assert_eq!(classify_specifier("@/lib/utils", None), SpecifierKind::Bare);
    }

    #[test]
    fn classify_bare_external_imports() {
        assert_eq!(classify_specifier("react", Some("@/")), SpecifierKind::Bare);
        assert_eq!(
            classify_specifier("next/link", Some("@/")),
            SpecifierKind::Bare
        );
        assert_eq!(
            classify_specifier("@radix-ui/react-slot", Some("@/")),
            SpecifierKind::Bare
        );
        assert_eq!(
            classify_specifier("lodash.merge", Some("@/")),
            SpecifierKind::Bare
        );
    }

    // ── collect_bare_specifiers ─────────────────────────────────────

    #[test]
    fn collect_bare_specifiers_picks_up_es_imports() {
        let src = r#"
import { useState } from "react";
import Link from "next/link";
import { Slot } from "@radix-ui/react-slot";
import { cn } from "./utils";
import Foo from "../components/Foo";
"#;
        let bare = collect_bare_specifiers(src, None);
        assert!(bare.contains("react"));
        assert!(bare.contains("next/link"));
        assert!(bare.contains("@radix-ui/react-slot"));
        assert!(!bare.contains("./utils"));
        assert!(!bare.contains("../components/Foo"));
    }

    #[test]
    fn rewrite_and_bare_import_collection_share_one_lexical_pass() {
        let src_to_dest = HashMap::from([("lib.ts", "moved/lib.ts")]);
        let dest_files = HashSet::from(["moved/lib.ts"]);
        let mut bare = HashSet::new();
        let content = r#"import React from "react"; import { lib } from "@/lib";"#;

        let rewritten = rewrite_imports_indexed_collecting_bare(
            content,
            "entry.ts",
            "moved/entry.ts",
            Some("@/"),
            Some("#/"),
            &src_to_dest,
            &dest_files,
            &mut bare,
        )
        .unwrap();

        assert_eq!(bare, HashSet::from(["react".to_string()]));
        assert_eq!(
            rewritten,
            r##"import React from "react"; import { lib } from "#/moved/lib";"##
        );
    }

    #[test]
    fn collect_bare_specifiers_picks_up_dynamic_import_and_require() {
        let src = r#"
const m = await import("react");
const fs = require('fs');
import("./local").then(...);
require("../also-local");
"#;
        let bare = collect_bare_specifiers(src, None);
        assert!(bare.contains("react"));
        assert!(bare.contains("fs"));
        assert!(!bare.contains("./local"));
        assert!(!bare.contains("../also-local"));
    }

    #[test]
    fn collect_bare_specifiers_skips_line_and_multiline_comments() {
        let src = r#"
// import { fake } from "should-be-skipped";
import { real } from "react";
/*
multiline
import { hidden } from "also-also-skipped";
*/
"#;
        let bare = collect_bare_specifiers(src, None);
        assert!(bare.contains("react"));
        assert!(!bare.contains("should-be-skipped"));
        assert!(!bare.contains("also-also-skipped"));
    }

    #[test]
    fn collect_bare_specifiers_ignores_inline_block_comment_imports() {
        let source = r#"/* require("comment-only") */ const real = require("react");"#;

        let bare = collect_bare_specifiers(source, None);

        assert_eq!(bare, HashSet::from(["react".to_string()]));
    }

    #[test]
    fn rewrite_imports_leaves_inline_block_comment_specifiers_unchanged() {
        let src_to_dest = HashMap::from([
            ("fake.ts".to_string(), "moved/fake.ts".to_string()),
            ("real.ts".to_string(), "moved/real.ts".to_string()),
        ]);
        let src_files = src_to_dest.keys().cloned().collect();
        let dest_files = src_to_dest.values().cloned().collect();
        let content = r#"/* require("@/fake") */ const real = require("@/real");"#;

        let rewritten = rewrite_imports(
            content,
            "entry.ts",
            "entry.ts",
            Some("@/"),
            Some("#/"),
            &src_to_dest,
            &src_files,
            &dest_files,
        )
        .expect("the executable import must be rewritten");

        assert_eq!(
            rewritten,
            r##"/* require("@/fake") */ const real = require("#/moved/real");"##
        );
    }

    #[test]
    fn collect_bare_specifiers_treats_author_alias_as_internal() {
        let src = r#"
import { utils } from "@/lib/utils";
import { thing } from "react";
"#;
        // With author alias `@/`, the alias-prefixed import is internal.
        let bare = collect_bare_specifiers(src, Some("@/"));
        assert!(bare.contains("react"));
        assert!(!bare.contains("@/lib/utils"));

        // Without author alias, it's just an unrecognized scoped pkg → Bare.
        let bare = collect_bare_specifiers(src, None);
        assert!(bare.contains("@/lib/utils"));
    }

    #[test]
    fn collect_bare_specifiers_finds_multiple_on_same_line() {
        // Single line with multiple require() calls — line_specifiers
        // iterates ALL occurrences (deliberately diverges from rewriter
        // first-only behavior; see line_specifiers doc).
        let src = r#"const a = require("react"); const b = require("lodash");"#;
        let bare = collect_bare_specifiers(src, None);
        assert!(bare.contains("react"));
        assert!(bare.contains("lodash"));
    }

    #[test]
    fn collect_bare_specifiers_dedupes() {
        let src = r#"
import { a } from "react";
import { b } from "react";
import { c } from "react";
"#;
        let bare = collect_bare_specifiers(src, None);
        assert_eq!(bare.len(), 1);
        assert!(bare.contains("react"));
    }

    #[test]
    fn collect_bare_specifiers_empty_on_no_imports() {
        let src = "const x = 5;\nfunction foo() { return 42; }\n";
        let bare = collect_bare_specifiers(src, None);
        assert!(bare.is_empty());
    }

    #[test]
    fn rewrite_imports_updates_every_same_line_occurrence() {
        let src_to_dest = HashMap::from([
            ("src/a.ts".to_string(), "moved/a.ts".to_string()),
            ("src/b.ts".to_string(), "moved/b.ts".to_string()),
        ]);
        let src_files = src_to_dest.keys().cloned().collect();
        let dest_files = src_to_dest.values().cloned().collect();
        let content = r#"const a = require("./a"); const b = require("./b");"#;

        let rewritten = rewrite_imports(
            content,
            "src/index.ts",
            "moved/index.ts",
            Some("@/"),
            Some("@/components/"),
            &src_to_dest,
            &src_files,
            &dest_files,
        )
        .expect("both relative imports must be rewritten");

        assert_eq!(
            rewritten,
            r#"const a = require("@/components/moved/a"); const b = require("@/components/moved/b");"#
        );
    }

    #[test]
    fn rewrite_imports_preserves_crlf_and_final_newline_state() {
        let src_to_dest = HashMap::from([("src/a.ts".to_string(), "moved/a.ts".to_string())]);
        let src_files = src_to_dest.keys().cloned().collect();
        let dest_files = src_to_dest.values().cloned().collect();
        let content = "import a from \"./a\";\r\nexport { a };";

        let rewritten = rewrite_imports(
            content,
            "src/index.ts",
            "moved/index.ts",
            Some("@/"),
            Some("@/components/"),
            &src_to_dest,
            &src_files,
            &dest_files,
        )
        .expect("relative import must be rewritten");

        assert_eq!(
            rewritten,
            "import a from \"@/components/moved/a\";\r\nexport { a };"
        );
    }

    #[test]
    fn rewrite_imports_accepts_windows_logical_path_separators() {
        let src_to_dest = HashMap::from([("src/util.ts".to_string(), "moved/util.ts".to_string())]);
        let src_files = src_to_dest.keys().cloned().collect();
        let dest_files = src_to_dest.values().cloned().collect();

        let rewritten = rewrite_imports(
            "import util from \"./util\";",
            "src\\index.ts",
            "moved\\index.ts",
            Some("@/"),
            Some("@/components/"),
            &src_to_dest,
            &src_files,
            &dest_files,
        )
        .expect("Windows logical paths must resolve");

        assert_eq!(rewritten, "import util from \"@/components/moved/util\";");
    }

    #[test]
    fn rewrite_imports_ignores_import_syntax_inside_string_literals() {
        let src_to_dest = HashMap::from([("src/util.ts".to_string(), "moved/util.ts".to_string())]);
        let src_files = src_to_dest.keys().cloned().collect();
        let dest_files = src_to_dest.values().cloned().collect();
        let content = r#"const example = 'require("@/src/util")';"#;

        let rewritten = rewrite_imports(
            content,
            "src/index.ts",
            "moved/index.ts",
            Some("@/"),
            Some("#/"),
            &src_to_dest,
            &src_files,
            &dest_files,
        );

        assert!(rewritten.is_none());
    }

    #[test]
    fn collect_bare_specifiers_ignores_import_syntax_inside_string_literals() {
        let content = r#"const example = 'require("not-a-dependency")';"#;

        assert!(collect_bare_specifiers(content, None).is_empty());
    }

    #[test]
    fn rewrite_imports_without_buyer_alias_converts_author_alias_to_relative() {
        let src_to_dest = HashMap::from([
            (
                "src/index.ts".to_string(),
                "components/index.ts".to_string(),
            ),
            ("src/util.ts".to_string(), "lib/util.ts".to_string()),
        ]);
        let src_files = src_to_dest.keys().cloned().collect();
        let dest_files = src_to_dest.values().cloned().collect();

        let rewritten = rewrite_imports(
            r#"import util from "@/src/util";"#,
            "src/index.ts",
            "components/index.ts",
            Some("@/"),
            None,
            &src_to_dest,
            &src_files,
            &dest_files,
        )
        .expect("author alias must be replaced");

        assert_eq!(rewritten, r#"import util from "../lib/util";"#);
    }

    #[test]
    fn rewrite_imports_without_alias_repairs_relocated_relative_import() {
        let src_to_dest = HashMap::from([
            (
                "src/index.ts".to_string(),
                "components/index.ts".to_string(),
            ),
            ("src/util.ts".to_string(), "lib/util.ts".to_string()),
        ]);
        let src_files = src_to_dest.keys().cloned().collect();
        let dest_files = src_to_dest.values().cloned().collect();

        let rewritten = rewrite_imports(
            r#"import util from "./util";"#,
            "src/index.ts",
            "components/index.ts",
            None,
            None,
            &src_to_dest,
            &src_files,
            &dest_files,
        )
        .expect("relocated relative import must be repaired");

        assert_eq!(rewritten, r#"import util from "../lib/util";"#);
    }

    #[test]
    fn rewrite_imports_updates_side_effect_imports() {
        let src_to_dest = HashMap::from([
            (
                "src/index.ts".to_string(),
                "components/index.ts".to_string(),
            ),
            ("src/polyfill.ts".to_string(), "lib/polyfill.ts".to_string()),
        ]);
        let src_files = src_to_dest.keys().cloned().collect();
        let dest_files = src_to_dest.values().cloned().collect();

        let rewritten = rewrite_imports(
            r#"import "./polyfill";"#,
            "src/index.ts",
            "components/index.ts",
            None,
            None,
            &src_to_dest,
            &src_files,
            &dest_files,
        )
        .expect("side-effect import must be repaired");

        assert_eq!(rewritten, r#"import "../lib/polyfill";"#);
    }

    #[test]
    fn rewrite_imports_scans_executable_template_interpolations() {
        let src_to_dest = HashMap::from([("util.ts".to_string(), "shared/util.ts".to_string())]);
        let src_files = src_to_dest.keys().cloned().collect();
        let dest_files = src_to_dest.values().cloned().collect();

        let rewritten = rewrite_imports(
            r#"const value = `literal require("@/util") ${require("@/util")}`;"#,
            "index.ts",
            "components/index.ts",
            Some("@/"),
            Some("@/app/"),
            &src_to_dest,
            &src_files,
            &dest_files,
        )
        .expect("template interpolation import must be rewritten");

        assert_eq!(
            rewritten,
            r#"const value = `literal require("@/util") ${require("@/app/shared/util")}`;"#
        );
    }

    #[test]
    fn every_rewrite_branch_prepends_the_consumer_alias_as_given() {
        let src_to_dest = HashMap::from([("util.ts".to_string(), "shared/util.ts".to_string())]);
        let src_files = src_to_dest.keys().cloned().collect();
        let dest_files =
            HashSet::from(["shared/util.ts".to_string(), "shared/extra.ts".to_string()]);

        let rewritten = rewrite_imports(
            "import a from \"@/util\";\nimport b from \"@/shared/extra\";\nimport c from \"@/missing\";\nimport d from \"./util\";\nimport e from \"./shared/extra\";",
            "index.ts",
            "index.ts",
            Some("@/"),
            Some("@ui"),
            &src_to_dest,
            &src_files,
            &dest_files,
        )
        .expect("aliased imports must be rewritten");

        for expected in [
            r#"import a from "@uishared/util""#,
            r#"import b from "@uishared/extra""#,
            r#"import c from "@uimissing""#,
            r#"import d from "@uishared/util""#,
            r#"import e from "@uishared/extra""#,
        ] {
            assert!(rewritten.contains(expected), "{expected}\n{rewritten}");
        }
    }

    #[test]
    fn a_folder_import_resolves_to_the_folder_index_not_a_sibling_file() {
        let src_to_dest = HashMap::from([
            ("a.ts".to_string(), "x/a.ts".to_string()),
            ("a/index.ts".to_string(), "y/a/index.ts".to_string()),
            ("a/b.ts".to_string(), "y/a/b.ts".to_string()),
            ("index.ts".to_string(), "lib/index.ts".to_string()),
            ("app.ts".to_string(), "app.ts".to_string()),
        ]);
        let src_files = src_to_dest.keys().cloned().collect();
        let dest_files = src_to_dest.values().cloned().collect();

        let nested = rewrite_imports(
            "import a from \".\";\nimport b from \"../a/\";",
            "a/b.ts",
            "y/a/b.ts",
            None,
            Some("@/"),
            &src_to_dest,
            &src_files,
            &dest_files,
        )
        .expect("folder imports must be rewritten");
        assert!(nested.contains(r#"import a from "@/y/a""#), "{nested}");
        assert!(nested.contains(r#"import b from "@/y/a""#), "{nested}");

        let root = rewrite_imports(
            "import root from \".\";",
            "app.ts",
            "app.ts",
            None,
            Some("@/"),
            &src_to_dest,
            &src_files,
            &dest_files,
        )
        .expect("the root index import must be rewritten");
        assert!(root.contains(r#"import root from "@/lib""#), "{root}");
    }

    #[test]
    fn a_folder_import_keeps_its_index_when_a_file_of_the_same_name_ships() {
        let src_to_dest = HashMap::from([
            ("a.ts".to_string(), "a.ts".to_string()),
            ("a/index.ts".to_string(), "a/index.ts".to_string()),
            ("a/b/c/d.ts".to_string(), "a/b/c/d.ts".to_string()),
            ("components.ts".to_string(), "components.ts".to_string()),
            (
                "components/index.ts".to_string(),
                "components/index.ts".to_string(),
            ),
        ]);
        let src_files = src_to_dest.keys().cloned().collect();
        let dest_files = src_to_dest.values().cloned().collect();

        let rewritten = rewrite_imports(
            "import a from \"../..\";\nimport b from \"../../\";\nimport c from \"@/components/\";",
            "a/b/c/d.ts",
            "a/b/c/d.ts",
            Some("@/"),
            Some("~/ui/"),
            &src_to_dest,
            &src_files,
            &dest_files,
        )
        .expect("folder imports must be rewritten");

        for expected in [
            r#"import a from "~/ui/a/index""#,
            r#"import b from "~/ui/a/index""#,
            r#"import c from "~/ui/components/index""#,
        ] {
            assert!(rewritten.contains(expected), "{expected}\n{rewritten}");
        }
    }

    #[test]
    fn a_relative_import_that_leaves_the_package_stays_unchanged() {
        let src_to_dest = HashMap::from([
            ("index.ts".to_string(), "lib/index.ts".to_string()),
            ("x.ts".to_string(), "lib/x.ts".to_string()),
            ("app.ts".to_string(), "app.ts".to_string()),
            ("src/app.ts".to_string(), "src/app.ts".to_string()),
        ]);
        let src_files = src_to_dest.keys().cloned().collect();
        let dest_files = src_to_dest.values().cloned().collect();

        for (source, content) in [
            ("app.ts", "import up from \"..\";\nimport x from \"../x\";"),
            ("src/app.ts", "import up from \"../../\";"),
        ] {
            assert_eq!(
                rewrite_imports(
                    content,
                    source,
                    source,
                    None,
                    Some("@/"),
                    &src_to_dest,
                    &src_files,
                    &dest_files,
                ),
                None,
                "{source}: {content}"
            );
        }
    }

    fn rewrite(
        content: &str,
        source: &str,
        destination: &str,
        author_alias: Option<&str>,
        buyer_alias: Option<&str>,
        mapping: &[(&str, &str)],
        extra_destinations: &[&str],
    ) -> Option<String> {
        let src_to_dest: HashMap<String, String> = mapping
            .iter()
            .map(|(src, dest)| ((*src).to_string(), (*dest).to_string()))
            .collect();
        let src_files = src_to_dest.keys().cloned().collect();
        let mut dest_files: HashSet<String> = src_to_dest.values().cloned().collect();
        dest_files.extend(extra_destinations.iter().map(|dest| (*dest).to_string()));
        rewrite_imports(
            content,
            source,
            destination,
            author_alias,
            buyer_alias,
            &src_to_dest,
            &src_files,
            &dest_files,
        )
    }

    #[test]
    fn an_unchanged_import_is_judged_by_what_it_resolves_to() {
        let unmoved = [
            ("a.ts", "a.ts"),
            ("a/index.ts", "a/index.ts"),
            ("x.ts", "x.ts"),
        ];
        for import in ["./a/index.ts", "./a/index.js", "./a/", "./a/index"] {
            assert_eq!(
                rewrite(
                    &format!("import v from \"{import}\";"),
                    "x.ts",
                    "x.ts",
                    None,
                    None,
                    &unmoved,
                    &[]
                ),
                None,
                "{import}"
            );
        }

        let moved = [
            ("a/index/index.ts", "a/index.ts"),
            ("a.ts", "a.ts"),
            ("x.ts", "x.ts"),
        ];
        assert_eq!(
            rewrite(
                "import v from \"./a/index/\";",
                "x.ts",
                "x.ts",
                None,
                None,
                &moved,
                &[]
            )
            .as_deref(),
            Some("import v from \"./a/index\";")
        );
    }

    #[test]
    fn a_folder_index_keeps_index_beside_a_json_or_declaration_file() {
        for sibling in ["a.json", "a.d.ts"] {
            assert_eq!(
                rewrite(
                    "import v from \"@/a/\";",
                    "x.ts",
                    "x.ts",
                    Some("@/"),
                    Some("~/"),
                    &[("a/index.ts", "a/index.ts"), ("x.ts", "x.ts")],
                    &[sibling],
                )
                .as_deref(),
                Some("import v from \"~/a/index\";"),
                "{sibling}"
            );
        }
    }

    #[test]
    fn an_import_that_leaves_the_source_package_stays_unchanged_wherever_it_lands() {
        assert_eq!(
            rewrite(
                "import x from \"../x\";",
                "app.ts",
                "ui/app.ts",
                None,
                Some("@/"),
                &[("app.ts", "ui/app.ts"), ("x.ts", "x.ts")],
                &[],
            ),
            None
        );
        assert_eq!(
            rewrite(
                "import o from \"../../other\";",
                "ui/x.ts",
                "./ui/x.ts",
                None,
                Some("~/"),
                &[("ui/x.ts", "./ui/x.ts"), ("pkg/other.ts", "other.ts")],
                &[],
            ),
            None
        );
    }

    #[test]
    fn an_author_alias_import_found_only_among_delivered_files_becomes_relative() {
        assert_eq!(
            rewrite(
                "import c from \"@/lib/config.json\";",
                "ui/app.ts",
                "ui/app.ts",
                Some("@/"),
                None,
                &[
                    ("ui/app.ts", "ui/app.ts"),
                    ("data/config.json", "lib/config.json")
                ],
                &[],
            )
            .as_deref(),
            Some("import c from \"../lib/config.json\";")
        );
    }

    #[test]
    fn dot_and_dot_dot_specifiers_are_relative() {
        assert_eq!(classify_specifier(".", Some("@/")), SpecifierKind::Relative);
        assert_eq!(
            classify_specifier("..", Some("@/")),
            SpecifierKind::Relative
        );
        assert_eq!(classify_specifier(".", None), SpecifierKind::Relative);
    }

    #[test]
    fn rewrite_imports_does_not_scan_regex_literals_after_keywords() {
        let src_to_dest = HashMap::from([("util.ts".to_string(), "shared/util.ts".to_string())]);
        let src_files = src_to_dest.keys().cloned().collect();
        let dest_files = src_to_dest.values().cloned().collect();

        let rewritten = rewrite_imports(
            "function pattern() { return /require(\"alias:util\")/; }\nconst util = require(\"alias:util\");",
            "index.ts",
            "components/index.ts",
            Some("alias:"),
            Some("app:"),
            &src_to_dest,
            &src_files,
            &dest_files,
        )
        .expect("real require must be rewritten");

        assert!(rewritten.contains(r#"return /require("alias:util")/"#));
        assert!(rewritten.contains(r#"require("app:shared/util")"#));
    }

    #[test]
    fn rewrite_imports_allows_comments_between_call_tokens() {
        let src_to_dest = HashMap::from([("util.ts".to_string(), "shared/util.ts".to_string())]);
        let src_files = src_to_dest.keys().cloned().collect();
        let dest_files = src_to_dest.values().cloned().collect();

        let rewritten = rewrite_imports(
            r#"const util = require /* loader */ ( /* path */ "@/util" );"#,
            "index.ts",
            "components/index.ts",
            Some("@/"),
            Some("@/app/"),
            &src_to_dest,
            &src_files,
            &dest_files,
        )
        .expect("comment-separated require must be rewritten");

        assert!(rewritten.contains(r#""@/app/shared/util""#));
    }
}
