//! Smart import path rewriting for source-delivered packages.
//!
//! When `lpm add` copies source files into a project, internal imports need
//! to be rewritten from the author's alias to the buyer's alias. Relative
//! imports between installed files are also resolved through the src→dest
//! mapping to keep internal references correct.

use std::collections::{HashMap, HashSet};

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
                let source_named_file =
                    has_file_named(&resolved_src, |path| src_to_dest.contains_key(path));
                return compute_new_specifier(
                    dest_path,
                    file_dest_dir,
                    buyer_alias,
                    specifier,
                    true,
                    source_named_file,
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
                        specifier,
                        true,
                        false,
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
                    path,
                    false,
                    false,
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
                    path,
                    false,
                    false,
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
/// specifier is relative. A relative `requested` import that still reaches the
/// file stays as written when `keep_if_it_resolves` is set, and the result is
/// `None`. `source_named_file` says whether, in the package, a file of the
/// import's name sat beside the folder it reaches.
fn compute_new_specifier(
    resolved_dest_path: &str,
    file_dest_dir: &str,
    buyer_alias: Option<&str>,
    requested: &str,
    keep_if_it_resolves: bool,
    source_named_file: bool,
    dest_files: &HashSet<&str>,
) -> Option<String> {
    let path = import_path_for(
        resolved_dest_path,
        requested,
        buyer_alias.is_some(),
        dest_files,
    );
    if let Some(alias) = buyer_alias {
        return Some(format!("{alias}{path}"));
    }
    if keep_if_it_resolves && !leaves_the_root(file_dest_dir, requested) {
        let target = normalize_path(&join_path(file_dest_dir, requested));
        let folder = names_a_folder(requested);
        // A JSON or declaration file that now sits beside the folder would win
        // this import in a bundler or in TypeScript, so name the index instead.
        // One that sat there in the package already is the author's choice.
        let index_beside_a_new_file = !folder
            && !source_named_file
            && resolved_dest_path
                .strip_prefix(target.as_str())
                .is_some_and(|rest| rest.starts_with("/index"))
            && has_file_named(&target, |path| dest_files.contains(path));
        let declaration = file_extension(resolved_dest_path)
            .and_then(declaration_import_extension)
            .is_some();
        // TypeScript reaches a declaration file through the path `path` names,
        // whatever runtime file shares it.
        if (declaration && !folder && target == path)
            || (!index_beside_a_new_file
                && try_resolve_set(&target, folder, dest_files) == Some(resolved_dest_path))
        {
            return None;
        }
    }
    Some(relative_import_specifier(file_dest_dir, &path))
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

/// Source extensions, the files LPM CLI rewrites, in lookup order.
const SOURCE_EXTENSIONS: &[&str] = &[".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"];

/// JSON and declaration files. Bundlers and TypeScript also load them for an
/// extensionless import, but no runtime code sits in a declaration file, so
/// the lookup tries them after the folder's index.
const SECONDARY_EXTENSIONS: &[&str] = &[".json", ".d.ts", ".d.mts", ".d.cts"];

fn lookup_extensions() -> impl Iterator<Item = &'static str> {
    SOURCE_EXTENSIONS
        .iter()
        .chain(SECONDARY_EXTENSIONS)
        .copied()
}

/// LPM CLI's lookup for `candidate`, a path from the package root, which
/// prefers the file that runs: the file itself, the TypeScript source a
/// runtime extension stands for (`x.js` for `x.ts`), each source extension,
/// the folder's source index, then JSON and declaration files and their
/// index. A `folder` candidate only tries the index, and an empty one is the
/// package root.
fn try_resolve<'a>(
    candidate: &str,
    folder: bool,
    mut lookup: impl FnMut(&str) -> Option<&'a str>,
) -> Option<&'a str> {
    let candidate = candidate.strip_prefix("./").unwrap_or(candidate);
    let candidate = candidate.strip_suffix('/').unwrap_or(candidate);
    let file = !folder && !candidate.is_empty();
    let mut scratch = String::with_capacity(candidate.len() + "/index".len() + 6);
    if file {
        if let Some(path) = lookup(candidate) {
            return Some(path);
        }
        if let Some(runtime) = file_extension(candidate) {
            let stem = &candidate[..candidate.len() - runtime.len()];
            for source in typescript_sources_for(runtime) {
                scratch.clear();
                scratch.push_str(stem);
                scratch.push_str(source);
                if let Some(path) = lookup(&scratch) {
                    return Some(path);
                }
            }
        }
    }
    for extensions in [SOURCE_EXTENSIONS, SECONDARY_EXTENSIONS] {
        if file {
            for ext in extensions {
                scratch.clear();
                scratch.push_str(candidate);
                scratch.push_str(ext);
                if let Some(path) = lookup(&scratch) {
                    return Some(path);
                }
            }
        }
        for ext in extensions {
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
    }

    None
}

/// Whether a file named `stem`, with or without a lookup extension, is among
/// the files `contains` knows. Every toolchain loads such a file before a
/// folder of the same name.
fn has_file_named(stem: &str, contains: impl Fn(&str) -> bool) -> bool {
    let mut scratch = String::with_capacity(stem.len() + 6);
    contains(stem)
        || lookup_extensions().any(|extension| {
            scratch.clear();
            scratch.push_str(stem);
            scratch.push_str(extension);
            contains(&scratch)
        })
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

/// Extensions a rewritten import keeps: runtime files, named the way their
/// authors import them, and TypeScript's module-format sources, which
/// TypeScript can't reach through an extensionless import.
const NAMED_EXTENSIONS: &[&str] = &[".js", ".mjs", ".cjs", ".json", ".mts", ".cts"];

/// Source extensions a rewritten import may drop behind a consumer alias:
/// importing them by name needs `allowImportingTsExtensions`.
const TYPESCRIPT_SOURCE_EXTENSIONS: &[&str] = &[".ts", ".tsx"];

/// The TypeScript sources a runtime extension stands for: `./x.js` loads
/// `x.ts` or `x.tsx`.
fn typescript_sources_for(runtime: &str) -> &'static [&'static str] {
    match runtime {
        ".js" => &[".ts", ".tsx"],
        ".jsx" => &[".tsx"],
        ".mjs" => &[".mts"],
        ".cjs" => &[".cts"],
        _ => &[],
    }
}

/// How an import names a declaration file: `x` for `x.d.ts`, `x.mjs` for
/// `x.d.mts` and `x.cjs` for `x.d.cts`. TypeScript rejects a path that ends in
/// the declaration extension itself.
fn declaration_import_extension(extension: &str) -> Option<&'static str> {
    match extension {
        ".d.ts" => Some(""),
        ".d.mts" => Some(".mjs"),
        ".d.cts" => Some(".cjs"),
        _ => None,
    }
}

/// The extension of a path's last segment, with its dot. A declaration file's
/// extension is the whole `.d.ts`, `.d.mts` or `.d.cts`.
fn file_extension(path: &str) -> Option<&str> {
    let name = path.rsplit('/').next()?;
    for declaration in [".d.ts", ".d.mts", ".d.cts"] {
        if name.len() > declaration.len() && name.ends_with(declaration) {
            return Some(&name[name.len() - declaration.len()..]);
        }
    }
    name.rfind('.')
        .filter(|&dot| dot > 0)
        .map(|dot| &name[dot..])
}

/// The import path for `resolved`, a delivered file, in the style the author
/// wrote `requested`:
///
/// - The same runtime extension, or the runtime extension TypeScript maps to
///   it (`x.js` for `x.ts`).
/// - The same `.ts` or `.tsx` extension, unless the import goes through a
///   consumer alias and no other file shares the name: naming them there needs
///   `allowImportingTsExtensions`.
/// - Otherwise the shortest path that LPM CLI's lookup takes back to the same
///   file. A folder is named only when no file of its name ships.
fn import_path_for(
    resolved: &str,
    requested: &str,
    behind_alias: bool,
    dest_files: &HashSet<&str>,
) -> String {
    let resolved_extension = file_extension(resolved);
    if let Some(import_form) = resolved_extension.and_then(declaration_import_extension) {
        let stem = &resolved[..resolved.len() - resolved_extension.map_or(0, str::len)];
        return format!("{stem}{import_form}");
    }
    if let (Some(requested_extension), Some(resolved_extension)) =
        (file_extension(requested), resolved_extension)
    {
        let stem = &resolved[..resolved.len() - resolved_extension.len()];
        if requested_extension == resolved_extension {
            let droppable = TYPESCRIPT_SOURCE_EXTENSIONS.contains(&resolved_extension)
                && behind_alias
                && !dest_files.contains(stem)
                && lookup_extensions().all(|extension| {
                    extension == resolved_extension
                        || !dest_files.contains(format!("{stem}{extension}").as_str())
                });
            if !droppable {
                return resolved.to_owned();
            }
        } else if typescript_sources_for(requested_extension).contains(&resolved_extension) {
            let candidate = format!("{stem}{requested_extension}");
            if try_resolve_set(&candidate, false, dest_files) == Some(resolved) {
                return candidate;
            }
        }
    }
    let Some(extension) =
        resolved_extension.filter(|extension| !NAMED_EXTENSIONS.contains(extension))
    else {
        return resolved.to_owned();
    };
    let stem = &resolved[..resolved.len() - extension.len()];
    if let Some(folder) = stem.strip_suffix("/index")
        && !has_file_named(folder, |path| dest_files.contains(path))
        && try_resolve_set(folder, false, dest_files) == Some(resolved)
    {
        return folder.to_owned();
    }
    if try_resolve_set(stem, false, dest_files) == Some(resolved) {
        return stem.to_owned();
    }
    resolved.to_owned()
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
    fn import_path_drops_an_extension_only_when_the_shorter_path_reaches_the_same_file() {
        let files = HashSet::from([
            "foo/bar.js",
            "foo/baz.tsx",
            "foo/qux/index.ts",
            "foo/both.ts",
            "foo/both.js",
        ]);
        assert_eq!(
            import_path_for("foo/baz.tsx", "./x", false, &files),
            "foo/baz"
        );
        assert_eq!(
            import_path_for("foo/qux/index.ts", "./x", false, &files),
            "foo/qux"
        );
        assert_eq!(
            import_path_for("foo/bar.js", "./x", false, &files),
            "foo/bar.js"
        );
        assert_eq!(
            import_path_for("foo/both.ts", "./x", false, &files),
            "foo/both.ts"
        );
        assert_eq!(
            import_path_for("foo/baz.tsx", "./x.js", false, &files),
            "foo/baz.js"
        );
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

    type Mapping<'a> = &'a [(&'a str, &'a str)];

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
    fn an_import_that_still_reaches_its_file_stays_as_written() {
        let cases: [(&str, Mapping); 5] = [
            (
                "./config",
                &[
                    ("config/index.ts", "config/index.ts"),
                    ("config.json", "config.json"),
                    ("x.ts", "x.ts"),
                ],
            ),
            ("./a", &[("a.js", "a.js"), ("x.ts", "x.ts")]),
            (
                "./a/index",
                &[("a/index.ts", "a/index.ts"), ("x.ts", "x.ts")],
            ),
            ("./util.js", &[("util.ts", "util.ts"), ("x.ts", "x.ts")]),
            ("./view.mjs", &[("view.mts", "view.mts"), ("x.ts", "x.ts")]),
        ];
        for (import, mapping) in cases {
            assert_eq!(
                rewrite(
                    &format!("import v from \"{import}\";"),
                    "x.ts",
                    "x.ts",
                    None,
                    None,
                    mapping,
                    &[]
                ),
                None,
                "{import}"
            );
        }
    }

    #[test]
    fn a_rewritten_import_keeps_the_extension_style_its_author_chose() {
        let cases: [(&str, Mapping, &str); 4] = [
            (
                "./util.js",
                &[("util.ts", "lib/util.ts"), ("x.ts", "x.ts")],
                "./lib/util.js",
            ),
            (
                "./a.ts",
                &[("a.ts", "a/index.ts"), ("x.ts", "x.ts")],
                "./a/index.ts",
            ),
            (
                "./a/index.ts",
                &[
                    ("a/index.ts", "a/index.jsx"),
                    ("other.ts", "a/index.ts"),
                    ("a.ts", "a.ts"),
                    ("x.ts", "x.ts"),
                ],
                "./a/index",
            ),
            (
                "./view.mts",
                &[("view.mts", "lib/view.mts"), ("x.ts", "x.ts")],
                "./lib/view.mts",
            ),
        ];
        for (import, mapping, expected) in cases {
            assert_eq!(
                rewrite(
                    &format!("import v from \"{import}\";"),
                    "x.ts",
                    "x.ts",
                    None,
                    None,
                    mapping,
                    &[]
                )
                .as_deref(),
                Some(format!("import v from \"{expected}\";").as_str()),
                "{import}"
            );
        }

        assert_eq!(
            rewrite(
                "import v from \"@/lib/view.jsx\";",
                "x.ts",
                "x.ts",
                Some("@/"),
                Some("~/"),
                &[("x.ts", "x.ts")],
                &["lib/view.jsx", "lib/view.js"],
            )
            .as_deref(),
            Some("import v from \"~/lib/view.jsx\";")
        );
    }

    #[test]
    fn a_rewritten_import_drops_a_typescript_source_extension() {
        assert_eq!(
            rewrite(
                "import u from \"./util.ts\";\nimport c from \"./C.tsx\";",
                "x.ts",
                "x.ts",
                None,
                Some("@/c/"),
                &[
                    ("util.ts", "util.ts"),
                    ("C.tsx", "C/index.tsx"),
                    ("x.ts", "x.ts")
                ],
                &[],
            )
            .as_deref(),
            Some("import u from \"@/c/util\";\nimport c from \"@/c/C\";")
        );
    }

    #[test]
    fn an_import_is_rewritten_when_a_declaration_file_lands_beside_its_folder() {
        assert_eq!(
            rewrite(
                "import c from \"./config\";",
                "x.ts",
                "x.ts",
                None,
                None,
                &[
                    ("config/index.ts", "config/index.ts"),
                    ("types/config.d.ts", "config.d.ts"),
                    ("x.ts", "x.ts"),
                ],
                &[],
            )
            .as_deref(),
            Some("import c from \"./config/index\";")
        );
    }

    #[test]
    fn a_moved_declaration_file_is_imported_without_its_extension() {
        assert_eq!(
            rewrite(
                "import type { T } from \"./types\";",
                "x.ts",
                "x.ts",
                None,
                None,
                &[("types.d.ts", "lib/types.d.ts"), ("x.ts", "x.ts")],
                &[],
            )
            .as_deref(),
            Some("import type { T } from \"./lib/types\";")
        );
    }

    #[test]
    fn a_value_import_follows_the_runtime_file_over_json_and_declarations() {
        assert_eq!(
            rewrite(
                "import c from \"./config\";",
                "x.ts",
                "x.ts",
                None,
                None,
                &[
                    ("config/index.ts", "lib/config/index.ts"),
                    ("config.json", "config.json"),
                    ("x.ts", "x.ts"),
                ],
                &[],
            )
            .as_deref(),
            Some("import c from \"./lib/config\";")
        );
        let declaration_moves = [
            ("config.d.ts", "types/config.d.ts"),
            ("config/index.ts", "config/index.ts"),
            ("x.ts", "x.ts"),
        ];
        assert_eq!(
            rewrite(
                "import c from \"./config\";",
                "x.ts",
                "x.ts",
                None,
                None,
                &declaration_moves,
                &[]
            ),
            None
        );
        assert_eq!(
            rewrite(
                "import c from \"./config\";",
                "x.ts",
                "x.ts",
                None,
                Some("@/c/"),
                &declaration_moves,
                &[],
            )
            .as_deref(),
            Some("import c from \"@/c/config\";")
        );
    }

    #[test]
    fn a_typescript_extension_stays_unless_an_alias_import_can_drop_it_unambiguously() {
        assert_eq!(
            rewrite(
                "import u from \"./util.ts\";",
                "x.ts",
                "x.ts",
                None,
                None,
                &[("util.ts", "lib/util.ts"), ("x.ts", "x.ts")],
                &[],
            )
            .as_deref(),
            Some("import u from \"./lib/util.ts\";")
        );
        assert_eq!(
            rewrite(
                "import b from \"./Button.ts\";",
                "x.ts",
                "x.ts",
                None,
                Some("@/c/"),
                &[
                    ("Button.ts", "Button.ts"),
                    ("Button.tsx", "Button.tsx"),
                    ("x.ts", "x.ts")
                ],
                &[],
            )
            .as_deref(),
            Some("import b from \"@/c/Button.ts\";")
        );
    }

    #[test]
    fn a_declaration_file_is_never_imported_with_its_extension() {
        let moved = [
            ("types/foo.d.ts", "lib/foo.d.ts"),
            ("foo/index.ts", "lib/foo/index.ts"),
            ("x.ts", "x.ts"),
        ];
        for (alias, expected) in [(None, "./lib/foo"), (Some("@/c/"), "@/c/lib/foo")] {
            assert_eq!(
                rewrite(
                    "import type { T } from \"./types/foo\";",
                    "x.ts",
                    "x.ts",
                    None,
                    alias,
                    &moved,
                    &[],
                )
                .as_deref(),
                Some(format!("import type {{ T }} from \"{expected}\";").as_str())
            );
        }
        assert_eq!(
            rewrite(
                "import type { T } from \"./foo\";",
                "x.ts",
                "x.ts",
                None,
                None,
                &[
                    ("foo.d.ts", "foo.d.ts"),
                    ("bar/index.ts", "foo/index.ts"),
                    ("x.ts", "x.ts")
                ],
                &[],
            ),
            None
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
