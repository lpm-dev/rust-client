//! Source code behavioral tag detection (10 tags).
//!
//! Scans .js/.ts/.mjs/.cjs/.jsx/.tsx files for patterns indicating
//! what system-level capabilities a package uses. Uses `RegexSet` for
//! efficient single-pass multi-pattern matching.
//!
//! SECURITY: All patterns use the `regex` crate which guarantees linear-time
//! matching (Thompson NFA). NEVER use `fancy-regex` here — we scan untrusted input.

use regex::RegexSet;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Source code behavioral tags — parity with server `lib/security/behavioral-tags.js`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SourceTags {
    pub filesystem: bool,
    pub network: bool,
    pub child_process: bool,
    pub environment_vars: bool,
    pub eval: bool,
    pub native_bindings: bool,
    pub crypto: bool,
    pub shell: bool,
    pub web_socket: bool,
    pub dynamic_require: bool,
}

/// Index ranges into the compiled RegexSet for each tag.
/// Each tag owns a contiguous range of pattern indices.
struct TagRange {
    name: &'static str,
    start: usize,
    end: usize, // exclusive
}

/// All source tag patterns, grouped by tag. The order here defines the
/// index ranges used to map RegexSet matches back to tag booleans.
///
/// These patterns are exact ports from the server's `behavioral-tags.js`.
const SOURCE_PATTERNS: &[(&str, &[&str])] = &[
    // 0: filesystem
    (
        "filesystem",
        &[
            r#"\bfrom\s+["'](?:node:)?fs["']"#,
            r#"\bfrom\s+["'](?:node:)?fs/promises["']"#,
            r#"\brequire\s*\(\s*["'](?:node:)?fs["']\s*\)"#,
            r#"\brequire\s*\(\s*["'](?:node:)?fs/promises["']\s*\)"#,
            r"\b(?:readFile|writeFile|readdir|mkdir|unlink|rmdir|stat|access|rename|copyFile|appendFile)(?:Sync)?\s*\(",
        ],
    ),
    // 1: network
    (
        "network",
        &[
            r"\bfetch\s*\(",
            r#"\bfrom\s+["'](?:node:)?https?["']"#,
            r#"\brequire\s*\(\s*["'](?:node:)?https?["']\s*\)"#,
            r#"\bfrom\s+["'](?:node-fetch|axios|got|undici|ky|superagent|request)["']"#,
            r#"\brequire\s*\(\s*["'](?:node-fetch|axios|got|undici|ky|superagent|request)["']\s*\)"#,
            r"\bnew\s+XMLHttpRequest\s*\(",
            r#"\.(?:get|post|put|patch|delete)\s*\(\s*["']https?:"#,
        ],
    ),
    // 2: childProcess
    (
        "childProcess",
        &[
            r#"\bfrom\s+["'](?:node:)?child_process["']"#,
            r#"\brequire\s*\(\s*["'](?:node:)?child_process["']\s*\)"#,
            r"\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(",
        ],
    ),
    // 3: environmentVars
    ("environmentVars", &[r"\bprocess\.env\b", r"\bDeno\.env\b"]),
    // 4: eval
    ("eval", &[r"\beval\s*\(", r"\bnew\s+Function\s*\("]),
    // 5: nativeBindings
    (
        "nativeBindings",
        &[
            r#"\bfrom\s+["'].*\.node["']"#,
            r#"\brequire\s*\(\s*["'].*\.node["']\s*\)"#,
            r"\bnode-gyp\b",
            r"\bnode-pre-gyp\b",
            r"\bnapi\b",
        ],
    ),
    // 6: crypto
    (
        "crypto",
        &[
            r#"\bfrom\s+["'](?:node:)?crypto["']"#,
            r#"\brequire\s*\(\s*["'](?:node:)?crypto["']\s*\)"#,
            r"\b(?:createHash|createHmac|createCipher|createSign|randomBytes|pbkdf2|scrypt)\s*\(",
        ],
    ),
    // 7: shell
    (
        "shell",
        &[
            r#"\bfrom\s+["'](?:node:)?(?:child_process|shelljs|execa)["']"#,
            r#"\brequire\s*\(\s*["'](?:shelljs|execa)["']\s*\)"#,
            r#"\bexecSync\s*\(\s*["']"#,
            r#"\bexec\s*\(\s*["']"#,
        ],
    ),
    // 8: webSocket
    (
        "webSocket",
        &[
            r"\bnew\s+WebSocket\s*\(",
            r#"\bfrom\s+["']ws["']"#,
            r#"\brequire\s*\(\s*["']ws["']\s*\)"#,
            r#"\bfrom\s+["']socket\.io"#,
        ],
    ),
    // 9: dynamicRequire
    (
        "dynamicRequire",
        &[
            r#"\brequire\s*\(\s*[^"'`\s)]"#,
            r#"\bimport\s*\(\s*[^"'`\s)]"#,
        ],
    ),
];

/// Compiled regex set + tag ranges. Initialized once via `OnceLock`.
struct CompiledSourcePatterns {
    regex_set: RegexSet,
    tag_ranges: Vec<TagRange>,
}

/// Get or compile the source patterns (thread-safe, compile-once).
fn compiled_patterns() -> &'static CompiledSourcePatterns {
    static INSTANCE: OnceLock<CompiledSourcePatterns> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        let mut all_patterns = Vec::new();
        let mut tag_ranges = Vec::new();

        for (name, patterns) in SOURCE_PATTERNS {
            let start = all_patterns.len();
            all_patterns.extend_from_slice(patterns);
            let end = all_patterns.len();
            tag_ranges.push(TagRange { name, start, end });
        }

        let regex_set =
            RegexSet::new(&all_patterns).expect("source tag regex patterns must compile");

        CompiledSourcePatterns {
            regex_set,
            tag_ranges,
        }
    })
}

/// Strip JavaScript comments from source text.
///
/// Handles:
/// - `// line comments` → replaced with spaces (preserves line count)
/// - `/* block comments */` → replaced with spaces
/// - String literals (`"`, `'`, `` ` ``) → preserved (comments inside strings not stripped)
///
/// Operates on bytes for zero-copy efficiency. Returns a new Vec<u8> with
/// comments replaced by spaces. Reuse the output buffer across calls by
/// passing a pre-allocated Vec.
pub fn strip_comments(input: &[u8], output: &mut Vec<u8>) {
    output.clear();
    output.reserve(input.len());

    let len = input.len();
    let mut i = 0;

    while i < len {
        let b = input[i];

        // Check for string literals — pass through without stripping
        if b == b'"' || b == b'\'' || b == b'`' {
            let quote = b;
            output.push(b);
            i += 1;
            while i < len {
                let c = input[i];
                output.push(c);
                i += 1;
                if c == b'\\' && i < len {
                    // Escaped character — push it and skip
                    output.push(input[i]);
                    i += 1;
                } else if c == quote {
                    break;
                } else if quote == b'`' && c == b'$' && i < len && input[i] == b'{' {
                    // Template literal expression ${...} — handle nested braces
                    output.push(input[i]);
                    i += 1;
                    let mut depth = 1u32;
                    while i < len && depth > 0 {
                        let d = input[i];
                        output.push(d);
                        i += 1;
                        if d == b'{' {
                            depth += 1;
                        } else if d == b'}' {
                            depth -= 1;
                        } else if d == b'\\' && i < len {
                            output.push(input[i]);
                            i += 1;
                        }
                    }
                }
            }
            continue;
        }

        // Check for comments
        if b == b'/' && i + 1 < len {
            let next = input[i + 1];

            if next == b'/' {
                // Line comment — skip until newline, replace with spaces
                while i < len && input[i] != b'\n' {
                    output.push(b' ');
                    i += 1;
                }
                continue;
            }

            if next == b'*' {
                // Block comment — skip until */, replace with spaces (preserve newlines)
                output.push(b' ');
                output.push(b' ');
                i += 2;
                while i < len {
                    if input[i] == b'*' && i + 1 < len && input[i + 1] == b'/' {
                        output.push(b' ');
                        output.push(b' ');
                        i += 2;
                        break;
                    }
                    if input[i] == b'\n' {
                        output.push(b'\n');
                    } else {
                        output.push(b' ');
                    }
                    i += 1;
                }
                continue;
            }
        }

        output.push(b);
        i += 1;
    }
}

/// Analyze source text (after comment stripping) for the 10 behavioral tags.
///
/// Takes already-stripped source content as a string slice.
/// Returns `SourceTags` with boolean flags for each detected capability.
pub fn analyze_source(stripped: &str) -> SourceTags {
    let compiled = compiled_patterns();
    let matches = compiled.regex_set.matches(stripped);

    let mut tags = SourceTags::default();

    for range in &compiled.tag_ranges {
        let matched = (range.start..range.end).any(|idx| matches.matched(idx));
        match range.name {
            "filesystem" => tags.filesystem = matched,
            "network" => tags.network = matched,
            "childProcess" => tags.child_process = matched,
            "environmentVars" => tags.environment_vars = matched,
            "eval" => tags.eval = matched,
            "nativeBindings" => tags.native_bindings = matched,
            "crypto" => tags.crypto = matched,
            "shell" => tags.shell = matched,
            "webSocket" => tags.web_socket = matched,
            "dynamicRequire" => tags.dynamic_require = matched,
            _ => {}
        }
    }

    tags
}

/// Merge two SourceTags with OR logic (if either is true, result is true).
pub fn merge_source_tags(a: &SourceTags, b: &SourceTags) -> SourceTags {
    SourceTags {
        filesystem: a.filesystem || b.filesystem,
        network: a.network || b.network,
        child_process: a.child_process || b.child_process,
        environment_vars: a.environment_vars || b.environment_vars,
        eval: a.eval || b.eval,
        native_bindings: a.native_bindings || b.native_bindings,
        crypto: a.crypto || b.crypto,
        shell: a.shell || b.shell,
        web_socket: a.web_socket || b.web_socket,
        dynamic_require: a.dynamic_require || b.dynamic_require,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze(src: &str) -> SourceTags {
        let mut buf = Vec::new();
        strip_comments(src.as_bytes(), &mut buf);
        let stripped = String::from_utf8_lossy(&buf);
        analyze_source(&stripped)
    }

    // ── Comment stripping ─────────────────────────────────────

    #[test]
    fn strip_line_comment() {
        let mut buf = Vec::new();
        strip_comments(b"const x = 1 // this is a comment\nconst y = 2", &mut buf);
        let result = String::from_utf8_lossy(&buf);
        assert!(!result.contains("this is a comment"));
        assert!(result.contains("const x = 1"));
        assert!(result.contains("const y = 2"));
    }

    #[test]
    fn strip_block_comment() {
        let mut buf = Vec::new();
        strip_comments(b"const x = /* hidden */ 42", &mut buf);
        let result = String::from_utf8_lossy(&buf);
        assert!(!result.contains("hidden"));
        assert!(result.contains("const x ="));
        assert!(result.contains("42"));
    }

    #[test]
    fn preserve_comment_in_string() {
        let mut buf = Vec::new();
        strip_comments(b"const url = \"https://example.com\"", &mut buf);
        let result = String::from_utf8_lossy(&buf);
        assert!(result.contains("https://example.com"));
    }

    #[test]
    fn preserve_comment_in_single_quote_string() {
        let mut buf = Vec::new();
        strip_comments(b"const url = 'https://example.com'", &mut buf);
        let result = String::from_utf8_lossy(&buf);
        assert!(result.contains("https://example.com"));
    }

    #[test]
    fn preserve_comment_in_template_literal() {
        let mut buf = Vec::new();
        strip_comments(b"const msg = `hello // world`", &mut buf);
        let result = String::from_utf8_lossy(&buf);
        assert!(result.contains("hello // world"));
    }

    #[test]
    fn handle_escaped_quote() {
        let mut buf = Vec::new();
        strip_comments(br#"const s = "he said \"hello\"" // comment"#, &mut buf);
        let result = String::from_utf8_lossy(&buf);
        assert!(result.contains(r#"he said \"hello\""#));
        assert!(!result.contains("comment"));
    }

    #[test]
    fn preserve_newlines_in_block_comment() {
        let mut buf = Vec::new();
        strip_comments(b"a\n/* line1\nline2\nline3 */\nb", &mut buf);
        let result = String::from_utf8_lossy(&buf);
        // Should have 4 newlines total (before/after block + 2 inside)
        assert_eq!(result.chars().filter(|&c| c == '\n').count(), 4);
    }

    // ── Filesystem ────────────────────────────────────────────

    #[test]
    fn detect_fs_import() {
        let tags = analyze(r#"import fs from "fs""#);
        assert!(tags.filesystem);
    }

    #[test]
    fn detect_fs_node_prefix() {
        let tags = analyze(r#"import { readFile } from "node:fs""#);
        assert!(tags.filesystem);
    }

    #[test]
    fn detect_fs_promises() {
        let tags = analyze(r#"import fs from "node:fs/promises""#);
        assert!(tags.filesystem);
    }

    #[test]
    fn detect_fs_require() {
        let tags = analyze(r#"const fs = require("fs")"#);
        assert!(tags.filesystem);
    }

    #[test]
    fn detect_readfile_call() {
        let tags = analyze("readFileSync('path')");
        assert!(tags.filesystem);
    }

    #[test]
    fn detect_writefile_call() {
        let tags = analyze("writeFile('path', data, cb)");
        assert!(tags.filesystem);
    }

    #[test]
    fn no_false_positive_fs_in_string() {
        // "fs" in a word shouldn't trigger
        let tags = analyze("const offset = 10");
        assert!(!tags.filesystem);
    }

    // ── Network ───────────────────────────────────────────────

    #[test]
    fn detect_fetch() {
        let tags = analyze("fetch('https://api.example.com')");
        assert!(tags.network);
    }

    #[test]
    fn detect_http_import() {
        let tags = analyze(r#"import http from "node:http""#);
        assert!(tags.network);
    }

    #[test]
    fn detect_axios_import() {
        let tags = analyze(r#"import axios from "axios""#);
        assert!(tags.network);
    }

    #[test]
    fn detect_undici_require() {
        let tags = analyze(r#"const undici = require("undici")"#);
        assert!(tags.network);
    }

    #[test]
    fn detect_xhr() {
        let tags = analyze("new XMLHttpRequest()");
        assert!(tags.network);
    }

    #[test]
    fn no_false_positive_network() {
        let tags = analyze("const data = fetchConfig()");
        // "fetchConfig()" doesn't match because pattern requires `fetch\s*\(`
        // and "fetchConfig" has no space before (
        // Actually \bfetch\s*\( would match "fetch()" but not "fetchConfig("
        // because \b matches word boundary, and "fetch" in "fetchConfig" is not at boundary
        assert!(!tags.network);
    }

    // ── Child Process ─────────────────────────────────────────

    #[test]
    fn detect_child_process_import() {
        let tags = analyze(r#"import { exec } from "child_process""#);
        assert!(tags.child_process);
    }

    #[test]
    fn detect_spawn_call() {
        let tags = analyze("spawn('node', ['script.js'])");
        assert!(tags.child_process);
    }

    #[test]
    fn detect_exec_sync_call() {
        let tags = analyze("execSync('ls -la')");
        assert!(tags.child_process);
    }

    // ── Environment Vars ──────────────────────────────────────

    #[test]
    fn detect_process_env() {
        let tags = analyze("const key = process.env.API_KEY");
        assert!(tags.environment_vars);
    }

    #[test]
    fn detect_deno_env() {
        let tags = analyze("const key = Deno.env.get('KEY')");
        assert!(tags.environment_vars);
    }

    #[test]
    fn detect_process_env_node_env() {
        // React's common pattern
        let tags = analyze("if (process.env.NODE_ENV === 'production')");
        assert!(tags.environment_vars);
    }

    // ── Eval ──────────────────────────────────────────────────

    #[test]
    fn detect_eval() {
        let tags = analyze("eval('alert(1)')");
        assert!(tags.eval);
    }

    #[test]
    fn detect_new_function() {
        let tags = analyze("new Function('return 42')");
        assert!(tags.eval);
    }

    #[test]
    fn no_false_positive_eval_in_comment() {
        let tags = analyze("// eval('dangerous')");
        assert!(!tags.eval);
    }

    // ── Native Bindings ───────────────────────────────────────

    #[test]
    fn detect_node_gyp() {
        let tags = analyze("node-gyp rebuild");
        assert!(tags.native_bindings);
    }

    #[test]
    fn detect_napi() {
        let tags = analyze("const addon = require('napi')");
        assert!(tags.native_bindings);
    }

    #[test]
    fn detect_dot_node_import() {
        let tags = analyze(r#"const binding = require("./binding.node")"#);
        assert!(tags.native_bindings);
    }

    // ── Crypto ────────────────────────────────────────────────

    #[test]
    fn detect_crypto_import() {
        let tags = analyze(r#"import crypto from "crypto""#);
        assert!(tags.crypto);
    }

    #[test]
    fn detect_create_hash() {
        let tags = analyze("createHash('sha256')");
        assert!(tags.crypto);
    }

    #[test]
    fn detect_random_bytes() {
        let tags = analyze("const buf = randomBytes(32)");
        assert!(tags.crypto);
    }

    // ── Shell ─────────────────────────────────────────────────

    #[test]
    fn detect_shelljs_import() {
        let tags = analyze(r#"import shell from "shelljs""#);
        assert!(tags.shell);
    }

    #[test]
    fn detect_execa_require() {
        let tags = analyze(r#"const execa = require("execa")"#);
        assert!(tags.shell);
    }

    #[test]
    fn detect_exec_sync_with_string() {
        let tags = analyze(r#"execSync("npm install")"#);
        assert!(tags.shell);
    }

    // ── WebSocket ─────────────────────────────────────────────

    #[test]
    fn detect_websocket_constructor() {
        let tags = analyze("new WebSocket('wss://example.com')");
        assert!(tags.web_socket);
    }

    #[test]
    fn detect_ws_import() {
        let tags = analyze(r#"import WebSocket from "ws""#);
        assert!(tags.web_socket);
    }

    #[test]
    fn detect_socket_io_import() {
        let tags = analyze(r#"import io from "socket.io-client""#);
        assert!(tags.web_socket);
    }

    // ── Dynamic Require ───────────────────────────────────────

    #[test]
    fn detect_dynamic_require() {
        let tags = analyze("require(moduleName)");
        assert!(tags.dynamic_require);
    }

    #[test]
    fn detect_dynamic_import() {
        let tags = analyze("import(dynamicPath)");
        assert!(tags.dynamic_require);
    }

    #[test]
    fn no_false_positive_static_require() {
        let tags = analyze(r#"require("lodash")"#);
        assert!(!tags.dynamic_require);
    }

    #[test]
    fn no_false_positive_static_import() {
        let tags = analyze(r#"import("./module.js")"#);
        assert!(!tags.dynamic_require);
    }

    // ── Cross-cutting ─────────────────────────────────────────

    #[test]
    fn multiple_tags_detected() {
        let tags = analyze(
            r#"
			import fs from "fs"
			eval('code')
			process.env.KEY
			"#,
        );
        assert!(tags.filesystem);
        assert!(tags.eval);
        assert!(tags.environment_vars);
        assert!(!tags.network);
    }

    #[test]
    fn empty_source_no_tags() {
        let tags = analyze("");
        assert!(!tags.filesystem);
        assert!(!tags.network);
        assert!(!tags.eval);
    }

    #[test]
    fn merge_tags_or_logic() {
        let a = SourceTags {
            filesystem: true,
            eval: true,
            ..Default::default()
        };
        let b = SourceTags {
            network: true,
            eval: false,
            ..Default::default()
        };
        let merged = merge_source_tags(&a, &b);
        assert!(merged.filesystem);
        assert!(merged.network);
        assert!(merged.eval); // true from a
    }
}
