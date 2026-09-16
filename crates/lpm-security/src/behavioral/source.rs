//! Source code behavioral tag detection (10 tags).
//!
//! Scans .js/.ts/.mjs/.cjs/.jsx/.tsx files for patterns indicating
//! what system-level capabilities a package uses. Patterns are compiled once
//! and checked per tag so matching can short-circuit when a tag is found.
//!
//! SECURITY: All patterns use the `regex` crate which guarantees linear-time
//! matching (Thompson NFA). NEVER use `fancy-regex` here — we scan untrusted input.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Source capability fields shared with registry behavioral tags.
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

struct CompiledSourceTagPatterns {
    name: &'static str,
    regexes: Vec<Regex>,
}

/// All source tag patterns, grouped by tag.
///
/// Binding analysis refines process, shell, and module-loading matches on parsed source.
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
            r#"\b(?:require\s*\(\s*|from\s+)["'](?:node-gyp|node-pre-gyp|napi)(?:-[^"']*)?["']"#,
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

struct CompiledSourcePatterns {
    tags: Vec<CompiledSourceTagPatterns>,
}

/// Get or compile the source patterns (thread-safe, compile-once).
fn compiled_patterns() -> &'static CompiledSourcePatterns {
    static INSTANCE: OnceLock<CompiledSourcePatterns> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        let tags = SOURCE_PATTERNS
            .iter()
            .map(|(name, patterns)| CompiledSourceTagPatterns {
                name,
                regexes: patterns
                    .iter()
                    .map(|pattern| Regex::new(pattern).expect("source tag regex must compile"))
                    .collect(),
            })
            .collect();

        CompiledSourcePatterns { tags }
    })
}

/// Strip comments using syntax spans so literals and template expressions remain intact.
pub fn strip_comments(input: &[u8], output: &mut Vec<u8>) {
    let input = String::from_utf8_lossy(input);
    super::syntax::SourceContext::new(&input, "source.tsx", output);
}

/// Analyze source text (after comment stripping) for the 10 behavioral tags.
///
/// Takes already-stripped source content as a string slice.
/// Returns `SourceTags` with boolean flags for each detected capability.
pub fn analyze_source(stripped: &str) -> SourceTags {
    let mut buffer = Vec::new();
    let context = super::syntax::SourceContext::new(stripped, "source.tsx", &mut buffer);
    analyze_source_context(&context)
}

pub(super) fn analyze_source_context(context: &super::syntax::SourceContext<'_>) -> SourceTags {
    analyze_source_context_with_evidence(context, None).0
}

pub(super) fn analyze_source_context_with_evidence(
    context: &super::syntax::SourceContext<'_>,
    filename: Option<&str>,
) -> (SourceTags, Vec<super::evidence::SourceEvidence>) {
    let compiled = compiled_patterns();
    let mut tags = SourceTags::default();
    let mut evidence = Vec::new();

    for tag in &compiled.tags {
        let offset = tag
            .regexes
            .iter()
            .enumerate()
            .find_map(|(index, regex)| {
                if context.calls.is_some()
                    && (tag.name == "dynamicRequire"
                        || (tag.name == "childProcess" && index == 2)
                        || tag.name == "shell")
                {
                    return None;
                }
                context.find_with_context(regex, matches!(tag.name, "childProcess" | "shell"))
            })
            .or_else(|| {
                let calls = context.calls.as_ref()?;
                match tag.name {
                    "childProcess" => calls.process,
                    "shell" => calls.shell,
                    "dynamicRequire" => calls.dynamic_load,
                    _ => None,
                }
            });
        let matched = offset.is_some();
        if let (Some(offset), Some(filename)) = (offset, filename) {
            let rule = match tag.name {
                "filesystem" => "fs",
                "childProcess" => "child-process",
                "environmentVars" => "env",
                "nativeBindings" => "native",
                "webSocket" => "ws",
                "dynamicRequire" => "dynamic-require",
                other => other,
            };
            evidence.push(
                super::evidence::SourceEvidence::new(
                    rule,
                    filename,
                    "Source pattern indicates a capability; execution is not established.",
                )
                .at(&context.stripped, offset),
            );
        }
        match tag.name {
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

    (tags, evidence)
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

    #[test]
    fn local_exec_helpers_and_callbacks_are_not_child_processes() {
        for code in [
            "const exec = (text) => text.trim(); export const wrap = text => exec(text);",
            "module.exports = function (exec) { try { return !!exec(); } catch (_) { return true; } };",
            "(function exec() { setTimeout(() => exec(), 1); })();",
        ] {
            assert!(!analyze(code).child_process, "{code}");
        }
    }

    #[test]
    fn methods_and_declarations_named_import_or_require_are_not_dynamic_loads() {
        for code in [
            "class Css { import(node) { return node.text; } compile(node) { return this.import(node); } }",
            "class Args { require(keys) { return this.demand(keys); } }",
        ] {
            assert!(!analyze(code).dynamic_require, "{code}");
        }
    }

    #[test]
    fn spawning_a_process_without_a_shell_does_not_imply_shell_execution() {
        for code in [
            "import cp from 'node:child_process'; cp.spawn('node', args, {stdio: 'inherit'});",
            "import { execFileSync } from 'node:child_process'; execFileSync('node', args);",
        ] {
            let tags = analyze(code);
            assert!(tags.child_process, "{code}");
            assert!(!tags.shell, "{code}");
        }
    }

    #[test]
    fn constant_string_module_specifiers_are_static() {
        for code in [
            "const url = require('u' + 'rl');",
            "const load = () => import('./' + 'plugin.js');",
        ] {
            assert!(!analyze(code).dynamic_require, "{code}");
        }
    }

    #[test]
    fn constant_string_process_imports_retain_capabilities() {
        let tags = analyze("const cp = require('child_' + 'process'); cp.exec(command);");
        assert!(tags.child_process);
        assert!(tags.shell);
    }

    #[test]
    fn process_library_helpers_do_not_imply_process_or_shell_execution() {
        for code in [
            "import {parseCommand} from 'execa'; parseCommand(command);",
            "const shell = require('shelljs'); shell.which('node'); shell.cat('package.json');",
        ] {
            let tags = analyze(code);
            assert!(!tags.child_process, "{code}");
            assert!(!tags.shell, "{code}");
        }
    }

    #[test]
    fn execa_entry_points_and_shelljs_exec_retain_process_capabilities() {
        for code in [
            "import {execa} from 'execa'; execa(command, args);",
            "const run = require('execa'); run(command, args);",
            "const shell = require('shelljs'); shell.exec(command);",
        ] {
            assert!(analyze(code).child_process, "{code}");
        }
        assert!(analyze("const shell = require('shelljs'); shell.exec(command);").shell);
    }

    #[test]
    fn loaders_and_process_aliases_assigned_after_declaration_remain_detectable() {
        let loader = "import {createRequire} from 'node:module'; let require; function load(name) { if (!require) require = createRequire(import.meta.url); return require(name); }";
        assert!(analyze(loader).dynamic_require);
        let process = "import cp from 'node:child_process'; let run; if (condition) run = cp.exec; run(command);";
        assert!(analyze(process).shell);
    }

    #[test]
    fn shell_options_follow_constants_spreads_and_conditional_values() {
        for code in [
            "const {spawnSync} = require('child_process'); const options = {shell: true}; spawnSync(command, options);",
            "import {spawn} from 'node:child_process'; const options = {shell: '/bin/sh'}; spawn(command, [], {...options, stdio: 'pipe'});",
            "import {spawn} from 'node:child_process'; const options = flag ? {shell: true} : {shell: false}; spawn(command, [], options);",
        ] {
            assert!(analyze(code).shell, "{code}");
        }
    }

    #[test]
    fn explicit_false_shell_option_overrides_a_spread() {
        let code = "import {spawn} from 'node:child_process'; const options = {shell: true}; spawn(command, [], {...options, shell: false});";
        assert!(!analyze(code).shell);
    }

    #[test]
    fn literal_module_ids_in_bundled_loaders_are_static() {
        let code = "(function(require) { return require(3); })(loadModule);";
        assert!(!analyze(code).dynamic_require);
    }

    #[test]
    fn literal_examples_are_not_executable_capabilities() {
        for code in [
            r#"module.exports = "Example: eval(input)""#,
            "module.exports = 'require(\"fs\"); fetch(input); process.env.KEY'",
            "module.exports = `Example: eval(input)`",
            "module.exports = /eval(input)/",
            "const template = `text ${ \"eval(input)\" }`",
            "const template = `text ${ /* eval(input) */ 1 }`",
        ] {
            assert_eq!(analyze(code), SourceTags::default(), "{code}");
        }
    }

    #[test]
    fn template_expressions_and_code_after_regex_literals_are_scanned() {
        for code in [
            "const template = `text ${ /* ignored */ eval(input) }`",
            "const pattern = /[/*]/; module.exports = input => eval(input)",
            "const template = `outer ${ `inner ${eval(input)}` }`",
        ] {
            assert!(analyze(code).eval, "{code}");
        }
    }

    #[test]
    fn regex_exec_is_not_a_child_process_or_shell() {
        for code in [
            "/pattern/.exec(input)",
            "const pattern = /test/; pattern.exec('test')",
        ] {
            let tags = analyze(code);
            assert!(!tags.child_process, "{code}");
            assert!(!tags.shell, "{code}");
        }
    }

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
    fn shelljs_exec_is_shell_execution() {
        let tags = analyze(r#"import shell from "shelljs"; shell.exec(command);"#);
        assert!(tags.shell);
    }

    #[test]
    fn execa_without_shell_option_only_reports_child_processes() {
        let tags = analyze(r#"const execa = require("execa"); execa('node', args);"#);
        assert!(tags.child_process);
        assert!(!tags.shell);
    }

    #[test]
    fn process_aliases_and_explicit_shell_options_retain_detection() {
        for code in [
            "import {exec as run} from 'node:child_process'; run(command);",
            "const {exec: run} = require('child_process'); run(command);",
            "const cp = require('node:child_process'); cp.exec(command);",
            "const cp = require('node:child_process'); cp['exec'](command);",
            "const {spawn: run} = require('child_process'); run('node', args, {shell: true});",
            "const {promisify} = require('util'); const cp = require('child_process'); const run = promisify(cp.exec); run(command);",
        ] {
            let tags = analyze(code);
            assert!(tags.child_process && tags.shell, "{code}: {tags:?}");
        }
    }

    #[test]
    fn promisified_execfile_and_shadowed_exec_are_not_shell_execution() {
        for code in [
            "const {promisify} = require('util'); const cp = require('child_process'); const exec = promisify(cp.execFile); exec('node', args);",
            "import {exec} from 'child_process'; function invoke(exec) { exec(); }",
        ] {
            assert!(!analyze(code).shell, "{code}");
        }
    }

    #[test]
    fn dynamic_imports_and_created_require_aliases_retain_detection() {
        for code in [
            "import(`./plugins/${name}.js`);",
            "const {createRequire} = require('module'); const load = createRequire(__filename); load(name);",
            "import {createRequire} from 'node:module'; const load = createRequire(import.meta.url); load(name);",
            "module.require(name);",
            "import {createRequire} from 'node:module'; const require = createRequire ? createRequire(import.meta.url) : undefined; require(path);",
            "function dynamicRequire(mod, request) { return mod.require(request); } dynamicRequire(module, path);",
        ] {
            assert!(analyze(code).dynamic_require, "{code}");
        }
    }

    #[test]
    fn exported_and_conditional_promisified_exec_retain_shell_capability() {
        for code in [
            "import * as cp from 'child_process'; import * as util from 'util'; export const execAsync = util.promisify(cp.exec);",
            "import {exec} from 'child_process'; import {promisify} from 'util'; const run = promisify(custom?.exec ?? exec); run(command);",
        ] {
            assert!(analyze(code).shell, "{code}");
        }
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
