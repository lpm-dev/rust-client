use super::*;
use serde_json::{Value, json};
use std::cell::Cell;
use std::collections::HashMap;
use std::io::Write as _;
use std::process::{Command, Stdio};

struct ProbeAllocator;
thread_local! {
    static PROBE_ENABLED: Cell<bool> = const { Cell::new(false) };
    static MAX_ALLOCATION: Cell<usize> = const { Cell::new(0) };
}
fn record_allocation(size: usize) {
    if PROBE_ENABLED.try_with(Cell::get).unwrap_or(false) {
        MAX_ALLOCATION.with(|value| value.set(value.get().max(size)));
    }
}
#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;
unsafe impl std::alloc::GlobalAlloc for ProbeAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        record_allocation(layout.size());
        // SAFETY: System receives the caller's unchanged allocation contract.
        unsafe { std::alloc::System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        // SAFETY: System allocated the pointer with this layout.
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        record_allocation(size);
        // SAFETY: System receives the original pointer, layout, and requested size.
        unsafe { std::alloc::System.realloc(ptr, layout, size) }
    }
}

fn schema(value: Value) -> EnvSchema {
    serde_json::from_value(value).unwrap()
}
fn options() -> Options<'static> {
    Options {
        adapter: Adapter::Node,
        context: EvalContext::default(),
    }
}

fn node(generated: &Generated, role: &str, inputs: &[Value], extra: &str) -> Value {
    let directory = tempfile::tempdir().unwrap();
    for (name, bytes) in &generated.files {
        std::fs::write(directory.path().join(name), bytes).unwrap();
    }
    let script = format!(
        r#"
import {{createEnv,getEnv,EnvError}} from './{role}.js';
import fs from 'node:fs';
const inputs=JSON.parse(fs.readFileSync(0,'utf8'));
const results=inputs.map(input=>{{try{{const value=createEnv(input);return {{success:true,value}};}}catch(error){{return {{success:false,issues:error.issues}};}}}});
{extra}
console.log(JSON.stringify(results,(_,value)=>typeof value==='bigint'?{{bigint:String(value)}}:value));
"#
    );
    std::fs::write(directory.path().join("probe.mjs"), script).unwrap();
    let mut child = Command::new("node")
        .arg("probe.mjs")
        .current_dir(directory.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Node is required for generated runtime contract tests");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(inputs).unwrap())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}

fn assert_parity(schema: &EnvSchema, inputs: &[Value], context: EvalContext<'_>) {
    let generated = generate(
        schema,
        Options {
            context,
            ..options()
        },
    )
    .unwrap();
    let actual = node(&generated, "server", inputs, "");
    let validator = lpm_env::EnvValidator::new(schema);
    for (i, input) in inputs.iter().enumerate() {
        let mut values = input
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| (key.clone(), value.as_str().unwrap().to_string()))
            .collect::<HashMap<_, _>>();
        let errors = validator.validate_with_context(&mut values, context);
        let expected = errors
            .iter()
            .map(|error| {
                (
                    error.key.as_str(),
                    lpm_env_source::declaration_code(&error.kind),
                )
            })
            .collect::<Vec<_>>();
        let observed = actual[i]["issues"]
            .as_array()
            .map(|issues| {
                issues
                    .iter()
                    .map(|issue| {
                        (
                            issue["key"].as_str().unwrap(),
                            issue["code"].as_str().unwrap(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        assert_eq!(observed, expected, "input {input}; runtime {}", actual[i]);
        assert_eq!(actual[i]["success"], errors.is_empty(), "input {input}");
    }
}

#[test]
fn generated_formats_match_rust_on_lexical_edge_cases() {
    let cases: &[(&str, &[&str])] = &[
        (
            "integer",
            &[
                "0",
                "-00",
                "+01",
                "9223372036854775807",
                "-9223372036854775808",
                "9223372036854775808",
                "-9223372036854775809",
                "12\n",
                "12\r\n",
                " 12",
                "12 ",
                "+",
                "0x10",
                "1.0",
            ],
        ),
        (
            "port",
            &[
                "+0001", "65535", "65536", "0", "-1", "1\n", "01", "00000", "+65535",
            ],
        ),
        (
            "boolean",
            &[
                "1",
                "0",
                "true",
                "FALSE",
                "YES",
                "nO",
                "false\n",
                "true ",
                "2",
                "ｔｒｕｅ",
            ],
        ),
        (
            "hostname",
            &[
                "localhost",
                "123",
                "127.0.0.1",
                "a..b",
                "a.",
                "-a",
                "a-",
                "a_b",
                "é.test",
                "host\n",
            ],
        ),
        (
            "email",
            &[
                "x@a.123",
                "x+y@a.b",
                "x..y@a.b",
                ".x@a.b",
                "x.@a.b",
                "\"x\"@a.b",
                "é@a.b",
                "x@é.b",
                "x@a",
                "x@a.b\n",
            ],
        ),
        (
            "ip",
            &[
                "127.0.0.1",
                "::1",
                "::ffff:192.168.1.1",
                "1:2:3:4:5:6:7:8",
                "127.1",
                "0x7f000001",
                "2130706433",
                "01.2.3.4",
                "256.1.1.1",
                "[::1]",
                "fe80::1%eth0",
                "1::2::3",
                "1:2:3",
                ":::1",
                "1:::2",
                "192.1.1.1::",
            ],
        ),
        (
            "url",
            &[
                "https://example.com",
                "HTTPS://EXAMPLE.COM/path",
                "http://127.1",
                "http://0x7f000001",
                "file://server/path",
                "file://localhost/path",
                "file://server/C:/path",
                "custom://host/path",
                "custom://%ZZ/path",
                "custom://host/%ZZ",
                "https://u:p@host/path",
                "https://u@p@host/path",
                "https:///host",
                "https://host\\path",
                "https://host/a#b#c",
                "https://host/a#b",
                "https://host/\u{feff}",
                "https://host/\u{85}",
                "https://host/\u{fdd0}",
                "https://host/\u{e0000}",
                "https://host/[]",
                "https://host/?a={b}",
                "https://host/a%20b",
            ],
        ),
    ];
    for (format, values) in cases {
        let schema = schema(json!({"vars":{"VALUE":{"format":format,"empty":"allow"}}}));
        let inputs = values
            .iter()
            .map(|value| json!({"VALUE":value}))
            .collect::<Vec<_>>();
        assert_parity(&schema, &inputs, EvalContext::default());
    }
    let long = "0".repeat(10000) + "1";
    assert_parity(
        &schema(json!({"vars":{"VALUE":{"format":"integer"}}})),
        &[json!({"VALUE":long})],
        EvalContext::default(),
    );
}

#[test]
fn generated_patterns_match_rust_across_unicode_anchors_and_repetition() {
    let patterns = [
        r"a",
        r"^a$",
        r"\A(?:a|bc)*\z",
        r"(?m)^a$",
        r"(?mR)^a$",
        r"\b\w+\b",
        r"(?-u:\b)abc(?-u:\b)",
        r"\B",
        r"\b{start}",
        r"\b{end}",
        r"\b{start-half}",
        r"\b{end-half}",
        r"(?-u:\b{start})",
        r"(?-u:\b{end})",
        r"(?-u:\b{start-half})",
        r"(?-u:\b{end-half})",
        r"(?:a?)*",
        r"(?:a+)+$",
        r"[\p{Greek}\p{Emoji}]+",
        r"(?-u:\xA9)",
        r"(?-u:\B)",
    ];
    let values = [
        "",
        "a",
        "ba",
        "a\n",
        "a\r\n",
        "abc",
        " abc!",
        "é",
        "éabcé",
        "αβ",
        "😀",
        "\u{301}",
        "a\u{301}",
        "\r\na\r\n",
        "é😀αabc",
        "aaab",
    ];
    for pattern in patterns {
        let schema = schema(json!({"vars":{"VALUE":{"pattern":pattern,"empty":"allow"}}}));
        if !lpm_env::validate_schema(&schema).is_empty() {
            assert!(
                matches!(generate(&schema, options()), Err(GenerateError::Schema)),
                "invalid pattern {pattern}"
            );
            continue;
        }
        let inputs = values
            .iter()
            .map(|value| json!({"VALUE":value}))
            .collect::<Vec<_>>();
        assert_parity(&schema, &inputs, EvalContext::default());
    }
}

#[test]
fn generated_urls_reject_repaired_schemes_and_normalized_file_drives() {
    let schema = schema(json!({"vars":{"VALUE":{"format":"url"}}}));
    let inputs = [
        "https:/example.com?next=://foo",
        "https:example.com?next=://foo",
        "https:\\example.com?next=://foo",
        "file://host/./C:/bar",
        "file://host/foo/../C:/bar",
        "file://host/%2e/C:/bar",
        "file://host/share/path",
    ]
    .map(|value| json!({"VALUE":value}));
    assert_parity(&schema, &inputs, EvalContext::default());
}

#[test]
fn generated_url_authorities_match_native_uri_character_rules() {
    let schema = schema(json!({"vars":{"VALUE":{"format":"url"}}}));
    let mut inputs = Vec::with_capacity(95 * 3);
    for scheme in ["https", "custom", "file"] {
        for byte in 32u8..=126 {
            inputs.push(json!({"VALUE":format!("{scheme}://exa{}mple.com/path",char::from(byte))}));
        }
    }
    assert_parity(&schema, &inputs, EvalContext::default());
}

#[test]
fn framework_server_reads_include_static_public_values_and_private_runtime_values() {
    for (adapter, prefix, expression) in [
        (Adapter::Nextjs, "NEXT_PUBLIC_", "process.env."),
        (Adapter::Vite, "VITE_", "import.meta.env."),
    ] {
        let key = format!("{prefix}VALUE");
        let schema = schema(
            json!({"vars":{key.clone():{"client":true,"required":true},"PRIVATE":{"requiredWhen":{"variable":key,"equals":"built"}}}}),
        );
        let mut generated = generate(
            &schema,
            Options {
                adapter,
                ..options()
            },
        )
        .unwrap();
        let source = String::from_utf8(generated.files["server.js"].clone()).unwrap();
        assert!(
            source.contains(&format!("{expression}{prefix}VALUE")),
            "framework public read missing in server"
        );
        generated.files.insert(
            "server.js",
            source
                .replace(&format!("{expression}{prefix}VALUE"), "'built'")
                .into_bytes(),
        );
        node(
            &generated,
            "server",
            &[],
            r#"
process.env.PRIVATE='runtime';
const value=getEnv(); if(value.PRIVATE!=='runtime')throw new Error('private runtime source');
"#,
        );
    }
}

#[test]
fn raw_defaults_conditions_and_groups_precede_typed_conversion() {
    let schema = schema(json!({"vars":{
        "A":{"requiredWhen":{"variable":"Z","present":true}},
        "B":{"format":"integer","pattern":"^01$","enum":["01"]},
        "C":{"format":"boolean","default":"false"},
        "D":{"empty":"allow","default":"fallback"},
        "E":{"default":"fallback","defaultsIn":[{"when":{"stage":["test"]},"value":""}]},
        "Z":{"format":"boolean","default":"false"}
    },"groups":{"choice":{"mode":"atLeastOne","vars":["B","C"]}}}));
    let context = EvalContext {
        stage: lpm_env::EnvStage::Test,
        ..Default::default()
    };
    let inputs = [
        json!({}),
        json!({"A":"set","B":"01","D":""}),
        json!({"A":"set","B":"1"}),
        json!({"Z":"","B":"01"}),
    ];
    assert_parity(&schema, &inputs, context);
    let generated = generate(
        &schema,
        Options {
            context,
            ..options()
        },
    )
    .unwrap();
    let actual = node(&generated, "server", &inputs, "");
    assert_eq!(actual[1]["value"]["B"], json!({"bigint":"1"}));
    assert_eq!(actual[1]["value"]["C"], false);
    assert_eq!(actual[1]["value"]["D"], "");
    assert!(actual[1]["value"].get("E").is_none());
    assert!(
        String::from_utf8_lossy(&generated.files["server.d.ts"])
            .contains("\"E\": string | undefined")
    );
}

#[test]
fn client_modules_omit_private_rules_programs_and_mixed_relationships() {
    let schema = schema(json!({"vars":{
        "VITE_PUBLIC":{"client":true,"requiredWhen":{"variable":"PRIVATE","present":true},"pattern":"^public$"},
        "PRIVATE":{"pattern":"^private-pattern-marker$","default":"private-pattern-marker","description":"private-description-marker"}
    },"groups":{"mixed":{"mode":"exactlyOne","vars":["VITE_PUBLIC","PRIVATE"]}}}));
    let generated = generate(
        &schema,
        Options {
            adapter: Adapter::Vite,
            ..options()
        },
    )
    .unwrap();
    for name in ["client.js", "client.d.ts"] {
        let text = String::from_utf8_lossy(&generated.files[name]);
        for marker in [
            "PRIVATE",
            "private-pattern-marker",
            "private-description-marker",
            "mixed",
        ] {
            assert!(!text.contains(marker), "{name} leaked {marker}");
        }
    }
    assert_eq!(
        node(&generated, "client", &[json!({})], "")[0]["success"],
        true
    );
    assert!(
        String::from_utf8_lossy(&generated.files["client.js"])
            .contains("import.meta.env.VITE_PUBLIC")
    );
}

#[test]
fn own_properties_unicode_errors_and_hostile_accessors_are_secret_safe() {
    let schema = schema(
        json!({"vars":{"__proto__":{},"constructor":{},"toString":{},"TOKEN":{"format":"integer","secret":true}}}),
    );
    let generated = generate(&schema, options()).unwrap();
    node(
        &generated,
        "server",
        &[],
        r#"
const input=JSON.parse('{"__proto__":"own","constructor":"ctor","toString":"text","TOKEN":"01"}');
const value=createEnv(input);
if(Object.getPrototypeOf(value)!==null||value.__proto__!=='own'||value.TOKEN!==1n)throw new Error('property contract');
for(const input of [{TOKEN:'secret-marker'},{TOKEN:'\ud800'},Object.defineProperty({},'TOKEN',{get(){throw new Error('secret-marker')}}),new Proxy({},{getOwnPropertyDescriptor(){throw new Error('secret-marker')}})]){
  try{createEnv(input);throw new Error('expected validation failure')}catch(error){if(!(error instanceof EnvError)||JSON.stringify(error).includes('secret-marker')||error.message.includes('secret-marker')||error.cause!==undefined)throw new Error('unsafe error')}
}
"#,
    );
}

#[test]
fn generation_is_semantically_deterministic_and_validates_unused_defaults() {
    let a = schema(json!({"vars":{"B":{"default":"value"},"A":{"format":"integer"}}}));
    let b = schema(
        serde_json::from_str(r#"{"vars":{"A":{"format":"integer"},"B":{"default":"value"}}}"#)
            .unwrap(),
    );
    assert_eq!(
        generate(&a, options()).unwrap().files,
        generate(&b, options()).unwrap().files
    );
    let bad = schema(
        json!({"vars":{"A":{"format":"port","defaultsIn":[{"when":{"stage":["test"]},"value":"0"}]}}}),
    );
    assert!(matches!(
        generate(&bad, options()),
        Err(GenerateError::Schema)
    ));
    assert!(
        generate(
            &schema(json!({"vars":{"TOKEN":{"required":true,"secret":true}}})),
            options()
        )
        .is_ok()
    );
}

#[test]
fn runtime_reports_resource_exhaustion_without_pattern_mismatch() {
    let schema = schema(json!({"vars":{"VALUE":{"pattern":"^(a+)+$"}}}));
    let generated = generate(&schema, options()).unwrap();
    node(
        &generated,
        "server",
        &[],
        r#"
const encoder=globalThis.TextEncoder;
globalThis.TextEncoder=class{constructor(){throw new Error('must reject before encoder')}};
try{createEnv({VALUE:'x'.repeat(1048577)});throw new Error('expected failure')}catch(error){if(error.issues?.[0]?.code!=='env.resource_limit')throw error}
globalThis.TextEncoder=encoder;
const result=createEnv({VALUE:'a'.repeat(10000)});if(result.VALUE.length!==10000)throw new Error('linear matcher');
"#,
    );
}

#[test]
fn complete_output_budget_includes_package_and_ownership_metadata() {
    let empty = schema(json!({"vars":{"VALUE":{"empty":"allow","enum":[""]}}}));
    let base = generate(&empty, options()).unwrap();
    let four_files = base
        .files
        .iter()
        .filter(|(name, _)| name.ends_with(".js") || name.ends_with(".d.ts"))
        .map(|(_, bytes)| bytes.len())
        .sum::<usize>();
    let length = (MAX_OUTPUT_BYTES - four_files) / 2;
    let large = schema(json!({"vars":{"VALUE":{"empty":"allow","enum":["a".repeat(length)]}}}));
    assert!(matches!(
        generate(&large, options()),
        Err(GenerateError::Budget)
    ));
}

#[test]
fn oversized_pattern_sources_are_rejected_before_native_compilation() {
    let large = schema(json!({"vars":{"VALUE":{"pattern":"(".repeat(32769)}}}));
    assert!(matches!(
        generate(&large, options()),
        Err(GenerateError::Budget)
    ));
}

#[test]
fn automatic_source_errors_never_expose_values_or_original_causes() {
    for adapter in [
        Adapter::Default,
        Adapter::Node,
        Adapter::Nextjs,
        Adapter::Vite,
    ] {
        let prefix = if adapter == Adapter::Nextjs {
            "NEXT_PUBLIC_"
        } else {
            "VITE_"
        };
        let key = format!("{prefix}VALUE");
        let schema = schema(json!({"vars":{key.clone():{"client":true}}}));
        let mut generated = generate(
            &schema,
            Options {
                adapter,
                ..options()
            },
        )
        .unwrap();
        if adapter == Adapter::Vite {
            let source = String::from_utf8(generated.files["server.js"].clone()).unwrap();
            generated.files.insert(
                "server.js",
                source
                    .replace(
                        &format!("import.meta.env.{key}"),
                        "globalThis.publicSource.value",
                    )
                    .into_bytes(),
            );
        }
        node(
            &generated,
            "server",
            &[],
            r#"
const original=Object.getOwnPropertyDescriptor(globalThis,'process');
for(const sourceError of [new Error('credential-marker'),new Proxy({},{getPrototypeOf(){throw new Error('credential-marker')}}),new EnvError([{key:'credential-marker',code:'credential-marker'}])]) {
Object.defineProperty(globalThis,'process',{configurable:true,get(){throw sourceError}});
globalThis.publicSource=Object.defineProperty({},'value',{get(){throw sourceError}});
try {
  try { getEnv(); throw new Error('expected failure'); }
  catch(error) { if(!(error instanceof EnvError)||error.message.includes('credential-marker')||JSON.stringify(error).includes('credential-marker')||error.cause!==undefined)throw new Error('automatic source leaked original error'); }
} finally {Object.defineProperty(globalThis,'process',original);delete globalThis.publicSource;}
}
"#,
        );
    }
}

#[test]
fn condition_equality_uses_the_shared_runtime_work_budget() {
    let value = "a".repeat(1_040_000);
    let comparison = format!("{}b", "a".repeat(1_039_999));
    let schema = schema(json!({"vars":{
        "S0":{},"S1":{},"S2":{},"S3":{},
        "T0":{"requiredWhen":{"variable":"S0","equals":comparison}},
        "T1":{"requiredWhen":{"variable":"S1","equals":comparison}}
    }}));
    let generated = generate(&schema, options()).unwrap();
    let input =
        json!({"S0":value,"S1":value,"S2":"a".repeat(1_048_576),"S3":"a".repeat(1_048_576)});
    let actual = node(&generated, "server", &[input], "");
    assert_eq!(actual[0]["issues"][0]["code"], "env.resource_limit");
}

#[test]
fn complete_client_artifacts_equal_the_explicit_public_schema_projection() {
    let mixed = schema(json!({"vars":{
        "VITE_PUBLIC":{"client":true,"requiredWhen":{"variable":"PRIVATE","present":true},"pattern":"^public$"},
        "PRIVATE":{"pattern":"^hidden.*[0-9]+$","default":"hidden1"}
    },"groups":{"mixed":{"mode":"exactlyOne","vars":["VITE_PUBLIC","PRIVATE"]}}}));
    let public = schema(json!({"vars":{"VITE_PUBLIC":{"client":true,"pattern":"^public$"}}}));
    let options = Options {
        adapter: Adapter::Vite,
        ..options()
    };
    let mixed = generate(&mixed, options).unwrap();
    let public = generate(&public, options).unwrap();
    for name in ["client.js", "client.d.ts"] {
        assert_eq!(mixed.files[name], public.files[name]);
    }
}

#[test]
fn oversized_typed_enum_inputs_are_rejected_without_cloning_the_large_literal() {
    let schema = schema(json!({"vars":{"VALUE":{"enum":["a".repeat(16*1024*1024)]}}}));
    MAX_ALLOCATION.with(|value| value.set(0));
    PROBE_ENABLED.with(|value| value.set(true));
    let result = generate(&schema, options());
    PROBE_ENABLED.with(|value| value.set(false));
    assert!(matches!(result, Err(GenerateError::Budget)));
    assert!(
        MAX_ALLOCATION.with(Cell::get) < 1024 * 1024,
        "preflight cloned an oversized literal"
    );
}

#[test]
fn generated_constraints_match_rust_before_typed_conversion() {
    let schema = schema(json!({"vars":{
        "COUNT":{"format":"integer","min":-2,"max":2,"enum":["+01","-02","0"]},
        "PORT":{"format":"port","min":100,"max":3000},
        "TEXT":{"minLength":2,"maxLength":3},
        "URL":{"format":"url","protocols":["https"]}
    }}));
    let inputs = [
        json!({"COUNT":"+01","PORT":"0100","TEXT":"😀é","URL":"HTTPS://example.com"}),
        json!({"COUNT":"3","PORT":"99","TEXT":"😀","URL":"http://example.com"}),
        json!({"COUNT":"-3","PORT":"3001","TEXT":"😀éab","URL":"https:/example.com"}),
        json!({"COUNT":"1","PORT":"0","TEXT":"e\u{301}","URL":"custom://example.com"}),
    ];
    assert_parity(&schema, &inputs, EvalContext::default());
}

#[test]
fn expensive_pattern_validation_reports_the_shared_work_limit() {
    let schema = schema(json!({"vars":{"VALUE":{"pattern":"^(a|aa|aaa|aaaa)+$"}}}));
    let generated = generate(&schema, options()).unwrap();
    node(
        &generated,
        "server",
        &[],
        r#"
try{createEnv({VALUE:'a'.repeat(1048575)+'b'});throw new Error('expected limit');}
catch(error){if(error.issues?.[0]?.code!=='env.resource_limit')throw error;}
"#,
    );
}
