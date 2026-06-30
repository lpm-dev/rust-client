use lpm_common::LpmError;
use oxc_allocator::Allocator;
use oxc_codegen::{Codegen, CodegenOptions, CodegenReturn, IndentChar};
use oxc_parser::Parser;
use oxc_semantic::SemanticBuilder;
use oxc_span::SourceType;
use oxc_transformer::{
    JsxOptions, JsxRuntime, Module, TransformOptions, Transformer, TypeScriptOptions,
};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

pub const TRANSFORM_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TsTransformRequest {
    pub schema_version: u32,
    pub filename: PathBuf,
    pub source: String,
    pub format: TsModuleFormat,
    #[serde(default = "default_source_map")]
    pub source_map: bool,
    #[serde(default)]
    pub options: TsTransformOptions,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TsTransformResponse {
    pub schema_version: u32,
    pub code: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PersistentTsTransformResponse {
    schema_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TsModuleFormat {
    Commonjs,
    Module,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TsTransformOptions {
    #[serde(default)]
    pub jsx: TsJsxOptions,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TsJsxOptions {
    #[serde(default)]
    pub runtime: TsJsxRuntime,
    #[serde(default)]
    pub import_source: Option<String>,
    #[serde(default)]
    pub pragma: Option<String>,
    #[serde(default)]
    pub pragma_frag: Option<String>,
    #[serde(default)]
    pub development: bool,
}

impl Default for TsJsxOptions {
    fn default() -> Self {
        Self {
            runtime: TsJsxRuntime::Automatic,
            import_source: None,
            pragma: None,
            pragma_frag: None,
            development: false,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TsJsxRuntime {
    Classic,
    #[default]
    Automatic,
}

pub fn run_stdio() -> Result<(), LpmError> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| LpmError::Script(format!("failed to read LPM TS transform request: {e}")))?;

    let request: TsTransformRequest = serde_json::from_str(&input)
        .map_err(|e| LpmError::Script(format!("failed to decode LPM TS transform request: {e}")))?;
    let response = transform_request(&request)?;
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &response).map_err(|e| {
        LpmError::Script(format!("failed to encode LPM TS transform response: {e}"))
    })?;
    stdout
        .write_all(b"\n")
        .map_err(|e| LpmError::Script(format!("failed to write LPM TS transform response: {e}")))?;
    Ok(())
}

pub fn run_persistent_stdio() -> Result<(), LpmError> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    run_persistent_stdio_with(stdin.lock(), stdout.lock())
}

fn run_persistent_stdio_with<R, W>(mut reader: R, mut writer: W) -> Result<(), LpmError>
where
    R: std::io::BufRead,
    W: std::io::Write,
{
    let mut line = String::new();
    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).map_err(|e| {
            LpmError::Script(format!("failed to read LPM TS transform request: {e}"))
        })?;
        if bytes_read == 0 {
            return Ok(());
        }

        let request_json = line.trim_end_matches(['\r', '\n']);
        if request_json.is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<TsTransformRequest>(request_json) {
            Ok(request) => match transform_request(&request) {
                Ok(response) => PersistentTsTransformResponse {
                    schema_version: response.schema_version,
                    code: Some(response.code),
                    error: None,
                },
                Err(error) => persistent_error_response(error.to_string()),
            },
            Err(error) => persistent_error_response(format!(
                "failed to decode LPM TS transform request: {error}"
            )),
        };

        serde_json::to_writer(&mut writer, &response).map_err(|e| {
            LpmError::Script(format!("failed to encode LPM TS transform response: {e}"))
        })?;
        writer.write_all(b"\n").map_err(|e| {
            LpmError::Script(format!("failed to write LPM TS transform response: {e}"))
        })?;
        writer.flush().map_err(|e| {
            LpmError::Script(format!("failed to flush LPM TS transform response: {e}"))
        })?;
    }
}

fn persistent_error_response(message: String) -> PersistentTsTransformResponse {
    PersistentTsTransformResponse {
        schema_version: TRANSFORM_PROTOCOL_VERSION,
        code: None,
        error: Some(message),
    }
}

pub fn transform_request(request: &TsTransformRequest) -> Result<TsTransformResponse, LpmError> {
    if request.schema_version != TRANSFORM_PROTOCOL_VERSION {
        return Err(LpmError::Script(format!(
            "unsupported LPM TS transform protocol {}",
            request.schema_version
        )));
    }

    let code = transform_source(request)?;
    Ok(TsTransformResponse {
        schema_version: TRANSFORM_PROTOCOL_VERSION,
        code,
    })
}

fn transform_source(request: &TsTransformRequest) -> Result<String, LpmError> {
    let allocator = Allocator::default();
    let source_type = source_type_for(&request.filename, request.format)?;
    let parsed = Parser::new(&allocator, &request.source, source_type).parse();
    if !parsed.errors.is_empty() {
        return Err(transform_diagnostics_error("parse", parsed.errors));
    }

    let mut program = parsed.program;
    let semantic = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .with_excess_capacity(2.0)
        .with_enum_eval(true)
        .build(&program);
    if !semantic.errors.is_empty() {
        return Err(transform_diagnostics_error("analyze", semantic.errors));
    }

    let transform_options = transform_options(request);
    let transformed = Transformer::new(&allocator, &request.filename, &transform_options)
        .build_with_scoping(semantic.semantic.into_scoping(), &mut program);
    if !transformed.errors.is_empty() {
        return Err(transform_diagnostics_error("transform", transformed.errors));
    }

    let mut code = codegen(&program, &request.filename, request.source_map);
    if request.format == TsModuleFormat::Commonjs {
        code = strip_commonjs_empty_export_markers(&code);
    }
    Ok(code)
}

fn source_type_for(path: &Path, format: TsModuleFormat) -> Result<SourceType, LpmError> {
    let source_type = SourceType::from_path(path).map_err(|e| {
        LpmError::Script(format!(
            "unsupported TypeScript source path '{}': {e}",
            path.display()
        ))
    })?;
    Ok(match format {
        TsModuleFormat::Commonjs => source_type.with_commonjs(true),
        TsModuleFormat::Module => source_type.with_module(true),
    })
}

fn transform_options(request: &TsTransformRequest) -> TransformOptions {
    let mut jsx = JsxOptions::enable();
    jsx.runtime = match request.options.jsx.runtime {
        TsJsxRuntime::Classic => JsxRuntime::Classic,
        TsJsxRuntime::Automatic => JsxRuntime::Automatic,
    };
    jsx.development = request.options.jsx.development;
    jsx.import_source = request.options.jsx.import_source.clone();
    jsx.pragma = request.options.jsx.pragma.clone();
    jsx.pragma_frag = request.options.jsx.pragma_frag.clone();

    let mut typescript = TypeScriptOptions::default();
    if let Some(pragma) = &request.options.jsx.pragma {
        typescript.jsx_pragma = Cow::Owned(pragma.clone());
    }
    if let Some(pragma_frag) = &request.options.jsx.pragma_frag {
        typescript.jsx_pragma_frag = Cow::Owned(pragma_frag.clone());
    }

    TransformOptions {
        cwd: request
            .filename
            .parent()
            .map_or_else(PathBuf::new, Path::to_path_buf),
        typescript,
        jsx,
        env: oxc_transformer::EnvOptions {
            module: match request.format {
                TsModuleFormat::Commonjs => Module::CommonJS,
                TsModuleFormat::Module => Module::Preserve,
            },
            ..Default::default()
        },
        ..TransformOptions::default()
    }
}

fn codegen(program: &oxc_ast::ast::Program<'_>, path: &Path, source_map: bool) -> String {
    let options = CodegenOptions {
        source_map_path: source_map.then(|| path.to_path_buf()),
        indent_char: IndentChar::Space,
        indent_width: 2,
        ..CodegenOptions::default()
    };
    let CodegenReturn { mut code, map, .. } = Codegen::new().with_options(options).build(program);
    if let Some(map) = map {
        code.push_str("//# sourceMappingURL=");
        code.push_str(&map.to_data_url());
        code.push('\n');
    }
    code
}

fn strip_commonjs_empty_export_markers(code: &str) -> String {
    if !code.contains("export {};") {
        return code.to_string();
    }

    let mut stripped = String::with_capacity(code.len());
    for line in code.lines() {
        if line.trim() == "export {};" {
            continue;
        }
        stripped.push_str(line);
        stripped.push('\n');
    }
    stripped
}

fn transform_diagnostics_error(stage: &str, diagnostics: Vec<impl std::fmt::Debug>) -> LpmError {
    let mut message = format!("LPM OXC TypeScript {stage} failed");
    for diagnostic in diagnostics.into_iter().take(3) {
        message.push('\n');
        message.push_str(&format!("{diagnostic:?}"));
    }
    LpmError::Script(message)
}

fn default_source_map() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn transform(source: &str, filename: &str, format: TsModuleFormat) -> String {
        let request = TsTransformRequest {
            schema_version: TRANSFORM_PROTOCOL_VERSION,
            filename: PathBuf::from(filename),
            source: source.to_string(),
            format,
            source_map: true,
            options: TsTransformOptions::default(),
        };
        transform_request(&request)
            .expect("transform should succeed")
            .code
    }

    #[test]
    fn transform_request_strips_typescript_annotations() {
        let code = transform(
            "const value: string = 'typed';\nconsole.log(value);\n",
            "script.ts",
            TsModuleFormat::Commonjs,
        );

        assert!(
            code.contains("const value = \"typed\";"),
            "TypeScript annotations must be stripped, got:\n{code}"
        );
    }

    #[test]
    fn transform_request_lowers_tsx_with_automatic_runtime() {
        let code = transform(
            "const view = <main id=\"root\">hello</main>;\nconsole.log(view);\n",
            "view.tsx",
            TsModuleFormat::Commonjs,
        );

        assert!(
            code.contains("react/jsx-runtime") && code.contains("jsx"),
            "TSX must lower through the standard automatic JSX runtime, got:\n{code}"
        );
    }

    #[test]
    fn transform_request_emits_inline_source_map() {
        let code = transform(
            "console.log('map');\n",
            "script.ts",
            TsModuleFormat::Commonjs,
        );

        assert!(
            code.contains("sourceMappingURL=data:application/json"),
            "transformed code must include an inline source map, got:\n{code}"
        );
    }

    #[test]
    fn transform_request_removes_empty_export_marker_from_commonjs_output() {
        let code = transform(
            "export type SeedMessage = string;\nconst value: SeedMessage = 'cjs';\nconsole.log(value);\n",
            "script.ts",
            TsModuleFormat::Commonjs,
        );

        assert!(
            !code.contains("export {};"),
            "CommonJS output must not retain OXC's empty ESM marker, got:\n{code}"
        );
    }

    fn persistent_request(source: &str, filename: &str, format: &str) -> String {
        json!({
            "schemaVersion": TRANSFORM_PROTOCOL_VERSION,
            "filename": filename,
            "source": source,
            "format": format,
            "sourceMap": false,
            "options": {
                "jsx": {
                    "runtime": "automatic",
                    "development": false
                }
            }
        })
        .to_string()
    }

    #[test]
    fn run_persistent_stdio_returns_one_response_per_request_line() {
        let input = format!(
            "{}\n{}\n",
            persistent_request(
                "const one: number = 1;\nconsole.log(one);\n",
                "one.ts",
                "commonjs"
            ),
            persistent_request(
                "const two: number = 2;\nconsole.log(two);\n",
                "two.ts",
                "commonjs"
            )
        );
        let mut output = Vec::new();

        run_persistent_stdio_with(std::io::Cursor::new(input), &mut output)
            .expect("persistent transform session should succeed");

        let text = String::from_utf8(output).expect("persistent response should be utf8");
        let responses = text
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("valid response"))
            .collect::<Vec<_>>();
        assert_eq!(responses.len(), 2);
        assert!(
            responses.iter().all(|response| {
                response["schemaVersion"] == TRANSFORM_PROTOCOL_VERSION
                    && response["code"]
                        .as_str()
                        .is_some_and(|code| code.contains("const"))
                    && response.get("error").is_none()
            }),
            "persistent responses must all be successful, got:\n{text}"
        );
    }

    #[test]
    fn run_persistent_stdio_reports_malformed_request_without_closing_session() {
        let input = format!(
            "{{not json}}\n{}\n",
            persistent_request(
                "const value: string = 'ok';\nconsole.log(value);\n",
                "ok.ts",
                "commonjs"
            )
        );
        let mut output = Vec::new();

        run_persistent_stdio_with(std::io::Cursor::new(input), &mut output)
            .expect("persistent transform session should recover from bad request");

        let text = String::from_utf8(output).expect("persistent response should be utf8");
        let responses = text
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("valid response"))
            .collect::<Vec<_>>();
        assert_eq!(responses.len(), 2);
        assert!(
            responses[0]["error"]
                .as_str()
                .is_some_and(|error| error.contains("failed to decode")),
            "first response must describe malformed input, got:\n{text}"
        );
        assert!(
            responses[1]["code"]
                .as_str()
                .is_some_and(|code| code.contains("const value = \"ok\";")),
            "second response must prove the session stayed open, got:\n{text}"
        );
    }
}
