//! Generate isolated ESM modules with typed, bounded environment validation.

mod automaton;
#[cfg(test)]
mod tests;

use lpm_env::{EmptyPolicy, EnvSchema, EnvVarRule, EvalContext, RequiredWhen, VarFormat};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

pub const GENERATOR_VERSION: &str = "lpm-env-codegen-v1";
pub const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
pub const OWNED_FILES: [&str; 6] = [
    "server.js",
    "server.d.ts",
    "client.js",
    "client.d.ts",
    "package.json",
    ".lpm-env-generated.json",
];

/// Automatic runtime input source. Explicit `createEnv(input)` works in every adapter.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Adapter {
    #[default]
    Default,
    Node,
    Nextjs,
    Vite,
}

impl Adapter {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "default" => Some(Self::Default),
            "node" => Some(Self::Node),
            "nextjs" => Some(Self::Nextjs),
            "vite" => Some(Self::Vite),
            _ => None,
        }
    }
}

/// The fixed evaluation context baked into the generated artifacts.
#[derive(Clone, Copy)]
pub struct Options<'a> {
    pub adapter: Adapter,
    pub context: EvalContext<'a>,
}

#[derive(Debug, thiserror::Error)]
pub enum GenerateError {
    #[error("env.generate_invalid_schema")]
    Schema,
    #[error("env.generate_invalid_context")]
    Context,
    #[error("env.generate_pattern_limit")]
    Pattern,
    #[error("env.generate_output_limit")]
    Budget,
    #[error("env.generate_adapter_prefix")]
    AdapterPrefix,
}

/// A complete owned directory. Files and identity use deterministic semantic inputs.
pub struct Generated {
    pub files: BTreeMap<&'static str, Vec<u8>>,
    pub identity: String,
}

#[derive(Serialize)]
struct Rule<'a> {
    key: &'a str,
    required: bool,
    format: &'a Option<VarFormat>,
    empty: EmptyPolicy,
    default: Option<&'a str>,
    condition: Option<&'a RequiredWhen>,
    min: Option<String>,
    max: Option<String>,
    min_length: Option<u32>,
    max_length: Option<u32>,
    protocols: &'a Option<Vec<String>>,
    values: &'a Option<Vec<String>>,
    pattern: Option<usize>,
}

#[derive(Serialize)]
struct Canonical<'a> {
    version: &'static str,
    adapter: Adapter,
    environment: &'a str,
    stage: lpm_env::EnvStage,
    service: Option<&'a str>,
    vars: &'a BTreeMap<&'a str, &'a EnvVarRule>,
    groups: &'a BTreeMap<&'a String, &'a lpm_env::VarGroup>,
    client_prefixes: &'a [String],
}

/// Validate all declarations before projecting scopes or browser-visible rules.
pub fn generate(schema: &EnvSchema, options: Options<'_>) -> Result<Generated, GenerateError> {
    if lpm_env::resolver::validate_env_name(options.context.environment).is_err()
        || options
            .context
            .service
            .is_some_and(|name| lpm_env::resolver::validate_env_name(name).is_err())
    {
        return Err(GenerateError::Context);
    }
    if schema.vars.len() > 4096
        || schema.groups.len() > 128
        || schema.vars.values().any(|rule| {
            rule.pattern
                .as_ref()
                .is_some_and(|pattern| pattern.len() > 32768)
        })
    {
        return Err(GenerateError::Budget);
    }
    let vars = schema
        .vars
        .iter()
        .map(|(key, rule)| (key.as_str(), rule))
        .collect::<BTreeMap<_, _>>();
    let groups = schema.groups.iter().collect::<BTreeMap<_, _>>();
    let canonical = Canonical {
        version: GENERATOR_VERSION,
        adapter: options.adapter,
        environment: options.context.environment,
        stage: options.context.stage,
        service: options.context.service,
        vars: &vars,
        groups: &groups,
        client_prefixes: &schema.client_prefixes,
    };
    lpm_env_source::json_size(&canonical, MAX_OUTPUT_BYTES).map_err(|_| GenerateError::Budget)?;
    if !lpm_env::validate_schema(schema).is_empty() {
        return Err(GenerateError::Schema);
    }
    let identity = checksum(&json(&canonical)?);
    let mut files = BTreeMap::new();
    let mut total = 0usize;
    for client in [false, true] {
        let selected = vars
            .iter()
            .filter(|(_, rule)| !client || rule.client)
            .map(|(&key, &rule)| (key, rule))
            .collect::<BTreeMap<_, _>>();
        let module = module(&selected, &groups, options, client)?;
        let declarations = declarations(&selected, options.context)?;
        for (name, bytes) in [
            (if client { "client.js" } else { "server.js" }, module),
            (
                if client { "client.d.ts" } else { "server.d.ts" },
                declarations,
            ),
        ] {
            total = total
                .checked_add(bytes.len())
                .ok_or(GenerateError::Budget)?;
            if total > MAX_OUTPUT_BYTES {
                return Err(GenerateError::Budget);
            }
            files.insert(name, bytes);
        }
    }
    files.insert("package.json", br#"{"private":true,"type":"module","exports":{"./server":{"types":"./server.d.ts","default":"./server.js"},"./client":{"types":"./client.d.ts","default":"./client.js"}}}
"#.to_vec());
    let manifest = serde_json::json!({
        "generator": GENERATOR_VERSION, "identity": identity,
        "files": files.iter().map(|(&name, bytes)| (name, checksum(bytes))).collect::<BTreeMap<_, _>>(),
    });
    files.insert(".lpm-env-generated.json", json(&manifest)?);
    if files
        .values()
        .try_fold(0usize, |sum, bytes| sum.checked_add(bytes.len()))
        .is_none_or(|sum| sum > MAX_OUTPUT_BYTES)
    {
        return Err(GenerateError::Budget);
    }
    Ok(Generated { files, identity })
}

pub fn checksum(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut result = String::with_capacity(64);
    for byte in digest {
        let _ = write!(result, "{byte:02x}");
    }
    result
}

fn json(value: &impl Serialize) -> Result<Vec<u8>, GenerateError> {
    lpm_env_source::bounded_json(value, MAX_OUTPUT_BYTES).map_err(|_| GenerateError::Budget)
}

fn selected_default<'a>(rule: &'a EnvVarRule, context: EvalContext<'_>) -> Option<&'a str> {
    rule.defaults_in
        .iter()
        .find(|item| item.when.matches(context))
        .map(|item| item.value.as_str())
        .or(rule.default.as_deref())
}

fn module(
    vars: &BTreeMap<&str, &EnvVarRule>,
    groups: &BTreeMap<&String, &lpm_env::VarGroup>,
    options: Options<'_>,
    client: bool,
) -> Result<Vec<u8>, GenerateError> {
    let patterns = vars
        .values()
        .filter_map(|rule| rule.pattern.as_deref())
        .collect::<BTreeSet<_>>();
    let mut compiler = automaton::Compiler::default();
    let mut programs = Vec::with_capacity(patterns.len());
    let mut indices = BTreeMap::new();
    for pattern in patterns {
        indices.insert(pattern, programs.len());
        programs.push(compiler.compile(pattern)?);
    }
    let rules = vars
        .iter()
        .map(|(&key, &rule)| Rule {
            key,
            required: rule.required
                || rule
                    .required_in
                    .iter()
                    .any(|scope| scope.matches(options.context)),
            format: &rule.format,
            empty: rule.empty,
            default: selected_default(rule, options.context),
            condition: rule
                .required_when
                .as_ref()
                .filter(|condition| vars.contains_key(condition.variable())),
            min: rule.min.map(|value| value.to_string()),
            max: rule.max.map(|value| value.to_string()),
            min_length: rule.min_length,
            max_length: rule.max_length,
            protocols: &rule.protocols,
            values: &rule.enum_values,
            pattern: rule.pattern.as_deref().map(|pattern| indices[pattern]),
        })
        .collect::<Vec<_>>();
    let groups = groups
        .iter()
        .filter(|(_, group)| group.vars.iter().all(|key| vars.contains_key(key.as_str())))
        .map(|(name, group)| (name.as_str(), *group))
        .collect::<Vec<_>>();
    let word = if compiler.unicode {
        automaton::word_ranges()?
    } else {
        Vec::new()
    };
    let mut result = Vec::with_capacity(32_768);
    definition(&mut result, "rules", &rules)?;
    definition(&mut result, "groups", &groups)?;
    definition(&mut result, "programs", &programs)?;
    definition(&mut result, "wordRanges", &word)?;
    append(&mut result, include_bytes!("formats.js"))?;
    append(&mut result, include_bytes!("runtime.js"))?;
    append(
        &mut result,
        b"\nexport function getEnv() { let input; try { input = ",
    )?;
    let mut source = String::new();
    if matches!(options.adapter, Adapter::Nextjs | Adapter::Vite) {
        source.push_str("Object.fromEntries([");
        let prefix = if options.adapter == Adapter::Nextjs {
            "NEXT_PUBLIC_"
        } else {
            "VITE_"
        };
        for (key, rule) in vars {
            if rule.client && !key.starts_with(prefix) {
                return Err(GenerateError::AdapterPrefix);
            }
            let encoded = serde_json::to_string(key).map_err(|_| GenerateError::Budget)?;
            let accessor = if options.adapter == Adapter::Nextjs {
                "process.env."
            } else if rule.client {
                "import.meta.env."
            } else {
                "globalThis.process?.env?."
            };
            write!(source, "[{encoded},{accessor}{key}],").map_err(|_| GenerateError::Budget)?;
        }
        source.push_str("])");
    } else if client && options.adapter == Adapter::Default {
        source.push_str("Object.create(null)");
    } else {
        source.push_str("globalThis.process?.env ?? Object.create(null)");
    }
    append(&mut result, source.as_bytes())?;
    append(&mut result, b"; } catch { throw new EnvError([{key:'envSchema',code:'env.invalid_value'}]); } return createEnv(input); }\n")?;
    Ok(result)
}

fn append(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), GenerateError> {
    if bytes.len() > MAX_OUTPUT_BYTES.saturating_sub(output.len()) {
        return Err(GenerateError::Budget);
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn definition(
    output: &mut Vec<u8>,
    name: &str,
    value: &impl Serialize,
) -> Result<(), GenerateError> {
    struct Bounded<'a>(&'a mut Vec<u8>);
    impl std::io::Write for Bounded<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            append(self.0, bytes).map_err(|_| std::io::Error::other("env output limit"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    append(output, b"const ")?;
    append(output, name.as_bytes())?;
    append(output, b" = ")?;
    serde_json::to_writer(Bounded(output), value).map_err(|_| GenerateError::Budget)?;
    append(output, b";\n")
}

fn declarations(
    vars: &BTreeMap<&str, &EnvVarRule>,
    context: EvalContext<'_>,
) -> Result<Vec<u8>, GenerateError> {
    let mut output = Vec::with_capacity(vars.len().saturating_mul(64).min(MAX_OUTPUT_BYTES));
    append(&mut output, b"export type Env = Readonly<{\n")?;
    for (&key, &rule) in vars {
        let name = json(&key)?;
        append(&mut output, b"  ")?;
        append(&mut output, &name)?;
        append(&mut output, b": ")?;
        let kind = match rule.format {
            Some(VarFormat::Integer) => "bigint",
            Some(VarFormat::Port) => "number",
            Some(VarFormat::Boolean) => "boolean",
            _ => "string",
        };
        if kind == "string"
            && let Some(values) = &rule.enum_values
        {
            for (i, value) in values.iter().enumerate() {
                if i > 0 {
                    append(&mut output, b" | ")?;
                }
                append(&mut output, &json(value)?)?;
            }
        } else {
            append(&mut output, kind.as_bytes())?;
        }
        let required = rule.required || rule.required_in.iter().any(|scope| scope.matches(context));
        let default = selected_default(rule, context);
        let guaranteed_default =
            default.is_some_and(|value| !value.is_empty() || rule.empty == EmptyPolicy::Allow);
        if !required && !guaranteed_default {
            append(&mut output, b" | undefined")?;
        }
        append(&mut output, b";\n")?;
    }
    append(&mut output, b"}>;\nexport type EnvIssue = Readonly<{key:string;code:string;constraint?:string}>;\nexport declare class EnvError extends Error { constructor(issues: readonly EnvIssue[]); readonly issues: readonly EnvIssue[]; }\nexport declare function createEnv(input: Readonly<Record<string, string | undefined>>): Env;\nexport declare function getEnv(): Env;\n")?;
    Ok(output)
}
