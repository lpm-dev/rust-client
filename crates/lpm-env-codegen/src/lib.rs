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
pub const OWNED_FILES: [&str; 7] = [
    "server.js",
    "server.d.ts",
    "client.js",
    "client.d.ts",
    "package.json",
    ".gitattributes",
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

struct IdentityRules<'a>(&'a BTreeMap<&'a str, &'a EnvVarRule>);

impl Serialize for IdentityRules<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, rule) in self.0 {
            map.serialize_entry(
                key,
                &IdentityRule {
                    required: rule.required,
                    format: &rule.format,
                    pattern: &rule.pattern,
                    enum_values: &rule.enum_values,
                    default: &rule.default,
                    secret: rule.secret,
                    client: rule.client,
                    min: rule.min,
                    max: rule.max,
                    min_length: rule.min_length,
                    max_length: rule.max_length,
                    protocols: &rule.protocols,
                    required_when: &rule.required_when,
                    required_in: &rule.required_in,
                    defaults_in: &rule.defaults_in,
                    empty: rule.empty,
                },
            )?;
        }
        map.end()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentityRule<'a> {
    required: bool,
    format: &'a Option<VarFormat>,
    pattern: &'a Option<String>,
    #[serde(rename = "enum")]
    enum_values: &'a Option<Vec<String>>,
    default: &'a Option<String>,
    secret: bool,
    client: bool,
    min: Option<i64>,
    max: Option<i64>,
    min_length: Option<u32>,
    max_length: Option<u32>,
    protocols: &'a Option<Vec<String>>,
    required_when: &'a Option<RequiredWhen>,
    required_in: &'a [lpm_env::ScopeSelector],
    defaults_in: &'a [lpm_env::ScopedDefault],
    empty: EmptyPolicy,
}

#[derive(Serialize)]
struct Canonical<'a> {
    version: &'static str,
    adapter: Adapter,
    environment: &'a str,
    stage: lpm_env::EnvStage,
    service: Option<&'a str>,
    vars: IdentityRules<'a>,
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
        vars: IdentityRules(&vars),
        groups: &groups,
        client_prefixes: &schema.client_prefixes,
    };
    lpm_env_source::json_size(schema, MAX_OUTPUT_BYTES).map_err(|_| GenerateError::Budget)?;
    if !lpm_env::validate_schema(schema).is_empty() {
        return Err(GenerateError::Schema);
    }
    let identity = identity_checksum(&canonical)?;
    let mut files = BTreeMap::new();
    let mut total = 0usize;
    for client in [false, true] {
        let selected = vars
            .iter()
            .filter(|(_, rule)| !client || rule.client)
            .map(|(&key, &rule)| (key, rule))
            .collect::<BTreeMap<_, _>>();
        let module = module(
            &selected,
            &groups,
            options,
            client,
            MAX_OUTPUT_BYTES - total,
        )?;
        total += module.len();
        files.insert(if client { "client.js" } else { "server.js" }, module);
        let declarations = declarations(&selected, options.context, MAX_OUTPUT_BYTES - total)?;
        total += declarations.len();
        files.insert(
            if client { "client.d.ts" } else { "server.d.ts" },
            declarations,
        );
    }
    files.insert("package.json", br#"{"private":true,"type":"module","exports":{"./server":{"types":"./server.d.ts","default":"./server.js"},"./client":{"types":"./client.d.ts","default":"./client.js"}}}
"#.to_vec());
    files.insert(".gitattributes", b"* -text\n".to_vec());
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

fn identity_checksum(value: &impl Serialize) -> Result<String, GenerateError> {
    struct HashWriter {
        hash: Sha256,
        written: usize,
    }
    impl std::io::Write for HashWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > MAX_OUTPUT_BYTES.saturating_sub(self.written) {
                return Err(std::io::Error::other("env output limit"));
            }
            self.hash.update(bytes);
            self.written += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = HashWriter {
        hash: Sha256::new(),
        written: 0,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| GenerateError::Budget)?;
    let mut result = String::with_capacity(64);
    for byte in writer.hash.finalize() {
        let _ = write!(result, "{byte:02x}");
    }
    Ok(result)
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
    limit: usize,
) -> Result<Vec<u8>, GenerateError> {
    if limit < include_bytes!("formats.js").len() + include_bytes!("runtime.js").len() {
        return Err(GenerateError::Budget);
    }
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
    let mut result = Output::new(32_768, limit);
    definition(&mut result, "rules", &rules)?;
    definition(&mut result, "groups", &groups)?;
    definition(&mut result, "programs", &programs)?;
    definition(&mut result, "wordRanges", &word)?;
    append(&mut result, include_bytes!("formats.js"))?;
    if vars
        .values()
        .any(|rule| rule.format == Some(VarFormat::Url))
    {
        packed_ranges(&mut result, "bidiRanges", &bidi_ranges())?;
        packed_ranges(&mut result, "joiningRanges", &joining_ranges())?;
        packed_ranges(&mut result, "viramaRanges", &virama_ranges())?;
        append(&mut result, include_bytes!("url.js"))?;
    }
    append(&mut result, include_bytes!("runtime.js"))?;
    append(
        &mut result,
        b"\nexport function getEnv() { let input; try { input = ",
    )?;
    if matches!(options.adapter, Adapter::Nextjs | Adapter::Vite) {
        append(&mut result, b"Object.fromEntries([")?;
        let prefix = if options.adapter == Adapter::Nextjs {
            "NEXT_PUBLIC_"
        } else {
            "VITE_"
        };
        for (key, rule) in vars {
            if rule.client && !key.starts_with(prefix) {
                return Err(GenerateError::AdapterPrefix);
            }
            append(&mut result, b"[")?;
            serde_json::to_writer(&mut result, key).map_err(|_| GenerateError::Budget)?;
            if !rule.client {
                append(&mut result, b",privateValue(")?;
                serde_json::to_writer(&mut result, key).map_err(|_| GenerateError::Budget)?;
                append(&mut result, b")],")?;
            } else {
                append(
                    &mut result,
                    if options.adapter == Adapter::Nextjs {
                        b",process.env."
                    } else {
                        b",import.meta.env."
                    },
                )?;
                append(&mut result, key.as_bytes())?;
                append(&mut result, b"],")?;
            }
        }
        append(&mut result, b"])")?;
    } else if client && options.adapter == Adapter::Default {
        append(&mut result, b"Object.create(null)")?;
    } else {
        append(
            &mut result,
            b"globalThis.process?.env ?? Object.create(null)",
        )?;
    }
    append(&mut result, b"; } catch { throw new EnvError([{key:'envSchema',code:'env.invalid_value'}]); } return createEnv(input); }\n")?;
    Ok(result.bytes)
}

struct Output {
    bytes: Vec<u8>,
    limit: usize,
}

fn bidi_ranges() -> Vec<(u32, u32, u8)> {
    use icu_properties::{CodePointMapData, props::BidiClass};
    CodePointMapData::<BidiClass>::new()
        .iter_ranges_mapped(|class| match class {
            BidiClass::LeftToRight => 1,
            BidiClass::RightToLeft | BidiClass::ArabicLetter => 2,
            BidiClass::ArabicNumber => 4,
            BidiClass::EuropeanNumber => 8,
            BidiClass::NonspacingMark => 16,
            BidiClass::EuropeanSeparator
            | BidiClass::CommonSeparator
            | BidiClass::EuropeanTerminator
            | BidiClass::OtherNeutral
            | BidiClass::BoundaryNeutral => 32,
            _ => 0,
        })
        .filter(|range| range.value != 1)
        .map(|range| (*range.range.start(), *range.range.end(), range.value))
        .collect()
}
fn joining_ranges() -> Vec<(u32, u32, u8)> {
    use icu_properties::{CodePointMapData, props::JoiningType};
    CodePointMapData::<JoiningType>::new()
        .iter_ranges_mapped(|class| match class {
            JoiningType::LeftJoining => 1,
            JoiningType::RightJoining => 2,
            JoiningType::DualJoining => 3,
            JoiningType::Transparent => 4,
            _ => 0,
        })
        .filter(|range| range.value != 0)
        .map(|range| (*range.range.start(), *range.range.end(), range.value))
        .collect()
}

fn virama_ranges() -> Vec<(u32, u32, u8)> {
    use icu_properties::{CodePointMapData, props::CanonicalCombiningClass};
    CodePointMapData::<CanonicalCombiningClass>::new()
        .iter_ranges_mapped(|class| u8::from(class == CanonicalCombiningClass::Virama))
        .filter(|range| range.value != 0)
        .map(|range| (*range.range.start(), *range.range.end(), range.value))
        .collect()
}

fn packed_ranges(
    output: &mut Output,
    name: &str,
    ranges: &[(u32, u32, u8)],
) -> Result<(), GenerateError> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut encoded = String::with_capacity(ranges.len() * 4);
    let mut previous = 0;
    for &(start, end, class) in ranges {
        for mut value in [start - previous, end - start, u32::from(class)] {
            while value >= 32 {
                encoded.push(char::from(ALPHABET[((value & 31) | 32) as usize]));
                value >>= 5;
            }
            encoded.push(char::from(ALPHABET[value as usize]));
        }
        previous = end + 1;
    }
    append(output, b"const ")?;
    append(output, name.as_bytes())?;
    append(output, b" = decodeRanges(")?;
    serde_json::to_writer(&mut *output, &encoded).map_err(|_| GenerateError::Budget)?;
    append(output, b");\n")
}

impl Output {
    fn new(capacity: usize, limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity.min(limit)),
            limit,
        }
    }
}
impl std::io::Write for Output {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        append(self, bytes).map_err(|_| std::io::Error::other("env output limit"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn append(output: &mut Output, bytes: &[u8]) -> Result<(), GenerateError> {
    if bytes.len() > output.limit.saturating_sub(output.bytes.len()) {
        return Err(GenerateError::Budget);
    }
    let required = output.bytes.len() + bytes.len();
    if required > output.bytes.capacity() {
        let capacity = output
            .bytes
            .capacity()
            .saturating_mul(2)
            .max(required)
            .min(output.limit);
        output
            .bytes
            .try_reserve_exact(capacity - output.bytes.len())
            .map_err(|_| GenerateError::Budget)?;
    }
    output.bytes.extend_from_slice(bytes);
    Ok(())
}
fn definition(
    output: &mut Output,
    name: &str,
    value: &impl Serialize,
) -> Result<(), GenerateError> {
    append(output, b"const ")?;
    append(output, name.as_bytes())?;
    append(output, b" = ")?;
    serde_json::to_writer(&mut *output, value).map_err(|_| GenerateError::Budget)?;
    append(output, b";\n")
}

fn declarations(
    vars: &BTreeMap<&str, &EnvVarRule>,
    context: EvalContext<'_>,
    limit: usize,
) -> Result<Vec<u8>, GenerateError> {
    let mut output = Output::new(vars.len().saturating_mul(64), limit);
    append(&mut output, b"export type Env = Readonly<{\n")?;
    for (&key, &rule) in vars {
        append(&mut output, b"  ")?;
        serde_json::to_writer(&mut output, key).map_err(|_| GenerateError::Budget)?;
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
                serde_json::to_writer(&mut output, value).map_err(|_| GenerateError::Budget)?;
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
    Ok(output.bytes)
}
