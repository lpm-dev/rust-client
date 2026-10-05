//! Environment, command stage, and service selectors for validation.

use crate::EnvVarRule;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// The lifecycle stage supplied by the calling command.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum EnvStage {
    Development,
    Build,
    #[default]
    Runtime,
    Ci,
    Test,
}

impl EnvStage {
    /// Parse an explicit lifecycle stage.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "development" => Some(Self::Development),
            "build" => Some(Self::Build),
            "runtime" => Some(Self::Runtime),
            "ci" => Some(Self::Ci),
            "test" => Some(Self::Test),
            _ => None,
        }
    }

    /// Infer the stage from a named command, preserving pre/post hook stages.
    pub fn for_script(name: &str) -> Self {
        let name = name.split(':').next().unwrap_or(name);
        let name = name
            .strip_prefix("pre")
            .or_else(|| name.strip_prefix("post"))
            .unwrap_or(name);
        match name {
            "dev" | "development" => Self::Development,
            "build" => Self::Build,
            "ci" => Self::Ci,
            "test" => Self::Test,
            _ => Self::Runtime,
        }
    }

    /// Return the public stage name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Build => "build",
            Self::Runtime => "runtime",
            Self::Ci => "ci",
            Self::Test => "test",
        }
    }
}

/// Context comes from the resolved command identity, independently of env values.
#[derive(Debug, Clone, Copy)]
pub struct EvalContext<'a> {
    pub environment: &'a str,
    pub stage: EnvStage,
    pub service: Option<&'a str>,
}

impl Default for EvalContext<'_> {
    fn default() -> Self {
        Self {
            environment: "default",
            stage: EnvStage::Runtime,
            service: None,
        }
    }
}

impl EvalContext<'_> {
    pub(crate) fn is_valid(self) -> bool {
        valid_name(self.environment) && self.service.is_none_or(valid_name)
    }
}

/// Dimensions use AND; values within one dimension use OR.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, remote = "Self")]
#[schemars(deny_unknown_fields, extend("anyOf" = [{"required":["environment"]},{"required":["stage"]},{"required":["service"]}]))]
pub struct ScopeSelector {
    #[serde(
        default,
        deserialize_with = "deserialize_names",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "Vec<String>", length(min = 1, max = 32), extend("uniqueItems" = true, "items" = {"type":"string","pattern":"^(?!__index__$)(?!.*\\.\\.)[A-Za-z0-9_.-]{1,64}$"}))]
    pub environment: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_stages",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "Vec<EnvStage>", length(min = 1, max = 5), extend("uniqueItems" = true))]
    pub stage: Option<Vec<EnvStage>>,
    #[serde(
        default,
        deserialize_with = "deserialize_names",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "Vec<String>", length(min = 1, max = 32), extend("uniqueItems" = true, "items" = {"type":"string","pattern":"^(?!__index__$)(?!.*\\.\\.)[A-Za-z0-9_.-]{1,64}$"}))]
    pub service: Option<Vec<String>>,
}

impl ScopeSelector {
    /// Determine whether every supplied dimension matches this context.
    pub fn matches(&self, context: EvalContext<'_>) -> bool {
        self.environment
            .as_ref()
            .is_none_or(|names| names.iter().any(|name| name == context.environment))
            && self
                .stage
                .as_ref()
                .is_none_or(|stages| stages.contains(&context.stage))
            && self.service.as_ref().is_none_or(|names| {
                context
                    .service
                    .is_some_and(|service| names.iter().any(|name| name == service))
            })
    }

    fn is_valid(&self) -> bool {
        if self.environment.is_none() && self.stage.is_none() && self.service.is_none() {
            return false;
        }
        for values in [&self.environment, &self.service].into_iter().flatten() {
            if values.is_empty() || values.len() > 32 {
                return false;
            }
            let mut unique = HashSet::with_capacity(values.len());
            if values
                .iter()
                .any(|value| !valid_name(value) || !unique.insert(value))
            {
                return false;
            }
        }
        if let Some(stages) = &self.stage {
            if stages.is_empty() || stages.len() > 5 {
                return false;
            }
            let mut mask = 0u8;
            for stage in stages {
                let bit = 1 << (*stage as u8);
                if mask & bit != 0 {
                    return false;
                }
                mask |= bit;
            }
        }
        true
    }

    fn atom_count(&self) -> usize {
        self.environment.as_ref().map_or(0, Vec::len)
            + self.stage.as_ref().map_or(0, Vec::len)
            + self.service.as_ref().map_or(0, Vec::len)
    }
}

#[derive(PartialEq, Eq)]
struct PreparedNames<'a> {
    values: [&'a str; 32],
    length: usize,
}
impl<'a> PreparedNames<'a> {
    fn new(values: &'a [String]) -> Self {
        let mut prepared = Self {
            values: [""; 32],
            length: values.len(),
        };
        for (target, value) in prepared.values.iter_mut().zip(values) {
            *target = value;
        }
        prepared.values[..prepared.length].sort_unstable();
        prepared
    }
    fn intersects(&self, other: &Self) -> bool {
        let (mut first, mut second) = (0, 0);
        while first < self.length && second < other.length {
            match self.values[first].cmp(other.values[second]) {
                std::cmp::Ordering::Equal => return true,
                std::cmp::Ordering::Less => first += 1,
                std::cmp::Ordering::Greater => second += 1,
            }
        }
        false
    }
}
#[derive(PartialEq, Eq)]
struct PreparedSelector<'a> {
    stages: u8,
    environment: Option<PreparedNames<'a>>,
    service: Option<PreparedNames<'a>>,
}
impl<'a> PreparedSelector<'a> {
    fn new(selector: &'a ScopeSelector) -> Self {
        Self {
            stages: selector.stage.as_ref().map_or(31, |stages| {
                stages
                    .iter()
                    .fold(0, |mask, stage| mask | 1 << (*stage as u8))
            }),
            environment: selector.environment.as_deref().map(PreparedNames::new),
            service: selector.service.as_deref().map(PreparedNames::new),
        }
    }
    fn overlaps(&self, other: &Self) -> bool {
        self.stages & other.stages != 0
            && match (&self.environment, &other.environment) {
                (Some(first), Some(second)) => first.intersects(second),
                _ => true,
            }
            && match (&self.service, &other.service) {
                (Some(first), Some(second)) => first.intersects(second),
                _ => true,
            }
    }
}

fn valid_name(value: &str) -> bool {
    crate::resolver::validate_env_name(value).is_ok()
}

/// Select a literal default for one bounded context rectangle.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, remote = "Self")]
#[schemars(deny_unknown_fields)]
pub struct ScopedDefault {
    pub when: ScopeSelector,
    #[schemars(extend("pattern" = r"^[^\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]*$"))]
    pub value: String,
}

pub(crate) fn rule_error(rule: &EnvVarRule) -> Option<&'static str> {
    if rule.required_in.len() > 32 || rule.defaults_in.len() > 32 {
        return Some("requiredIn and defaultsIn each support at most 32 selectors");
    }
    if rule
        .required_in
        .iter()
        .chain(rule.defaults_in.iter().map(|default| &default.when))
        .any(|selector| !selector.is_valid())
    {
        return Some(
            "scope selectors require unique nonempty dimensions with valid environment, stage, and service names",
        );
    }
    let mut prepared = Vec::with_capacity(rule.required_in.len().max(rule.defaults_in.len()));
    for selector in &rule.required_in {
        let selector = PreparedSelector::new(selector);
        if prepared.contains(&selector) {
            return Some("requiredIn selectors must be unique");
        }
        prepared.push(selector);
    }
    prepared.clear();
    for default in &rule.defaults_in {
        let selector = PreparedSelector::new(&default.when);
        if prepared.iter().any(|previous| previous.overlaps(&selector)) {
            return Some("defaultsIn selectors cannot overlap");
        }
        prepared.push(selector);
    }
    if rule.secret && !rule.defaults_in.is_empty() {
        return Some("secret rules cannot contain literal scoped defaults");
    }
    None
}

pub(crate) fn budgets_valid(schema: &crate::EnvSchema) -> bool {
    let mut selectors = 0usize;
    let mut atoms = 0usize;
    for rule in schema.vars.values() {
        for selector in rule
            .required_in
            .iter()
            .chain(rule.defaults_in.iter().map(|default| &default.when))
        {
            selectors = selectors.saturating_add(1);
            atoms = atoms.saturating_add(selector.atom_count());
            if selectors > 4096 || atoms > 16384 {
                return false;
            }
        }
    }
    true
}

pub(crate) fn default_for_context<'a>(
    rule: &'a EnvVarRule,
    context: EvalContext<'_>,
) -> Option<&'a str> {
    rule.defaults_in
        .iter()
        .find(|default| default.when.matches(context))
        .map(|default| default.value.as_str())
        .or(rule.default.as_deref())
}

struct RejectExcess;
impl<'de> serde::de::DeserializeSeed<'de> for RejectExcess {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, _: D) -> Result<(), D::Error> {
        Err(serde::de::Error::custom(
            "scope list exceeds its entry limit",
        ))
    }
}

fn bounded_vec<'de, T: Deserialize<'de>, D: serde::Deserializer<'de>>(
    deserializer: D,
    limit: usize,
) -> Result<Vec<T>, D::Error> {
    struct Bounded<T> {
        limit: usize,
        marker: std::marker::PhantomData<T>,
    }
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Bounded<T> {
        type Value = Vec<T>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "an array with at most {} entries", self.limit)
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut access: A,
        ) -> Result<Vec<T>, A::Error> {
            let mut values = Vec::with_capacity(access.size_hint().unwrap_or(0).min(self.limit));
            while values.len() < self.limit {
                match access.next_element()? {
                    Some(value) => values.push(value),
                    None => return Ok(values),
                }
            }
            if access.next_element_seed(RejectExcess)?.is_some() {
                return Err(serde::de::Error::custom(
                    "scope list exceeds its entry limit",
                ));
            }
            Ok(values)
        }
    }
    deserializer.deserialize_seq(Bounded {
        limit,
        marker: std::marker::PhantomData,
    })
}

pub(crate) fn deserialize_selectors<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ScopeSelector>, D::Error> {
    bounded_vec(deserializer, 32)
}
pub(crate) fn deserialize_defaults<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ScopedDefault>, D::Error> {
    bounded_vec(deserializer, 32)
}

fn deserialize_names<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error> {
    bounded_vec(deserializer, 32).map(Some)
}
fn deserialize_stages<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<EnvStage>>, D::Error> {
    bounded_vec(deserializer, 5).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EnvSchema, EnvValidator, ValidationErrorKind};
    use std::collections::HashMap;

    fn schema(value: serde_json::Value) -> EnvSchema {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn scope_dimensions_use_and_and_values_use_or() {
        let selector: ScopeSelector = serde_json::from_value(serde_json::json!({"environment":["staging","production"],"stage":["build","runtime"],"service":["api"]})).unwrap();
        assert!(selector.matches(EvalContext {
            environment: "production",
            stage: EnvStage::Build,
            service: Some("api")
        }));
        assert!(!selector.matches(EvalContext {
            environment: "development",
            stage: EnvStage::Build,
            service: Some("api")
        }));
        assert!(!selector.matches(EvalContext {
            environment: "production",
            stage: EnvStage::Ci,
            service: Some("api")
        }));
        assert!(!selector.matches(EvalContext {
            environment: "production",
            stage: EnvStage::Build,
            service: None
        }));
    }

    #[test]
    fn scoped_defaults_precede_global_defaults_and_requirements_are_additive() {
        let schema = schema(
            serde_json::json!({"vars":{"PORT":{"format":"port","default":"3000","defaultsIn":[{"when":{"stage":["test"]},"value":"4000"}]},"TOKEN":{"requiredIn":[{"environment":["production"],"service":["api"]}]}}}),
        );
        let validator = EnvValidator::new(&schema);
        let mut values = HashMap::new();
        let errors = validator.validate_with_context(
            &mut values,
            EvalContext {
                environment: "production",
                stage: EnvStage::Test,
                service: Some("api"),
            },
        );
        assert_eq!(values["PORT"], "4000");
        assert!(matches!(errors[0].kind, ValidationErrorKind::Missing));
        assert!(
            validator
                .validate_with_context(&mut HashMap::new(), EvalContext::default())
                .is_empty()
        );
    }

    #[test]
    fn inactive_scopes_still_validate_supplied_values() {
        let schema = schema(
            serde_json::json!({"vars":{"COUNT":{"format":"integer","requiredIn":[{"stage":["ci"]}]}}}),
        );
        let mut values = HashMap::from([("COUNT".into(), "wrong".into())]);
        assert!(!EnvValidator::new(&schema).validate(&mut values).is_empty());
    }

    #[test]
    fn overlapping_scoped_defaults_and_all_invalid_literals_are_rejected_eagerly() {
        for rule in [
            serde_json::json!({"defaultsIn":[{"when":{"stage":["build"]},"value":"a"},{"when":{"environment":["production"]},"value":"b"}]}),
            serde_json::json!({"secret":true,"defaultsIn":[{"when":{"stage":["build"]},"value":"sensitive"}]}),
            serde_json::json!({"format":"port","defaultsIn":[{"when":{"stage":["build"]},"value":"70000"}]}),
            serde_json::json!({"defaultsIn":[{"when":{"stage":["build"]},"value":"bad\u{0000}value"}]}),
            serde_json::json!({"requiredIn":[{}]}),
        ] {
            let schema = schema(serde_json::json!({"vars":{"VALUE":rule}}));
            assert!(!EnvValidator::new(&schema).schema_errors().is_empty());
        }
    }

    #[test]
    fn malformed_dimensions_and_excess_selectors_fail_parsing() {
        for value in [
            serde_json::json!({"stage":null}),
            serde_json::json!({"stage":["unknown"]}),
            serde_json::json!({"environment":vec!["a";33]}),
        ] {
            assert!(serde_json::from_value::<ScopeSelector>(value).is_err());
        }
        assert!(serde_json::from_value::<EnvSchema>(serde_json::json!({"vars":{"VALUE":{"requiredIn":vec![serde_json::json!({"stage":["build"]});33]}}})).is_err());
    }

    #[test]
    fn command_names_select_stage_without_reading_project_values() {
        assert_eq!(EnvStage::for_script("build:api"), EnvStage::Build);
        assert_eq!(EnvStage::for_script("pretest:unit"), EnvStage::Test);
        assert_eq!(EnvStage::for_script("serve"), EnvStage::Runtime);
    }
}

#[cfg(test)]
mod optional_scope_tests {
    use super::*;
    use std::collections::HashMap;
    #[test]
    fn an_optional_scope_accepts_empty_defaults_when_required_scopes_have_nonempty_defaults() {
        for global in [false, true] {
            let mut rule = serde_json::json!({"empty":"allow","requiredIn":[{"stage":["build"]}],"defaultsIn":[{"when":{"stage":["build"]},"value":"ready"}]});
            if global {
                rule["default"] = serde_json::json!("");
            } else {
                rule["defaultsIn"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!({"when":{"stage":["runtime"]},"value":""}));
            }
            let schema: crate::EnvSchema =
                serde_json::from_value(serde_json::json!({"vars":{"VALUE":rule}})).unwrap();
            let plan = crate::EnvValidator::new(&schema);
            assert!(
                plan.schema_errors().is_empty(),
                "{:?}",
                plan.schema_errors()
            );
            assert!(plan.validate(&mut HashMap::new()).is_empty());
            let mut values = HashMap::new();
            assert!(
                plan.validate_with_context(
                    &mut values,
                    EvalContext {
                        stage: EnvStage::Build,
                        ..Default::default()
                    }
                )
                .is_empty()
            );
            assert_eq!(values["VALUE"], "ready");
        }
    }
}

#[cfg(test)]
mod selector_identity_tests {
    #[test]
    fn reordered_dimension_values_do_not_create_distinct_required_selectors() {
        let schema:crate::EnvSchema=serde_json::from_value(serde_json::json!({"vars":{"VALUE":{"requiredIn":[{"environment":["staging","production"],"stage":["build","runtime"],"service":["api","worker"]},{"environment":["production","staging"],"stage":["runtime","build"],"service":["worker","api"]}]}}})).unwrap();
        assert!(!crate::EnvValidator::new(&schema).schema_errors().is_empty());
    }
}

#[cfg(test)]
mod object_shape_tests {
    use super::*;
    #[test]
    fn scope_selectors_and_defaults_require_json_objects() {
        assert!(serde_json::from_str::<ScopeSelector>(r#"[["production"]]"#).is_err());
        assert!(serde_json::from_str::<ScopedDefault>(r#"[{"stage":["test"]},"4"]"#).is_err());
        assert!(serde_json::from_str::<ScopeSelector>(r#"{"stage":["test"]}"#).is_ok());
    }
}

crate::object::object_only!(ScopeSelector);
crate::object::object_only!(ScopedDefault);
