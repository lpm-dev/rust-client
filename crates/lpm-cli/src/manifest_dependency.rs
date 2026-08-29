use lpm_common::LpmError;
use lpm_resolver::specifier::Specifier;

#[derive(Debug, Clone)]
pub(crate) enum ManifestDependencySpec {
    Plain,
    NpmAlias { target: String },
}

impl ManifestDependencySpec {
    pub(crate) fn from_manifest_value(name: &str, value: &str) -> Result<(Self, String), LpmError> {
        if value.trim_start().starts_with("npm:") {
            return match Specifier::parse(value) {
                Ok(Specifier::NpmAlias { target, range }) => Ok((Self::NpmAlias { target }, range)),
                Ok(_) => Err(LpmError::Script(format!(
                    "dependency `{name}` uses invalid npm alias spec `{value}`"
                ))),
                Err(error) => Err(LpmError::Script(format!(
                    "dependency `{name}` uses invalid npm alias spec `{value}`: {error}"
                ))),
            };
        }

        Ok((Self::Plain, value.to_string()))
    }

    pub(crate) fn render_new_value(&self, new_range: &str) -> String {
        match self {
            Self::Plain => new_range.to_string(),
            Self::NpmAlias { target } => format!("npm:{target}@{new_range}"),
        }
    }
}
