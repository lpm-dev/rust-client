use serde::{Deserialize, Serialize};

const MAX_EVIDENCE_PER_RULE: usize = 3;
const MAX_EXCERPT_BYTES: usize = 240;

/// Bounded source evidence for a behavioral tag. A capability match does not prove execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SourceEvidence {
    pub rule_id: String,
    pub path: String,
    /// One-based source line, absent for whole-file heuristics and sampled files.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// One-based byte column, absent when the original position is unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excerpt: Option<String>,
    pub reason: String,
    /// Describes the file's apparent role; it is not a reachability verdict.
    pub file_context: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sampled: bool,
    /// Detector score, not a calibrated probability of maliciousness.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heuristic_score: Option<f64>,
}

impl SourceEvidence {
    pub(super) fn new(rule: &str, path: &str, reason: &str) -> Self {
        Self {
            rule_id: rule.to_owned(),
            path: path.to_owned(),
            line: None,
            column: None,
            excerpt: None,
            reason: reason.to_owned(),
            file_context: file_context(path).to_owned(),
            sampled: false,
            heuristic_score: None,
        }
    }

    pub(super) fn at(mut self, source: &str, offset: usize) -> Self {
        let prefix = &source[..offset];
        self.line = Some(bytecount::count(prefix.as_bytes(), b'\n') + 1);
        let line_start = prefix.rfind('\n').map_or(0, |index| index + 1);
        self.column = Some(offset - line_start + 1);
        let start = source.floor_char_boundary(offset.saturating_sub(60).max(line_start));
        let end = source.floor_char_boundary((start + MAX_EXCERPT_BYTES).min(source.len()));
        self.excerpt = Some(source[start..end].to_owned());
        self
    }
}

fn file_context(path: &str) -> &'static str {
    if path.split('/').any(|part| {
        matches!(
            part,
            "test" | "tests" | "__tests__" | "fixtures" | "examples" | "example"
        )
    }) {
        "test-or-example"
    } else if super::supply_chain::is_minified_filename(path) {
        "minified"
    } else {
        "source"
    }
}

pub(super) fn merge_evidence(target: &mut Vec<SourceEvidence>, entries: Vec<SourceEvidence>) {
    for entry in entries {
        let start = target.partition_point(|current| current.rule_id < entry.rule_id);
        let end = target.partition_point(|current| current.rule_id <= entry.rule_id);
        let key = (&entry.path, entry.line, entry.column);
        let position = target[start..end]
            .binary_search_by(|current| (&current.path, current.line, current.column).cmp(&key));
        let Err(position) = position else { continue };
        if position >= MAX_EVIDENCE_PER_RULE {
            continue;
        }
        if end - start == MAX_EVIDENCE_PER_RULE {
            target.remove(end - 1);
        }
        target.insert(start + position, entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_positions_and_excerpts_preserve_utf8_boundaries() {
        let text = "// λ\nconst π = 1; eval(input);";
        let entry = SourceEvidence::new("eval", "lib/index.js", "capability")
            .at(text, text.find("eval").unwrap());
        assert_eq!((entry.line, entry.column), (Some(2), Some(15)));
        assert!(entry.excerpt.unwrap().contains("eval(input)"));
    }

    #[test]
    fn evidence_retention_is_bounded_and_independent_of_merge_order() {
        let entries: Vec<_> = (0..20)
            .map(|index| SourceEvidence::new("eval", &format!("{index:02}.js"), "capability"))
            .collect();
        let mut forward = Vec::new();
        let mut reverse = Vec::new();
        merge_evidence(&mut forward, entries.clone());
        merge_evidence(&mut reverse, entries.into_iter().rev().collect());
        assert_eq!(forward, reverse);
        assert_eq!(forward.len(), MAX_EVIDENCE_PER_RULE);
        assert_eq!(forward[0].path, "00.js");
    }
}
