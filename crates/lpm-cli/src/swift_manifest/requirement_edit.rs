use super::{CallSpan, SwiftRequirement, parse_string_literal, skip_space_and_comments};
use lpm_common::LpmError;
use std::ops::Range;

fn argument_tokens(content: &str, call: CallSpan) -> Option<Vec<Range<usize>>> {
    let bytes = content.as_bytes();
    let mut tokens = Vec::with_capacity(7);
    let mut index = call.open + 1;
    while index < call.close {
        index = skip_space_and_comments(content, index, call.close);
        if index >= call.close {
            break;
        }
        let start = index;
        index = match bytes[index] {
            b'"' => parse_string_literal(content, index, call.close)?.1,
            b':' | b',' => index + 1,
            b'.' if bytes[index..].starts_with(b"..<") => index + 3,
            byte if byte.is_ascii_alphabetic() => super::identifier_end(bytes, index, call.close),
            _ => return None,
        };
        tokens.push(start..index);
        if tokens.len() == 7 {
            index = skip_space_and_comments(content, index, call.close);
            return (index == call.close || bytes.get(index) == Some(&b',')).then_some(tokens);
        }
    }
    Some(tokens)
}

pub(super) fn update_requirement(
    content: &str,
    call: CallSpan,
    desired: &SwiftRequirement,
) -> Result<String, LpmError> {
    let unsupported = || {
        LpmError::Registry(
        "Cannot safely update this Package.swift registry requirement. Use a literal `from:`, `exact:`, or half-open version range before installation.".into(),
    )
    };
    let tokens = argument_tokens(content, call).ok_or_else(unsupported)?;
    let text = |index: usize| &content[tokens[index].clone()];
    if tokens.len() != 7
        || text(0) != "id"
        || text(1) != ":"
        || text(3) != ","
        || !text(2).starts_with('"')
    {
        return Err(unsupported());
    }
    let literal = |index: usize| {
        parse_string_literal(content, tokens[index].start, tokens[index].end)
            .map(|(value, _)| value)
    };
    let current = match (text(4), text(5), text(6)) {
        ("from", ":", _) => SwiftRequirement::UpToNextMajor(literal(6).ok_or_else(unsupported)?),
        ("exact", ":", _) => SwiftRequirement::Exact(literal(6).ok_or_else(unsupported)?),
        (_, "..<", _) => SwiftRequirement::UpToNextMinor {
            lower: literal(4).ok_or_else(unsupported)?,
            upper: literal(6).ok_or_else(unsupported)?,
        },
        _ => return Err(unsupported()),
    };
    if current == *desired {
        return Ok(content.to_owned());
    }
    let replacements = match desired {
        SwiftRequirement::UpToNextMajor(version) => {
            ["from".into(), ":".into(), format!("\"{version}\"")]
        }
        SwiftRequirement::Exact(version) => ["exact".into(), ":".into(), format!("\"{version}\"")],
        SwiftRequirement::UpToNextMinor { lower, upper } => [
            format!("\"{lower}\""),
            " ..< ".into(),
            format!("\"{upper}\""),
        ],
    };
    let mut updated = content.to_owned();
    for index in (0..3).rev() {
        if text(index + 4) != replacements[index].trim() {
            updated.replace_range(tokens[index + 4].clone(), &replacements[index]);
        }
    }
    Ok(updated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_requirement_updates_preserve_trailing_package_traits() {
        let original = r#".package(id: "lpmdev.acme_kit", from: "1.0.0", /* traits */ traits: [.trait(name: "UI", condition: .when(traits: ["Views"]))])"#;
        let call = CallSpan {
            start: 0,
            open: original.find('(').unwrap(),
            close: original.len() - 1,
        };
        assert_eq!(
            update_requirement(
                original,
                call,
                &SwiftRequirement::UpToNextMajor("1.0.0".into())
            )
            .unwrap(),
            original
        );
        assert_eq!(
            update_requirement(
                original,
                call,
                &SwiftRequirement::UpToNextMajor("2.0.0".into())
            )
            .unwrap(),
            original.replace("1.0.0", "2.0.0")
        );
    }

    #[test]
    fn requirement_mode_changes_preserve_comments_and_produce_stable_edits() {
        let original = r#".package(id: "lpmdev.acme_kit", from/* note */: /* lower */"1.0.0",)"#;
        let call = CallSpan {
            start: 0,
            open: original.find('(').unwrap(),
            close: original.len() - 1,
        };
        let range = SwiftRequirement::UpToNextMinor {
            lower: "2.0.0".into(),
            upper: "2.1.0".into(),
        };
        let updated = update_requirement(original, call, &range).unwrap();
        assert_eq!(
            updated,
            r#".package(id: "lpmdev.acme_kit", "2.0.0"/* note */ ..<  /* lower */"2.1.0",)"#
        );
        let call = CallSpan {
            close: updated.len() - 1,
            ..call
        };
        assert_eq!(update_requirement(&updated, call, &range).unwrap(), updated);
        let exact =
            update_requirement(&updated, call, &SwiftRequirement::Exact("3.0.0".into())).unwrap();
        assert_eq!(
            exact,
            r#".package(id: "lpmdev.acme_kit", exact/* note */ :  /* lower */"3.0.0",)"#
        );
    }
}
