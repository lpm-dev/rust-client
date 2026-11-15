//! The explanation a Touch ID prompt shows when a Keychain read needs it.
//!
//! macOS shows a context's `localizedReason` after the app's name, as in
//! "LPM CLI is trying to access env values for my-app", when a Keychain
//! operation authenticates through that context. Without one the prompt
//! names no project, so a prompt raised by something the person didn't run
//! looks the same as one they expect.

use std::cell::RefCell;
use std::path::Path;

/// Longest project name a prompt shows, in characters. A checkout chooses its
/// own name, so a long one could push the rest of the sentence off the
/// prompt.
const MAX_PROJECT_NAME_CHARS: usize = 64;

thread_local! {
    static PROJECT: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Names the project in every prompt raised on this thread while it lives,
/// and restores the previous name when dropped.
#[must_use]
pub(crate) struct PromptProject {
    previous: Option<String>,
}

impl Drop for PromptProject {
    fn drop(&mut self) {
        PROJECT.with_borrow_mut(|current| *current = self.previous.take());
    }
}

/// Names the project at `project_dir`, by the name LPM Vault lists it under,
/// in the prompts raised while the returned guard lives.
pub(crate) fn naming_project(project_dir: &Path) -> PromptProject {
    naming(&crate::vault_id::read_project_name(project_dir))
}

pub(crate) fn naming(name: &str) -> PromptProject {
    let previous = PROJECT.with_borrow_mut(|current| current.replace(name.to_owned()));
    PromptProject { previous }
}

/// The named project's name as a prompt may show it, when one is named.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn current_project() -> Option<String> {
    PROJECT.with_borrow(|project| shown_name(project.as_deref()))
}

/// The reason the next prompt on this thread shows when the Keychain call
/// that raises it gives none of its own.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn current_reason() -> String {
    PROJECT.with_borrow(|project| reason(project.as_deref()))
}

fn reason(project: Option<&str>) -> String {
    match shown_name(project) {
        Some(name) => format!("access env values for {name}"),
        None => "access LPM env values".to_owned(),
    }
}

fn shown_name(project: Option<&str>) -> Option<String> {
    project.map(displayable).filter(|name| !name.is_empty())
}

/// `name` on one line, without control or bidirectional-override characters,
/// cut to [`MAX_PROJECT_NAME_CHARS`].
fn displayable(name: &str) -> String {
    let mut shown = String::with_capacity(name.len().min(4 * MAX_PROJECT_NAME_CHARS));
    let mut kept = 0;
    for character in name.chars() {
        if character.is_control() || is_bidi_control(character) {
            continue;
        }
        if kept == MAX_PROJECT_NAME_CHARS {
            shown.push('…');
            break;
        }
        shown.push(character);
        kept += 1;
    }
    shown.trim().to_owned()
}

fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_prompt_names_the_project_it_reads_for() {
        let _prompt = naming("my-app");
        assert_eq!(current_reason(), "access env values for my-app");
    }

    #[test]
    fn a_prompt_outside_any_project_names_none() {
        assert_eq!(current_reason(), "access LPM env values");
    }

    #[test]
    fn a_project_name_is_forgotten_when_its_guard_ends() {
        {
            let _outer = naming("outer");
            {
                let _inner = naming("inner");
                assert_eq!(current_reason(), "access env values for inner");
            }
            assert_eq!(current_reason(), "access env values for outer");
        }
        assert_eq!(current_reason(), "access LPM env values");
    }

    #[test]
    fn a_project_name_cannot_rewrite_the_rest_of_the_prompt() {
        let name = format!(
            "my-app\nApprove to continue \u{202E}evil{}",
            "x".repeat(200)
        );
        let shown = reason(Some(&name));
        assert!(!shown.contains('\n'), "{shown}");
        assert!(!shown.contains('\u{202E}'), "{shown}");
        assert!(
            shown.chars().count() <= "access env values for ".len() + MAX_PROJECT_NAME_CHARS + 1,
            "{shown}"
        );
        assert!(shown.ends_with('…'), "{shown}");
    }

    #[test]
    fn a_blank_project_name_reads_as_no_project() {
        assert_eq!(reason(Some(" \u{202E}\n")), "access LPM env values");
    }
}
