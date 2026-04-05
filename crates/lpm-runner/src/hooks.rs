//! Pre/post script hook detection and execution.
//!
//! npm convention: before running script `X`, check for `preX`.
//! After `X` completes successfully, check for `postX`.
//!
//! If `preX` fails (non-zero exit), abort without running `X` or `postX`.

use std::collections::HashMap;

/// Check if a pre-hook exists for the given script name.
pub fn pre_hook_name(script_name: &str) -> String {
    format!("pre{script_name}")
}

/// Check if a post-hook exists for the given script name.
pub fn post_hook_name(script_name: &str) -> String {
    format!("post{script_name}")
}

/// Find the pre-hook command for a script, if it exists.
pub fn find_pre_hook<'a>(
    scripts: &'a HashMap<String, String>,
    script_name: &str,
) -> Option<&'a str> {
    let hook_name = pre_hook_name(script_name);
    scripts.get(&hook_name).map(|s| s.as_str())
}

/// Find the post-hook command for a script, if it exists.
pub fn find_post_hook<'a>(
    scripts: &'a HashMap<String, String>,
    script_name: &str,
) -> Option<&'a str> {
    let hook_name = post_hook_name(script_name);
    scripts.get(&hook_name).map(|s| s.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scripts() -> HashMap<String, String> {
        let mut s = HashMap::new();
        s.insert("prebuild".into(), "rm -rf dist".into());
        s.insert("build".into(), "tsup".into());
        s.insert("postbuild".into(), "echo done".into());
        s.insert("test".into(), "vitest run".into());
        s
    }

    #[test]
    fn finds_pre_hook() {
        let s = scripts();
        assert_eq!(find_pre_hook(&s, "build"), Some("rm -rf dist"));
    }

    #[test]
    fn finds_post_hook() {
        let s = scripts();
        assert_eq!(find_post_hook(&s, "build"), Some("echo done"));
    }

    #[test]
    fn no_pre_hook_for_test() {
        let s = scripts();
        assert_eq!(find_pre_hook(&s, "test"), None);
    }

    #[test]
    fn no_post_hook_for_test() {
        let s = scripts();
        assert_eq!(find_post_hook(&s, "test"), None);
    }

    #[test]
    fn hook_names_for_empty_script() {
        // Edge case: empty script name produces "pre" and "post"
        assert_eq!(pre_hook_name(""), "pre");
        assert_eq!(post_hook_name(""), "post");
    }

    #[test]
    fn hook_names_for_nested_pre() {
        // "preprebuild" — hooks on hooks. npm does support this.
        let mut s = HashMap::new();
        s.insert("preprebuild".into(), "echo prep".into());
        s.insert("prebuild".into(), "echo pre".into());
        s.insert("build".into(), "echo build".into());

        // Looking for pre-hook of "prebuild" should find "preprebuild"
        assert_eq!(find_pre_hook(&s, "prebuild"), Some("echo prep"));
        // Looking for pre-hook of "build" should find "prebuild"
        assert_eq!(find_pre_hook(&s, "build"), Some("echo pre"));
    }

    #[test]
    fn hook_lookup_is_case_sensitive() {
        let mut s = HashMap::new();
        s.insert("preBuild".into(), "echo wrong".into());
        s.insert("prebuild".into(), "echo right".into());
        s.insert("build".into(), "echo build".into());

        // Hook names are case-sensitive — "prebuild" not "preBuild"
        assert_eq!(find_pre_hook(&s, "build"), Some("echo right"));
    }
}
