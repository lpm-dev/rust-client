//! Whether the Node a sandboxed script runs can start child processes.

/// The first libuv whose child-process pipes can be created inside a
/// Windows AppContainer. An earlier one names them where an AppContainer
/// may not create pipes and retries forever, so a script that starts a
/// child with piped output never returns.
const FIRST_LIBUV_FOR_APPCONTAINER: [u64; 3] = [1, 53, 0];

/// A Node that can't start a child process inside the Windows sandbox.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct StuckNode {
    node: String,
    libuv: String,
}

impl StuckNode {
    /// From what `node -p "process.version + ' ' + process.versions.uv"`
    /// prints, when that libuv is affected. Text that isn't two versions
    /// says nothing.
    fn from_versions(printed: &str) -> Option<Self> {
        let is_version = |text: &str| {
            !text.is_empty()
                && text.len() <= 64
                && text
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
        };
        let mut versions = printed.split_whitespace();
        let (node, libuv) = (versions.next()?, versions.next()?);
        if versions.next().is_some() || !is_version(node) || !is_version(libuv) {
            return None;
        }
        let mut numbers = libuv.split('.').map(|number| {
            let digits = number
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(number.len());
            number[..digits].parse::<u64>().ok()
        });
        let release = [numbers.next()??, numbers.next()??, numbers.next()??];
        (release < FIRST_LIBUV_FOR_APPCONTAINER).then(|| Self {
            node: node.to_owned(),
            libuv: libuv.to_owned(),
        })
    }

    /// The `node` a script finds first on `path`, when it is affected.
    #[cfg(windows)]
    pub(super) fn on(path: Option<&std::ffi::OsStr>) -> Option<Self> {
        let node = super::bundled_node_gyp::node_on(path?)?;
        let printed = std::process::Command::new(node)
            .args(["-p", "process.version + ' ' + process.versions.uv"])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .ok()?;
        Self::from_versions(std::str::from_utf8(&printed.stdout).ok()?)
    }

    /// What a run is told before its scripts start.
    pub(super) fn warning(&self) -> String {
        format!(
            "Node {} can't start child processes inside the Windows sandbox: it bundles libuv {}, and libuv {} fixes this. An install script that starts one stops at its time limit.",
            self.node,
            self.libuv,
            FIRST_LIBUV_FOR_APPCONTAINER
                .map(|number| number.to_string())
                .join("."),
        )
    }

    /// What a script that ran out of time is told.
    pub(super) fn timeout_hint(&self) -> String {
        format!(
            "Node {} can't start a child process inside the Windows sandbox (libuv {}), which is the likely reason this script didn't finish",
            self.node, self.libuv,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_with_a_libuv_before_the_fix_is_stuck() {
        for printed in ["v22.23.5 1.51.0\n", "v24.11.0 1.52.1", "v20.0.0 1.44.2-dev"] {
            let stuck = StuckNode::from_versions(printed).expect(printed);
            assert!(
                stuck.warning().contains("libuv 1.53.0 fixes this"),
                "{printed}"
            );
            assert!(stuck.timeout_hint().starts_with("Node v2"), "{printed}");
        }
        assert_eq!(
            StuckNode::from_versions("v22.23.5 1.51.0"),
            Some(StuckNode {
                node: "v22.23.5".into(),
                libuv: "1.51.0".into(),
            })
        );
    }

    #[test]
    fn a_node_with_the_fixed_libuv_or_later_is_not() {
        for printed in ["v26.3.0 1.53.0", "v27.0.0 1.60.2", "v30.0.0 2.0.0"] {
            assert_eq!(StuckNode::from_versions(printed), None, "{printed}");
        }
    }

    #[test]
    fn output_that_is_not_two_versions_says_nothing() {
        for printed in [
            "",
            "v22.23.5",
            "v22.23.5 1.51",
            "v22.23.5 1.51.0 extra",
            "v22.23.5 \u{1b}[31m1.51.0",
            "v22.23.5 one.two.three",
        ] {
            assert_eq!(StuckNode::from_versions(printed), None, "{printed:?}");
        }
    }
}
