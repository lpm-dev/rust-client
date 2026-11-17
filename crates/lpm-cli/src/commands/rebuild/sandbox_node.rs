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

    /// The host's `node` on the script environment's `PATH`, when it is
    /// affected. It is asked the way a toolchain probe is, so a `node` the
    /// project controls is never run here, and its answer is kept for the
    /// process. A `node` that gave none, one too slow to start in the
    /// probe's time for example, is asked again by the next rebuild. A
    /// script that finds another `node` first, one a dependency supplies,
    /// runs that one instead, and this says nothing about it.
    #[cfg(windows)]
    pub(super) fn on_host(
        environment: &super::sandbox_env::ChildEnvironment,
        project_dir: &std::path::Path,
    ) -> Option<&'static Self> {
        static HOST: std::sync::OnceLock<Option<StuckNode>> = std::sync::OnceLock::new();
        if let Some(answered) = HOST.get() {
            return answered.as_ref();
        }
        let printed = super::build_cache::trusted_host_output(
            "node.exe",
            &["-p", "process.version + ' ' + process.versions.uv"],
            environment,
            project_dir,
        )?;
        HOST.get_or_init(|| Self::from_versions(&printed)).as_ref()
    }

    /// What a process is told once, before the first scripts it runs
    /// start; `None` after that.
    #[cfg(windows)]
    pub(super) fn warning_once(&self, timeout: std::time::Duration) -> Option<String> {
        static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        (!WARNED.swap(true, std::sync::atomic::Ordering::Relaxed)).then(|| self.warning(timeout))
    }

    fn warning(&self, timeout: std::time::Duration) -> String {
        format!(
            "The Node on PATH ({}) bundles libuv {}, which can't create a child process's output pipes inside the Windows sandbox. An install script that starts a child process and reads its output stops responding until its time limit ({}s). A Node that bundles libuv {} or later doesn't have this problem.",
            self.node,
            self.libuv,
            timeout.as_secs(),
            FIRST_LIBUV_FOR_APPCONTAINER
                .map(|number| number.to_string())
                .join("."),
        )
    }

    /// What a script that ran out of time is told.
    pub(super) fn timeout_hint(&self) -> String {
        format!(
            "one possible cause: Node {} (libuv {}) can't create a child process's output pipes inside the Windows sandbox",
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
            let warning = stuck.warning(std::time::Duration::from_secs(300));
            assert!(
                warning.contains("bundles libuv 1.53.0 or later"),
                "{printed}"
            );
            assert!(warning.contains("its time limit (300s)"), "{printed}");
            assert!(stuck.timeout_hint().contains("Node v2"), "{printed}");
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
