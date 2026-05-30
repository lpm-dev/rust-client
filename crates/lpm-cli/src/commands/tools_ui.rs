use crate::install_ui;
use std::path::Path;
use std::time::Duration;

pub fn plugin_version_label(bin: &Path, configured_version: Option<&str>) -> String {
    configured_version
        .map(str::to_owned)
        .or_else(|| {
            bin.parent()
                .and_then(Path::parent)
                .and_then(Path::file_name)
                .and_then(|name| name.to_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "latest".to_owned())
}

pub fn using_tool(name: &str, version: &str) {
    install_ui::phase(&format!("Using {name} {version}"));
}

pub fn using_check_engine(binary: &str) {
    install_ui::phase(&format!("Using {binary} --noEmit"));
}

pub fn detected_test_runner(runner_name: &str) {
    match runner_name {
        "scripts.test" => install_ui::phase("Using package.json test script"),
        _ => install_ui::phase(&format!(
            "Auto-detected {}",
            runner_display_name(runner_name)
        )),
    }
}

pub fn detected_bench_runner(runner_name: &str) {
    match runner_name {
        "vitest" => install_ui::phase("Auto-detected Vitest bench runner"),
        "scripts.bench" => install_ui::phase("Using package.json bench script"),
        _ => install_ui::phase(&format!(
            "Auto-detected {} bench runner",
            runner_display_name(runner_name)
        )),
    }
}

pub fn done_fmt_write_elapsed(elapsed: Duration) {
    let duration = install_ui::format_duration(elapsed);
    install_ui::done(&format!(
        "Done · codebase is now formatted in {}",
        install_ui::green(&duration)
    ));
}

pub fn done_fmt_check(elapsed: Duration) {
    done_passed("fmt check", elapsed);
}

pub fn done_lint(elapsed: Duration) {
    done_passed("lint", elapsed);
}

pub fn done_typecheck(elapsed: Duration) {
    done_passed("typecheck", elapsed);
}

pub fn done_test(elapsed: Duration) {
    let duration = install_ui::format_duration(elapsed);
    install_ui::done(&format!(
        "Tests complete in {}",
        install_ui::green(&duration)
    ));
}

pub fn done_bench(elapsed: Duration) {
    let duration = install_ui::format_duration(elapsed);
    install_ui::done(&format!(
        "Benchmarks complete in {}",
        install_ui::green(&duration)
    ));
}

pub fn done_no_packages_affected(tool: &str, base_ref: &str) {
    install_ui::done(&format!(
        "no packages affected vs {base_ref} — nothing to {tool}"
    ));
}

pub fn warn_no_packages_matched() {
    install_ui::warn("No packages matched");
}

pub fn done_workspace(tool: &str, total: usize, elapsed: Duration) {
    let duration = install_ui::format_duration(elapsed);
    install_ui::done(&format!(
        "{tool} passed in {} {} in {}",
        install_ui::bold(&total.to_string()),
        install_ui::packages_word(total),
        install_ui::green(&duration)
    ));
}

pub fn failed_workspace(
    tool: &str,
    succeeded: usize,
    failed: usize,
    total: usize,
    elapsed: Duration,
) {
    let duration = install_ui::format_duration(elapsed);
    install_ui::failed(&format!(
        "{tool}: {succeeded} passed, {failed} failed out of {total} packages in {duration}"
    ));
}

pub fn failed(label: &str, code: i32) {
    install_ui::failed(&format!("{label} failed · exit code {code}"));
}

fn done_passed(label: &str, elapsed: Duration) {
    let duration = install_ui::format_duration(elapsed);
    install_ui::done(&format!(
        "{label} passed in {}",
        install_ui::green(&duration)
    ));
}

fn runner_display_name(runner_name: &str) -> String {
    match runner_name {
        "vitest" => "Vitest".to_owned(),
        "jest" => "Jest".to_owned(),
        "mocha" => "Mocha".to_owned(),
        other => other.to_owned(),
    }
}
