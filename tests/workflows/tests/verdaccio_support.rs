mod support;

use std::path::Path;

use support::verdaccio::verdaccio_log_confirms_current_instance;

#[test]
fn verdaccio_startup_log_rejects_stale_process_with_same_port() {
    let logs = "config file - /tmp/old/config.yaml\nhttp address - http://127.0.0.1:4873/";

    assert!(!verdaccio_log_confirms_current_instance(
        logs,
        Path::new("/tmp/current/config.yaml"),
        "http://127.0.0.1:4873",
    ));
}

#[test]
fn verdaccio_startup_log_rejects_current_config_on_wrong_port() {
    let logs = "config file - /tmp/current/config.yaml\nhttp address - http://127.0.0.1:4874/";

    assert!(!verdaccio_log_confirms_current_instance(
        logs,
        Path::new("/tmp/current/config.yaml"),
        "http://127.0.0.1:4873",
    ));
}

#[test]
fn verdaccio_startup_log_accepts_current_config_and_listen_url() {
    let logs = concat!(
        "config file - \u{1b}[32m/tmp/current/config.yaml\u{1b}[37m\n",
        "http address - \u{1b}[32mhttp://127.0.0.1:4873/\u{1b}[37m\n",
    );

    assert!(verdaccio_log_confirms_current_instance(
        logs,
        Path::new("/tmp/current/config.yaml"),
        "http://127.0.0.1:4873",
    ));
}
