fn main() {
    let mut args = std::env::args();
    let _program = args.next();
    let command = args.next();
    let action = args.next();
    let command_name = match (command.as_deref(), action.as_deref()) {
        (Some(command), Some(action)) => format!("{command} {action}"),
        (Some(command), None) => command.to_string(),
        _ => String::new(),
    };

    if let Ok(path) = std::env::var("LPM_TEST_SWIFT_COMMAND_LOG") {
        use std::io::Write as _;
        let mut log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open Swift command log");
        writeln!(log, "{command_name}").expect("append Swift command log");
    }
    if let Ok(path) = std::env::var("LPM_TEST_SWIFT_ENV_CAPTURE") {
        const SENSITIVE: &[&str] = &[
            "LPM_TOKEN",
            "GITHUB_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "LD_LIBRARY_PATH",
            "DYLD_LIBRARY_PATH",
        ];
        use std::io::Write as _;
        let mut capture = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open Swift environment capture");
        for key in SENSITIVE {
            writeln!(
                capture,
                "{command_name}\t{key}\t{}",
                std::env::var_os(key).is_some()
            )
            .expect("append Swift environment capture");
        }
    }

    match (command.as_deref(), action.as_deref()) {
        (Some("package"), Some("dump-package")) => {
            if let (Ok(path), Ok(process_id)) = (
                std::env::var("LPM_TEST_SWIFT_INTERVAL_LOG"),
                std::env::var("LPM_TEST_SWIFT_PROCESS_ID"),
            ) {
                use std::io::Write as _;
                let mut log = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .expect("open Swift interval log");
                writeln!(log, "{process_id}:start").expect("append Swift interval start");
                drop(log);
                let delay = std::env::var("LPM_TEST_SWIFT_DUMP_DELAY_MS")
                    .ok()
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(0);
                std::thread::sleep(std::time::Duration::from_millis(delay));
                let mut log = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .expect("reopen Swift interval log");
                writeln!(log, "{process_id}:end").expect("append Swift interval end");
            }
            let exit_code = std::env::var("LPM_TEST_SWIFT_DUMP_EXIT_CODE")
                .ok()
                .and_then(|value| value.parse::<i32>().ok())
                .unwrap_or(0);
            if exit_code != 0 {
                eprintln!("configured dump-package failure");
                std::process::exit(exit_code);
            }
            let manifest = std::env::var("LPM_TEST_SWIFT_DUMP_PACKAGE")
                .expect("LPM_TEST_SWIFT_DUMP_PACKAGE must be set");
            println!("{manifest}");
        }
        (Some("package"), Some("resolve")) => {
            if let Ok(content) = std::env::var("LPM_TEST_SWIFT_PACKAGE_RESOLVED") {
                std::fs::write("Package.resolved", content)
                    .expect("write Package.resolved fixture");
            }
            let exit_code = std::env::var("LPM_TEST_SWIFT_RESOLVE_EXIT_CODE")
                .expect("LPM_TEST_SWIFT_RESOLVE_EXIT_CODE must be set")
                .parse::<i32>()
                .expect("LPM_TEST_SWIFT_RESOLVE_EXIT_CODE must be an integer");
            if exit_code != 0 {
                println!("inherited Swift stdout");
                eprintln!("inherited Swift stderr");
            }
            std::process::exit(exit_code);
        }
        (Some("package-registry"), Some("set")) => {
            let remaining: Vec<_> = args.collect();
            let scope = remaining
                .windows(2)
                .find(|pair| pair[0] == "--scope")
                .map(|pair| pair[1].as_str())
                .expect("package-registry set must include --scope");
            let registry_url = remaining
                .last()
                .expect("package-registry set must include a registry URL");
            let config_path = std::path::Path::new(".swiftpm/configuration/registries.json");
            std::fs::create_dir_all(config_path.parent().unwrap())
                .expect("create Swift registry configuration directory");
            std::fs::write(
                config_path,
                serde_json::to_vec(&serde_json::json!({
                    "registries": {
                        (scope): {
                            "url": registry_url
                        }
                    }
                }))
                .unwrap(),
            )
            .expect("write Swift registry configuration");
        }
        (Some("package-registry"), Some("login")) => {
            let remaining: Vec<_> = args.collect();
            if let Ok(path) = std::env::var("LPM_TEST_SWIFT_LOGIN_ARGS_PATH") {
                std::fs::write(
                    path,
                    serde_json::to_vec(&remaining).expect("serialize Swift login arguments"),
                )
                .expect("write Swift login arguments");
            }
            let token_file = remaining
                .windows(2)
                .find(|pair| pair[0] == "--token-file")
                .map(|pair| std::path::PathBuf::from(&pair[1]));
            if let Ok(path) = std::env::var("LPM_TEST_SWIFT_LOGIN_TOKEN_PATH") {
                let token = if let Some(token_file) = token_file.as_deref() {
                    std::fs::read_to_string(token_file).expect("read Swift login token file")
                } else {
                    remaining
                        .windows(2)
                        .find(|pair| pair[0] == "--token")
                        .map(|pair| pair[1].clone())
                        .unwrap_or_default()
                };
                std::fs::write(path, token).expect("write captured Swift login token");
            }
            #[cfg(unix)]
            if let Ok(path) = std::env::var("LPM_TEST_SWIFT_LOGIN_TOKEN_MODE_PATH") {
                use std::os::unix::fs::PermissionsExt;

                let mode = token_file
                    .as_deref()
                    .map(|token_file| {
                        std::fs::metadata(token_file)
                            .expect("read Swift login token file metadata")
                            .permissions()
                            .mode()
                            & 0o777
                    })
                    .map_or_else(|| "argv".to_string(), |mode| format!("{mode:o}"));
                std::fs::write(path, mode).expect("write Swift login token file mode");
            }
            let exit_code = std::env::var("LPM_TEST_SWIFT_LOGIN_EXIT_CODE")
                .ok()
                .and_then(|value| value.parse::<i32>().ok())
                .unwrap_or(0);
            std::process::exit(exit_code);
        }
        _ => std::process::exit(64),
    }
}
