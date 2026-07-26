fn main() {
    let mut args = std::env::args();
    let _program = args.next();
    let command = args.next();
    let action = args.next();

    match (command.as_deref(), action.as_deref()) {
        (Some("package"), Some("dump-package")) => {
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
        _ => std::process::exit(64),
    }
}
