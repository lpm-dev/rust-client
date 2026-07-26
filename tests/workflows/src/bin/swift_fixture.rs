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
        _ => std::process::exit(64),
    }
}
