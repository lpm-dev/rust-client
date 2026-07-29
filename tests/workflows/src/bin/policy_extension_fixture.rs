use std::io::Read;

fn main() {
    let mut action = "allow".to_string();
    let mut name = "policy-pkg".to_string();
    let mut version = "1.0.0".to_string();
    let mut code = "fixture".to_string();
    let mut reason = "fixture decision".to_string();
    let mut log_path = None;
    let mut count_path = None;
    let mut forced_exit = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--action" => action = next_arg(&mut args, "--action"),
            "--name" => name = next_arg(&mut args, "--name"),
            "--version" => version = next_arg(&mut args, "--version"),
            "--code" => code = next_arg(&mut args, "--code"),
            "--reason" => reason = next_arg(&mut args, "--reason"),
            "--log" => log_path = Some(next_arg(&mut args, "--log")),
            "--count" => count_path = Some(next_arg(&mut args, "--count")),
            "--exit" => forced_exit = Some(next_arg(&mut args, "--exit")),
            other => panic!("unknown fixture arg {other}"),
        }
    }

    let mut request = String::new();
    std::io::stdin()
        .read_to_string(&mut request)
        .expect("read policy extension request");

    if let Some(path) = log_path {
        std::fs::write(path, &request).expect("write policy extension request log");
    }
    if let Some(path) = count_path {
        let count = std::fs::read_to_string(&path)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        std::fs::write(path, count.saturating_add(1).to_string())
            .expect("write policy extension invocation count");
    }

    if let Some(exit) = forced_exit {
        let code = exit.parse::<i32>().unwrap_or(1);
        eprintln!("fixture forced exit {code}");
        std::process::exit(code);
    }

    let response = serde_json::json!({
        "schema_version": 1,
        "decisions": [{
            "name": name,
            "version": version,
            "action": action,
            "code": code,
            "reason": reason,
        }]
    });
    println!(
        "{}",
        serde_json::to_string(&response).expect("serialize fixture response")
    );
}

fn next_arg(args: &mut impl Iterator<Item = String>, flag: &str) -> String {
    args.next()
        .unwrap_or_else(|| panic!("{flag} requires a value"))
}
