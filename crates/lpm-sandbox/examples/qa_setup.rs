#[cfg(windows)]
fn main() {
    use lpm_sandbox::helper_appcontainer::setup;
    let args: Vec<String> = std::env::args().collect();
    let user = (args[3] != "current").then_some(args[3].as_str());
    let tools: Vec<std::path::PathBuf> = args[4..].iter().map(Into::into).collect();
    let result = (|| {
        let plan = setup::preview(std::path::Path::new(&args[2]), &tools, user)?;
        if args[1] != "preview" { setup::apply(&plan, args[1] == "remove")?; }
        println!("{}", serde_json::json!({"elevated": setup::is_elevated()?, "plan": setup::preview(std::path::Path::new(&args[2]), &tools, user)?}));
        Ok::<_,lpm_sandbox::helper_appcontainer::AppContainerError>(())
    })();
    if let Err(error) = result { eprintln!("{error}"); std::process::exit(1); }
}
#[cfg(not(windows))]
fn main() {}
