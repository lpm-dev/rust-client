//! Scan newline-delimited package paths without executing package code.

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::time::Instant;

use lpm_security::behavioral::analyze_package_from_open_dir;
use serde::Deserialize;

#[derive(Deserialize)]
struct Request {
    name: String,
    version: String,
    path: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::BufWriter::new(std::io::stdout().lock());
    for line in stdin.lock().lines() {
        let request: Request = serde_json::from_str(&line?)?;
        let root = cap_std::fs::Dir::open_ambient_dir(&request.path, cap_std::ambient_authority())?;
        let start = Instant::now();
        let analysis = analyze_package_from_open_dir(&root);
        let elapsed_ns = start.elapsed().as_nanos();
        serde_json::to_writer(
            &mut stdout,
            &serde_json::json!({
                "name": request.name,
                "version": request.version,
                "analysis": analysis,
                "elapsed_ns": elapsed_ns,
            }),
        )?;
        writeln!(stdout)?;
        stdout.flush()?;
    }
    Ok(())
}
