//! Measure runtime identity capture separately from task execution and artifact I/O.

use lpm_runtime::task_identity::PortableRuntimeSnapshot;
use std::error::Error;
use std::time::Instant;

fn main() -> Result<(), Box<dyn Error>> {
    let cwd = std::env::current_dir()?;
    let path = std::env::var_os("PATH").ok_or("PATH is unset")?;
    let samples = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "1000".into())
        .parse::<usize>()?;
    if samples == 0 {
        return Err("sample count must be positive".into());
    }
    let first = Instant::now();
    let snapshot =
        PortableRuntimeSnapshot::capture(&cwd, &path).ok_or("unstable runtime identity")?;
    let first_us = first.elapsed().as_secs_f64() * 1e6;
    let mut elapsed = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        let next =
            PortableRuntimeSnapshot::capture(&cwd, &path).ok_or("unstable runtime identity")?;
        if next.identities() != snapshot.identities() {
            return Err("runtime identity changed".into());
        }
        elapsed.push(start.elapsed().as_secs_f64() * 1e6);
    }
    elapsed.sort_unstable_by(f64::total_cmp);
    println!(
        "samples={samples} first_capture_us={first_us:.3} warm_median_us={:.3}",
        elapsed[samples / 2]
    );
    Ok(())
}
