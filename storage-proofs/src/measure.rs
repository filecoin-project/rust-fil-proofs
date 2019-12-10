use cpu_time::ProcessTime;
use log::info;
use std::time::Instant;

pub fn measure_log<T, F>(label: &str, f: F) -> anyhow::Result<T>
where
    F: FnOnce() -> anyhow::Result<T>,
{
    let cpu_time_start = ProcessTime::now();
    let wall_start_time = Instant::now();

    let x = f()?;

    let cpu_time = cpu_time_start.elapsed().as_secs();
    let wall_time = wall_start_time.elapsed().as_secs();

    info!(
        "operation: {}, cpu_time_secs: {}, wall_time_secs: {}",
        label, cpu_time, wall_time
    );

    Ok(x)
}
