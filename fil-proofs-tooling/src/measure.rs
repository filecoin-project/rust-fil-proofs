use std::time::{Duration, Instant};

use anyhow::Result;
use cpu_time::ProcessTime;

pub struct FuncMeasurement<T> {
    pub cpu_time: Duration,
    pub wall_time: Duration,
    pub return_value: T,
}

pub fn measure<T, F>(f: F) -> Result<FuncMeasurement<T>>
where
    F: FnOnce() -> Result<T>,
{
    let cpu_time_start = ProcessTime::now();
    let wall_start_time = Instant::now();

    let x = f()?;

    Ok(FuncMeasurement {
        cpu_time: cpu_time_start.elapsed(),
        wall_time: wall_start_time.elapsed(),
        return_value: x,
    })
}
