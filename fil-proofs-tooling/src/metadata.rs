use chrono::{DateTime, TimeZone, Utc};
use failure::Error;
use git2::Repository;
use serde::Serialize;

/// Captures metadata about the current setup.
#[derive(Debug, Serialize)]
pub struct Metadata<T> {
    git: GitMetadata,
    system: SystemMetadata,
    benchmarks: T,
}

impl<T> Metadata<T> {
    pub fn wrap(benchmarks: T) -> Result<Self, failure::Error> {
        Ok(Metadata {
            git: GitMetadata::new()?,
            system: SystemMetadata::new()?,
            benchmarks,
        })
    }
}

/// Captures git specific metadata about the current repo.
#[derive(Debug, Serialize)]
pub struct GitMetadata {
    hash: String,
    date: DateTime<Utc>,
}

impl GitMetadata {
    pub fn new() -> Result<Self, Error> {
        let repo_path = std::env::var("CARGO_MANIFEST_DIR")?;
        let repo = Repository::discover(&repo_path)?;
        let head = repo.head()?;
        let commit = head.peel_to_commit()?;
        let date = Utc.timestamp(commit.time().seconds(), 0);

        Ok(GitMetadata {
            hash: commit.id().to_string(),
            date,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct SystemMetadata {
    system: String,
    release: String,
    version: String,
    architecture: String,
    processor: String,
    processor_base_frequency_hz: u16,
    processor_max_frequency_hz: u16,
    processor_features: String,
    processor_cores_logical: u64,
    processor_cores_physical: u64,
    memory_total_bytes: u64,
}

impl SystemMetadata {
    pub fn new() -> Result<Self, Error> {
        let host = futures::executor::block_on(heim::host::platform())
            .map_err(|_| failure::format_err!("Failed to retrieve host information"))?;

        let memory = futures::executor::block_on(heim::memory::memory())
            .map_err(|_| failure::format_err!("Failed to retrieve memory information"))?;
        let cpu_logical =
            futures::executor::block_on(heim::cpu::logical_count()).map_err(|_| {
                failure::format_err!("Failed to retrieve cpu logical count information")
            })?;
        let cpu_physical = futures::executor::block_on(heim::cpu::physical_count())
            .map_err(|_| failure::format_err!("Failed to retrieve cpu physical count information"))?
            .unwrap_or_default();

        let cpuid = raw_cpuid::CpuId::new();
        let cpu_info = cpuid.get_extended_function_info().unwrap();
        let cpu_freq = cpuid.get_processor_frequency_info().unwrap();

        Ok(SystemMetadata {
            system: host.system().into(),
            release: host.release().into(),
            version: host.version().into(),
            architecture: host.architecture().as_str().into(),
            processor: cpu_info.processor_brand_string().unwrap().into(),
            processor_base_frequency_hz: cpu_freq.processor_base_frequency(),
            processor_max_frequency_hz: cpu_freq.processor_max_frequency(),
            processor_features: format!("{:?}", cpuid.get_feature_info().unwrap()),
            processor_cores_logical: cpu_logical,
            processor_cores_physical: cpu_physical,
            memory_total_bytes: memory.total().get(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata() {
        let m = Metadata::wrap(()).unwrap();
        println!("{:#?}", m);

        assert!(m.system.memory_total_bytes > 0);
        assert!(m.system.processor_base_frequency_hz > 0);
        assert!(m.system.processor_max_frequency_hz > 0);
    }
}
