use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use failure::SyncFailure;
use rexpect::session::PtyReplSession;
use tempfile;
use tempfile::TempDir;

use crate::support::{cargo_bin, spawn_bash_with_retries};

pub struct ParamFetchSessionBuilder {
    cache_dir: TempDir,
    session_timeout_ms: u64,
    whitelisted_sector_sizes: Option<Vec<String>>,
    manifest: Option<PathBuf>,
    prompt_enabled: bool,
}

impl ParamFetchSessionBuilder {
    pub fn new(manifest: Option<PathBuf>) -> ParamFetchSessionBuilder {
        let temp_dir = tempfile::tempdir().expect("could not create temp dir");

        ParamFetchSessionBuilder {
            cache_dir: temp_dir,
            session_timeout_ms: 1000,
            manifest,
            prompt_enabled: true,
            whitelisted_sector_sizes: None,
        }
    }

    /// Configure the pty timeout (see documentation for `rexpect::spawn_bash`).
    pub fn with_session_timeout_ms(mut self, timeout_ms: u64) -> ParamFetchSessionBuilder {
        self.session_timeout_ms = timeout_ms;
        self
    }

    /// Configure the pty timeout (see documentation for `rexpect::spawn_bash`).
    pub fn whitelisted_sector_sizes(
        mut self,
        sector_sizes: Vec<String>,
    ) -> ParamFetchSessionBuilder {
        self.whitelisted_sector_sizes = Some(sector_sizes);
        self
    }

    /// Create a file with the provided bytes in the cache directory.
    pub fn with_file_and_bytes<P: AsRef<Path>, R: Read>(
        self,
        filename: P,
        r: &mut R,
    ) -> ParamFetchSessionBuilder {
        let mut pbuf = self.cache_dir.path().to_path_buf();
        pbuf.push(filename.as_ref());

        let mut file = File::create(&pbuf).expect("failed to create file in temp dir");

        std::io::copy(r, &mut file).expect("failed to copy bytes to file");

        self
    }

    /// Launch paramfetch in an environment configured by the builder.
    pub fn build(self) -> ParamFetchSession {
        let mut p = spawn_bash_with_retries(10, Some(self.session_timeout_ms))
            .unwrap_or_else(|err| panic!(err));

        let cache_dir_path = format!("{:?}", self.cache_dir.path());

        let paramfetch_path = cargo_bin("paramfetch");

        let whitelist: String = self
            .whitelisted_sector_sizes
            .map(|wl| {
                let mut s = "--params-for-sector-sizes=".to_string();
                s.push_str(&wl.join(","));
                s
            })
            .unwrap_or_else(|| "".to_string());

        let json_argument = if self.manifest.is_some() {
            format!("--json={:?}", self.manifest.expect("missing manifest"))
        } else {
            "".to_string()
        };

        let cmd = format!(
            "{}={} {:?} {} {} {} --ipget-bin={:?}",
            "FIL_PROOFS_PARAMETER_CACHE", // related to var name in core/src/settings.rs
            cache_dir_path,
            paramfetch_path,
            if self.prompt_enabled { "" } else { "--all" },
            json_argument,
            whitelist,
            "true"
        );

        p.execute(&cmd, ".*").expect("could not execute paramfetch");

        ParamFetchSession {
            pty_session: p,
            _cache_dir: self.cache_dir,
        }
    }
}

/// An active pseudoterminal (pty) used to interact with paramfetch.
pub struct ParamFetchSession {
    pty_session: PtyReplSession,
    _cache_dir: TempDir,
}

impl ParamFetchSession {
    /// Block until provided string is seen on stdout from paramfetch and
    /// return remaining output.
    pub fn exp_string(
        &mut self,
        needle: &str,
    ) -> Result<String, SyncFailure<rexpect::errors::Error>> {
        self.pty_session
            .exp_string(needle)
            .map_err(SyncFailure::new)
    }
}
