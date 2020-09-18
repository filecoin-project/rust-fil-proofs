use std::path::{Path, PathBuf};
use std::{env, thread};

use failure::format_err;
use rexpect::session::PtyReplSession;
use rexpect::spawn_bash;
use storage_proofs::parameter_cache::ParameterData;

use std::collections::btree_map::BTreeMap;
use std::fs::File;
use std::process::Command;
use std::time::Duration;

pub struct FakeIpfsBin {
    bin_path: PathBuf,
}

impl FakeIpfsBin {
    pub fn new() -> FakeIpfsBin {
        FakeIpfsBin {
            bin_path: cargo_bin("fakeipfsadd"),
        }
    }

    pub fn compute_checksum<P: AsRef<Path>>(&self, path: P) -> Result<String, failure::Error> {
        let output = Command::new(&self.bin_path)
            .arg("add")
            .arg("-Q")
            .arg(path.as_ref())
            .output()?;

        if !output.status.success() {
            Err(format_err!(
                "{:?} produced non-zero exit code",
                &self.bin_path
            ))
        } else {
            Ok(String::from_utf8(output.stdout)?.trim().to_string())
        }
    }

    pub fn bin_path(&self) -> &Path {
        &self.bin_path
    }
}

/// Get the path of the target directory.
pub fn target_dir() -> PathBuf {
    env::current_exe()
        .ok()
        .map(|mut path| {
            path.pop();
            if path.ends_with("deps") {
                path.pop();
            }
            path
        })
        .expect("failed to get current exe path")
}

/// Look up the path to a cargo-built binary within an integration test.
pub fn cargo_bin<S: AsRef<str>>(name: S) -> PathBuf {
    target_dir().join(format!("{}{}", name.as_ref(), env::consts::EXE_SUFFIX))
}

/// Spawn a pty and, if an error is produced, retry with linear backoff (to 5s).
pub fn spawn_bash_with_retries(
    retries: u8,
    timeout: Option<u64>,
) -> Result<PtyReplSession, rexpect::errors::Error> {
    let result = spawn_bash(timeout);
    if result.is_ok() || retries == 0 {
        result
    } else {
        let sleep_d = Duration::from_millis(5000 / u64::from(retries));
        eprintln!(
            "failed to spawn pty: {} retries remaining - sleeping {:?}",
            retries, sleep_d
        );
        thread::sleep(sleep_d);
        spawn_bash_with_retries(retries - 1, timeout)
    }
}

/// Create a parameters.json manifest file in a temp directory and return its
/// path.
pub fn tmp_manifest(
    opt_manifest: Option<BTreeMap<String, ParameterData>>,
) -> Result<PathBuf, failure::Error> {
    let manifest_dir = tempfile::tempdir()?;
    let mut pbuf = manifest_dir.into_path();
    pbuf.push("parameters.json");

    let mut file = File::create(&pbuf)?;
    if let Some(map) = opt_manifest {
        // JSON encode the manifest and write bytes to temp file
        serde_json::to_writer(&mut file, &map)?;
    }

    Ok(pbuf)
}
