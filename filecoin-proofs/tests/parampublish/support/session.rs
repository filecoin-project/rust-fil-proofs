use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use failure::SyncFailure;
use rand::Rng;
use rexpect::session::PtyReplSession;
use tempfile;
use tempfile::TempDir;

use storage_proofs::parameter_cache::CacheEntryMetadata;

use crate::support::{cargo_bin, spawn_bash_with_retries, FakeIpfsBin};

pub struct ParamPublishSessionBuilder {
    cache_dir: TempDir,
    cached_file_pbufs: Vec<PathBuf>,
    session_timeout_ms: u64,
    manifest: PathBuf,
    ipfs_bin_path: PathBuf,
    prompt_enabled: bool,
}

impl ParamPublishSessionBuilder {
    pub fn new() -> ParamPublishSessionBuilder {
        let temp_dir = tempfile::tempdir().expect("could not create temp dir");

        let mut pbuf = temp_dir.path().to_path_buf();
        pbuf.push("parameters.json");

        File::create(&pbuf).expect("failed to create file in temp dir");

        ParamPublishSessionBuilder {
            cache_dir: temp_dir,
            cached_file_pbufs: vec![],
            session_timeout_ms: 1000,
            manifest: pbuf,
            ipfs_bin_path: cargo_bin("fakeipfsadd"),
            prompt_enabled: true,
        }
    }

    /// Configure the path used by `parampublish` to add files to IPFS daemon.
    pub fn with_ipfs_bin(mut self, ipfs_bin: &FakeIpfsBin) -> ParamPublishSessionBuilder {
        let pbuf: PathBuf = PathBuf::from(&ipfs_bin.bin_path());
        self.ipfs_bin_path = pbuf;
        self
    }

    /// Create empty files with the given names in the cache directory.
    pub fn with_files<P: AsRef<Path>>(self, filenames: &[P]) -> ParamPublishSessionBuilder {
        filenames.iter().fold(self, |acc, item| acc.with_file(item))
    }

    /// Create a file containing 32 random bytes with the given name in the
    /// cache directory.
    pub fn with_file<P: AsRef<Path>>(mut self, filename: P) -> ParamPublishSessionBuilder {
        let mut pbuf = self.cache_dir.path().to_path_buf();
        pbuf.push(filename.as_ref());

        let mut file = File::create(&pbuf).expect("failed to create file in temp dir");

        let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
        file.write_all(&random_bytes)
            .expect("failed to write bytes");

        self.cached_file_pbufs.push(pbuf);
        self
    }

    /// Create a file with the provided bytes in the cache directory.
    pub fn with_file_and_bytes<P: AsRef<Path>, R: Read>(
        mut self,
        filename: P,
        r: &mut R,
    ) -> ParamPublishSessionBuilder {
        let mut pbuf = self.cache_dir.path().to_path_buf();
        pbuf.push(filename.as_ref());

        let mut file = File::create(&pbuf).expect("failed to create file in temp dir");

        std::io::copy(r, &mut file).expect("failed to copy bytes to file");

        self.cached_file_pbufs.push(pbuf);
        self
    }

    /// Create a metadata file with the provided name in the cache directory.
    pub fn with_metadata<P: AsRef<Path>>(
        self,
        filename: P,
        meta: &CacheEntryMetadata,
    ) -> ParamPublishSessionBuilder {
        let mut meta_bytes: &[u8] = &serde_json::to_vec(meta)
            .expect("failed to serialize CacheEntryMetadata to JSON byte array");

        self.with_file_and_bytes(filename, &mut meta_bytes)
    }

    /// Configure the pty timeout (see documentation for `rexpect::spawn_bash`).
    pub fn with_session_timeout_ms(mut self, timeout_ms: u64) -> ParamPublishSessionBuilder {
        self.session_timeout_ms = timeout_ms;
        self
    }

    /// If prompt is disabled, `--all` flag will be passed to parampublish.
    pub fn with_prompt_disabled(mut self) -> ParamPublishSessionBuilder {
        self.prompt_enabled = false;
        self
    }

    /// When publishing, write JSON manifest to provided path.
    pub fn write_manifest_to(mut self, manifest_dest: PathBuf) -> ParamPublishSessionBuilder {
        self.manifest = manifest_dest;
        self
    }

    /// Launch parampublish in an environment configured by the builder.
    pub fn build(self) -> (ParamPublishSession, Vec<PathBuf>) {
        let mut p = spawn_bash_with_retries(10, Some(self.session_timeout_ms))
            .unwrap_or_else(|err| panic!(err));

        let cache_dir_path = format!("{:?}", self.cache_dir.path());

        let cache_contents: Vec<PathBuf> = std::fs::read_dir(&self.cache_dir)
            .unwrap_or_else(|_| panic!("failed to read cache dir {:?}", self.cache_dir))
            .map(|x| x.expect("failed to get dir entry"))
            .map(|x| x.path())
            .collect();

        let parampublish_path = cargo_bin("parampublish");

        let cmd = format!(
            "{}={} {:?} {} --ipfs-bin={:?} --json={:?}",
            "FIL_PROOFS_PARAMETER_CACHE", // related to var name in core/src/settings.rs
            cache_dir_path,
            parampublish_path,
            if self.prompt_enabled { "" } else { "--all" },
            self.ipfs_bin_path,
            self.manifest
        );

        p.execute(&cmd, ".*")
            .expect("could not execute parampublish");

        (
            ParamPublishSession {
                pty_session: p,
                _cache_dir: self.cache_dir,
            },
            cache_contents,
        )
    }
}

/// An active pseudoterminal (pty) used to interact with parampublish.
pub struct ParamPublishSession {
    pty_session: PtyReplSession,
    _cache_dir: TempDir,
}

impl ParamPublishSession {
    /// Send provided string and trailing newline to parampublish.
    pub fn send_line(&mut self, line: &str) -> Result<usize, SyncFailure<rexpect::errors::Error>> {
        self.pty_session.send_line(line).map_err(SyncFailure::new)
    }

    /// Block until provided string is seen on stdout from parampublish and
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
