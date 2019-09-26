use crate::scratch_area::{IntoFile, Key, ScratchArea};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use storage_proofs::sector::SectorId;

/// ScratchDirectory provides threadsafe write and read access to a directory.
pub struct ScratchDirectory {
    version: usize,
    root: PathBuf,
    sector_id: SectorId,
}

/// NamedFile is a file descriptor and absolute path to the opened file.
pub struct NamedFile {
    file: File,
    abs_path: PathBuf,
}

impl NamedFile {
    pub fn new(file: File, abs_path: PathBuf) -> NamedFile {
        NamedFile { file, abs_path }
    }
}

impl IntoFile for NamedFile {
    fn into_file(self) -> File {
        self.file
    }
}

impl ScratchArea for ScratchDirectory {
    type Item = NamedFile;

    fn new_item(&mut self) -> std::result::Result<Self::Item, failure::Error> {
        tempfile::NamedTempFile::new_in(&self.root)
            .map_err(Into::into)
            .and_then(|f| f.keep().map_err(Into::into))
            .map(|(f, p)| NamedFile::new(f, p))
    }

    fn save_item(&mut self, k: Key, v: Self::Item) -> std::result::Result<(), failure::Error> {
        std::fs::rename(v.abs_path, self.abs_path(k)).map_err(|err| err.into())
    }

    fn open_item(&mut self, k: Key) -> std::result::Result<Option<Self::Item>, failure::Error> {
        if !self.abs_path(k).exists() {
            return Ok(None);
        }

        OpenOptions::new()
            .create(false)
            .write(true)
            .read(true)
            .open(self.abs_path(k))
            .map(|file| {
                Some(NamedFile {
                    file,
                    abs_path: self.abs_path(k),
                })
            })
            .map_err(|err| err.into())
    }
}

impl ScratchDirectory {
    pub fn new<T: AsRef<Path>>(sector_id: SectorId, root: T) -> ScratchDirectory {
        ScratchDirectory {
            version: 0,
            root: root.as_ref().to_path_buf(),
            sector_id,
        }
    }

    fn abs_path(&self, k: Key) -> PathBuf {
        let file_name = match k {
            Key::CommRMerkleTree(b) => {
                (format!(
                    "v{}-commr-{}",
                    self.version,
                    if b { "top" } else { "leaves" }
                ))
            }
            Key::LayerMerkleTree(n, b) => {
                (format!(
                    "v{}-layer{}-{}",
                    self.version,
                    n,
                    if b { "top" } else { "leaves" }
                ))
            }
        };

        self.root.join(file_name)
    }
}
