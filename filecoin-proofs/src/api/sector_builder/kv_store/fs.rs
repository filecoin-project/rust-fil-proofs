use crate::api::sector_builder::kv_store::KeyValueStore;
use crate::error::Result;
use blake2::{Blake2b, Digest};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

const FATAL_NOCREATE: &str = "[KeyValueStore#put] could not create path";

// FileSystemKvs is a file system-backed key/value store, mostly lifted from
// sile/ekvsb
pub struct FileSystemKvs {
    root_dir: PathBuf,
}

impl FileSystemKvs {
    pub fn initialize<P: AsRef<Path>>(root_dir: P) -> Result<Self> {
        fs::create_dir_all(&root_dir)?;

        Ok(FileSystemKvs {
            root_dir: root_dir.as_ref().to_path_buf(),
        })
    }

    fn key_to_path(&self, key: &[u8]) -> PathBuf {
        let mut hasher = Blake2b::new();
        hasher.input(key);

        let result = hasher.result();
        let file = format!("{:.32x}", &result);

        self.root_dir.join(file)
    }
}

impl KeyValueStore for FileSystemKvs {
    fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let path = self.key_to_path(key);

        fs::create_dir_all(path.parent().expect(FATAL_NOCREATE))?;

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;

        file.write_all(value)?;

        Ok(())
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let path = self.key_to_path(key);

        match File::open(path) {
            Err(e) => {
                if e.kind() != ErrorKind::NotFound {
                    Err(e)?;
                }
                Ok(None)
            }
            Ok(mut file) => {
                let mut buf = Vec::new();
                file.read_to_end(&mut buf)?;
                Ok(Some(buf))
            }
        }
    }
}
