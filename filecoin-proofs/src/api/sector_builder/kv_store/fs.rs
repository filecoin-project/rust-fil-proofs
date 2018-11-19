use api::sector_builder::kv_store::KeyValueStore;
use error::Result;
use percent_encoding::{percent_encode, DEFAULT_ENCODE_SET};
use std::collections::hash_map::DefaultHasher;
use std::fs::{self, File, OpenOptions};
use std::hash::Hasher;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

// a file system-backed key/value store, mostly lifted from sile/ekvsb

#[derive(Debug)]
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
        let name = percent_encode(key, DEFAULT_ENCODE_SET).to_string();

        let mut hasher = DefaultHasher::new();
        hasher.write(name.as_bytes());

        let file = format!("{:04x}/{}", hasher.finish() as u16, name);

        self.root_dir.join(file)
    }
}

impl KeyValueStore for FileSystemKvs {
    fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let path = self.key_to_path(key);

        fs::create_dir_all(path.parent().unwrap())?;

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
