use std::path::Path;

use crate::error::Result;

pub mod fs;
pub mod sled;

pub use self::fs::FileSystemKvs;
pub use self::sled::SledKvs;

pub trait KeyValueStore: Sized {
    fn initialize<P: AsRef<Path>>(root_dir: P) -> Result<Self>;
    fn put(&self, key: &[u8], value: &[u8]) -> Result<()>;
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;
}
