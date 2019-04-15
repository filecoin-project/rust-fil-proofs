use std::path::Path;

use crate::error::Result;

pub mod fs;
pub mod rocks;

pub use self::fs::FileSystemKvs;
pub use self::rocks::RocksKvs;

pub trait KeyValueStore: Sized + std::fmt::Debug {
    fn initialize<P: AsRef<Path>>(root_dir: P) -> Result<Self>;
    fn put(&self, key: &[u8], value: &[u8]) -> Result<()>;
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;
}

#[cfg(test)]
mod tests {
    use crate::api::sector_builder::kv_store::fs::FileSystemKvs;
    use crate::api::sector_builder::kv_store::KeyValueStore;

    #[test]
    fn test_alpha() {
        let metadata_dir = tempfile::tempdir().unwrap();
        println!("dir: {:?}", metadata_dir);
        let db = FileSystemKvs::initialize(metadata_dir).unwrap();

        let k_a = b"key-xx";
        let k_b = b"key-yy";
        let v_a = b"value-aa";
        let v_b = b"value-bb";

        db.put(k_a, v_a).unwrap();
        db.put(k_b, v_b).unwrap();

        let opt = db.get(k_a).unwrap();
        assert_eq!(format!("{:x?}", opt.unwrap()), format!("{:x?}", v_a));
    }
}
