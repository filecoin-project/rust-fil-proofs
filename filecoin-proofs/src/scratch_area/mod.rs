use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use storage_proofs::sector::SectorId;

pub mod persisted;

trait IntoFile {
    fn into_file(self) -> File;
}

trait ScratchArea {
    type Item: IntoFile;

    fn new_item(&mut self) -> std::result::Result<Self::Item, failure::Error>;

    fn save_item(&mut self, k: Key, v: Self::Item) -> std::result::Result<(), failure::Error>;

    fn open_item(&mut self, k: Key) -> std::result::Result<Option<Self::Item>, failure::Error>;
}

#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub enum Key {
    CommRMerkleTree(bool),
    LayerMerkleTree(usize, bool),
}
