use std::fs::File;

pub mod persisted;

pub trait IntoFile {
    fn into_file(self) -> File;
}

pub trait ScratchArea {
    type Item: IntoFile;

    fn new_item(&mut self) -> std::result::Result<Self::Item, failure::Error>;

    fn save_item(&mut self, k: Key, v: Self::Item) -> std::result::Result<(), failure::Error>;

    fn open_item(&mut self, k: Key) -> std::result::Result<Option<Self::Item>, failure::Error>;
}

#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub enum Key {
    CommRMerkleTree {
        is_top_half_tree: bool,
    },
    LayerMerkleTree {
        layer_number: usize,
        is_top_half_tree: bool,
    },
}
