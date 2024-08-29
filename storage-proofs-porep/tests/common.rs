use std::fs::remove_file;
use std::io::Result;
use std::path::{Path, PathBuf};

use filecoin_hashers::Hasher;
use merkletree::store::StoreConfig;
use storage_proofs_core::{
    cache_key::CacheKey,
    data::Data,
    merkle::{get_base_tree_count, split_config, MerkleTreeTrait},
};
use storage_proofs_porep::stacked::{PersistentAux, PublicParams, StackedDrg, Tau, TemporaryAux};

// This method should ONLY be used in purposed test code.
#[allow(dead_code)]
pub fn remove_replica_and_tree_r<Tree: MerkleTreeTrait + 'static>(cache_path: &Path) -> Result<()> {
    let replica_path = cache_path.join("replica-path");
    let tree_r_last_config = StoreConfig {
        path: cache_path.to_path_buf(),
        id: CacheKey::CommRLastTree.to_string(),
        size: Some(0),
        rows_to_discard: 0,
    };
    let tree_count = get_base_tree_count::<Tree>();
    if tree_count > 1 {
        let configs =
            split_config(tree_r_last_config, tree_count).expect("Failed to split configs");
        for config in configs {
            let cur_path = StoreConfig::data_path(&config.path, &config.id);
            remove_file(cur_path).expect("Failed to remove TreeR");
        }
    }
    remove_file(replica_path)
}

#[allow(clippy::type_complexity)]
pub fn transform_and_replicate_layers<Tree: 'static + MerkleTreeTrait, G: 'static + Hasher>(
    pp: &PublicParams<Tree>,
    replica_id: &<Tree::Hasher as Hasher>::Domain,
    data: Data<'_>,
    cache_dir: PathBuf,
    replica_path: PathBuf,
) -> (
    Tau<<Tree::Hasher as Hasher>::Domain, <G as Hasher>::Domain>,
    (
        PersistentAux<<Tree::Hasher as Hasher>::Domain>,
        TemporaryAux<Tree, G>,
    ),
) {
    let (labels, _) = StackedDrg::<Tree, G>::replicate_phase1(pp, replica_id, &cache_dir)
        .expect("failed to generate labels");
    StackedDrg::replicate_phase2(pp, labels, data, None, cache_dir, replica_path)
        .expect("failed to transform")
}
