use std::path::PathBuf;

use anyhow::Result;
use merkletree::store::StoreConfig;
use storage_proofs_core::{
    data::Data,
    hasher::Hasher,
    merkle::{BinaryMerkleTree, MerkleTreeTrait},
};

use super::{NarrowStackedExpander, PublicParams};
use crate::PoRep;

impl<'a, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher> NarrowStackedExpander<'a, Tree, G> {
    /// Replication Phase 1.
    ///
    /// This phase construct the individual layers and encodes the data.
    /// It also constructs the merkle trees over the individual windows.
    pub fn replicate_phase1(
        pp: &PublicParams<Tree>,
        replica_id: &<Tree::Hasher as Hasher>::Domain,
        config: StoreConfig,
    ) {
        todo!()
    }

    /// Replication Phase 2.
    ///
    /// This phase constructs the top level merkle trees.
    pub fn replicate_phase2(
        pp: &PublicParams<Tree>,
        layers: Vec<StoreConfig>,
        data: Data<'_>,
        data_tree: BinaryMerkleTree<G>,
        config: StoreConfig,
        replica_path: PathBuf,
    ) -> Result<(
        <Self as PoRep<'a, Tree::Hasher, G>>::Tau,
        <Self as PoRep<'a, Tree::Hasher, G>>::ProverAux,
    )> {
        todo!()
    }
}
