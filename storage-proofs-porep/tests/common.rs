use std::path::PathBuf;

use filecoin_hashers::Hasher;
use merkletree::store::StoreConfig;
use storage_proofs_core::{data::Data, merkle::MerkleTreeTrait};
use storage_proofs_porep::stacked::{PersistentAux, PublicParams, StackedDrg, Tau, TemporaryAux};

#[allow(clippy::type_complexity)]
pub fn transform_and_replicate_layers<Tree: 'static + MerkleTreeTrait, G: 'static + Hasher>(
    pp: &PublicParams<Tree>,
    replica_id: &<Tree::Hasher as Hasher>::Domain,
    data: Data<'_>,
    config: StoreConfig,
    replica_path: PathBuf,
) -> (
    Tau<<Tree::Hasher as Hasher>::Domain, <G as Hasher>::Domain>,
    (
        PersistentAux<<Tree::Hasher as Hasher>::Domain>,
        TemporaryAux<Tree, G>,
    ),
) {
    let (labels, _) = StackedDrg::<Tree, G>::replicate_phase1(pp, replica_id, config.clone())
        .expect("failed to generate labels");
    StackedDrg::replicate_phase2(pp, labels, data, None, config, replica_path)
        .expect("failed to transform")
}
