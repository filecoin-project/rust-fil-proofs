use std::path::PathBuf;

use merkletree::store::StoreConfig;
use storage_proofs_core::{
    error::Result,
    hasher::Hasher,
    merkle::{BinaryMerkleTree, MerkleTreeTrait},
    Data,
};

use super::{
    params::{PersistentAux, PublicParams, Tau, TemporaryAux},
    proof::StackedDrg,
};
use crate::PoRep;

impl<'a, 'c, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher> PoRep<'a, Tree::Hasher, G>
    for StackedDrg<'a, Tree, G>
{
    type Tau = Tau<<Tree::Hasher as Hasher>::Domain, <G as Hasher>::Domain>;
    type ProverAux = (
        PersistentAux<<Tree::Hasher as Hasher>::Domain>,
        TemporaryAux<Tree, G>,
    );

    fn replicate(
        pp: &'a PublicParams<Tree>,
        replica_id: &<Tree::Hasher as Hasher>::Domain,
        data: Data<'a>,
        data_tree: Option<BinaryMerkleTree<G>>,
        config: StoreConfig,
        replica_path: PathBuf,
    ) -> Result<(Self::Tau, Self::ProverAux)> {
        let (tau, p_aux, t_aux) = Self::transform_and_replicate_layers(
            &pp.graph,
            &pp.layer_challenges,
            replica_id,
            data,
            data_tree,
            config,
            replica_path,
        )?;

        Ok((tau, (p_aux, t_aux)))
    }

    fn extract_all<'b>(
        pp: &'b PublicParams<Tree>,
        replica_id: &'b <Tree::Hasher as Hasher>::Domain,
        data: &'b [u8],
        config: Option<StoreConfig>,
    ) -> Result<Vec<u8>> {
        let mut data = data.to_vec();

        Self::extract_and_invert_transform_layers(
            &pp.graph,
            &pp.layer_challenges,
            replica_id,
            &mut data,
            config.expect("Missing store config"),
        )?;

        Ok(data)
    }

    fn extract(
        _pp: &PublicParams<Tree>,
        _replica_id: &<Tree::Hasher as Hasher>::Domain,
        _data: &[u8],
        _node: usize,
        _config: Option<StoreConfig>,
    ) -> Result<Vec<u8>> {
        unimplemented!();
    }
}
