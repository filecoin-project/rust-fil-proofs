use std::path::PathBuf;

use super::{
    params::{BinaryTree, PersistentAux, PublicParams, Tau, TemporaryAux},
    proof::StackedDrg,
};

use crate::error::Result;
use crate::hasher::Hasher;
use crate::porep::PoRep;
use crate::Data;

use merkletree::store::StoreConfig;

impl<'a, 'c, H: 'static + Hasher, G: 'static + Hasher> PoRep<'a, H, G> for StackedDrg<'a, H, G> {
    type Tau = Tau<<H as Hasher>::Domain, <G as Hasher>::Domain>;
    type ProverAux = (PersistentAux<H::Domain>, TemporaryAux<H, G>);

    fn replicate(
        pp: &'a PublicParams<H>,
        replica_id: &H::Domain,
        data: Data<'a>,
        data_tree: Option<BinaryTree<G>>,
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
        pp: &'b PublicParams<H>,
        replica_id: &'b <H as Hasher>::Domain,
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
        _pp: &PublicParams<H>,
        _replica_id: &<H as Hasher>::Domain,
        _data: &[u8],
        _node: usize,
        _config: Option<StoreConfig>,
    ) -> Result<Vec<u8>> {
        unimplemented!();
    }
}
