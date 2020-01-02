use crate::error::Result;
use crate::hasher::Hasher;
use crate::measurements::measure_op;
use crate::measurements::Operation::PorepCommitTime;
use crate::porep::{Data, PoRep};
use crate::stacked::{
    params::{PersistentAux, PublicParams, Tau, TemporaryAux, Tree},
    proof::StackedDrg,
};
use crate::util::NODE_SIZE;

use merkletree::store::StoreConfig;

impl<'a, 'c, H: 'static + Hasher, G: 'static + Hasher> PoRep<'a, H, G> for StackedDrg<'a, H, G> {
    type Tau = Tau<<H as Hasher>::Domain, <G as Hasher>::Domain>;
    type ProverAux = (PersistentAux<H::Domain>, TemporaryAux<H, G>);

    fn replicate(
        pp: &'a PublicParams<H>,
        replica_id: &H::Domain,
        data: Data<'a>,
        data_tree: Option<Tree<G>>,
        config: Option<StoreConfig>,
    ) -> Result<(Self::Tau, Self::ProverAux)> {
        let (tau, p_aux, t_aux) = measure_op(PorepCommitTime, || {
            Self::transform_and_replicate_layers(pp, replica_id, data, data_tree, config)
        })?;

        Ok((tau, (p_aux, t_aux)))
    }

    fn extract_all<'b>(
        pp: &'b PublicParams<H>,
        replica_id: &'b <H as Hasher>::Domain,
        data: &'b [u8],
        config: Option<StoreConfig>,
    ) -> Result<Vec<u8>> {
        let mut data = data.to_vec();

        Self::extract_all_windows(pp, replica_id, &mut data, config)?;

        Ok(data)
    }

    fn extract(
        pp: &PublicParams<H>,
        replica_id: &<H as Hasher>::Domain,
        data: &[u8],
        node: usize,
        config: Option<StoreConfig>,
    ) -> Result<Vec<u8>> {
        let start = node * NODE_SIZE;
        let num_bytes = NODE_SIZE;
        let node = Self::extract_range(pp, replica_id, &data, config, start, num_bytes)?;

        Ok(node)
    }
}
