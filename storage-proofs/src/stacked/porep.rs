use crate::error::Result;
use crate::hasher::Hasher;
use crate::porep::PoRep;
use crate::stacked::{
    params::{PersistentAux, PublicParams, Tau, TemporaryAux, Tree},
    proof::{StackedDrg, WINDOW_SIZE_BYTES, WINDOW_SIZE_NODES},
};
use crate::util::NODE_SIZE;

use merkletree::store::StoreConfig;

impl<'a, 'c, H: 'static + Hasher, G: 'static + Hasher> PoRep<'a, H, G> for StackedDrg<'a, H, G> {
    type Tau = Tau<<H as Hasher>::Domain, <G as Hasher>::Domain>;
    type ProverAux = (PersistentAux<H::Domain>, TemporaryAux<H, G>);

    fn replicate(
        pp: &'a PublicParams<H>,
        replica_id: &H::Domain,
        data: &mut [u8],
        data_tree: Option<Tree<G>>,
        config: Option<StoreConfig>,
    ) -> Result<(Self::Tau, Self::ProverAux)> {
        let (tau, p_aux, t_aux) = Self::transform_and_replicate_layers(
            &pp.window_graph,
            &pp.wrapper_graph,
            &pp.layer_challenges,
            replica_id,
            data,
            data_tree,
            config,
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

        Self::extract_all_windows(
            &pp.window_graph,
            &pp.layer_challenges,
            replica_id,
            &mut data,
            config,
        )?;

        Ok(data)
    }

    fn extract(
        pp: &PublicParams<H>,
        replica_id: &<H as Hasher>::Domain,
        data: &[u8],
        node: usize,
        _config: Option<StoreConfig>,
    ) -> Result<Vec<u8>> {
        // grab the window for this node
        let window_start_index = node / WINDOW_SIZE_NODES;
        let window_start = window_start_index * WINDOW_SIZE_BYTES;
        let window_end = (window_start_index + 1) * WINDOW_SIZE_BYTES;
        let mut window = data[window_start..window_end].to_vec();

        Self::extract_single_window(
            &pp.window_graph,
            pp.layer_challenges.layers(),
            replica_id,
            &mut window,
            window_start_index,
        );

        let node_window_index = node % WINDOW_SIZE_NODES;
        let start = node_window_index * NODE_SIZE;
        let end = (node_window_index + 1) * NODE_SIZE;
        let node = window[start..end].to_vec();

        Ok(node)
    }
}
