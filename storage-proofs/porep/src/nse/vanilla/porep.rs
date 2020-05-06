use std::path::PathBuf;

use generic_array::typenum::{Unsigned, U2, U8};
use merkletree::{merkle::get_merkle_tree_len, store::StoreConfig};
use rayon::prelude::*;
use storage_proofs_core::{
    cache_key::CacheKey,
    error::Result,
    hasher::{Domain, Hasher},
    merkle::{BinaryMerkleTree, LCTree, MerkleTreeTrait},
    util::NODE_SIZE,
    Data,
};

use super::{labels, NarrowStackedExpander, PersistentAux, PublicParams, Tau, TemporaryAux};
use crate::PoRep;

impl<'a, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher> PoRep<'a, Tree::Hasher, G>
    for NarrowStackedExpander<'a, Tree, G>
{
    type Tau = Tau<<Tree::Hasher as Hasher>::Domain, <G as Hasher>::Domain>;
    type ProverAux = (
        PersistentAux<<Tree::Hasher as Hasher>::Domain>,
        TemporaryAux<Tree, G>,
    );

    fn replicate(
        pp: &'a PublicParams<Tree>,
        replica_id: &<Tree::Hasher as Hasher>::Domain,
        mut data: Data<'a>,
        data_tree: Option<BinaryMerkleTree<G>>,
        store_config: StoreConfig,
        _replica_path: PathBuf,
    ) -> Result<(Self::Tau, Self::ProverAux)> {
        let config = &pp.config;

        let num_nodes_sector = config.sector_size / NODE_SIZE;

        // ensure there is a data tree
        let mut data_tree_config = StoreConfig::from_config(
            &store_config,
            CacheKey::CommDTree.to_string(),
            Some(get_merkle_tree_len(num_nodes_sector, U2::to_usize())?),
        );
        data_tree_config.levels =
            StoreConfig::default_cached_above_base_layer(num_nodes_sector, U2::to_usize());
        data.ensure_data()?;

        let data_tree = match data_tree {
            Some(tree) => tree,
            None => BinaryMerkleTree::from_par_iter_with_config(
                data.as_ref()
                    .par_chunks(NODE_SIZE)
                    .map(|chunk| G::Domain::try_from_bytes(chunk).expect("invalid data")),
                data_tree_config.clone(),
            )?,
        };

        // phase 1
        // replicate each window and build its tree

        let mut layered_trees: Vec<Vec<_>> =
            (0..config.num_windows()).map(|_| Vec::new()).collect();

        for (window_index, window_data) in
            data.as_mut().chunks_mut(config.window_size()).enumerate()
        {
            let window_trees = labels::encode_with_trees::<Tree::Hasher>(
                config,
                store_config.clone(),
                window_index as u32,
                replica_id,
                window_data,
            )?;

            for (layer, el) in window_trees.into_iter().enumerate() {
                layered_trees[layer].push(el);
            }
        }

        // phase 2

        // build main trees for each layer
        let mut trees_layers = Vec::new();
        let mut layer_configs = Vec::new();
        for trees_configs in layered_trees.into_iter() {
            let (trees, configs): (Vec<_>, Vec<_>) = trees_configs.into_iter().unzip();
            trees_layers.push(LCTree::<
                Tree::Hasher,
                U8,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >::from_trees(trees)?);
            layer_configs.push(configs);
        }

        let p_aux = PersistentAux {
            comm_layers: trees_layers.iter().map(|tree| tree.root()).collect(),
        };

        let tau = Tau::<<Tree::Hasher as Hasher>::Domain, G::Domain> {
            comm_d: data_tree.root(),
            comm_r: *p_aux.comm_replica(),
        };

        let t_aux = TemporaryAux::new(layer_configs, data_tree_config);

        Ok((tau, (p_aux, t_aux)))
    }

    fn extract_all<'b>(
        pp: &'b PublicParams<Tree>,
        replica_id: &'b <Tree::Hasher as Hasher>::Domain,
        data: &'b [u8],
        _config: Option<StoreConfig>,
    ) -> Result<Vec<u8>> {
        let config = &pp.config;
        let mut result = data.to_vec();

        result
            .par_chunks_mut(config.window_size())
            .enumerate()
            .try_for_each(|(window_index, window_data)| {
                labels::decode::<Tree::Hasher>(config, window_index as u32, replica_id, window_data)
            })?;

        Ok(result)
    }

    fn extract(
        _pp: &PublicParams<Tree>,
        _replica_id: &<Tree::Hasher as Hasher>::Domain,
        _data: &[u8],
        _node: usize,
        _config: Option<StoreConfig>,
    ) -> Result<Vec<u8>> {
        todo!()
    }
}
