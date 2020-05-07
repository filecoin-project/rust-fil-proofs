use std::path::PathBuf;

use anyhow::Context;
use generic_array::typenum::{Unsigned, U2};
use merkletree::{merkle::get_merkle_tree_len, store::StoreConfig};
use rayon::prelude::*;
use storage_proofs_core::{
    cache_key::CacheKey,
    error::Result,
    hasher::{Domain, Hasher},
    merkle::{BinaryMerkleTree, DiskStore, MerkleTreeTrait, MerkleTreeWrapper},
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
        replica_path: PathBuf,
    ) -> Result<(Self::Tau, Self::ProverAux)> {
        let config = &pp.config;
        let num_nodes_sector = config.num_nodes_sector();

        assert_eq!(num_nodes_sector % config.num_nodes_window, 0);
        assert_eq!(data.len(), config.sector_size);
        assert_eq!(config.sector_size % config.window_size(), 0);

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

        let trees = data
            .as_mut()
            .par_chunks_mut(config.window_size())
            .enumerate()
            .map(|(window_index, window_data)| {
                let tree = labels::encode_with_trees::<Tree>(
                    config,
                    store_config.clone(),
                    window_index as u32,
                    replica_id,
                    window_data,
                )?;

                // write replica
                std::fs::write(
                    replica_path.with_extension(format!("w{}", window_index)),
                    window_data.as_ref(),
                )
                .context("failed to write replica data")?;
                Ok(tree)
            })
            .collect::<Result<Vec<Vec<(_, _)>>>>()?;

        data.drop_data();

        let mut layered_trees: Vec<Vec<(_, _)>> = (0..config.num_layers())
            .map(|_| Vec::with_capacity(config.num_windows()))
            .collect();

        for window_trees in trees.into_iter() {
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

            trees_layers.push(MerkleTreeWrapper::<
                Tree::Hasher,
                _,
                Tree::Arity,
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

#[cfg(test)]
mod tests {
    use super::*;

    use generic_array::typenum::{U0, U8};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::{
        hasher::{PoseidonHasher, Sha256Hasher},
        merkle::LCTree,
        proof::ProofScheme,
    };

    use super::super::{Config, SetupParams};

    #[test]
    fn test_extract_all() {
        type Tree = LCTree<PoseidonHasher, U8, U8, U0>;
        // femme::pretty::Logger::new()
        //     .start(log::LevelFilter::Trace)
        //     .ok();

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);
        let replica_id = <PoseidonHasher as Hasher>::Domain::random(rng);
        let config = Config {
            k: 8,
            num_nodes_window: 64,
            degree_expander: 12,
            degree_butterfly: 8,
            num_expander_layers: 3,
            num_butterfly_layers: 3,
            sector_size: 64 * 32 * 8,
        };

        let data: Vec<u8> = (0..config.num_nodes_sector())
            .flat_map(|_| {
                let v = <PoseidonHasher as Hasher>::Domain::random(rng);
                v.into_bytes()
            })
            .collect();

        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();

        let sp = SetupParams {
            config: config.clone(),
            num_challenges_window: 2,
        };

        let pp = NarrowStackedExpander::<Tree, Sha256Hasher>::setup(&sp).expect("setup failed");

        // MT for original data is always named tree-d, and it will be
        // referenced later in the process as such.
        let cache_dir = tempfile::tempdir().unwrap();
        let config = StoreConfig::new(
            cache_dir.path(),
            CacheKey::CommDTree.to_string(),
            StoreConfig::default_cached_above_base_layer(config.num_nodes_sector(), U2::to_usize()),
        );

        // Generate a replica path.
        let temp_dir = tempdir::TempDir::new("test-extract-all").unwrap();
        let temp_path = temp_dir.path();
        let replica_path = temp_path.join("replica-path");

        NarrowStackedExpander::<Tree, Sha256Hasher>::replicate(
            &pp,
            &replica_id,
            (&mut data_copy[..]).into(),
            None,
            config.clone(),
            replica_path.clone(),
        )
        .expect("replication failed");

        assert_ne!(data, data_copy);

        let decoded_data = NarrowStackedExpander::<Tree, Sha256Hasher>::extract_all(
            &pp,
            &replica_id,
            data_copy.as_mut_slice(),
            Some(config.clone()),
        )
        .expect("failed to extract data");

        assert_eq!(data, decoded_data);
    }
}
