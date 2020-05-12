use std::path::PathBuf;

use anyhow::Context;
use generic_array::typenum::{Unsigned, U2};
use merkletree::{merkle::get_merkle_tree_len, store::StoreConfig};
use rayon::prelude::*;
use storage_proofs_core::{
    cache_key::CacheKey,
    error::Result,
    hasher::{Domain, Hasher},
    merkle::{
        split_config, split_config_and_replica, BinaryMerkleTree, MerkleTreeTrait,
        MerkleTreeWrapper,
    },
    util::NODE_SIZE,
    Data,
};

use super::{
    hash_comm_r, labels, NarrowStackedExpander, PersistentAux, PublicParams, Tau, TemporaryAux,
};
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

        let mut layer_store_config = StoreConfig::from_config(
            &store_config,
            CacheKey::LabelLayer.to_string(),
            Some(get_merkle_tree_len(
                config.num_nodes_window as usize,
                Tree::Arity::to_usize(),
            )?),
        );
        // Ensure the right levels are set for the config.
        layer_store_config.levels = StoreConfig::default_cached_above_base_layer(
            config.num_nodes_window,
            Tree::Arity::to_usize(),
        );

        let layered_store_configs = split_config(layer_store_config.clone(), config.num_layers())?;

        let mut windowed_store_configs =
            vec![Vec::with_capacity(config.num_layers()); config.num_windows()];

        let mut windowed_replica_paths = None;

        for (layer_index, store_config) in layered_store_configs.into_iter().enumerate() {
            if layer_index < config.num_layers() - 1 {
                let configs = split_config(store_config, config.num_windows())?;
                for (window_index, store_config) in configs.into_iter().enumerate() {
                    windowed_store_configs[window_index].push(store_config);
                }
            } else {
                // create replica paths for the last one
                let (configs, paths) = split_config_and_replica(
                    store_config,
                    replica_path.clone(),
                    config.num_windows(),
                )?;
                windowed_replica_paths = Some(paths);
                for (window_index, store_config) in configs.into_iter().enumerate() {
                    windowed_store_configs[window_index].push(store_config);
                }
            }
        }

        let trees = data
            .as_mut()
            .par_chunks_mut(config.window_size())
            .enumerate()
            .zip(windowed_store_configs.into_par_iter())
            .zip(windowed_replica_paths.unwrap().into_par_iter())
            .map(
                |(((window_index, window_data), store_configs), replica_path)| {
                    let (trees, replica_tree) = labels::encode_with_trees::<Tree>(
                        config,
                        store_configs,
                        window_index as u32,
                        replica_id,
                        window_data,
                    )?;

                    // write replica
                    std::fs::write(replica_path, window_data.as_ref())
                        .context("failed to write replica data")?;
                    Ok((trees, replica_tree))
                },
            )
            .collect::<Result<Vec<(Vec<_>, _)>>>()?;

        debug_assert_eq!(trees.len(), config.num_windows());
        data.drop_data();

        let mut layered_trees: Vec<Vec<_>> = (0..config.num_layers() - 1)
            .map(|_| Vec::with_capacity(config.num_windows()))
            .collect();
        let mut replica_trees = Vec::with_capacity(config.num_windows());

        for (window_trees, replica_tree) in trees.into_iter() {
            debug_assert_eq!(window_trees.len(), config.num_layers() - 1);
            for (layer_index, trees) in window_trees.into_iter().enumerate() {
                layered_trees[layer_index].push(trees);
            }
            replica_trees.push(replica_tree);
        }

        // phase 2

        // build main trees for each layer
        let mut trees_layers = Vec::new();
        for trees in layered_trees.into_iter() {
            debug_assert_eq!(trees.len(), config.num_windows());
            trees_layers.push(MerkleTreeWrapper::<
                Tree::Hasher,
                _,
                Tree::Arity,
                Tree::SubTreeArity,
                Tree::TopTreeArity,
            >::from_trees(trees)?);
        }

        let replica_tree = MerkleTreeWrapper::<
            Tree::Hasher,
            _,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >::from_trees(replica_trees)?;

        let p_aux = PersistentAux {
            comm_layers: trees_layers.iter().map(|tree| tree.root()).collect(),
            comm_replica: replica_tree.root(),
        };

        let comm_r = hash_comm_r(&p_aux.comm_layers, p_aux.comm_replica);
        let tau = Tau::<<Tree::Hasher as Hasher>::Domain, G::Domain> {
            comm_d: data_tree.root(),
            comm_r: comm_r.into(),
        };

        let t_aux = TemporaryAux::new(layer_store_config, data_tree_config);

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
        util::NODE_SIZE,
    };

    use super::super::{Config, SetupParams};

    #[test]
    fn test_bench_encode() {
        type Tree = LCTree<PoseidonHasher, U8, U8, U0>;
        // femme::pretty::Logger::new()
        //     .start(log::LevelFilter::Trace)
        //     .ok();

        let sector_size = 1024 * 1024 * 512; //1024 * 1; // 1GiB
        let num_windows = 1;

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);
        let replica_id = <PoseidonHasher as Hasher>::Domain::random(rng);
        let config = Config {
            k: 8,
            num_nodes_window: (sector_size / num_windows) / NODE_SIZE,
            degree_expander: 384,
            degree_butterfly: 16,
            num_expander_layers: 8,
            num_butterfly_layers: 7,
            sector_size,
        };
        assert_eq!(config.num_windows(), num_windows);

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

        println!("replication start");
        let now = std::time::Instant::now();
        NarrowStackedExpander::<Tree, Sha256Hasher>::replicate(
            &pp,
            &replica_id,
            (&mut data_copy[..]).into(),
            None,
            config.clone(),
            replica_path.clone(),
        )
        .expect("replication failed");

        println!(
            "replicated {:02}GiB in {:04}s",
            sector_size as f64 / 1024. / 1024. / 1024.,
            now.elapsed().as_millis() as f64 / 1000.
        );
        assert_ne!(data, data_copy);
    }

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
