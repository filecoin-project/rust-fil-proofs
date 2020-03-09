use std::collections::HashMap;
use std::marker::PhantomData;
use std::path::PathBuf;

use log::{info, trace};
use merkletree::merkle::{
    get_merkle_tree_len, is_merkle_tree_size_valid, FromIndexedParallelIterator,
};
use merkletree::store::{DiskStore, StoreConfig};
use rayon::prelude::*;

use super::{
    challenges::LayerChallenges,
    column::Column,
    create_label, create_label_exp,
    graph::StackedBucketGraph,
    hash::hash_single_column,
    params::{
        get_node, BinaryTree, Labels, LabelsCache, PersistentAux, Proof, PublicInputs,
        PublicParams, ReplicaColumnProof, Tau, TemporaryAux, TemporaryAuxCache, TransformedLayers,
        BINARY_ARITY, OCT_ARITY,
    },
    EncodingProof, LabelingProof,
};

use crate::cache_key::CacheKey;
use crate::data::Data;
use crate::drgraph::Graph;
use crate::encode::{decode, encode};
use crate::error::Result;
use crate::hasher::{Domain, HashFunction, Hasher};
use crate::measurements::{
    measure_op,
    Operation::{CommD, EncodeWindowTimeAll, GenerateTreeC, GenerateTreeRLast},
};
use crate::merkle::{MerkleProof, MerkleTree, OctLCMerkleTree, OctMerkleTree, Store};
use crate::porep::PoRep;
use crate::util::NODE_SIZE;
pub const TOTAL_PARENTS: usize = 37;

#[derive(Debug)]
pub struct StackedDrg<'a, H: 'a + Hasher, G: 'a + Hasher> {
    _a: PhantomData<&'a H>,
    _b: PhantomData<&'a G>,
}

impl<'a, H: 'static + Hasher, G: 'static + Hasher> StackedDrg<'a, H, G> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prove_layers(
        graph: &StackedBucketGraph<H>,
        pub_inputs: &PublicInputs<<H as Hasher>::Domain, <G as Hasher>::Domain>,
        p_aux: &PersistentAux<H::Domain>,
        t_aux: &TemporaryAuxCache<H, G>,
        layer_challenges: &LayerChallenges,
        layers: usize,
        _total_layers: usize,
        partition_count: usize,
    ) -> Result<Vec<Vec<Proof<H, G>>>> {
        assert!(layers > 0);
        assert_eq!(t_aux.labels.len(), layers);

        let graph_size = graph.size();

        // Sanity checks on restored trees.
        assert!(pub_inputs.tau.is_some());
        assert_eq!(pub_inputs.tau.as_ref().unwrap().comm_d, t_aux.tree_d.root());
        assert_eq!(p_aux.comm_r_last, t_aux.tree_r_last.root());
        assert_eq!(p_aux.comm_c, t_aux.tree_c.root());

        let get_drg_parents_columns = |x: usize| -> Result<Vec<Column<H>>> {
            let base_degree = graph.base_graph().degree();

            let mut columns = Vec::with_capacity(base_degree);

            let mut parents = vec![0; base_degree];
            graph.base_parents(x, &mut parents)?;

            for parent in &parents {
                columns.push(t_aux.column(*parent)?);
            }

            debug_assert!(columns.len() == base_degree);

            Ok(columns)
        };

        let get_exp_parents_columns = |x: usize| -> Result<Vec<Column<H>>> {
            let mut parents = vec![0; graph.expansion_degree()];
            graph.expanded_parents(x, &mut parents);

            parents.iter().map(|parent| t_aux.column(*parent)).collect()
        };

        (0..partition_count)
            .map(|k| {
                trace!("proving partition {}/{}", k + 1, partition_count);

                // Derive the set of challenges we are proving over.
                let challenges = pub_inputs.challenges(layer_challenges, graph_size, Some(k));

                // Stacked commitment specifics
                challenges
                    .into_par_iter()
                    .enumerate()
                    .map(|(challenge_index, challenge)| {
                        trace!(" challenge {} ({})", challenge, challenge_index);
                        assert!(challenge < graph.size(), "Invalid challenge");
                        assert!(challenge > 0, "Invalid challenge");

                        // Initial data layer openings (c_X in Comm_D)
                        let comm_d_proof =
                            MerkleProof::new_from_proof(&t_aux.tree_d.gen_proof(challenge)?);
                        assert!(comm_d_proof.validate(challenge));

                        // Stacked replica column openings
                        let rpc = {
                            // All labels in C_X
                            trace!("  c_x");
                            let c_x = t_aux.column(challenge as u32)?.into_proof(&t_aux.tree_c)?;

                            // All labels in the DRG parents.
                            trace!("  drg_parents");
                            let drg_parents = get_drg_parents_columns(challenge)?
                                .into_iter()
                                .map(|column| column.into_proof(&t_aux.tree_c))
                                .collect::<Result<_>>()?;

                            // Labels for the expander parents
                            trace!("  exp_parents");
                            let exp_parents = get_exp_parents_columns(challenge)?
                                .into_iter()
                                .map(|column| column.into_proof(&t_aux.tree_c))
                                .collect::<Result<_>>()?;

                            ReplicaColumnProof {
                                c_x,
                                drg_parents,
                                exp_parents,
                            }
                        };

                        // Final replica layer openings
                        trace!("final replica layer openings");
                        let tree_r_last_proof = {
                            if t_aux.tree_r_last_config_levels == 0 {
                                t_aux.tree_r_last.gen_proof(challenge)?
                            } else {
                                let (proof, _) = t_aux.tree_r_last.gen_proof_and_partial_tree(
                                    challenge,
                                    t_aux.tree_r_last_config_levels,
                                )?;

                                proof
                            }
                        };
                        let comm_r_last_proof = MerkleProof::new_from_proof(&tree_r_last_proof);
                        assert!(comm_r_last_proof.validate(challenge));

                        // Labeling Proofs Layer 1..l
                        let mut labeling_proofs = HashMap::with_capacity(layers);
                        let mut encoding_proof = None;

                        for layer in 1..=layers {
                            trace!("  encoding proof layer {}", layer,);
                            let parents_data: Vec<H::Domain> = if layer == 1 {
                                let mut parents = vec![0; graph.base_graph().degree()];
                                graph.base_parents(challenge, &mut parents)?;

                                parents
                                    .into_iter()
                                    .map(|parent| t_aux.domain_node_at_layer(layer, parent))
                                    .collect::<Result<_>>()?
                            } else {
                                let mut parents = vec![0; graph.degree()];
                                graph.parents(challenge, &mut parents)?;
                                let base_parents_count = graph.base_graph().degree();

                                parents
                                    .into_iter()
                                    .enumerate()
                                    .map(|(i, parent)| {
                                        if i < base_parents_count {
                                            // parents data for base parents is from the current layer
                                            t_aux.domain_node_at_layer(layer, parent)
                                        } else {
                                            // parents data for exp parents is from the previous layer
                                            t_aux.domain_node_at_layer(layer - 1, parent)
                                        }
                                    })
                                    .collect::<Result<_>>()?
                            };

                            // repeat parents
                            let mut parents_data_full = vec![Default::default(); TOTAL_PARENTS];
                            for chunk in parents_data_full.chunks_mut(parents_data.len()) {
                                chunk.copy_from_slice(&parents_data[..chunk.len()]);
                            }

                            let proof = LabelingProof::<H>::new(
                                challenge as u64,
                                parents_data_full.clone(),
                            );

                            {
                                let labeled_node = rpc.c_x.get_node_at_layer(layer)?;
                                assert!(
                                    proof.verify(&pub_inputs.replica_id, &labeled_node),
                                    format!("Invalid encoding proof generated at layer {}", layer)
                                );
                                trace!("Valid encoding proof generated at layer {}", layer);
                            }

                            labeling_proofs.insert(layer, proof);

                            if layer == layers {
                                encoding_proof =
                                    Some(EncodingProof::new(challenge as u64, parents_data_full));
                            }
                        }

                        Ok(Proof {
                            comm_d_proofs: comm_d_proof,
                            replica_column_proofs: rpc,
                            comm_r_last_proof,
                            labeling_proofs,
                            encoding_proof: encoding_proof.expect("invalid tapering"),
                        })
                    })
                    .collect()
            })
            .collect()
    }

    pub(crate) fn extract_and_invert_transform_layers(
        graph: &StackedBucketGraph<H>,
        layer_challenges: &LayerChallenges,
        replica_id: &<H as Hasher>::Domain,
        data: &mut [u8],
        config: StoreConfig,
    ) -> Result<()> {
        trace!("extract_and_invert_transform_layers");

        let layers = layer_challenges.layers();
        assert!(layers > 0);

        // generate labels
        let (labels, _) = Self::generate_labels(graph, layer_challenges, replica_id, config)?;

        let last_layer_labels = labels.labels_for_last_layer()?;
        let size = merkletree::store::Store::len(last_layer_labels);

        for (key, encoded_node_bytes) in last_layer_labels
            .read_range(0..size)?
            .into_iter()
            .zip(data.chunks_mut(NODE_SIZE))
        {
            let encoded_node = H::Domain::try_from_bytes(encoded_node_bytes)?;
            let data_node = decode::<H::Domain>(key, encoded_node);

            // store result in the data
            encoded_node_bytes.copy_from_slice(AsRef::<[u8]>::as_ref(&data_node));
        }

        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn generate_labels(
        graph: &StackedBucketGraph<H>,
        layer_challenges: &LayerChallenges,
        replica_id: &<H as Hasher>::Domain,
        config: StoreConfig,
    ) -> Result<(LabelsCache<H>, Labels<H>)> {
        info!("generate labels");

        let layers = layer_challenges.layers();
        // For now, we require it due to changes in encodings structure.
        let mut labels: Vec<DiskStore<H::Domain>> = Vec::with_capacity(layers);
        let mut label_configs: Vec<StoreConfig> = Vec::with_capacity(layers);

        let layer_size = graph.size() * NODE_SIZE;
        // NOTE: this means we currently keep 2x sector size around, to improve speed.
        let mut labels_buffer = vec![0u8; 2 * layer_size];

        for layer in 1..=layers {
            info!("generating layer: {}", layer);

            if layer == 1 {
                let layer_labels = &mut labels_buffer[..layer_size];
                for node in 0..graph.size() {
                    create_label(graph, replica_id, layer_labels, node)?;
                }
            } else {
                let (layer_labels, exp_labels) = labels_buffer.split_at_mut(layer_size);
                for node in 0..graph.size() {
                    create_label_exp(graph, replica_id, exp_labels, layer_labels, node)?;
                }
            }

            info!("  setting exp parents");
            labels_buffer.copy_within(..layer_size, layer_size);

            // Write the result to disk to avoid keeping it in memory all the time.
            let layer_config =
                StoreConfig::from_config(&config, CacheKey::label_layer(layer), Some(graph.size()));

            info!("  storing labels on disk");
            // Construct and persist the layer data.
            let layer_store: DiskStore<H::Domain> = DiskStore::new_from_slice_with_config(
                graph.size(),
                OCT_ARITY,
                &labels_buffer[..layer_size],
                layer_config.clone(),
            )?;
            info!(
                "  generated layer {} store with id {}",
                layer, layer_config.id
            );

            // Track the layer specific store and StoreConfig for later retrieval.
            labels.push(layer_store);
            label_configs.push(layer_config);
        }

        assert_eq!(
            labels.len(),
            layers,
            "Invalid amount of layers encoded expected"
        );

        Ok((
            LabelsCache::<H> {
                labels,
                _h: PhantomData,
            },
            Labels::<H> {
                labels: label_configs,
                _h: PhantomData,
            },
        ))
    }

    fn build_binary_tree<K: Hasher>(
        tree_data: &[u8],
        config: StoreConfig,
    ) -> Result<BinaryTree<K>> {
        trace!("building tree (size: {})", tree_data.len());

        let leafs = tree_data.len() / NODE_SIZE;
        assert_eq!(tree_data.len() % NODE_SIZE, 0);

        MerkleTree::from_par_iter_with_config(
            (0..leafs)
                .into_par_iter()
                // TODO: proper error handling instead of `unwrap()`
                .map(|i| get_node::<K>(tree_data, i).unwrap()),
            config,
        )
    }

    pub(crate) fn transform_and_replicate_layers(
        graph: &StackedBucketGraph<H>,
        layer_challenges: &LayerChallenges,
        replica_id: &<H as Hasher>::Domain,
        data: Data,
        data_tree: Option<BinaryTree<G>>,
        config: StoreConfig,
        replica_path: PathBuf,
    ) -> Result<TransformedLayers<H, G>> {
        // Generate key layers.
        let (_, labels) = measure_op(EncodeWindowTimeAll, || {
            Self::generate_labels(graph, layer_challenges, replica_id, config.clone())
        })?;

        Self::transform_and_replicate_layers_inner(
            graph,
            layer_challenges,
            data,
            data_tree,
            config,
            replica_path,
            labels,
        )
    }

    pub(crate) fn transform_and_replicate_layers_inner(
        graph: &StackedBucketGraph<H>,
        layer_challenges: &LayerChallenges,
        mut data: Data,
        data_tree: Option<BinaryTree<G>>,
        config: StoreConfig,
        replica_path: PathBuf,
        label_configs: Labels<H>,
    ) -> Result<TransformedLayers<H, G>> {
        trace!("transform_and_replicate_layers");
        let nodes_count = graph.size();

        assert_eq!(data.len(), nodes_count * NODE_SIZE);
        trace!("nodes count {}, data len {}", nodes_count, data.len());

        // Ensure that the node count will work for binary and oct arities.
        trace!(
            "is_merkle_tree_size_valid({}, BINARY_ARITY) = {}",
            nodes_count,
            is_merkle_tree_size_valid(nodes_count, BINARY_ARITY)
        );
        trace!(
            "is_merkle_tree_size_valid({}, OCT_ARITY) = {}",
            nodes_count,
            is_merkle_tree_size_valid(nodes_count, OCT_ARITY)
        );
        assert!(is_merkle_tree_size_valid(nodes_count, BINARY_ARITY));
        assert!(is_merkle_tree_size_valid(nodes_count, OCT_ARITY));

        let layers = layer_challenges.layers();
        assert!(layers > 0);

        // Generate all store configs that we need based on the
        // cache_path in the specified config.
        let mut tree_d_config = StoreConfig::from_config(
            &config,
            CacheKey::CommDTree.to_string(),
            Some(get_merkle_tree_len(nodes_count, BINARY_ARITY)),
        );
        tree_d_config.levels =
            StoreConfig::default_cached_above_base_layer(nodes_count, BINARY_ARITY);

        let mut tree_r_last_config = StoreConfig::from_config(
            &config,
            CacheKey::CommRLastTree.to_string(),
            Some(get_merkle_tree_len(nodes_count, OCT_ARITY)),
        );
        tree_r_last_config.levels =
            StoreConfig::default_cached_above_base_layer(nodes_count, OCT_ARITY);

        let mut tree_c_config = StoreConfig::from_config(
            &config,
            CacheKey::CommCTree.to_string(),
            Some(get_merkle_tree_len(nodes_count, OCT_ARITY)),
        );
        tree_c_config.levels = StoreConfig::default_cached_above_base_layer(nodes_count, OCT_ARITY);

        let labels = LabelsCache::new(&label_configs)?;

        // Build the tree for CommC
        let tree_c = measure_op(GenerateTreeC, || {
            info!("Building column hashes");

            let gsize = graph.size();

            let mut hashes: Vec<H::Domain> = vec![H::Domain::default(); gsize];

            rayon::scope(|s| {
                // spawn n = num_cpus * 2 threads
                let n = num_cpus::get() * 2;

                // only split if we have at least two elements per thread
                let num_chunks = if n > gsize * 2 { 1 } else { n };

                // chunk into n chunks
                let chunk_size = (gsize as f64 / num_chunks as f64).ceil() as usize;

                // calculate all n chunks in parallel
                for (chunk, hashes_chunk) in hashes.chunks_mut(chunk_size).enumerate() {
                    let labels = &labels;

                    s.spawn(move |_| {
                        for (i, hash) in hashes_chunk.iter_mut().enumerate() {
                            let data: Vec<_> = (1..=layers)
                                .map(|layer| {
                                    let store = labels.labels_for_layer(layer);
                                    store.read_at(i + chunk * chunk_size).unwrap().into()
                                })
                                .collect();

                            *hash = hash_single_column(&data).into();
                        }
                    });
                }
            });

            info!("building tree_c");
            OctMerkleTree::<_, H::Function>::from_par_iter_with_config(
                hashes.into_par_iter(),
                tree_c_config.clone(),
            )
        })?;
        info!("tree_c done");

        // Build the MerkleTree over the original data (if needed).
        let tree_d = match data_tree {
            Some(t) => {
                trace!("using existing original data merkle tree");
                assert_eq!(t.len(), 2 * (data.len() / NODE_SIZE) - 1);

                t
            }
            None => {
                trace!("building merkle tree for the original data");
                data.ensure_data()?;
                measure_op(CommD, || {
                    Self::build_binary_tree::<G>(data.as_ref(), tree_d_config.clone())
                })?
            }
        };

        // Encode original data into the last layer.
        info!("building tree_r_last");
        let tree_r_last = measure_op(GenerateTreeRLast, || {
            data.ensure_data()?;

            let last_layer_labels = labels.labels_for_last_layer()?;
            let size = Store::len(last_layer_labels);

            let encoded_data = last_layer_labels
                .read_range(0..size)?
                .into_par_iter()
                .zip(data.as_mut().par_chunks_mut(NODE_SIZE))
                .map(|(key, data_node_bytes)| {
                    let data_node = H::Domain::try_from_bytes(data_node_bytes).unwrap();
                    let encoded_node = encode::<H::Domain>(key, data_node);
                    data_node_bytes.copy_from_slice(AsRef::<[u8]>::as_ref(&encoded_node));

                    encoded_node
                });

            OctLCMerkleTree::<_, H::Function>::from_par_iter_with_config(
                encoded_data,
                tree_r_last_config.clone(),
            )
        })?;
        info!("tree_r_last done");

        assert_eq!(tree_c.len(), tree_r_last.len());

        assert_eq!(tree_d_config.size.unwrap(), tree_d.len());
        assert_eq!(tree_r_last_config.size.unwrap(), tree_r_last.len());
        assert_eq!(tree_c_config.size.unwrap(), tree_c.len());

        trace!("tree d len {}", tree_d.len());
        trace!("tree c len {}", tree_c.len());
        trace!("tree r_last len {}", tree_r_last.len());

        // Store and persist encoded replica data.
        {
            use std::fs::OpenOptions;
            use std::io::prelude::*;

            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .open(&replica_path)?;

            // Only write the replica's base layer of leaf data.
            trace!("Wrote replica data for {} nodes", tree_r_last.leafs());
            f.write_all(&data.as_ref()[0..tree_r_last.leafs() * NODE_SIZE])?;
        }

        data.drop_data();

        // comm_r = H(comm_c || comm_r_last)
        let comm_r: H::Domain = H::Function::hash2(&tree_c.root(), &tree_r_last.root());

        Ok((
            Tau {
                comm_d: tree_d.root(),
                comm_r,
            },
            PersistentAux {
                comm_c: tree_c.root(),
                comm_r_last: tree_r_last.root(),
            },
            TemporaryAux {
                labels: label_configs,
                tree_d_config,
                tree_r_last_config,
                tree_c_config,
                _g: PhantomData,
            },
        ))
    }

    /// Phase1 of replication.
    pub fn replicate_phase1(
        pp: &'a PublicParams<H>,
        replica_id: &H::Domain,
        config: StoreConfig,
    ) -> Result<Labels<H>> {
        info!("replicate_phase1");

        let (_, labels) = measure_op(EncodeWindowTimeAll, || {
            Self::generate_labels(&pp.graph, &pp.layer_challenges, replica_id, config)
        })?;

        Ok(labels)
    }

    #[allow(clippy::type_complexity)]
    /// Phase2 of replication.
    #[allow(clippy::type_complexity)]
    pub fn replicate_phase2(
        pp: &'a PublicParams<H>,
        labels: Labels<H>,
        data: Data<'a>,
        data_tree: BinaryTree<G>,
        config: StoreConfig,
        replica_path: PathBuf,
    ) -> Result<(
        <Self as PoRep<'a, H, G>>::Tau,
        <Self as PoRep<'a, H, G>>::ProverAux,
    )> {
        info!("replicate_phase2");

        let (tau, paux, taux) = Self::transform_and_replicate_layers_inner(
            &pp.graph,
            &pp.layer_challenges,
            data,
            Some(data_tree),
            config,
            replica_path,
            labels,
        )?;

        Ok((tau, (paux, taux)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ff::Field;
    use paired::bls12_381::{Bls12, Fr};
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    use crate::drgraph::{new_seed, BASE_DEGREE};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::{Blake2sHasher, PedersenHasher, PoseidonHasher, Sha256Hasher};
    use crate::porep::stacked::{PrivateInputs, SetupParams, EXP_DEGREE};
    use crate::porep::PoRep;
    use crate::proof::ProofScheme;

    const DEFAULT_STACKED_LAYERS: usize = 11;

    #[test]
    fn test_calculate_fixed_challenges() {
        let layer_challenges = LayerChallenges::new(10, 333);
        let expected = 333;

        let calculated_count = layer_challenges.challenges_count_all();
        assert_eq!(expected as usize, calculated_count);
    }

    #[test]
    fn extract_all_pedersen() {
        test_extract_all::<PedersenHasher>();
    }

    #[test]
    fn extract_all_sha256() {
        test_extract_all::<Sha256Hasher>();
    }

    #[test]
    fn extract_all_blake2s() {
        test_extract_all::<Blake2sHasher>();
    }

    #[test]
    fn extract_all_poseidon() {
        test_extract_all::<PoseidonHasher>();
    }

    fn test_extract_all<H: 'static + Hasher>() {
        // femme::pretty::Logger::new()
        //     .start(log::LevelFilter::Trace)
        //     .ok();

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);
        let replica_id: H::Domain = H::Domain::random(rng);
        let nodes = 64;

        let data: Vec<u8> = (0..nodes)
            .flat_map(|_| {
                let v: H::Domain = H::Domain::random(rng);
                v.into_bytes()
            })
            .collect();

        let challenges = LayerChallenges::new(DEFAULT_STACKED_LAYERS, 5);

        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();

        let sp = SetupParams {
            nodes,
            degree: BASE_DEGREE,
            expansion_degree: EXP_DEGREE,
            seed: new_seed(),
            layer_challenges: challenges.clone(),
        };

        let pp = StackedDrg::<H, Blake2sHasher>::setup(&sp).expect("setup failed");

        // MT for original data is always named tree-d, and it will be
        // referenced later in the process as such.
        let cache_dir = tempfile::tempdir().unwrap();
        let config = StoreConfig::new(
            cache_dir.path(),
            CacheKey::CommDTree.to_string(),
            StoreConfig::default_cached_above_base_layer(nodes, BINARY_ARITY),
        );

        // Generate a replica path.
        let temp_dir = tempdir::TempDir::new("test-extract-all").unwrap();
        let temp_path = temp_dir.path();
        let replica_path = temp_path.join("replica-path");

        StackedDrg::<H, Blake2sHasher>::replicate(
            &pp,
            &replica_id,
            (&mut data_copy[..]).into(),
            None,
            config.clone(),
            replica_path.clone(),
        )
        .expect("replication failed");

        assert_ne!(data, data_copy);

        let decoded_data = StackedDrg::<H, Blake2sHasher>::extract_all(
            &pp,
            &replica_id,
            data_copy.as_mut_slice(),
            Some(config.clone()),
        )
        .expect("failed to extract data");

        assert_eq!(data, decoded_data);
    }

    fn prove_verify_fixed(n: usize) {
        let challenges = LayerChallenges::new(DEFAULT_STACKED_LAYERS, 5);

        test_prove_verify::<PedersenHasher>(n, challenges.clone());
        test_prove_verify::<Sha256Hasher>(n, challenges.clone());
        test_prove_verify::<Blake2sHasher>(n, challenges.clone());
        test_prove_verify::<PoseidonHasher>(n, challenges.clone());
    }

    fn test_prove_verify<H: 'static + Hasher>(n: usize, challenges: LayerChallenges) {
        // This will be called multiple times, only the first one succeeds, and that is ok.
        // femme::pretty::Logger::new()
        //     .start(log::LevelFilter::Trace)
        //     .ok();

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let degree = BASE_DEGREE;
        let expansion_degree = EXP_DEGREE;
        let replica_id: H::Domain = H::Domain::random(rng);
        let data: Vec<u8> = (0..n)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
            .collect();

        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();
        let partitions = 2;

        let sp = SetupParams {
            nodes: n,
            degree,
            expansion_degree,
            seed: new_seed(),
            layer_challenges: challenges.clone(),
        };

        // MT for original data is always named tree-d, and it will be
        // referenced later in the process as such.
        let cache_dir = tempfile::tempdir().unwrap();
        let config = StoreConfig::new(
            cache_dir.path(),
            CacheKey::CommDTree.to_string(),
            StoreConfig::default_cached_above_base_layer(n, BINARY_ARITY),
        );

        // Generate a replica_path.
        let temp_dir = tempdir::TempDir::new("test-prove-verify").unwrap();
        let temp_path = temp_dir.path();
        let replica_path = temp_path.join("replica-path");

        let pp = StackedDrg::<H, Blake2sHasher>::setup(&sp).expect("setup failed");
        let (tau, (p_aux, t_aux)) = StackedDrg::<H, Blake2sHasher>::replicate(
            &pp,
            &replica_id,
            (&mut data_copy[..]).into(),
            None,
            config,
            replica_path.clone(),
        )
        .expect("replication failed");
        assert_ne!(data, data_copy);

        let seed = rng.gen();

        let pub_inputs = PublicInputs::<H::Domain, <Blake2sHasher as Hasher>::Domain> {
            replica_id,
            seed,
            tau: Some(tau),
            k: None,
        };

        // Store a copy of the t_aux for later resource deletion.
        let t_aux_orig = t_aux.clone();

        // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
        // elements based on the configs stored in TemporaryAux.
        let t_aux = TemporaryAuxCache::<H, Blake2sHasher>::new(&t_aux, replica_path)
            .expect("failed to restore contents of t_aux");

        let priv_inputs = PrivateInputs { p_aux, t_aux };

        let all_partition_proofs = &StackedDrg::<H, Blake2sHasher>::prove_all_partitions(
            &pp,
            &pub_inputs,
            &priv_inputs,
            partitions,
        )
        .expect("failed to generate partition proofs");

        let proofs_are_valid = StackedDrg::<H, Blake2sHasher>::verify_all_partitions(
            &pp,
            &pub_inputs,
            all_partition_proofs,
        )
        .expect("failed to verify partition proofs");

        // Discard cached MTs that are no longer needed.
        TemporaryAux::<H, Blake2sHasher>::clear_temp(t_aux_orig).expect("t_aux delete failed");

        assert!(proofs_are_valid);
    }

    table_tests! {
        prove_verify_fixed {
           prove_verify_fixed_64_64(64);
        }
    }

    #[test]
    // We are seeing a bug, in which setup never terminates for some sector sizes.
    // This test is to debug that and should remain as a regression teset.
    fn setup_terminates() {
        let degree = BASE_DEGREE;
        let expansion_degree = EXP_DEGREE;
        let nodes = 1024 * 1024 * 32 * 8; // This corresponds to 8GiB sectors (32-byte nodes)
        let layer_challenges = LayerChallenges::new(10, 333);
        let sp = SetupParams {
            nodes,
            degree,
            expansion_degree,
            seed: new_seed(),
            layer_challenges: layer_challenges.clone(),
        };

        // When this fails, the call to setup should panic, but seems to actually hang (i.e. neither return nor panic) for some reason.
        // When working as designed, the call to setup returns without error.
        let _pp = StackedDrg::<PedersenHasher, Blake2sHasher>::setup(&sp).expect("setup failed");
    }
}
