use std::collections::HashMap;
use std::marker::PhantomData;

use log::{info, trace};
use merkletree::merkle::FromIndexedParallelIterator;
use merkletree::store::{DiskStore, StoreConfig};
use paired::bls12_381::Fr;
use rayon::prelude::*;
use sha2::{digest::generic_array::GenericArray, Digest, Sha256};

use crate::drgraph::Graph;
use crate::encode::{decode, encode};
use crate::error::Result;
use crate::hasher::{Domain, Hasher};
use crate::measurements::{
    measure_op,
    Operation::{
        CommD, EncodeWindowTimeAll, GenerateTreeC, GenerateTreeRLast, WindowCommLeavesTime,
    },
};
use crate::merkle::{MerkleProof, MerkleTree, Store};
use crate::porep::Data;
use crate::stacked_old::{
    challenges::LayerChallenges,
    column::Column,
    graph::StackedBucketGraph,
    hash::hash2,
    params::{
        get_node, CacheKey, Labels, LabelsCache, PersistentAux, Proof, PublicInputs,
        ReplicaColumnProof, Tau, TemporaryAux, TemporaryAuxCache, TransformedLayers, Tree,
    },
    EncodingProof, LabelingProof,
};
use crate::util::{data_at_node, data_at_node_offset, NODE_SIZE};

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
        assert_eq!(p_aux.comm_c, t_aux.tree_c.root());
        assert_eq!(p_aux.comm_r_last, t_aux.tree_r_last.root());

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
                        let comm_r_last_proof =
                            MerkleProof::new_from_proof(&t_aux.tree_r_last.gen_proof(challenge)?);
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

                            let proof =
                                LabelingProof::<H>::new(challenge as u64, parents_data.clone());

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
                                    Some(EncodingProof::new(challenge as u64, parents_data));
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
        config: Option<StoreConfig>,
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
        config: Option<StoreConfig>,
    ) -> Result<(LabelsCache<H>, Labels<H>)> {
        info!("generate labels");
        use gperftools::profiler::PROFILER;
        PROFILER
            .lock()
            .unwrap()
            .start("./labeling.profile")
            .unwrap();

        let layers = layer_challenges.layers();
        // For now, we require it due to changes in encodings structure.
        assert!(config.is_some());
        let config = config.unwrap();
        let mut labels: Vec<DiskStore<H::Domain>> = Vec::with_capacity(layers);
        let mut label_configs: Vec<StoreConfig> = Vec::with_capacity(layers);

        let layer_size = graph.size() * NODE_SIZE;
        let mut parents = vec![0; graph.degree()];
        let mut layer_labels = vec![0u8; layer_size];

        let mut exp_parents_data: Option<Vec<u8>> = None;

        // setup hasher to reuse
        let mut base_hasher = Sha256::new();
        // hash replica id
        base_hasher.input(AsRef::<[u8]>::as_ref(replica_id));

        for layer in 1..=layers {
            info!("generating layer: {}", layer);

            for node in 0..graph.size() {
                graph.parents(node, &mut parents)?;

                let key = create_key(
                    graph,
                    base_hasher.clone(),
                    &parents,
                    exp_parents_data.as_ref(),
                    &layer_labels,
                    node,
                )?;

                // store the newly generated key
                let start = data_at_node_offset(node);
                let end = start + NODE_SIZE;
                layer_labels[start..end].copy_from_slice(&key[..]);
            }

            // NOTE: this means we currently keep 2x sector size around, to improve speed.
            if let Some(ref mut exp_parents_data) = exp_parents_data {
                exp_parents_data.copy_from_slice(&layer_labels);
            } else {
                exp_parents_data = Some(layer_labels.clone());
            }

            // Write the result to disk to avoid keeping it in memory all the time.
            let layer_config =
                StoreConfig::from_config(&config, CacheKey::label_layer(layer), Some(layer_size));

            // Construct and persist the layer data.
            let layer_store: DiskStore<H::Domain> = DiskStore::new_from_slice_with_config(
                layer_size,
                &layer_labels,
                layer_config.clone(),
            )?;
            trace!(
                "Generated layer {} store with id {}",
                layer,
                layer_config.id
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

        PROFILER.lock().unwrap().stop().unwrap();

        info!("Labels generated");
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

    fn build_tree<K: Hasher>(tree_data: &[u8], config: Option<StoreConfig>) -> Result<Tree<K>> {
        trace!("building tree (size: {})", tree_data.len());

        let leafs = tree_data.len() / NODE_SIZE;
        assert_eq!(tree_data.len() % NODE_SIZE, 0);
        if let Some(config) = config {
            MerkleTree::from_par_iter_with_config(
                (0..leafs)
                    .into_par_iter()
                    // TODO proper error handling instead of `unwrap()`
                    .map(|i| get_node::<K>(tree_data, i).unwrap()),
                config,
            )
        } else {
            MerkleTree::from_par_iter(
                (0..leafs)
                    .into_par_iter()
                    // TODO proper error handling instead of `unwrap()`
                    .map(|i| get_node::<K>(tree_data, i).unwrap()),
            )
        }
    }

    fn build_column_hashes(
        nodes_count: usize,
        layers: usize,
        labels: &LabelsCache<H>,
    ) -> Result<Vec<[u8; 32]>> {
        (0..nodes_count)
            .into_par_iter()
            .map(|i| Self::build_column_hash(layers, i, labels))
            .collect()
    }

    fn build_column_hash(
        layers: usize,
        column_index: usize,
        labels: &LabelsCache<H>,
    ) -> Result<[u8; 32]> {
        let first_label = labels.labels_for_layer(1).read_at(column_index)?;
        let mut hasher = crate::crypto::pedersen::Hasher::new(AsRef::<[u8]>::as_ref(&first_label))?;

        for layer in 1..layers {
            if layer == 1 {
                // first label
                continue;
            }

            let label = labels.labels_for_layer(layer).read_at(column_index)?;

            hasher.update(AsRef::<[u8]>::as_ref(&label))?;
        }

        Ok(hasher.finalize_bytes())
    }

    pub(crate) fn transform_and_replicate_layers(
        graph: &StackedBucketGraph<H>,
        layer_challenges: &LayerChallenges,
        replica_id: &<H as Hasher>::Domain,
        mut data: Data<'a>,
        data_tree: Option<Tree<G>>,
        config: Option<StoreConfig>,
    ) -> Result<TransformedLayers<H, G>> {
        trace!("transform_and_replicate_layers");
        let nodes_count = graph.size();

        assert_eq!(data.len(), nodes_count * NODE_SIZE);

        let layers = layer_challenges.layers();
        assert!(layers > 0);

        // Generate all store configs that we need based on the
        // cache_path in the specified config.
        assert!(config.is_some());
        let config = config.unwrap();
        let mut tree_d_config =
            StoreConfig::from_config(&config, CacheKey::CommDTree.to_string(), None);
        let mut tree_r_last_config =
            StoreConfig::from_config(&config, CacheKey::CommRLastTree.to_string(), None);
        let mut tree_c_config =
            StoreConfig::from_config(&config, CacheKey::CommCTree.to_string(), None);

        let (labels, label_configs, column_hashes, tree_d) = crossbeam::thread::scope(|s| {
            // Generate key layers.
            let h = s.spawn(|_| {
                measure_op(EncodeWindowTimeAll, || {
                    Self::generate_labels(graph, layer_challenges, replica_id, Some(config.clone()))
                })
            });

            // Build the MerkleTree over the original data (if needed).
            let tree_d = match data_tree {
                Some(t) => {
                    trace!("using existing original data merkle tree");
                    assert_eq!(t.len(), 2 * (data.len() / NODE_SIZE) - 1);

                    t
                }
                None => {
                    trace!("building merkle tree for the original data");
                    data.ensure_data().unwrap();
                    measure_op(CommD, || {
                        Self::build_tree::<G>(data.as_ref(), Some(tree_d_config.clone())).unwrap()
                    })
                    // FIXME: error handling
                }
            };

            trace!("Retrieved MT for original data");
            let (labels, label_configs) = h.join().unwrap().unwrap(); // FIXME: error handling

            // construct column hashes
            info!("building column hashes");
            let column_hashes = measure_op(WindowCommLeavesTime, || {
                Self::build_column_hashes(nodes_count, layers, &labels)
            })
            .unwrap();

            (labels, label_configs, column_hashes, tree_d)
        })
        .unwrap(); // FIXME: error handling

        let (tree_r_last, tree_c, comm_r): (Tree<H>, Tree<H>, H::Domain) =
            crossbeam::thread::scope(|s| -> Result<_> {
                // Encode original data into the last layer.
                let tree_r_last_handle = s.spawn(|_| {
                    measure_op(GenerateTreeRLast, || {
                        info!("encoding data");
                        let last_layer_labels = labels.labels_for_last_layer()?;
                        let size = Store::len(last_layer_labels);
                        data.ensure_data()?;

                        last_layer_labels
                            .read_range(0..size)?
                            .into_par_iter()
                            .zip(data.as_mut().par_chunks_mut(NODE_SIZE))
                            .for_each(|(key, data_node_bytes)| {
                                let data_node = H::Domain::try_from_bytes(data_node_bytes).unwrap();
                                let encoded_node = encode::<H::Domain>(key, data_node);

                                // Store the result in the place of the original data.
                                data_node_bytes
                                    .copy_from_slice(AsRef::<[u8]>::as_ref(&encoded_node));
                            });

                        // Construct the final replica commitment.
                        info!("building tree_r_last");
                        Self::build_tree::<H>(data.as_ref(), Some(tree_r_last_config.clone()))
                    })
                });

                // Build the tree for CommC
                let tree_c_config = tree_c_config.clone();
                let tree_c_handle = s.spawn(move |_| {
                    measure_op(GenerateTreeC, || {
                        info!("building tree_c");
                        let column_hashes_flat = unsafe {
                            // Column_hashes is of type Vec<[u8; 32]>, so this is safe to do.
                            // We do this to avoid unnecessary allocations.
                            std::slice::from_raw_parts(
                                column_hashes.as_ptr() as *const _,
                                column_hashes.len() * 32,
                            )
                        };
                        Self::build_tree::<H>(column_hashes_flat, Some(tree_c_config))
                    })
                });

                let tree_c: Tree<H> = tree_c_handle.join().unwrap().unwrap(); // FIXME: error handling
                info!("tree_c done");
                let tree_r_last: Tree<H> = tree_r_last_handle.join().unwrap().unwrap(); // FIXME: error handling
                info!("tree_r_last done");

                // comm_r = H(comm_c || comm_r_last)
                let comm_r: H::Domain = Fr::from(hash2(tree_c.root(), tree_r_last.root())).into();

                Ok((tree_r_last, tree_c, comm_r))
            })
            .unwrap()
            .unwrap(); // FIXME: error handling

        assert_eq!(tree_d.len(), tree_r_last.len());
        assert_eq!(tree_d.len(), tree_c.len());
        tree_d_config.size = Some(tree_d.len());
        tree_r_last_config.size = Some(tree_r_last.len());
        tree_c_config.size = Some(tree_c.len());

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
}

pub fn create_key<H: Hasher>(
    graph: &StackedBucketGraph<H>,
    mut hasher: Sha256,
    parents: &[u32],
    exp_parents_data: Option<&Vec<u8>>,
    layer_labels: &[u8],
    node: usize,
) -> Result<GenericArray<u8, <Sha256 as Digest>::OutputSize>> {
    let mut inputs = if node > 0 {
        if exp_parents_data.is_some() {
            vec![0u8; graph.degree() * NODE_SIZE + 8]
        } else {
            vec![0u8; graph.base_graph().degree() * NODE_SIZE + 8]
        }
    } else {
        (node as u64).to_be_bytes().to_vec()
    };

    // hash parents for all non 0 nodes
    if node > 0 {
        // hash node id
        inputs[..8].copy_from_slice(&(node as u64).to_be_bytes());

        let base_parents_count = graph.base_graph().degree();

        // Base parents
        for (i, parent) in parents.iter().take(base_parents_count).enumerate() {
            let buf = data_at_node(&layer_labels, *parent as usize)?;
            inputs[8 + i * NODE_SIZE..8 + (i + 1) * NODE_SIZE].copy_from_slice(buf);
            // hasher.input(buf);
        }

        // Expander parents
        // This will happen for all layers > 1
        if let Some(ref parents_data) = exp_parents_data {
            for (i, parent) in parents.iter().skip(base_parents_count).enumerate() {
                let j = i + base_parents_count;
                let buf = data_at_node(parents_data, *parent as usize)?;
                inputs[8 + j * NODE_SIZE..8 + (j + 1) * NODE_SIZE].copy_from_slice(buf);
                // hasher.input(&buf);
            }
        }
    }

    hasher.input(&inputs);
    // finalize the key
    let mut key = hasher.result();
    // strip last two bits, to ensure result is in Fr.
    key[31] &= 0b0011_1111;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ff::Field;
    use paired::bls12_381::Bls12;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    use crate::drgraph::{new_seed, BASE_DEGREE};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::{Blake2sHasher, PedersenHasher, Sha256Hasher};
    use crate::porep::PoRep;
    use crate::proof::ProofScheme;
    use crate::stacked_old::{PrivateInputs, SetupParams, EXP_DEGREE};

    const DEFAULT_STACKED_LAYERS: usize = 4;

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

    fn test_extract_all<H: 'static + Hasher>() {
        use merkletree::store::DEFAULT_CACHED_ABOVE_BASE_LAYER;

        // femme::pretty::Logger::new()
        //     .start(log::LevelFilter::Trace)
        //     .ok();

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);
        let replica_id: H::Domain = H::Domain::random(rng);
        let nodes = 8;

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
            DEFAULT_CACHED_ABOVE_BASE_LAYER,
        );

        StackedDrg::<H, Blake2sHasher>::replicate(
            &pp,
            &replica_id,
            (&mut data_copy[..]).into(),
            None,
            Some(config.clone()),
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
        use merkletree::store::DEFAULT_CACHED_ABOVE_BASE_LAYER;
        let cache_dir = tempfile::tempdir().unwrap();
        let config = StoreConfig::new(
            cache_dir.path(),
            CacheKey::CommDTree.to_string(),
            DEFAULT_CACHED_ABOVE_BASE_LAYER,
        );

        let pp = StackedDrg::<H, Blake2sHasher>::setup(&sp).expect("setup failed");
        let (tau, (p_aux, t_aux)) = StackedDrg::<H, Blake2sHasher>::replicate(
            &pp,
            &replica_id,
            (&mut data_copy[..]).into(),
            None,
            Some(config),
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

        // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
        // elements based on the configs stored in TemporaryAux.
        let t_aux: TemporaryAuxCache<H, Blake2sHasher> =
            TemporaryAuxCache::new(&t_aux).expect("failed to restore contents of t_aux");

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

        assert!(proofs_are_valid);
    }

    table_tests! {
        prove_verify_fixed{
           prove_verify_fixed_32_4(4);
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
