use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Mutex;

use merkletree::merkle::FromIndexedParallelIterator;
use merkletree::store::{DiskStore, StoreConfig};
use paired::bls12_381::Fr;
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use crate::drgraph::Graph;
use crate::encode::{decode, encode};
use crate::error::Result;
use crate::hasher::{Domain, Hasher};
use crate::merkle::{MerkleProof, MerkleTree, Store};
use crate::stacked::{
    challenges::LayerChallenges,
    column::Column,
    graph::StackedBucketGraph,
    hash::hash3,
    params::{
        get_node, CacheKey, Labels, LabelsCache, PersistentAux, Proof, PublicInputs,
        ReplicaColumnProof, Tau, TemporaryAux, TemporaryAuxCache, TransformedLayers, Tree,
    },
    EncodingProof, LabelingProof,
};
use crate::util::{data_at_node, data_at_node_offset, NODE_SIZE};

pub const WINDOW_SIZE_BYTES: usize = 4 * 1024;
pub const WINDOW_SIZE_NODES: usize = WINDOW_SIZE_BYTES / NODE_SIZE;

#[derive(Debug)]
pub struct StackedDrg<'a, H: 'a + Hasher, G: 'a + Hasher> {
    _a: PhantomData<&'a H>,
    _b: PhantomData<&'a G>,
}

impl<'a, H: 'static + Hasher, G: 'static + Hasher> StackedDrg<'a, H, G> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prove_layers(
        graph: &StackedBucketGraph<H>,
        wrapper_graph: &StackedBucketGraph<H>,
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
            graph.base_parents(x, &mut parents);

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
                let challenges = pub_inputs.all_challenges(layer_challenges, graph_size, Some(k));

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
                            MerkleProof::new_from_proof(&t_aux.tree_d.gen_proof(challenge));
                        assert!(comm_d_proof.validate(challenge));

                        // Stacked replica column openings
                        let rpc = {
                            // All labels in C_X
                            trace!("  c_x");
                            let c_x = t_aux.column(challenge as u32)?.into_proof(&t_aux.tree_c);

                            // All labels in the DRG parents.
                            trace!("  drg_parents");
                            let drg_parents = get_drg_parents_columns(challenge)?
                                .into_iter()
                                .map(|column| column.into_proof(&t_aux.tree_c))
                                .collect::<Vec<_>>();

                            // Labels for the expander parents
                            trace!("  exp_parents");
                            let exp_parents = get_exp_parents_columns(challenge)?
                                .into_iter()
                                .map(|column| column.into_proof(&t_aux.tree_c))
                                .collect::<Vec<_>>();

                            ReplicaColumnProof {
                                c_x,
                                drg_parents,
                                exp_parents,
                            }
                        };

                        // Final replica layer openings
                        trace!("final replica layer openings");
                        let comm_r_last_proof =
                            MerkleProof::new_from_proof(&t_aux.tree_r_last.gen_proof(challenge));
                        assert!(comm_r_last_proof.validate(challenge));

                        // Labeling Proofs Layer 1..l
                        let mut labeling_proofs = HashMap::with_capacity(layers);
                        let mut encoding_proof = None;

                        for layer in 1..=layers {
                            let include_challenge =
                                layer_challenges.include_challenge_at_layer(layer, challenge_index);
                            trace!(
                                "  encoding proof layer {} (include: {})",
                                layer,
                                include_challenge
                            );
                            // Due to tapering for some layers and some challenges we do not
                            // create an encoding proof.
                            if !include_challenge {
                                continue;
                            }

                            let parents_data: Vec<H::Domain> = if layer == 1 {
                                let mut parents = vec![0; graph.base_graph().degree()];
                                graph.base_parents(challenge, &mut parents);

                                parents
                                    .into_iter()
                                    .map(|parent| t_aux.domain_node_at_layer(layer, parent))
                                    .collect()
                            } else {
                                let mut parents = vec![0; graph.degree()];
                                graph.parents(challenge, &mut parents);
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
                                    .collect()
                            };

                            let proof =
                                LabelingProof::<H>::new(challenge as u64, parents_data.clone());

                            {
                                let labeled_node = rpc.c_x.get_node_at_layer(layer);
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

    pub(crate) fn extract_all_windows(
        window_graph: &StackedBucketGraph<H>,
        layer_challenges: &LayerChallenges,
        replica_id: &<H as Hasher>::Domain,
        data: &mut [u8],
        config: Option<StoreConfig>,
    ) -> Result<()> {
        trace!("extract_all_windows");

        let layers = layer_challenges.layers();
        assert!(layers > 0);

        assert_eq!(data.len() % WINDOW_SIZE_BYTES, 0, "invalid data size");

        data.par_chunks_mut(WINDOW_SIZE_BYTES)
            .for_each(|data_chunk| {
                Self::extract_single_window(window_graph, layers, replica_id, data_chunk);
            });

        Ok(())
    }

    pub(crate) fn extract_single_window(
        window_graph: &StackedBucketGraph<H>,
        layers: usize,
        replica_id: &<H as Hasher>::Domain,
        data_chunk: &mut [u8],
    ) {
        trace!("extract_single_window");

        let mut layer_labels = vec![0u8; WINDOW_SIZE_BYTES];
        let mut parents = vec![0; window_graph.degree()];
        let mut exp_parents_data: Option<Vec<u8>> = None;

        // setup hasher to reuse
        let mut base_hasher = Sha256::new();

        // hash replica id
        base_hasher.input(AsRef::<[u8]>::as_ref(replica_id));

        for layer in 1..=layers {
            info!("generating layer: {}", layer);

            for node in 0..window_graph.size() {
                window_graph.parents(node, &mut parents);

                let mut hasher = base_hasher.clone();

                // hash node id
                let node_arr = (node as u64).to_be_bytes();
                hasher.input(&node_arr);

                // hash parents for all non 0 nodes
                if node > 0 {
                    let base_parents_count = window_graph.base_graph().degree();

                    // Base parents
                    for parent in parents.iter().take(base_parents_count) {
                        let buf =
                            data_at_node(&layer_labels, *parent as usize).expect("invalid node");
                        hasher.input(buf);
                    }

                    // Expander parents
                    // This will happen for all layers > 1
                    if let Some(ref parents_data) = exp_parents_data {
                        for parent in parents.iter().skip(base_parents_count) {
                            let buf =
                                data_at_node(parents_data, *parent as usize).expect("invalid node");
                            hasher.input(&buf);
                        }
                    }
                }

                let start = data_at_node_offset(node);
                let end = start + NODE_SIZE;

                // finalize the key
                let mut key = hasher.result();
                // strip last two bits, to ensure result is in Fr.
                key[31] &= 0b0011_1111;

                // store the newly generated key
                if layer < layers {
                    layer_labels[start..end].copy_from_slice(&key[..]);
                } else {
                    // on the last layer we encode the data
                    let keyd = H::Domain::try_from_bytes(&key).unwrap();
                    let data_node = H::Domain::try_from_bytes(
                        &data_chunk[node * NODE_SIZE..(node + 1) * NODE_SIZE],
                    )
                    .unwrap();
                    let encoded_node = decode::<H::Domain>(keyd, data_node);
                    data_chunk[node * NODE_SIZE..(node + 1) * NODE_SIZE].copy_from_slice(AsRef::<
                        [u8],
                    >::as_ref(
                        &encoded_node,
                    ));
                }
            }

            if let Some(ref mut exp_parents_data) = exp_parents_data {
                exp_parents_data.copy_from_slice(&layer_labels);
            } else {
                exp_parents_data = Some(layer_labels.clone());
            }
        }
    }

    fn encode_all_windows(
        graph: &StackedBucketGraph<H>,
        layers: usize,
        replica_id: &<H as Hasher>::Domain,
        data: &mut [u8],
        config: StoreConfig,
    ) -> Result<(LabelsCache<H>, Labels<H>)> {
        trace!("encode_all_windows");

        let layer_size = data.len();
        let num_windows = layer_size / WINDOW_SIZE_BYTES;

        let labels: Vec<Mutex<(DiskStore<_>, _)>> = (0..layers - 1)
            .map(|layer| -> Result<_> {
                let layer_config = StoreConfig::from_config(
                    &config,
                    CacheKey::label_layer(layer),
                    Some(layer_size),
                );

                let layer_store: DiskStore<H::Domain> =
                    DiskStore::new_with_config(layer_size, layer_config.clone())?;

                let r = Mutex::new((layer_store, layer_config));
                Ok(r)
            })
            .collect::<Result<_>>()?;

        (0..num_windows)
            .into_par_iter()
            .zip(data.par_chunks_mut(WINDOW_SIZE_BYTES))
            .for_each(|(window_index, data_chunk)| {
                let mut layer_labels = vec![0u8; WINDOW_SIZE_BYTES];
                let mut parents = vec![0; graph.degree()];
                let mut exp_parents_data: Option<Vec<u8>> = None;

                // setup hasher to reuse
                let mut base_hasher = Sha256::new();

                // hash replica id
                base_hasher.input(AsRef::<[u8]>::as_ref(replica_id));

                for layer in 1..=layers {
                    info!("generating layer: {}", layer);

                    for node in 0..graph.size() {
                        graph.parents(node, &mut parents);

                        let mut hasher = base_hasher.clone();

                        // hash node id
                        let node_arr = (node as u64).to_be_bytes();
                        hasher.input(&node_arr);

                        // hash parents for all non 0 nodes
                        if node > 0 {
                            let base_parents_count = graph.base_graph().degree();

                            // Base parents
                            for parent in parents.iter().take(base_parents_count) {
                                let buf = data_at_node(&layer_labels, *parent as usize)
                                    .expect("invalid node");
                                hasher.input(buf);
                            }

                            // Expander parents
                            // This will happen for all layers > 1
                            if let Some(ref parents_data) = exp_parents_data {
                                for parent in parents.iter().skip(base_parents_count) {
                                    let buf = data_at_node(parents_data, *parent as usize)
                                        .expect("invalid node");
                                    hasher.input(&buf);
                                }
                            }
                        }

                        let start = data_at_node_offset(node);
                        let end = start + NODE_SIZE;

                        // finalize the key
                        let mut key = hasher.result();
                        // strip last two bits, to ensure result is in Fr.
                        key[31] &= 0b0011_1111;

                        // store the newly generated key
                        if layer < layers {
                            layer_labels[start..end].copy_from_slice(&key[..]);
                        } else {
                            // on the last layer we encode the data
                            let keyd = H::Domain::try_from_bytes(&key).unwrap();
                            let data_node = H::Domain::try_from_bytes(
                                &data_chunk[node * NODE_SIZE..(node + 1) * NODE_SIZE],
                            )
                            .unwrap();
                            let encoded_node = encode(keyd, data_node);
                            data_chunk[node * NODE_SIZE..(node + 1) * NODE_SIZE]
                                .copy_from_slice(AsRef::<[u8]>::as_ref(&encoded_node));
                        }
                    }

                    if let Some(ref mut exp_parents_data) = exp_parents_data {
                        exp_parents_data.copy_from_slice(&layer_labels);
                    } else {
                        exp_parents_data = Some(layer_labels.clone());
                    }

                    if layer < layers {
                        // write result to disk
                        labels[layer - 1]
                            .lock()
                            .unwrap()
                            .0
                            .copy_from_slice(&layer_labels, window_index * WINDOW_SIZE_BYTES);
                    }
                }
            });

        info!("Labels generated");

        let (labels, configs) = labels.into_iter().map(|v| v.into_inner().unwrap()).unzip();

        Ok((
            LabelsCache::<H>::from_stores(labels),
            Labels::<H>::new(configs),
        ))
    }

    fn build_tree<K: Hasher>(tree_data: &[u8], config: Option<StoreConfig>) -> Tree<K> {
        trace!("building tree (size: {})", tree_data.len());

        let leafs = tree_data.len() / NODE_SIZE;
        assert_eq!(tree_data.len() % NODE_SIZE, 0);
        if let Some(config) = config {
            MerkleTree::from_par_iter_with_config(
                (0..leafs)
                    .into_par_iter()
                    .map(|i| get_node::<K>(tree_data, i).unwrap()),
                config,
            )
        } else {
            MerkleTree::from_par_iter(
                (0..leafs)
                    .into_par_iter()
                    .map(|i| get_node::<K>(tree_data, i).unwrap()),
            )
        }
    }

    fn build_column_hashes(
        layers: usize,
        layer_size: usize,
        labels: &LabelsCache<H>,
    ) -> Result<Vec<[u8; 32]>> {
        let num_windows = layer_size / WINDOW_SIZE_BYTES;

        let mut hashes = Vec::with_capacity(WINDOW_SIZE_NODES);

        // TODO: parallelize
        for i in 0..WINDOW_SIZE_NODES {
            let first_label = labels.labels_for_layer(1).read_at(i);
            let mut hasher =
                crate::crypto::pedersen::Hasher::new(AsRef::<[u8]>::as_ref(&first_label));

            for window_index in 0..num_windows {
                for layer in 1..layers {
                    if window_index == 0 && layer == 1 {
                        // first label
                        continue;
                    }

                    let label = labels
                        .labels_for_layer(layer)
                        .read_at(i + window_index * WINDOW_SIZE_NODES);

                    hasher.update(AsRef::<[u8]>::as_ref(&label));
                }
            }

            hashes.push(hasher.finalize_bytes());
        }

        Ok(hashes)
    }

    pub(crate) fn transform_and_replicate_layers(
        window_graph: &StackedBucketGraph<H>,
        wrapper_graph: &StackedBucketGraph<H>,
        layer_challenges: &LayerChallenges,
        replica_id: &<H as Hasher>::Domain,
        data: &mut [u8],
        data_tree: Option<Tree<G>>,
        config: Option<StoreConfig>,
    ) -> Result<TransformedLayers<H, G>> {
        trace!("transform_and_replicate_layers");
        let window_nodes_count = window_graph.size();
        assert_eq!(data.len(), window_nodes_count * WINDOW_SIZE_BYTES);

        let wrapper_nodes_count = wrapper_graph.size();
        assert_eq!(data.len(), wrapper_nodes_count * NODE_SIZE);

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
            StoreConfig::from_config(&config, CacheKey::CommQTree.to_string(), None);
        let mut tree_q_config =
            StoreConfig::from_config(&config, CacheKey::CommCTree.to_string(), None);

        // Build the MerkleTree over the original data (if needed).
        let tree_d = match data_tree {
            Some(t) => {
                trace!("using existing original data merkle tree");
                assert_eq!(t.len(), 2 * (data.len() / NODE_SIZE) - 1);

                t
            }
            None => {
                trace!("building merkle tree for the original data");

                Self::build_tree::<G>(&data, Some(tree_d_config.clone()))
            }
        };

        let (labels, label_configs) = Self::encode_all_windows(
            window_graph,
            layer_challenges.layers(),
            replica_id,
            data,
            config.clone(),
        )?;

        // construct column hashes
        let column_hashes =
            Self::build_column_hashes(layer_challenges.layers(), data.len(), &labels)?;

        let tree_q: Tree<H> = Self::build_tree::<H>(&data, Some(tree_q_config.clone()));

        let tree_r_last: Tree<H> =
            MerkleTree::from_par_iter((0..wrapper_nodes_count).into_par_iter().map(|node| {
                // 1 Wrapping Layer

                let mut hasher = Sha256::new();
                hasher.input(AsRef::<[u8]>::as_ref(replica_id));
                hasher.input(&(node as u64).to_be_bytes()[..]);

                // Only expansion parents
                let mut exp_parents = vec![0; wrapper_graph.expansion_degree()];
                wrapper_graph.expanded_parents(node, &mut exp_parents);

                let wrapper_layer = &data;
                for parent in &exp_parents {
                    hasher.input(
                        data_at_node(wrapper_layer, *parent as usize).expect("invalid node math"),
                    );
                }

                // finalize key
                let mut val = hasher.result();
                // strip last two bits, to ensure result is in Fr.
                val[31] &= 0b0011_1111;

                H::Domain::try_from_bytes(&val).expect("invalid node created")
            }));

        let tree_c: Tree<H> = {
            info!("building tree_c");
            let column_hashes_flat = unsafe {
                // Column_hashes is of type Vec<[u8; 32]>, so this is safe to do.
                // We do this to avoid unnecessary allocations.
                std::slice::from_raw_parts(
                    column_hashes.as_ptr() as *const _,
                    column_hashes.len() * 32,
                )
            };
            Self::build_tree::<H>(column_hashes_flat, Some(tree_c_config.clone()))
        };

        // comm_r = H(comm_c || comm_q || comm_r_last)
        let comm_r: H::Domain =
            Fr::from(hash3(tree_c.root(), tree_q.root(), tree_r_last.root())).into();

        assert_eq!(tree_d.len(), tree_r_last.len());
        assert_eq!(tree_d.len(), tree_q.len());

        tree_d_config.size = Some(tree_d.len());
        tree_r_last_config.size = Some(tree_r_last.len());
        tree_c_config.size = Some(tree_c.len());
        tree_q_config.size = Some(tree_q.len());

        Ok((
            Tau {
                comm_d: tree_d.root(),
                comm_r,
            },
            PersistentAux {
                comm_c: tree_c.root(),
                comm_q: tree_q.root(),
                comm_r_last: tree_r_last.root(),
            },
            TemporaryAux {
                labels: label_configs,
                tree_d_config,
                tree_r_last_config,
                tree_c_config,
                tree_q_config,
                _g: PhantomData,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ff::Field;
    use merkletree::store::DEFAULT_CACHED_ABOVE_BASE_LAYER;
    use paired::bls12_381::Bls12;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    use crate::drgraph::{new_seed, BASE_DEGREE};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::{Blake2sHasher, PedersenHasher, Sha256Hasher};
    use crate::porep::PoRep;
    use crate::proof::ProofScheme;
    use crate::stacked::{PrivateInputs, SetupParams, EXP_DEGREE};

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
        // femme::pretty::Logger::new()
        //     .start(log::LevelFilter::Trace)
        //     .ok();

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);
        let replica_id: H::Domain = H::Domain::random(rng);
        let nodes = 8 * 32;

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
            data_copy.as_mut_slice(),
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

    #[test]
    fn extract_node_pedersen() {
        test_extract_node::<PedersenHasher>();
    }

    #[test]
    fn extract_node_sha256() {
        test_extract_node::<Sha256Hasher>();
    }

    #[test]
    fn extract_node_blake2s() {
        test_extract_node::<Blake2sHasher>();
    }

    fn test_extract_node<H: 'static + Hasher>() {
        // femme::pretty::Logger::new()
        //     .start(log::LevelFilter::Trace)
        //     .ok();

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);
        let replica_id: H::Domain = H::Domain::random(rng);
        let nodes = 8 * 32;

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
            data_copy.as_mut_slice(),
            None,
            Some(config.clone()),
        )
        .expect("replication failed");

        assert_ne!(data, data_copy);

        // extract parts
        for node in 0..nodes {
            println!("decoding node {}", node);
            let decoded_node = StackedDrg::<H, Blake2sHasher>::extract(
                &pp,
                &replica_id,
                &data_copy,
                node,
                Some(config.clone()),
            )
            .expect("failed to extract data");

            assert_eq!(data_at_node(&data, node).unwrap(), &decoded_node[..]);
        }
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
            data_copy.as_mut_slice(),
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

    #[cfg(not(feature = "mem-trees"))]
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
