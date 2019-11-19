use std::collections::HashMap;
use std::marker::PhantomData;

use merkletree::merkle::FromIndexedParallelIterator;
use merkletree::store::DiskStore;
use paired::bls12_381::Fr;
use rayon::prelude::*;
use sha2::{digest::generic_array::GenericArray, Digest, Sha256};

use crate::drgraph::Graph;
use crate::encode::{decode, encode};
use crate::error::Result;
use crate::hasher::{Domain, Hasher};
use crate::merkle::{MerkleProof, MerkleTree, Store};
use crate::stacked::{
    challenges::LayerChallenges,
    column::Column,
    graph::StackedBucketGraph,
    hash::hash2,
    params::{
        get_node, Labels, PersistentAux, Proof, PublicInputs, ReplicaColumnProof, Tau,
        TemporaryAux, TransformedLayers, Tree,
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
        _p_aux: &PersistentAux<H::Domain>,
        t_aux: &TemporaryAux<H, G>,
        layer_challenges: &LayerChallenges,
        layers: usize,
        _total_layers: usize,
        partition_count: usize,
    ) -> Result<Vec<Vec<Proof<H, G>>>> {
        assert!(layers > 0);
        assert_eq!(t_aux.labels.len(), layers);

        let graph_size = graph.size();

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
                                    "Invalid encoding proof generated"
                                );
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
    ) -> Result<()> {
        trace!("extract_and_invert_transform_layers");

        let layers = layer_challenges.layers();
        assert!(layers > 0);

        // generate labels
        let (labels, _) = Self::generate_labels(graph, layer_challenges, replica_id, false)?;

        let size = Store::len(labels.labels_for_last_layer());

        for (key, encoded_node_bytes) in labels
            .labels_for_last_layer()
            .read_range(0..size)
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
        with_hashing: bool,
    ) -> Result<(Labels<H>, Option<Vec<[u8; 32]>>)> {
        info!("generate labels");
        let layers = layer_challenges.layers();
        let mut labels: Vec<DiskStore<H::Domain>> = Vec::with_capacity(layers);

        let layer_size = graph.size() * NODE_SIZE;
        let mut parents = vec![0; graph.degree()];
        let mut layer_labels = vec![0u8; layer_size];

        use crate::crypto::pedersen::Hasher as PedersenHasher;

        let mut exp_parents_data: Option<Vec<u8>> = None;

        // setup hasher to reuse
        let mut base_hasher = Sha256::new();
        // hash replica id
        base_hasher.input(AsRef::<[u8]>::as_ref(replica_id));

        enum Message {
            Init(usize, GenericArray<u8, <Sha256 as Digest>::OutputSize>),
            Hash(usize, GenericArray<u8, <Sha256 as Digest>::OutputSize>),
            Done,
        }

        let graph_size = graph.size();

        // 1 less, to account for the thread we are on.
        let chunks = std::cmp::min(graph_size / 4, num_cpus::get() - 1);
        let chunk_len = (graph_size as f64 / chunks as f64).ceil() as usize;

        // Construct column hashes on a background thread.
        let cs_handle = if with_hashing {
            info!("hashing columns with {} chunks", chunks);
            let handles = (0..chunks)
                .map(|i| {
                    let (sender, receiver) = crossbeam::channel::unbounded();
                    let handle = std::thread::spawn(move || {
                        let mut column_hashes = Vec::with_capacity(chunk_len);
                        loop {
                            match receiver.recv().unwrap() {
                                Message::Init(_node, ref hash) => {
                                    column_hashes.push(PedersenHasher::new(hash))
                                }
                                Message::Hash(node, ref hash) => {
                                    column_hashes[node - i * chunk_len].update(hash)
                                }
                                Message::Done => {
                                    trace!("Finalizing column commitments {}", i);
                                    return column_hashes
                                        .into_iter()
                                        .map(|h| h.finalize_bytes())
                                        .collect::<Vec<[u8; 32]>>();
                                }
                            }
                        }
                    });

                    (handle, sender)
                })
                .collect::<Vec<_>>();

            Some(handles)
        } else {
            None
        };

        for i in 0..layers {
            let layer = i + 1;
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
                layer_labels[start..end].copy_from_slice(&key[..]);

                if with_hashing {
                    let sender_index = node / chunk_len;
                    let sender = &cs_handle.as_ref().unwrap()[sender_index].1;
                    if layer == 1 {
                        // Initialize hashes on layer 1.
                        sender
                            .send(Message::Init(node, key))
                            .expect("failed to init hasher");
                    } else {
                        // Update hashes for all other layers.
                        sender
                            .send(Message::Hash(node, key))
                            .expect("failed to update hasher");
                    }
                }
            }

            if with_hashing && layer == layers {
                // Finalize column hashes.
                for (_, sender) in cs_handle.as_ref().unwrap().iter() {
                    sender
                        .send(Message::Done)
                        .expect("failed to finalize hasher");
                }
            }

            // NOTE: this means we currently keep 2x sector size around, to improve speed.
            if let Some(ref mut exp_parents_data) = exp_parents_data {
                exp_parents_data.copy_from_slice(&layer_labels);
            } else {
                exp_parents_data = Some(layer_labels.clone());
            }

            // Write the result to disk to avoid keeping it in memory all the time.
            labels.push(DiskStore::new_from_slice(layer_size, &layer_labels)?);
        }

        assert_eq!(
            labels.len(),
            layers,
            "Invalid amount of layers encoded expected"
        );

        // Collect the column hashes from the spawned threads.
        let column_hashes = cs_handle.map(|handles| {
            handles
                .into_iter()
                .flat_map(|(h, _)| h.join().unwrap())
                .collect()
        });

        info!("Labels generated");
        Ok((Labels::<H>::new(labels), column_hashes))
    }

    fn build_tree<K: Hasher>(tree_data: &[u8]) -> Tree<K> {
        trace!("building tree (size: {})", tree_data.len());

        let leafs = tree_data.len() / NODE_SIZE;
        assert_eq!(tree_data.len() % NODE_SIZE, 0);
        MerkleTree::from_par_iter(
            (0..leafs)
                .into_par_iter()
                .map(|i| get_node::<K>(tree_data, i).unwrap()),
        )
    }

    pub(crate) fn transform_and_replicate_layers(
        graph: &StackedBucketGraph<H>,
        layer_challenges: &LayerChallenges,
        replica_id: &<H as Hasher>::Domain,
        data: &mut [u8],
        data_tree: Option<Tree<G>>,
    ) -> Result<TransformedLayers<H, G>> {
        trace!("transform_and_replicate_layers");
        let nodes_count = graph.size();

        assert_eq!(data.len(), nodes_count * NODE_SIZE);

        let layers = layer_challenges.layers();
        assert!(layers > 0);

        let (labels, column_hashes, tree_d) = crossbeam::thread::scope(|s| {
            // Generate key layers.
            let h = s.spawn(|_| Self::generate_labels(graph, layer_challenges, replica_id, true));

            // Build the MerkleTree over the original data.
            let tree_d = match data_tree {
                Some(t) => t,
                None => {
                    info!("building merkle tree for the original data");
                    Self::build_tree::<G>(&data)
                }
            };

            let (labels, column_hashes) = h.join().unwrap().unwrap();
            let column_hashes = column_hashes.unwrap();

            (labels, column_hashes, tree_d)
        })?;

        let (tree_r_last, tree_c, comm_r): (Tree<H>, Tree<H>, H::Domain) =
            crossbeam::thread::scope(|s| -> Result<_> {
                // Encode original data into the last layer.
                let tree_r_last_handle = s.spawn(|_| {
                    info!("encoding data");
                    let size = Store::len(labels.labels_for_last_layer());
                    labels
                        .labels_for_last_layer()
                        .read_range(0..size)
                        .into_par_iter()
                        .zip(data.par_chunks_mut(NODE_SIZE))
                        .for_each(|(key, data_node_bytes)| {
                            let data_node = H::Domain::try_from_bytes(data_node_bytes).unwrap();
                            let encoded_node = encode::<H::Domain>(key, data_node);

                            // Store the result in the place of the original data.
                            data_node_bytes.copy_from_slice(AsRef::<[u8]>::as_ref(&encoded_node));
                        });

                    // Construct the final replica commitment.
                    info!("building tree_r_last");
                    Self::build_tree::<H>(data)
                });

                // Build the tree for CommC
                let tree_c_handle = s.spawn(|_| {
                    info!("building tree_c");
                    let column_hashes_flat = unsafe {
                        // Column_hashes is of type Vec<[u8; 32]>, so this is safe to do.
                        // We do this to avoid unnecessary allocations.
                        std::slice::from_raw_parts(
                            column_hashes.as_ptr() as *const _,
                            column_hashes.len() * 32,
                        )
                    };
                    Self::build_tree::<H>(column_hashes_flat)
                });

                let tree_c: Tree<H> = tree_c_handle.join()?;
                info!("tree_c done");
                let tree_r_last: Tree<H> = tree_r_last_handle.join()?;
                info!("tree_r_last done");

                // comm_r = H(comm_c || comm_r_last)
                let comm_r: H::Domain = Fr::from(hash2(tree_c.root(), tree_r_last.root())).into();

                Ok((tree_r_last, tree_c, comm_r))
            })??;

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
                labels,
                tree_c,
                tree_d,
                tree_r_last,
            },
        ))
    }
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

        StackedDrg::<H, Blake2sHasher>::replicate(&pp, &replica_id, data_copy.as_mut_slice(), None)
            .expect("replication failed");

        assert_ne!(data, data_copy);

        let decoded_data =
            StackedDrg::<H, Blake2sHasher>::extract_all(&pp, &replica_id, data_copy.as_mut_slice())
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

        let pp = StackedDrg::<H, Blake2sHasher>::setup(&sp).expect("setup failed");
        let (tau, (p_aux, t_aux)) = StackedDrg::<H, Blake2sHasher>::replicate(
            &pp,
            &replica_id,
            data_copy.as_mut_slice(),
            None,
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
