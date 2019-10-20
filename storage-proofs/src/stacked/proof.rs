use std::marker::PhantomData;

use blake2s_simd::Params as Blake2s;
use merkletree::merkle::FromIndexedParallelIterator;
use merkletree::store::DiskStore;
use paired::bls12_381::Fr;
use rayon::prelude::*;

use crate::drgraph::Graph;
use crate::error::Result;
use crate::hasher::{Domain, Hasher};
use crate::merkle::{MerkleProof, MerkleTree, Store};
use crate::stacked::{
    challenges::LayerChallenges,
    column::Column,
    encode::{decode, encode},
    encoding_proof::EncodingProof,
    graph::StackedBucketGraph,
    hash::hash2,
    params::{
        get_node, Encodings, PersistentAux, Proof, PublicInputs, ReplicaColumnProof, Tau,
        TemporaryAux, TransformedLayers, Tree,
    },
};
use crate::util::{data_at_node, data_at_node_offset, NODE_SIZE};

#[derive(Debug)]
pub struct StackedDrg<'a, H: 'a + Hasher> {
    _a: PhantomData<&'a H>,
}

impl<'a, H: 'static + Hasher> StackedDrg<'a, H> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prove_layers(
        graph: &StackedBucketGraph<H>,
        pub_inputs: &PublicInputs<<H as Hasher>::Domain>,
        _p_aux: &PersistentAux<H::Domain>,
        t_aux: &TemporaryAux<H>,
        layer_challenges: &LayerChallenges,
        layers: usize,
        _total_layers: usize,
        partition_count: usize,
    ) -> Result<Vec<Vec<Proof<H>>>> {
        assert!(layers > 0);
        assert_eq!(t_aux.encodings.len(), layers);

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
            graph.expanded_parents(x, |parents| {
                parents
                    .iter()
                    .map(|parent| t_aux.column(*parent as usize))
                    .collect()
            })
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
                            let c_x = t_aux.column(challenge)?.into_proof(&t_aux.tree_c);

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

                        // Encoding Proof Layer 1..l
                        let mut encoding_proofs = Vec::with_capacity(layers);

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

                            let parents_data = if layer == 1 {
                                let mut parents = vec![0; graph.base_graph().degree()];
                                graph.base_parents(challenge, &mut parents);

                                parents
                                    .into_iter()
                                    .map(|parent| t_aux.domain_node_at_layer(layer, parent))
                                    .collect::<Result<_>>()?
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
                                    .collect::<Result<_>>()?
                            };

                            let proof = EncodingProof::<H>::new(challenge as u64, parents_data);

                            {
                                let (encoded_node, decoded_node) = if layer == layers {
                                    (comm_r_last_proof.leaf(), Some(comm_d_proof.leaf()))
                                } else {
                                    (rpc.c_x.get_node_at_layer(layer), None)
                                };

                                assert!(
                                    proof.verify(
                                        &pub_inputs.replica_id,
                                        &encoded_node,
                                        decoded_node
                                    ),
                                    "Invalid encoding proof generated"
                                );
                            }

                            encoding_proofs.push(proof);
                        }

                        Ok(Proof {
                            comm_d_proofs: comm_d_proof,
                            replica_column_proofs: rpc,
                            comm_r_last_proof,
                            encoding_proofs,
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

        // generate encodings
        let (encodings, _) = Self::generate_layers(graph, layer_challenges, replica_id, false)?;

        let size = encodings.encoding_at_last_layer().len();

        for (key, encoded_node_bytes) in encodings
            .encoding_at_last_layer()
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
    fn generate_layers(
        graph: &StackedBucketGraph<H>,
        layer_challenges: &LayerChallenges,
        replica_id: &<H as Hasher>::Domain,
        with_hashing: bool,
    ) -> Result<(Encodings<H>, Option<Vec<[u8; 32]>>)> {
        info!("generate layers");
        let layers = layer_challenges.layers();
        let mut encodings: Vec<DiskStore<H::Domain>> = Vec::with_capacity(layers);

        let layer_size = graph.size() * NODE_SIZE;
        let mut parents = vec![0; graph.degree()];
        let mut encoding = vec![0u8; layer_size];

        use crate::crypto::pedersen::Hasher as PedersenHasher;

        let mut exp_parents_data: Option<Vec<u8>> = None;

        // setup hasher to reuse
        let mut base_hasher = Blake2s::new().hash_length(NODE_SIZE).to_state();
        // hash replica id
        base_hasher.update(AsRef::<[u8]>::as_ref(replica_id));

        let (sender, receiver) = crossbeam::channel::unbounded();
        enum Message {
            Init(usize, [u8; 32]),
            Hash(usize, [u8; 32]),
            Done,
        }

        let graph_size = graph.size();

        // Construct column hashes on a background thread.
        let cs_handle = if with_hashing {
            Some(std::thread::spawn(move || {
                let mut column_hashes = Vec::with_capacity(graph_size);
                while let Ok(msg) = receiver.recv() {
                    match msg {
                        Message::Init(_node, ref hash) => {
                            column_hashes.push(PedersenHasher::new(hash))
                        }
                        Message::Hash(node, ref hash) => column_hashes[node].update(hash),
                        Message::Done => {
                            return column_hashes
                                .into_iter()
                                .map(|h| h.finalize_bytes())
                                .collect::<Vec<[u8; 32]>>();
                        }
                    }
                }
                panic!("Need to finalize with a Done call");
            }))
        } else {
            None
        };

        for i in 0..layers {
            let layer = i + 1;
            info!("generating layer: {}", layer);

            for node in 0..graph.size() {
                graph.parents(node, &mut parents);

                // CreateKey inlined, to avoid borrow issues

                let mut hasher = base_hasher.clone();

                // hash node id
                let node_arr = (node as u64).to_le_bytes();
                hasher.update(&node_arr);

                // hash parents for all non 0 nodes
                if node > 0 {
                    let base_parents_count = graph.base_graph().degree();

                    // Base parents
                    for parent in parents.iter().take(base_parents_count) {
                        let buf = data_at_node(&encoding, *parent).expect("invalid node");
                        hasher.update(buf);
                    }

                    if let Some(ref parents_data) = exp_parents_data {
                        // Expander parents
                        for parent in parents.iter().skip(base_parents_count) {
                            let buf = data_at_node(parents_data, *parent).expect("invalid node");
                            hasher.update(&buf);
                        }
                    }
                }

                let start = data_at_node_offset(node);
                let end = start + NODE_SIZE;

                // store resulting key
                let mut key = *hasher.finalize().as_array();
                // strip last two bits, to ensure result is in Fr.
                key[31] &= 0b0011_1111;

                encoding[start..end].copy_from_slice(&key[..]);

                if with_hashing {
                    if layer == 1 {
                        sender
                            .send(Message::Init(node, key))
                            .expect("failed to init hasher");
                    } else {
                        sender
                            .send(Message::Hash(node, key))
                            .expect("failed to update hasher");
                    }
                }
            }

            // NOTE: this means we currently keep 2x sector size around, to improve speed.
            if let Some(ref mut exp_parents_data) = exp_parents_data {
                exp_parents_data.copy_from_slice(&encoding);
            } else {
                exp_parents_data = Some(encoding.clone());
            }

            // Write the result to disk to avoid keeping it in memory all the time.
            encodings.push(DiskStore::new_from_slice(layer_size, &encoding)?);
        }

        if with_hashing {
            sender
                .send(Message::Done)
                .expect("failed to finalize hasher");
        }

        assert_eq!(
            encodings.len(),
            layers,
            "Invalid amount of layers encoded expected"
        );

        let column_hashes_vec = cs_handle.map(|handle| handle.join().unwrap());
        Ok((Encodings::<H>::new(encodings), column_hashes_vec))
    }

    pub(crate) fn transform_and_replicate_layers(
        graph: &StackedBucketGraph<H>,
        layer_challenges: &LayerChallenges,
        replica_id: &<H as Hasher>::Domain,
        data: &mut [u8],
        data_tree: Option<Tree<H>>,
    ) -> Result<TransformedLayers<H>> {
        trace!("transform_and_replicate_layers");
        let nodes_count = graph.size();

        assert_eq!(data.len(), nodes_count * NODE_SIZE);

        let layers = layer_challenges.layers();
        assert!(layers > 0);

        let build_tree = |tree_data: &[u8]| {
            trace!("building tree (size: {})", tree_data.len());

            let leafs = tree_data.len() / NODE_SIZE;
            assert_eq!(tree_data.len() % NODE_SIZE, 0);
            MerkleTree::from_par_iter(
                (0..leafs)
                    .into_par_iter()
                    .map(|i| get_node::<H>(tree_data, i).unwrap()),
            )
        };

        // encode layers
        let (encodings, column_hashes) =
            Self::generate_layers(graph, layer_challenges, replica_id, true)?;
        let column_hashes = column_hashes.unwrap();

        // Build the MerkleTree over the original data
        info!("building merkle tree for the original data");
        let tree_d = match data_tree {
            Some(t) => t,
            None => build_tree(&data),
        };

        let (tree_r_last, tree_c, comm_r): (Tree<H>, Tree<H>, H::Domain) =
            crossbeam::thread::scope(|s| -> Result<_> {
                // encode original data into the last layer
                let tree_r_last_handle = s.spawn(|_| {
                    info!("encoding data");
                    let size = encodings.encoding_at_last_layer().len();
                    encodings
                        .encoding_at_last_layer()
                        .read_range(0..size)
                        .into_par_iter()
                        .zip(data.par_chunks_mut(NODE_SIZE))
                        .for_each(|(key, data_node_bytes)| {
                            let data_node = H::Domain::try_from_bytes(data_node_bytes).unwrap();
                            let encoded_node = encode::<H::Domain>(key, data_node);

                            // store result in the data
                            data_node_bytes.copy_from_slice(AsRef::<[u8]>::as_ref(&encoded_node));
                        });

                    // construct final replica commitment
                    build_tree(data)
                });

                // build the tree for CommC
                let tree_c_handle = s.spawn(|_| {
                    let column_hashes_flat = unsafe {
                        // column_hashes is of type Vec<[u8; 32]>
                        std::slice::from_raw_parts(
                            column_hashes.as_ptr() as *const _,
                            column_hashes.len() * 32,
                        )
                    };
                    build_tree(column_hashes_flat)
                });

                let tree_c = tree_c_handle.join()?;
                let tree_r_last = tree_r_last_handle.join()?;

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
                encodings,
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

    use paired::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};

    use crate::drgporep;
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

        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let replica_id: H::Domain = rng.gen();
        let nodes = 8;

        let data: Vec<u8> = (0..nodes)
            .flat_map(|_| {
                let v: H::Domain = rng.gen();
                v.into_bytes()
            })
            .collect();
        let challenges = LayerChallenges::new(DEFAULT_STACKED_LAYERS, 5);

        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();

        let sp = SetupParams {
            drg: drgporep::DrgParams {
                nodes,
                degree: BASE_DEGREE,
                expansion_degree: EXP_DEGREE,
                seed: new_seed(),
            },
            layer_challenges: challenges.clone(),
        };

        let pp = StackedDrg::<H>::setup(&sp).expect("setup failed");

        StackedDrg::<H>::replicate(&pp, &replica_id, data_copy.as_mut_slice(), None)
            .expect("replication failed");

        assert_ne!(data, data_copy);

        let decoded_data = StackedDrg::<H>::extract_all(&pp, &replica_id, data_copy.as_mut_slice())
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

        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let degree = BASE_DEGREE;
        let expansion_degree = EXP_DEGREE;
        let replica_id: H::Domain = rng.gen();
        let data: Vec<u8> = (0..n)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();
        let partitions = 2;

        let sp = SetupParams {
            drg: drgporep::DrgParams {
                nodes: n,
                degree,
                expansion_degree,
                seed: new_seed(),
            },
            layer_challenges: challenges.clone(),
        };

        let pp = StackedDrg::<H>::setup(&sp).expect("setup failed");
        let (tau, (p_aux, t_aux)) =
            StackedDrg::<H>::replicate(&pp, &replica_id, data_copy.as_mut_slice(), None)
                .expect("replication failed");
        assert_ne!(data, data_copy);

        let pub_inputs = PublicInputs::<H::Domain> {
            replica_id,
            seed: None,
            tau: Some(tau),
            k: None,
        };

        let priv_inputs = PrivateInputs { p_aux, t_aux };

        let all_partition_proofs =
            &StackedDrg::<H>::prove_all_partitions(&pp, &pub_inputs, &priv_inputs, partitions)
                .expect("failed to generate partition proofs");

        let proofs_are_valid =
            StackedDrg::<H>::verify_all_partitions(&pp, &pub_inputs, all_partition_proofs)
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
            drg: drgporep::DrgParams {
                nodes,
                degree,
                expansion_degree,
                seed: new_seed(),
            },
            layer_challenges: layer_challenges.clone(),
        };

        // When this fails, the call to setup should panic, but seems to actually hang (i.e. neither return nor panic) for some reason.
        // When working as designed, the call to setup returns without error.
        let _pp = StackedDrg::<PedersenHasher>::setup(&sp).expect("setup failed");
    }
}
