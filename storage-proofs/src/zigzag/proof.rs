use std::marker::PhantomData;

use paired::bls12_381::Fr;
use rayon::prelude::*;

use crate::drgraph::Graph;
use crate::error::Result;
use crate::hasher::Hasher;
use crate::merkle::{next_pow2, populate_leaves, MerkleProof, MerkleStore, Store};
use crate::util::NODE_SIZE;
use crate::vde;
use crate::zigzag::{
    challenges::LayerChallenges,
    column::Column,
    encoding_proof::EncodingProof,
    graph::ZigZagBucketGraph,
    hash::hash2,
    params::{
        get_node, Encodings, PersistentAux, Proof, PublicInputs, ReplicaColumnProof, Tau,
        TemporaryAux, TransformedLayers, Tree,
    },
};

#[derive(Debug)]
pub struct ZigZagDrgPoRep<'a, H: 'a + Hasher> {
    _a: PhantomData<&'a H>,
}

impl<'a, H: 'static + Hasher> ZigZagDrgPoRep<'a, H> {
    /// Transform a layer's public parameters, returning new public parameters corresponding to the next layer.
    /// Warning: This method will likely need to be extended for other implementations
    /// but because it is not clear what parameters they will need, only the ones needed
    /// for zizag are currently present (same applies to [invert_transform]).
    pub(crate) fn transform(graph: &ZigZagBucketGraph<H>) -> ZigZagBucketGraph<H> {
        graph.zigzag()
    }

    /// Transform a layer's public parameters, returning new public parameters corresponding to the previous layer.
    pub(crate) fn invert_transform(graph: &ZigZagBucketGraph<H>) -> ZigZagBucketGraph<H> {
        graph.zigzag_invert()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prove_layers(
        graph_0: &ZigZagBucketGraph<H>,
        pub_inputs: &PublicInputs<<H as Hasher>::Domain>,
        _p_aux: &PersistentAux<H::Domain>,
        t_aux: &TemporaryAux<H>,
        layer_challenges: &LayerChallenges,
        layers: usize,
        _total_layers: usize,
        partition_count: usize,
    ) -> Result<Vec<Vec<Proof<H>>>> {
        assert!(layers > 0);
        assert_eq!(t_aux.encodings.len(), layers - 1);

        let graph_size = graph_0.size();
        assert_eq!(t_aux.es.len(), graph_size);
        assert_eq!(t_aux.os.len(), graph_size);

        let graph_1 = Self::transform(&graph_0);
        let graph_2 = Self::transform(&graph_1);

        assert_eq!(graph_0.layer(), 0);
        assert_eq!(graph_1.layer(), 1);
        assert_eq!(graph_2.layer(), 2);

        let get_drg_parents_columns = |x: usize| -> Result<Vec<Column<H>>> {
            let base_degree = graph_0.base_graph().degree();

            let mut columns = Vec::with_capacity(base_degree);

            let mut parents = vec![0; base_degree];
            graph_0.base_parents(x, &mut parents);

            for parent in &parents {
                columns.push(t_aux.full_column(graph_0, *parent)?);
            }

            debug_assert!(columns.len() == base_degree);

            Ok(columns)
        };

        let get_exp_parents_even_columns = |x: usize| -> Result<Vec<Column<H>>> {
            let exp_degree = graph_1.expansion_degree();

            let mut columns = Vec::with_capacity(exp_degree);

            let mut parents = vec![0; exp_degree];
            graph_1.expanded_parents(x, |p| {
                parents.copy_from_slice(p);
            });

            for parent in &parents {
                columns.push(t_aux.even_column(*parent as usize)?);
            }
            debug_assert!(columns.len() == exp_degree);

            Ok(columns)
        };

        let get_exp_parents_odd_columns = |x: usize| -> Result<Vec<Column<H>>> {
            let exp_degree = graph_2.expansion_degree();

            let mut columns = Vec::with_capacity(exp_degree);

            let mut parents = vec![0; exp_degree];
            graph_2.expanded_parents(x, |p| {
                parents.copy_from_slice(p);
            });

            for parent in &parents {
                columns.push(t_aux.odd_column(*parent as usize)?);
            }
            debug_assert!(columns.len() == exp_degree);

            Ok(columns)
        };

        (0..partition_count)
            .map(|k| {
                trace!("proving partition {}/{}", k + 1, partition_count);

                // Derive the set of challenges we are proving over.
                let challenges = pub_inputs.challenges(layer_challenges, graph_size, Some(k));

                // ZigZag commitment specifics
                challenges
                    .into_par_iter()
                    .map(|challenge| {
                        trace!(" challenge {}", challenge);
                        assert!(challenge < graph_0.size());

                        let inv_challenge = graph_0.inv_index(challenge);

                        // Initial data layer openings (D_X in Comm_D)
                        let comm_d_proof =
                            MerkleProof::new_from_proof(&t_aux.tree_d.gen_proof(challenge));

                        // ZigZag replica column openings
                        let rpc = {
                            // All labels in C_X
                            trace!("  c_x");
                            let c_x = t_aux
                                .full_column(&graph_0, challenge)?
                                .into_proof_all(&t_aux.tree_c);

                            // Only odd-layer labels in the renumbered column C_\bar{X}
                            trace!("  c_inv_x");
                            let c_inv_x = t_aux
                                .full_column(&graph_0, inv_challenge)?
                                .into_proof_all(&t_aux.tree_c);

                            // All labels in the DRG parents.
                            trace!("  drg_parents");
                            let drg_parents = get_drg_parents_columns(challenge)?
                                .into_iter()
                                .map(|column| column.into_proof_all(&t_aux.tree_c))
                                .collect::<Vec<_>>();

                            // Odd layer labels for the expander parents
                            trace!("  exp_parents_odd");
                            let exp_parents_odd = get_exp_parents_odd_columns(challenge)?
                                .into_iter()
                                .map(|column| {
                                    let index = column.index();
                                    column.into_proof_odd(&t_aux.tree_c, t_aux.es[index])
                                })
                                .collect::<Vec<_>>();

                            // Even layer labels for the expander parents
                            trace!("  exp_parents_even");
                            let exp_parents_even = get_exp_parents_even_columns(inv_challenge)?
                                .into_iter()
                                .map(|column| {
                                    let index = graph_1.inv_index(column.index());
                                    column.into_proof_even(&t_aux.tree_c, &graph_1, t_aux.os[index])
                                })
                                .collect::<Vec<_>>();

                            ReplicaColumnProof {
                                c_x,
                                c_inv_x,
                                drg_parents,
                                exp_parents_even,
                                exp_parents_odd,
                            }
                        };

                        // Final replica layer openings
                        trace!("final replica layer openings");
                        let comm_r_last_proofs = {
                            // All challenged Labels e_\bar{X}^(L)
                            trace!("  inclusion proof");
                            let inclusion_proof = MerkleProof::new_from_proof(
                                &t_aux.tree_r_last.gen_proof(inv_challenge),
                            );

                            // Even challenged parents (any kind)
                            trace!(" even parents");
                            let mut parents = vec![0; graph_1.degree()];
                            graph_1.parents(inv_challenge, &mut parents);

                            let even_parents_proof = parents
                                .into_iter()
                                .map(|parent| {
                                    MerkleProof::new_from_proof(
                                        &t_aux.tree_r_last.gen_proof(parent),
                                    )
                                })
                                .collect::<Vec<_>>();

                            (inclusion_proof, even_parents_proof)
                        };

                        // Encoding Proof layer 1
                        trace!("  encoding proof layer 1");
                        let encoding_proof_1 = {
                            let encoded_node = rpc.c_x.get_verified_node_at_layer(1);
                            let decoded_node = comm_d_proof.verified_leaf();

                            let mut parents = vec![0; graph_0.degree()];
                            graph_0.parents(challenge, &mut parents);

                            let parents_data = parents
                                .into_iter()
                                .map(|parent| t_aux.domain_node_at_layer(1, parent))
                                .collect::<Result<_>>()?;

                            EncodingProof::<H>::new(encoded_node, decoded_node, parents_data)
                        };

                        // Encoding Proof Layer 2..l-1
                        let mut encoding_proofs = Vec::with_capacity(layers - 2);
                        {
                            for layer in 2..layers {
                                trace!("  encoding proof layer {}", layer);
                                let (graph, challenge, encoded_node, decoded_node) =
                                    if layer % 2 == 0 {
                                        (
                                            &graph_1,
                                            inv_challenge,
                                            rpc.c_x.get_verified_node_at_layer(layer),
                                            rpc.c_inv_x.get_verified_node_at_layer(layer - 1),
                                        )
                                    } else {
                                        (
                                            &graph_2,
                                            challenge,
                                            rpc.c_x.get_verified_node_at_layer(layer),
                                            rpc.c_inv_x.get_verified_node_at_layer(layer - 1),
                                        )
                                    };

                                let mut parents = vec![0; graph.degree()];
                                graph.parents(challenge, &mut parents);

                                let parents_data = parents
                                    .into_iter()
                                    .map(|parent| t_aux.domain_node_at_layer(layer, parent))
                                    .collect::<Result<_>>()?;

                                let proof = EncodingProof::<H>::new(
                                    encoded_node.clone(),
                                    decoded_node.clone(),
                                    parents_data,
                                );

                                debug_assert!(
                                    proof.verify(
                                        &pub_inputs.replica_id,
                                        &encoded_node,
                                        &decoded_node
                                    ),
                                    "Invalid encoding proof generated"
                                );

                                encoding_proofs.push(proof);
                            }
                        }

                        Ok(Proof {
                            comm_d_proofs: comm_d_proof,
                            replica_column_proofs: rpc,
                            comm_r_last_proofs,
                            encoding_proof_1,
                            encoding_proofs,
                        })
                    })
                    .collect()
            })
            .collect()
    }

    pub(crate) fn extract_and_invert_transform_layers(
        graph: &ZigZagBucketGraph<H>,
        layer_challenges: &LayerChallenges,
        replica_id: &<H as Hasher>::Domain,
        data: &mut [u8],
    ) -> Result<()> {
        trace!("extract_and_invert_transform_layers");

        let layers = layer_challenges.layers();
        assert!(layers > 0);
        assert_eq!(graph.layer(), layers, "invalid graph passed");

        let last_graph = (0..layers).try_fold(
            graph.clone(),
            |current_graph, _layer| -> Result<ZigZagBucketGraph<H>> {
                let inverted = Self::invert_transform(&current_graph);
                let res = vde::decode(&inverted, replica_id, data)?;

                data.copy_from_slice(&res);

                Ok(inverted)
            },
        )?;

        assert_eq!(last_graph.layer(), 0);

        Ok(())
    }

    pub(crate) fn transform_and_replicate_layers(
        graph: &ZigZagBucketGraph<H>,
        layer_challenges: &LayerChallenges,
        replica_id: &<H as Hasher>::Domain,
        data: &mut [u8],
        data_tree: Option<Tree<H>>,
    ) -> Result<TransformedLayers<H>> {
        trace!("transform_and_replicate_layers");
        let nodes_count = graph.size();

        assert_eq!(data.len(), nodes_count * NODE_SIZE);

        // FIXME: The implementation below is a memory hog.

        let layers = layer_challenges.layers();
        assert!(layers > 0);

        let build_tree = |tree_data: &[u8]| {
            trace!("building tree {}", tree_data.len());

            let leafs = tree_data.len() / NODE_SIZE;
            assert_eq!(tree_data.len() % NODE_SIZE, 0);
            let pow = next_pow2(leafs);
            let mut leaves_store = MerkleStore::new(pow);
            populate_leaves::<_, <H as Hasher>::Function, _, std::iter::Map<_, _>>(
                &mut leaves_store,
                (0..leafs).map(|i| get_node::<H>(tree_data, i).unwrap()),
            );

            graph.merkle_tree_from_leaves(leaves_store, leafs)
        };

        // 1. Build the MerkleTree over the original data
        trace!("build merkle tree for the original data");
        let tree_d = match data_tree {
            Some(t) => t,
            None => build_tree(&data)?,
        };

        // 2. Encode all layers
        trace!("encode layers");
        let mut encodings: Vec<Vec<u8>> = Vec::with_capacity(layers - 1);
        let mut current_graph = graph.clone();
        let mut to_encode = data.to_vec();

        for layer in 0..layers {
            trace!("encoding (layer: {})", layer);
            vde::encode(&current_graph, replica_id, &mut to_encode)?;
            current_graph = Self::transform(&current_graph);

            assert_eq!(to_encode.len(), NODE_SIZE * nodes_count);

            if layer != layers - 1 {
                let p = to_encode.clone();
                encodings.push(p);
            }
        }

        assert_eq!(encodings.len(), layers - 1);

        let encodings = Encodings::<H>::new(encodings);

        let r_last = to_encode;

        // store the last layer in the original data
        data[..NODE_SIZE * nodes_count].copy_from_slice(&r_last);

        // 3. Construct Column Commitments
        let odd_columns = (0..nodes_count)
            .into_par_iter()
            .map(|x| encodings.odd_column(x));

        let even_columns = (0..nodes_count)
            .into_par_iter()
            .map(|x| encodings.even_column(graph.inv_index(x)));

        // O_i = H( e_i^(1) || .. )
        let os = odd_columns
            .map(|c| c.map(|c| Fr::from(c.hash()).into()))
            .collect::<Result<Vec<H::Domain>>>()?;

        // E_i = H( e_\bar{i}^(2) || .. )
        let es = even_columns
            .map(|c| c.map(|c| Fr::from(c.hash()).into()))
            .collect::<Result<Vec<H::Domain>>>()?;

        // C_i = H(O_i || E_i)
        let cs = os
            .par_iter()
            .zip(es.par_iter())
            .flat_map(|(o_i, e_i)| hash2(o_i, e_i).as_ref().to_vec())
            .collect::<Vec<u8>>();

        // Build the tree for CommC
        let tree_c = build_tree(&cs)?;

        // sanity check
        debug_assert_eq!(tree_c.read_at(0).as_ref(), &cs[..NODE_SIZE]);
        debug_assert_eq!(tree_c.read_at(1).as_ref(), &cs[NODE_SIZE..NODE_SIZE * 2]);

        // 4. Construct final replica commitment
        let tree_r_last = build_tree(&r_last)?;

        // comm_r = H(comm_c || comm_r_last)
        let comm_r: H::Domain = Fr::from(hash2(tree_c.root(), tree_r_last.root())).into();

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
                es,
                os,
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
    use crate::hasher::blake2s::Blake2sDomain;
    use crate::hasher::{Blake2sHasher, Domain, PedersenHasher, Sha256Hasher};
    use crate::porep::PoRep;
    use crate::proof::ProofScheme;
    use crate::zigzag::{PrivateInputs, SetupParams, EXP_DEGREE};

    const DEFAULT_ZIGZAG_LAYERS: usize = 4;

    #[test]
    fn test_calculate_fixed_challenges() {
        let layer_challenges = LayerChallenges::new_fixed(10, 333);
        let expected = 333;

        let calculated_count = layer_challenges.challenges_count();
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
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let replica_id: H::Domain = rng.gen();
        let nodes = 8;

        let data: Vec<u8> = (0..nodes)
            .flat_map(|_| {
                let v: H::Domain = rng.gen();
                v.as_ref().to_vec()
            })
            .collect();
        let challenges = LayerChallenges::new_fixed(DEFAULT_ZIGZAG_LAYERS, 5);

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

        let pp = ZigZagDrgPoRep::<H>::setup(&sp).expect("setup failed");

        ZigZagDrgPoRep::<H>::replicate(&pp, &replica_id, data_copy.as_mut_slice(), None)
            .expect("replication failed");

        assert_ne!(data, data_copy);

        let transformed_pp = pp.transform_to_last_layer();

        let decoded_data = ZigZagDrgPoRep::<H>::extract_all(
            &transformed_pp,
            &replica_id,
            data_copy.as_mut_slice(),
        )
        .expect("failed to extract data");

        assert_eq!(data, decoded_data);
    }

    fn prove_verify_fixed(n: usize) {
        let challenges = LayerChallenges::new_fixed(DEFAULT_ZIGZAG_LAYERS, 5);

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

        let pp = ZigZagDrgPoRep::<H>::setup(&sp).expect("setup failed");
        let (tau, (p_aux, t_aux)) =
            ZigZagDrgPoRep::<H>::replicate(&pp, &replica_id, data_copy.as_mut_slice(), None)
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
            &ZigZagDrgPoRep::<H>::prove_all_partitions(&pp, &pub_inputs, &priv_inputs, partitions)
                .expect("failed to generate partition proofs");

        let proofs_are_valid =
            ZigZagDrgPoRep::<H>::verify_all_partitions(&pp, &pub_inputs, all_partition_proofs)
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
        let layer_challenges = LayerChallenges::new_fixed(10, 333);
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
        let _pp = ZigZagDrgPoRep::<PedersenHasher>::setup(&sp).expect("setup failed");
    }

    #[test]
    fn test_odd_column() {
        let encodings = Encodings::<Blake2sHasher>::new(vec![
            vec![1; NODE_SIZE],
            vec![2; NODE_SIZE],
            vec![3; NODE_SIZE],
            vec![4; NODE_SIZE],
            vec![5; NODE_SIZE],
        ]);

        assert_eq!(
            encodings.odd_column(0).unwrap(),
            Column::new_odd(
                0,
                vec![
                    Blake2sDomain::try_from_bytes(&vec![1; NODE_SIZE]).unwrap(),
                    Blake2sDomain::try_from_bytes(&vec![3; NODE_SIZE]).unwrap(),
                    Blake2sDomain::try_from_bytes(&vec![5; NODE_SIZE]).unwrap(),
                ]
            )
        );
    }

    #[test]
    fn test_even_column() {
        let encodings = Encodings::<Blake2sHasher>::new(vec![
            vec![1; NODE_SIZE],
            vec![2; NODE_SIZE],
            vec![3; NODE_SIZE],
            vec![4; NODE_SIZE],
            vec![5; NODE_SIZE],
        ]);

        assert_eq!(
            encodings.even_column(0).unwrap(),
            Column::new_even(
                0,
                vec![
                    Blake2sDomain::try_from_bytes(&vec![2; NODE_SIZE]).unwrap(),
                    Blake2sDomain::try_from_bytes(&vec![4; NODE_SIZE]).unwrap(),
                ]
            ),
        );
    }

    #[test]
    fn test_full_column() {
        use itertools::Itertools;
        let nodes: usize = 8;

        let make_nodes = |x| {
            let mut res = Vec::new();
            for i in 0..nodes {
                res.extend_from_slice(&vec![x as u8; NODE_SIZE / 2]);
                res.extend_from_slice(&vec![i as u8; NODE_SIZE / 2]);
            }
            res
        };

        let encodings = Encodings::<Blake2sHasher>::new(vec![
            make_nodes(1),
            make_nodes(2),
            make_nodes(3),
            make_nodes(4),
            make_nodes(5),
        ]);

        let graph = ZigZagBucketGraph::<Blake2sHasher>::new_zigzag(
            nodes,
            BASE_DEGREE,
            EXP_DEGREE,
            0,
            new_seed(),
        );

        for node in 0..nodes {
            let even = encodings.even_column(graph.inv_index(node)).unwrap();
            let odd = encodings.odd_column(node).unwrap();
            let all = encodings.full_column(&graph, node).unwrap();
            assert_eq!(all.index(), node);

            assert_eq!(
                odd.rows()
                    .iter()
                    .cloned()
                    .interleave(even.rows().iter().cloned())
                    .collect::<Vec<_>>(),
                all.rows().clone(),
            );

            let col_hash = all.hash();
            let e_hash = even.hash();
            let o_hash = odd.hash();
            let combined_hash = hash2(&o_hash, &e_hash);

            assert_eq!(col_hash, combined_hash);
        }
    }
}
