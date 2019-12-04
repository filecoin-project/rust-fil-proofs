use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Mutex;

use anyhow::{ensure, Context};
use generic_array::GenericArray;
use log::{info, trace};
use merkletree::merkle::FromIndexedParallelIterator;
use merkletree::store::{DiskStore, StoreConfig};
use paired::bls12_381::Fr;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
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
        get_node, CacheKey, Labels, LabelsCache, PersistentAux, Proof, PublicInputs, PublicParams,
        ReplicaColumnProof, Tau, TemporaryAux, TemporaryAuxCache, TransformedLayers, Tree,
        WindowProof, WrapperProof,
    },
    EncodingProof, LabelingProof, OPENINGS_PER_WINDOW,
};
use crate::util::{data_at_node, data_at_node_offset, NODE_SIZE};

#[derive(Debug)]
pub struct StackedDrg<'a, H: 'a + Hasher, G: 'a + Hasher> {
    _a: PhantomData<&'a H>,
    _b: PhantomData<&'a G>,
}

fn get_drg_parents_columns<H: Hasher, G: Hasher>(
    graph: &StackedBucketGraph<H>,
    t_aux: &TemporaryAuxCache<H, G>,
    x: usize,
    pub_params: &PublicParams<H>,
) -> Result<Vec<Column<H>>> {
    let base_degree = graph.base_graph().degree();

    let mut columns = Vec::with_capacity(base_degree);

    let mut parents = vec![0; base_degree];
    graph.base_parents(x, &mut parents)?;

    for parent in &parents {
        columns.push(t_aux.column(*parent, pub_params)?);
    }

    debug_assert!(columns.len() == base_degree);

    Ok(columns)
}

fn get_exp_parents_columns<H: Hasher, G: Hasher>(
    graph: &StackedBucketGraph<H>,
    t_aux: &TemporaryAuxCache<H, G>,
    x: usize,
    pub_params: &PublicParams<H>,
) -> Result<Vec<Column<H>>> {
    let mut parents = vec![0; graph.expansion_degree()];
    graph.expanded_parents(x, &mut parents)?;

    parents
        .iter()
        .map(|parent| t_aux.column(*parent, pub_params))
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackedConfig {
    pub window_challenges: LayerChallenges,
    pub wrapper_challenges: LayerChallenges,
}

impl StackedConfig {
    pub fn new(layers: usize, window_count: usize, wrapper_count: usize) -> Result<Self> {
        Ok(StackedConfig {
            window_challenges: LayerChallenges::new(layers, window_count)?,
            wrapper_challenges: LayerChallenges::new(layers, wrapper_count)?,
        })
    }

    pub fn layers(&self) -> usize {
        // they are both the same
        self.window_challenges.layers()
    }
}

impl<'a, H: 'static + Hasher, G: 'static + Hasher> StackedDrg<'a, H, G> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prove_single_partition(
        pub_params: &PublicParams<H>,
        pub_inputs: &PublicInputs<<H as Hasher>::Domain, <G as Hasher>::Domain>,
        t_aux: &TemporaryAuxCache<H, G>,
        k: usize,
    ) -> Result<Proof<H, G>> {
        // Sanity checks on restored trees.
        ensure!(pub_inputs.tau.is_some(), "no tau in inputs");
        ensure!(
            pub_inputs.tau.as_ref().context("no tau in inputs")?.comm_d == t_aux.tree_d.root(),
            "comm_d must equal the tree_d root"
        );

        // Derive the set of challenges we are proving over.
        let config = &pub_params.config;
        let window_graph = &pub_params.window_graph;
        let wrapper_graph = &pub_params.wrapper_graph;

        let window_challenges =
            pub_inputs.all_challenges(&config.window_challenges, window_graph.size(), Some(k))?;

        let window_proofs: Vec<_> = window_challenges
            .into_par_iter()
            .enumerate()
            .map(|(challenge_index, challenge)| {
                Self::prove_window_challenge(
                    challenge,
                    challenge_index,
                    pub_params,
                    pub_inputs,
                    t_aux,
                )
            })
            .collect::<Result<_>>()?;

        let wrapper_challenges =
            pub_inputs.all_challenges(&config.wrapper_challenges, wrapper_graph.size(), Some(k))?;

        let wrapper_proofs: Vec<_> = wrapper_challenges
            .into_par_iter()
            .enumerate()
            .map(|(challenge_index, challenge)| {
                Self::prove_wrapper_challenge(challenge, challenge_index, wrapper_graph, t_aux)
            })
            .collect::<Result<_>>()?;

        Ok(Proof {
            window_proofs,
            wrapper_proofs,
            comm_c: t_aux.tree_c.root(),
            comm_q: t_aux.tree_q.root(),
            comm_r_last: t_aux.tree_r_last.root(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn prove_window_challenge(
        challenge: usize,
        challenge_index: usize,
        pub_params: &PublicParams<H>,
        pub_inputs: &PublicInputs<<H as Hasher>::Domain, <G as Hasher>::Domain>,
        t_aux: &TemporaryAuxCache<H, G>,
    ) -> Result<WindowProof<H, G>> {
        let window_graph = &pub_params.window_graph;
        let layer_challenges = &pub_params.config.window_challenges;
        ensure!(
            challenge < pub_params.window_size_nodes(),
            "Invalide challenge"
        );

        trace!("challenge {} ({})", challenge, challenge_index);
        ensure!(challenge < window_graph.size(), "Invalid challenge");
        ensure!(challenge > 0, "Invalid challenge");

        let layers = layer_challenges.layers();
        let num_windows = pub_params.num_windows();

        // Initial data layer openings (c_X in Comm_D)
        let comm_d_proofs = (0..OPENINGS_PER_WINDOW)
            .map(|window_index| {
                let c = window_index * pub_params.window_size_nodes() + challenge;
                Ok(MerkleProof::new_from_proof(&t_aux.tree_d.gen_proof(c)?))
            })
            .collect::<Result<_>>()?;

        // Stacked replica column openings
        let replica_column_proof = Self::prove_replica_column(pub_params, challenge, t_aux)?;

        trace!("q openings");
        let comm_q_proofs = (0..OPENINGS_PER_WINDOW)
            .map(|window_index| {
                let c = window_index * pub_params.window_size_nodes() + challenge;
                Ok(MerkleProof::new_from_proof(&t_aux.tree_q.gen_proof(c)?))
            })
            .collect::<Result<_>>()?;

        let mut encoding_proofs = Vec::with_capacity(num_windows);
        let labeling_proofs = (0..OPENINGS_PER_WINDOW)
            .map(|window_index| {
                // Labeling Proofs Layer 1..l
                let mut labeling_proofs = HashMap::with_capacity(layers);

                for layer in 1..=layers {
                    let parents_data = Self::get_parents_data_for_challenge(
                        pub_params,
                        window_index,
                        challenge,
                        layer,
                        t_aux,
                    )?;

                    if layer < layers {
                        trace!("labeling proof window: {}, layer {}", window_index, layer);
                        let proof = LabelingProof::<H>::new(
                            Some(window_index as u64),
                            challenge as u64,
                            parents_data.clone(),
                        );

                        {
                            let expected_labeled_node = replica_column_proof
                                .c_x
                                .get_node_at_layer(window_index, layer)?;

                            ensure!(
                                proof.verify(&pub_inputs.replica_id, &expected_labeled_node)?,
                                "Invalid labeling proof generated"
                            );
                        }

                        labeling_proofs.insert(layer, proof);
                    } else {
                        trace!("encoding proof window: {}, layer {}", window_index, layer);
                        encoding_proofs.push(EncodingProof::new(
                            window_index as u64,
                            challenge as u64,
                            parents_data,
                        ));
                    }
                }
                Ok(labeling_proofs)
            })
            .collect::<Result<_>>()?;

        Ok(WindowProof {
            comm_d_proofs,
            comm_q_proofs,
            replica_column_proof,
            labeling_proofs,
            encoding_proofs,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn prove_wrapper_challenge(
        challenge: usize,
        challenge_index: usize,
        wrapper_graph: &StackedBucketGraph<H>,
        t_aux: &TemporaryAuxCache<H, G>,
    ) -> Result<WrapperProof<H>> {
        trace!(" challenge {} ({})", challenge, challenge_index);
        ensure!(challenge < wrapper_graph.size(), "Invalid challenge");
        ensure!(challenge > 0, "Invalid challenge");

        // Final replica layer openings
        trace!("final replica layer openings");
        let comm_r_last_proof =
            MerkleProof::new_from_proof(&t_aux.tree_r_last.gen_proof(challenge)?);

        trace!("comm_q_parents proof");
        let mut parents = vec![0; wrapper_graph.expansion_degree()];
        wrapper_graph.expanded_parents(challenge, &mut parents)?;

        let mut comm_q_parents_proofs = Vec::with_capacity(parents.len());
        for parent in &parents {
            comm_q_parents_proofs.push(MerkleProof::new_from_proof(
                &t_aux.tree_q.gen_proof(*parent as usize)?,
            ));
        }

        trace!("labeling proof");
        let parents_data: Vec<_> = parents
            .iter()
            .map(|p| t_aux.tree_q.read_at(*p as usize))
            .collect::<Result<_>>()?;
        let labeling_proof = LabelingProof::<H>::new(None, challenge as u64, parents_data);

        Ok(WrapperProof {
            comm_r_last_proof,
            comm_q_parents_proofs,
            labeling_proof,
        })
    }

    fn prove_replica_column(
        pub_params: &PublicParams<H>,
        challenge: usize,
        t_aux: &TemporaryAuxCache<H, G>,
    ) -> Result<ReplicaColumnProof<H>> {
        ensure!(
            challenge < pub_params.window_size_nodes(),
            "Invalid challenge"
        );
        let graph = &pub_params.window_graph;

        // All labels in C_X
        trace!("  c_x");
        let c_x = t_aux
            .column(challenge as u32, pub_params)?
            .into_proof(&t_aux.tree_c)?;

        // All labels in the DRG parents.
        trace!("  drg_parents");
        let drg_parents = get_drg_parents_columns(graph, t_aux, challenge, pub_params)?
            .into_iter()
            .map(|column| column.into_proof(&t_aux.tree_c))
            .collect::<Result<_>>()?;

        // Labels for the expander parents
        trace!("  exp_parents");
        let exp_parents = get_exp_parents_columns(graph, t_aux, challenge, pub_params)?
            .into_iter()
            .map(|column| column.into_proof(&t_aux.tree_c))
            .collect::<Result<_>>()?;

        Ok(ReplicaColumnProof {
            c_x,
            drg_parents,
            exp_parents,
        })
    }

    fn get_parents_data_for_challenge(
        pub_params: &PublicParams<H>,
        window_index: usize,
        challenge: usize,
        layer: usize,
        t_aux: &TemporaryAuxCache<H, G>,
    ) -> Result<Vec<H::Domain>> {
        let graph = &pub_params.window_graph;

        let parents_data: Vec<H::Domain> = if layer == 1 {
            let mut parents = vec![0; graph.base_graph().degree()];
            graph.base_parents(challenge, &mut parents)?;

            parents
                .into_iter()
                .map(|parent| {
                    let index =
                        window_index as u32 * pub_params.window_size_nodes() as u32 + parent;
                    t_aux.domain_node_at_layer(layer, index)
                })
                .collect::<Result<_>>()?
        } else {
            let mut parents = vec![0; graph.degree()];
            graph.parents(challenge, &mut parents)?;
            let base_parents_count = graph.base_graph().degree();

            parents
                .into_iter()
                .enumerate()
                .map(|(i, parent)| {
                    let index =
                        window_index as u32 * pub_params.window_size_nodes() as u32 + parent;
                    if i < base_parents_count {
                        // parents data for base parents is from the current layer
                        t_aux.domain_node_at_layer(layer, index)
                    } else {
                        // parents data for exp parents is from the previous layer
                        t_aux.domain_node_at_layer(layer - 1, index)
                    }
                })
                .collect::<Result<_>>()?
        };

        Ok(parents_data)
    }

    pub(crate) fn verify_single_partition(
        pub_params: &PublicParams<H>,
        pub_inputs: &PublicInputs<<H as Hasher>::Domain, <G as Hasher>::Domain>,
        proof: &Proof<H, G>,
        expected_comm_r: &H::Domain,
        k: usize,
    ) -> Result<bool> {
        info!("verifying partition {}", k);
        let window_graph = &pub_params.window_graph;
        let wrapper_graph = &pub_params.wrapper_graph;

        let comm_c = &proof.comm_c;
        let comm_q = &proof.comm_q;
        let comm_r_last = &proof.comm_r_last;

        trace!("verify comm_r");
        let actual_comm_r: H::Domain = Fr::from(hash3(comm_c, comm_q, comm_r_last)).into();

        if expected_comm_r != &actual_comm_r {
            return Ok(false);
        }

        let window_challenges = pub_inputs.all_challenges(
            &pub_params.config.window_challenges,
            window_graph.size(),
            Some(k),
        )?;
        let wrapper_challenges = pub_inputs.all_challenges(
            &pub_params.config.wrapper_challenges,
            wrapper_graph.size(),
            Some(k),
        )?;

        if proof.window_proofs.len() != window_challenges.len() {
            return Ok(false);
        }

        if proof.wrapper_proofs.len() != wrapper_challenges.len() {
            return Ok(false);
        }

        for window_proof in &proof.window_proofs {
            // make sure all proofs have the same comm_c
            if window_proof.comm_c() != comm_c {
                return Ok(false);
            }
        }

        for wrapper_proof in &proof.wrapper_proofs {
            // make sure all proofs have the same comm_r_last
            if wrapper_proof.comm_r_last() != comm_r_last {
                return Ok(false);
            }
        }

        let window_valid = proof
            .window_proofs
            .par_iter()
            .enumerate()
            .all(|(i, proof)| {
                trace!("verify challenge {}/{}", i + 1, window_challenges.len());

                // Validate for this challenge
                let window_challenge = window_challenges[i];
                // TODO replace unwrap with proper error handling
                proof
                    .verify(pub_params, pub_inputs, window_challenge, comm_q, comm_c)
                    .unwrap()
            });
        if !window_valid {
            return Ok(false);
        }

        let wrapper_valid = proof
            .wrapper_proofs
            .par_iter()
            .enumerate()
            .all(|(i, proof)| {
                trace!("verify challenge {}/{}", i + 1, wrapper_challenges.len());

                // Validate for this challenge
                let wrapper_challenge = wrapper_challenges[i];
                // TODO replace unwrap with proper error handling
                proof
                    .verify::<G>(pub_inputs, wrapper_challenge, wrapper_graph, comm_q)
                    .unwrap()
            });
        Ok(wrapper_valid)
    }

    pub(crate) fn extract_all_windows(
        pub_params: &PublicParams<H>,
        replica_id: &<H as Hasher>::Domain,
        data: &mut [u8],
        _config: Option<StoreConfig>,
    ) -> Result<()> {
        trace!("extract_all_windows");

        let layers = pub_params.config.layers();
        ensure!(layers > 0, "No layer found.");

        ensure!(
            data.len() % pub_params.window_size_bytes() == 0,
            "invalid data size"
        );

        data.par_chunks_mut(pub_params.window_size_bytes())
            .enumerate()
            .try_for_each(|(window_index, data_chunk)| {
                Self::extract_single_window(pub_params, replica_id, data_chunk, window_index)
            })?;

        Ok(())
    }

    pub fn extract_range(
        pp: &PublicParams<H>,
        replica_id: &<H as Hasher>::Domain,
        data: &[u8],
        _config: Option<StoreConfig>,
        offset: usize,
        num_bytes: usize,
    ) -> Result<Vec<u8>> {
        ensure!(offset + num_bytes <= data.len(), "Out of bounds");

        // determine the first window needed to be decoded
        let first_window_index = offset / pp.window_size_bytes();

        // offset into the first window
        let first_window_offset = offset % pp.window_size_bytes();

        // determine the last window needed to be decoded
        let last_window_index =
            ((offset + num_bytes) as f64 / pp.window_size_bytes() as f64).ceil() as usize;

        let mut decoded: Vec<u8> = data
            .par_chunks(pp.window_size_bytes())
            .enumerate()
            .take(last_window_index)
            .skip(first_window_index)
            .flat_map(|(window_index, chunk)| {
                let mut decoded_chunk = chunk.to_vec();
                // TODO replace unwrap with proper error handling
                Self::extract_single_window(pp, replica_id, &mut decoded_chunk, window_index)
                    .unwrap();
                decoded_chunk
            })
            .collect();

        // remove elements at the front
        for _i in 0..first_window_offset {
            decoded.remove(0);
        }

        // remove elements at the end
        decoded.truncate(num_bytes);

        ensure!(
            decoded.len() == num_bytes,
            "Internal error: expected {} == {}",
            decoded.len(),
            num_bytes
        );

        Ok(decoded)
    }

    pub(crate) fn extract_single_window(
        pub_params: &PublicParams<H>,
        replica_id: &<H as Hasher>::Domain,
        data_chunk: &mut [u8],
        window_index: usize,
    ) -> Result<()> {
        trace!("extract_single_window");
        let window_graph = &pub_params.window_graph;
        let layers = pub_params.config.layers();

        let mut layer_labels = vec![0u8; pub_params.window_size_bytes()];
        let mut parents = vec![0; window_graph.degree()];
        let mut exp_parents_data: Option<Vec<u8>> = None;

        // setup hasher to reuse
        let mut base_hasher = Sha256::new();

        // hash replica id
        base_hasher.input(AsRef::<[u8]>::as_ref(replica_id));

        for layer in 1..=layers {
            trace!("generating layer: {}", layer);

            for node in 0..window_graph.size() {
                window_graph.parents(node, &mut parents)?;

                let key = create_key(
                    window_graph,
                    base_hasher.clone(),
                    &parents,
                    exp_parents_data.as_ref(),
                    &layer_labels,
                    window_index,
                    node,
                )?;

                let start = data_at_node_offset(node);
                let end = start + NODE_SIZE;

                // store the newly generated key
                layer_labels[start..end].copy_from_slice(&key[..]);

                if layer == layers {
                    // on the last layer we encode the data
                    let keyd = H::Domain::try_from_bytes(&key)?;
                    let data_node = H::Domain::try_from_bytes(
                        &data_chunk[node * NODE_SIZE..(node + 1) * NODE_SIZE],
                    )?;
                    let decoded_node = decode::<H::Domain>(keyd, data_node);
                    data_chunk[node * NODE_SIZE..(node + 1) * NODE_SIZE].copy_from_slice(AsRef::<
                        [u8],
                    >::as_ref(
                        &decoded_node,
                    ));
                }
            }

            if layer < layers {
                if let Some(ref mut exp_parents_data) = exp_parents_data {
                    exp_parents_data.copy_from_slice(&layer_labels);
                } else {
                    exp_parents_data = Some(layer_labels.clone());
                }
            }
        }

        Ok(())
    }

    fn label_encode_all_windows(
        pub_params: &PublicParams<H>,
        replica_id: &<H as Hasher>::Domain,
        data: &mut [u8],
        config: StoreConfig,
    ) -> Result<(LabelsCache<H>, Labels<H>)> {
        trace!("encode_all_windows");
        let window_graph = &pub_params.window_graph;
        let layers = pub_params.config.layers();

        ensure!(
            window_graph.size() == pub_params.window_size_nodes(),
            "Invalid window size."
        );

        let layer_size = data.len();
        let num_windows = pub_params.num_windows();

        let labels: Vec<Mutex<(DiskStore<_>, _)>> = (0..layers)
            .map(|layer| -> Result<_> {
                let layer_config = StoreConfig::from_config(
                    &config,
                    CacheKey::label_layer(layer),
                    Some(layer_size / NODE_SIZE),
                );

                let layer_store: DiskStore<H::Domain> =
                    DiskStore::new_with_config(layer_size / NODE_SIZE, layer_config.clone())?;

                let r = Mutex::new((layer_store, layer_config));
                Ok(r)
            })
            .collect::<Result<_>>()?;

        (0..num_windows)
            .into_par_iter()
            .zip(data.par_chunks_mut(pub_params.window_size_bytes()))
            .try_for_each(|(window_index, data_chunk)| -> Result<()> {
                let mut layer_labels = vec![0u8; pub_params.window_size_bytes()];
                let mut parents = vec![0; window_graph.degree()];
                let mut exp_parents_data: Option<Vec<u8>> = None;

                // setup hasher to reuse
                let mut base_hasher = Sha256::new();

                // hash replica id
                base_hasher.input(AsRef::<[u8]>::as_ref(replica_id));

                for layer in 1..=layers {
                    trace!("generating layer: {}", layer);

                    Self::label_encode_window_layer(
                        layer,
                        layers,
                        window_graph,
                        base_hasher.clone(),
                        &mut parents,
                        exp_parents_data.as_ref(),
                        &mut layer_labels,
                        data_chunk,
                        window_index,
                    )?;

                    if layer < layers {
                        if let Some(ref mut exp_parents_data) = exp_parents_data {
                            exp_parents_data.copy_from_slice(&layer_labels);
                        } else {
                            exp_parents_data = Some(layer_labels.clone());
                        }
                    }
                    // write result to disk
                    labels[layer - 1].lock().unwrap().0.copy_from_slice(
                        &layer_labels,
                        window_index * pub_params.window_size_nodes(),
                    )?;
                }
                Ok(())
            })?;

        let (labels, configs) = labels.into_iter().map(|v| v.into_inner().unwrap()).unzip();

        Ok((
            LabelsCache::<H>::from_stores(labels),
            Labels::<H>::new(configs),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn label_encode_window_layer(
        layer: usize,
        layers: usize,
        window_graph: &StackedBucketGraph<H>,
        base_hasher: Sha256,
        parents: &mut [u32],
        exp_parents_data: Option<&Vec<u8>>,
        layer_labels: &mut [u8],
        data_chunk: &mut [u8],
        window_index: usize,
    ) -> Result<()> {
        for node in 0..window_graph.size() {
            window_graph.parents(node, parents)?;

            let key = create_key(
                window_graph,
                base_hasher.clone(),
                parents,
                exp_parents_data,
                &layer_labels,
                window_index,
                node,
            )?;
            let start = node * NODE_SIZE;
            let end = (node + 1) * NODE_SIZE;

            // store the newly generated key
            layer_labels[start..end].copy_from_slice(&key[..]);

            if layer == layers {
                // on the last layer we encode the data
                let keyd = H::Domain::try_from_bytes(&key)?;
                let data_node = H::Domain::try_from_bytes(&data_chunk[start..end])?;
                let encoded_node = encode(keyd, data_node);
                data_chunk[start..end].copy_from_slice(AsRef::<[u8]>::as_ref(&encoded_node));
            }
        }

        Ok(())
    }

    fn build_tree<K: Hasher>(tree_data: &[u8], config: Option<StoreConfig>) -> Result<Tree<K>> {
        trace!("building tree (size: {})", tree_data.len());

        let leafs = tree_data.len() / NODE_SIZE;
        ensure!(tree_data.len() % NODE_SIZE == 0, "Invalid tree data.");
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
        pub_params: &PublicParams<H>,
        labels: &LabelsCache<H>,
    ) -> Result<Vec<[u8; 32]>> {
        (0..pub_params.window_size_nodes())
            .into_par_iter()
            .map(|i| Self::build_column_hash(pub_params, i, labels))
            .collect()
    }

    fn build_column_hash(
        pub_params: &PublicParams<H>,
        column_index: usize,
        labels: &LabelsCache<H>,
    ) -> Result<[u8; 32]> {
        let num_windows = pub_params.num_windows();
        let layers = pub_params.config.layers();

        let first_label = labels.labels_for_layer(1)?.read_at(column_index)?;
        let mut hasher = crate::crypto::pedersen::Hasher::new(AsRef::<[u8]>::as_ref(&first_label))?;

        for window_index in 0..num_windows {
            for layer in 1..layers {
                if window_index == 0 && layer == 1 {
                    // first label
                    continue;
                }

                let label = labels
                    .labels_for_layer(layer)?
                    .read_at(window_index * pub_params.window_size_nodes() + column_index)?;

                hasher.update(AsRef::<[u8]>::as_ref(&label))?;
            }
        }

        Ok(hasher.finalize_bytes())
    }

    pub(crate) fn transform_and_replicate_layers(
        pub_params: &PublicParams<H>,
        replica_id: &<H as Hasher>::Domain,
        data: &mut [u8],
        data_tree: Option<Tree<G>>,
        config: Option<StoreConfig>,
    ) -> Result<TransformedLayers<H, G>> {
        trace!("transform_and_replicate_layers");
        let window_graph = &pub_params.window_graph;
        let wrapper_graph = &pub_params.wrapper_graph;

        ensure!(
            window_graph.size() == pub_params.window_size_nodes(),
            "Invalid window size."
        );

        let wrapper_nodes_count = wrapper_graph.size();
        ensure!(
            data.len() == wrapper_nodes_count * NODE_SIZE,
            "Invalid data size."
        );

        let layers = pub_params.config.layers();
        ensure!(layers > 0, "No layer found.");

        // Generate all store configs that we need based on the
        // cache_path in the specified config.
        let config = config.context("missing config")?;
        let mut tree_d_config =
            StoreConfig::from_config(&config, CacheKey::CommDTree.to_string(), None);
        let mut tree_r_last_config =
            StoreConfig::from_config(&config, CacheKey::CommRLastTree.to_string(), None);
        let mut tree_c_config =
            StoreConfig::from_config(&config, CacheKey::CommCTree.to_string(), None);
        let mut tree_q_config =
            StoreConfig::from_config(&config, CacheKey::CommQTree.to_string(), None);

        // Build the MerkleTree over the original data (if needed).
        let tree_d = match data_tree {
            Some(t) => {
                trace!("using existing original data merkle tree");
                ensure!(
                    t.len() == 2 * (data.len() / NODE_SIZE) - 1,
                    "Invalid data tree."
                );

                t
            }
            None => {
                trace!("building merkle tree for the original data");
                Self::build_tree::<G>(&data, Some(tree_d_config.clone()))?
            }
        };

        info!(
            "encoding {} windows",
            data.len() / pub_params.window_size_bytes()
        );

        let (labels, label_configs) =
            Self::label_encode_all_windows(pub_params, replica_id, data, config)?;

        // construct column hashes
        info!("building column hashes");
        let column_hashes = Self::build_column_hashes(pub_params, &labels)?;

        info!("building tree_q");
        let tree_q: Tree<H> = Self::build_tree::<H>(&data, Some(tree_q_config.clone()))?;

        info!("building tree_r_last");
        let tree_r_last: Tree<H> = MerkleTree::from_par_iter_with_config(
            (0..wrapper_nodes_count).into_par_iter().map(|node| {
                // 1 Wrapping Layer

                let mut hasher = Sha256::new();
                hasher.input(AsRef::<[u8]>::as_ref(replica_id));
                hasher.input(&(node as u64).to_be_bytes()[..]);

                // Only expansion parents
                let mut exp_parents = vec![0; wrapper_graph.expansion_degree()];
                // TODO Do proper error handling and not just `expect()`.
                wrapper_graph
                    .expanded_parents(node, &mut exp_parents)
                    .expect("cannot expand parents");

                let wrapper_layer = &data;
                for parent in &exp_parents {
                    // TODO Do proper error handling and not just `expect()`.
                    hasher.input(
                        data_at_node(wrapper_layer, *parent as usize).expect("invalid node math"),
                    );
                }

                // finalize key
                let mut val = hasher.result();
                // strip last two bits, to ensure result is in Fr.
                val[31] &= 0b0011_1111;

                // TODO Do proper error handling and not just `expect()`.
                H::Domain::try_from_bytes(&val).expect("invalid node created")
            }),
            tree_r_last_config.clone(),
        )?;

        info!("building tree_c");
        let tree_c: Tree<H> = {
            let column_hashes_flat = unsafe {
                // Column_hashes is of type Vec<[u8; 32]>, so this is safe to do.
                // We do this to avoid unnecessary allocations.
                std::slice::from_raw_parts(
                    column_hashes.as_ptr() as *const _,
                    column_hashes.len() * 32,
                )
            };
            Self::build_tree::<H>(column_hashes_flat, Some(tree_c_config.clone()))?
        };

        // comm_r = H(comm_c || comm_q || comm_r_last)
        let comm_r: H::Domain =
            Fr::from(hash3(tree_c.root(), tree_q.root(), tree_r_last.root())).into();

        ensure!(tree_d.len() == tree_r_last.len(), "Invalid tree_r.");
        ensure!(tree_d.len() == tree_q.len(), "Invlaid tree_q.");

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

fn create_key<H: Hasher>(
    window_graph: &StackedBucketGraph<H>,
    mut hasher: Sha256,
    parents: &[u32],
    exp_parents_data: Option<&Vec<u8>>,
    layer_labels: &[u8],
    window_index: usize,
    node: usize,
) -> Result<GenericArray<u8, <Sha256 as Digest>::OutputSize>> {
    // hash window_index
    hasher.input(&(window_index as u64).to_be_bytes());

    // hash node id
    hasher.input(&(node as u64).to_be_bytes());

    // hash parents for all non 0 nodes
    if node > 0 {
        let base_parents_count = window_graph.base_graph().degree();

        // Base parents
        for parent in parents.iter().take(base_parents_count) {
            let buf = data_at_node(&layer_labels, *parent as usize).context("invalid node")?;
            hasher.input(buf);
        }

        // Expander parents
        // This will happen for all layers > 1
        if let Some(ref parents_data) = exp_parents_data {
            for parent in parents.iter().skip(base_parents_count) {
                let buf = data_at_node(parents_data, *parent as usize).context("invalid node")?;
                hasher.input(&buf);
            }
        }
    }

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
        let layer_challenges = LayerChallenges::new(10, 333).unwrap();
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
        let config = StackedConfig::new(DEFAULT_STACKED_LAYERS, 5, 8).unwrap();

        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();

        let sp = SetupParams {
            nodes,
            degree: BASE_DEGREE,
            expansion_degree: EXP_DEGREE,
            seed: new_seed(),
            config: config.clone(),
            window_size_nodes: nodes / 2,
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
    #[ignore]
    fn extract_nodes_pedersen() {
        test_extract_nodes::<PedersenHasher>();
    }

    #[test]
    #[ignore]
    fn extract_nodes_sha256() {
        test_extract_nodes::<Sha256Hasher>();
    }

    #[test]
    #[ignore]
    fn extract_nodes_blake2s() {
        test_extract_nodes::<Blake2sHasher>();
    }

    fn test_extract_nodes<H: 'static + Hasher>() {
        // femme::pretty::Logger::new()
        //     .start(log::LevelFilter::Trace)
        //     .ok();

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);
        let replica_id: H::Domain = H::Domain::random(rng);
        let nodes = 4 * 32;

        let data: Vec<u8> = (0..nodes)
            .flat_map(|_| {
                let v: H::Domain = H::Domain::random(rng);
                v.into_bytes()
            })
            .collect();
        let config = StackedConfig::new(DEFAULT_STACKED_LAYERS, 5, 8).unwrap();

        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();

        let sp = SetupParams {
            nodes,
            degree: BASE_DEGREE,
            expansion_degree: EXP_DEGREE,
            seed: new_seed(),
            config: config.clone(),
            window_size_nodes: nodes / 4,
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
        for start in 0..nodes {
            for len in 2..=(nodes - start) {
                let nodes = StackedDrg::<H, Blake2sHasher>::extract_range(
                    &pp,
                    &replica_id,
                    &data_copy,
                    Some(config.clone()),
                    start * NODE_SIZE,
                    len * NODE_SIZE,
                )
                .expect("failed to extract data");

                for (i, node) in nodes.chunks(NODE_SIZE).enumerate() {
                    assert_eq!(
                        data_at_node(&data, i + start).unwrap(),
                        &node[..],
                        "{} - {}",
                        start,
                        len
                    );
                }
                assert_eq!(nodes.len(), len * NODE_SIZE);
            }
        }
    }

    fn prove_verify_fixed(n: usize) {
        let config = StackedConfig::new(DEFAULT_STACKED_LAYERS, 5, 8).unwrap();

        test_prove_verify::<PedersenHasher>(n, config.clone());
        test_prove_verify::<Sha256Hasher>(n, config.clone());
        test_prove_verify::<Blake2sHasher>(n, config.clone());
    }

    fn test_prove_verify<H: 'static + Hasher>(n: usize, config: StackedConfig) {
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
            config: config.clone(),
            window_size_nodes: n / 2,
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

    table_tests! {
        prove_verify_fixed{
           prove_verify_fixed_32_4(8 * 32);
        }
    }

    #[test]
    // We are seeing a bug, in which setup never terminates for some sector sizes.
    // This test is to debug that and should remain as a regression teset.
    fn setup_terminates() {
        let degree = BASE_DEGREE;
        let expansion_degree = EXP_DEGREE;
        let nodes = 1024 * 1024 * 32 * 8; // This corresponds to 8GiB sectors (32-byte nodes)
        let config = StackedConfig::new(10, 333, 444).unwrap();
        let sp = SetupParams {
            nodes,
            degree,
            expansion_degree,
            seed: new_seed(),
            config: config.clone(),
            window_size_nodes: nodes / 2,
        };

        // When this fails, the call to setup should panic, but seems to actually hang (i.e. neither return nor panic) for some reason.
        // When working as designed, the call to setup returns without error.
        let _pp = StackedDrg::<PedersenHasher, Blake2sHasher>::setup(&sp).expect("setup failed");
    }
}
