use std::cmp::{max, min};
use std::marker::PhantomData;
use std::sync::mpsc::channel;

use crossbeam_utils::thread;
use memmap::MmapMut;
use memmap::MmapOptions;
use rayon::prelude::*;
use serde::de::Deserialize;
use serde::ser::Serialize;

use crate::challenge_derivation::derive_challenges;
use crate::drgporep::{self, DrgPoRep};
use crate::drgraph::Graph;
use crate::error::{Error, Result};
use crate::hasher::hybrid::HybridDomain;
use crate::hasher::{Domain, HashFunction, Hasher};
use crate::hybrid_merkle::HybridMerkleTree;
use crate::parameter_cache::ParameterSetMetadata;
use crate::porep::{self, PoRep};
use crate::proof::ProofScheme;
use crate::settings;
use crate::vde;

#[cfg(feature = "disk-trees")]
use rand;
#[cfg(feature = "disk-trees")]
use std::fs;
#[cfg(feature = "disk-trees")]
use std::io;
#[cfg(feature = "disk-trees")]
use std::path::PathBuf;

fn anonymous_mmap(len: usize) -> MmapMut {
    MmapOptions::new()
        .len(len)
        .map_anon()
        .expect("Failed to create memory map")
}

#[derive(Debug, Clone)]
pub enum LayerChallenges {
    Fixed {
        layers: usize,
        count: usize,
    },
    Tapered {
        layers: usize,
        count: usize,
        taper: f64,
        taper_layers: usize,
    },
}

impl LayerChallenges {
    pub const fn new_fixed(layers: usize, count: usize) -> Self {
        LayerChallenges::Fixed { layers, count }
    }

    pub fn new_tapered(layers: usize, challenges: usize, taper_layers: usize, taper: f64) -> Self {
        LayerChallenges::Tapered {
            layers,
            count: challenges,
            taper,
            taper_layers,
        }
    }

    pub fn layers(&self) -> usize {
        match self {
            LayerChallenges::Fixed { layers, .. } => *layers,
            LayerChallenges::Tapered { layers, .. } => *layers,
        }
    }

    pub fn challenges_for_layer(&self, layer: usize) -> usize {
        match self {
            LayerChallenges::Fixed { count, .. } => *count,
            LayerChallenges::Tapered {
                taper,
                taper_layers,
                count,
                layers,
            } => {
                assert!(layer < *layers);
                let l = (layers - 1) - layer;

                let r: f64 = 1.0 - *taper;
                let t = min(l, *taper_layers);
                let total_taper = r.powi(t as i32);

                let calculated = (total_taper * *count as f64).ceil() as usize;

                // Although implied by the call to `ceil()` above, be explicit that a layer cannot contain 0 challenges.
                max(1, calculated)
            }
        }
    }

    pub fn total_challenges(&self) -> usize {
        (0..self.layers())
            .map(|x| self.challenges_for_layer(x))
            .sum()
    }
    pub fn all_challenges(&self) -> Vec<usize> {
        (0..self.layers())
            .map(|x| self.challenges_for_layer(x))
            .collect()
    }
}

#[derive(Debug)]
pub struct SetupParams {
    pub drg: drgporep::DrgParams,
    pub layer_challenges: LayerChallenges,
    pub beta_heights: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct PublicParams<AH, BH, G>
where
    AH: Hasher,
    BH: Hasher,
    G: Graph<AH, BH> + ParameterSetMetadata,
{
    pub graph: G,
    pub layer_challenges: LayerChallenges,
    pub beta_heights: Vec<usize>,
    _ah: PhantomData<AH>,
    _bh: PhantomData<BH>,
}

#[derive(Debug, Clone)]
pub struct Tau<AD, BD>
where
    AD: Domain,
    BD: Domain,
{
    pub layer_taus: Vec<porep::Tau<AD, BD>>,
    pub comm_r_star: HybridDomain<AD, BD>,
}

#[derive(Default)]
pub struct ChallengeRequirements {
    pub minimum_challenges: usize,
}

impl<AD, BD> Tau<AD, BD>
where
    AD: Domain,
    BD: Domain,
{
    /// Return a single porep::Tau with the initial data and final replica commitments of layer_taus.
    pub fn simplify(&self) -> porep::Tau<AD, BD> {
        porep::Tau {
            comm_r: self.layer_taus[self.layer_taus.len() - 1].comm_r,
            comm_d: self.layer_taus[0].comm_d,
        }
    }
}

impl<AH, BH, G> PublicParams<AH, BH, G>
where
    AH: Hasher,
    BH: Hasher,
    G: Graph<AH, BH> + ParameterSetMetadata,
{
    pub fn new(graph: G, layer_challenges: LayerChallenges, beta_heights: Vec<usize>) -> Self {
        PublicParams {
            graph,
            layer_challenges,
            beta_heights,
            _ah: PhantomData,
            _bh: PhantomData,
        }
    }
}

impl<AH, BH, G> ParameterSetMetadata for PublicParams<AH, BH, G>
where
    AH: Hasher,
    BH: Hasher,
    G: Graph<AH, BH> + ParameterSetMetadata,
{
    fn identifier(&self) -> String {
        format!(
            "layered_drgporep::PublicParams{{ graph: {}, challenges: {:?}, beta_heights: {:?} }}",
            self.graph.identifier(),
            self.layer_challenges,
            self.beta_heights,
        )
    }

    fn sector_size(&self) -> u64 {
        self.graph.sector_size()
    }
}

impl<'a, AH, BH, G> From<&'a PublicParams<AH, BH, G>> for PublicParams<AH, BH, G>
where
    AH: Hasher,
    BH: Hasher,
    G: Graph<AH, BH> + ParameterSetMetadata,
{
    fn from(other: &'a PublicParams<AH, BH, G>) -> Self {
        PublicParams::new(
            other.graph.clone(),
            other.layer_challenges.clone(),
            other.beta_heights.clone(),
        )
    }
}

pub type EncodingProof<AH, BH> = drgporep::Proof<AH, BH>;

#[derive(Debug, Clone)]
pub struct PublicInputs<AD, BD>
where
    AD: Domain,
    BD: Domain,
{
    pub replica_id: HybridDomain<AD, BD>,
    pub seed: Option<HybridDomain<AD, BD>>,
    pub tau: Option<porep::Tau<AD, BD>>,
    pub comm_r_star: HybridDomain<AD, BD>,
    pub k: Option<usize>,
}

impl<AD, BD> PublicInputs<AD, BD>
where
    AD: Domain,
    BD: Domain,
{
    pub fn challenges(
        &self,
        layer_challenges: &LayerChallenges,
        leaves: usize,
        layer: u8,
        partition_k: Option<usize>,
    ) -> Vec<usize> {
        if let Some(ref seed) = self.seed {
            derive_challenges::<AD, BD>(
                layer_challenges,
                layer,
                leaves,
                &self.replica_id,
                seed,
                partition_k.unwrap_or(0) as u8,
            )
        } else {
            derive_challenges::<AD, BD>(
                layer_challenges,
                layer,
                leaves,
                &self.replica_id,
                &self.comm_r_star,
                partition_k.unwrap_or(0) as u8,
            )
        }
    }
}

pub struct PrivateInputs<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    pub aux: Vec<HybridMerkleTree<AH, BH>>,
    pub tau: Vec<porep::Tau<AH::Domain, BH::Domain>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    #[serde(bound(
        serialize = "EncodingProof<AH, BH>: Serialize",
        deserialize = "EncodingProof<AH, BH>: Deserialize<'de>"
    ))]
    pub encoding_proofs: Vec<EncodingProof<AH, BH>>,
    pub tau: Vec<porep::Tau<AH::Domain, BH::Domain>>,
}

impl<AH, BH> Proof<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    pub fn new(
        encoding_proofs: Vec<EncodingProof<AH, BH>>,
        tau: Vec<porep::Tau<AH::Domain, BH::Domain>>,
    ) -> Self {
        Proof {
            encoding_proofs,
            tau,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        unimplemented!();
    }
}

pub type PartitionProofs<AH, BH> = Vec<Proof<AH, BH>>;

pub trait Layerable<AH, BH>: Graph<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
}

type PorepTau<AH, BH> = porep::Tau<<AH as Hasher>::Domain, <BH as Hasher>::Domain>;
type TransformedLayers<AH, BH> = (Vec<PorepTau<AH, BH>>, Vec<HybridMerkleTree<AH, BH>>);

/// Layers provides default implementations of methods required to handle proof and verification
/// of layered proofs of replication. Implementations must provide transform and invert_transform methods.
pub trait Layers {
    type AlphaHasher: Hasher;
    type BetaHasher: Hasher;
    type Graph: Layerable<Self::AlphaHasher, Self::BetaHasher> + ParameterSetMetadata + Sync + Send;

    /// Transform a layer's public parameters, returning new public parameters corresponding to the next layer.
    /// Warning: This method will likely need to be extended for other implementations
    /// but because it is not clear what parameters they will need, only the ones needed
    /// for zizag are currently present (same applies to [invert_transform]).
    fn transform(graph: &Self::Graph) -> Self::Graph;

    /// Transform a layer's public parameters, returning new public parameters corresponding to the previous layer.
    fn invert_transform(graph: &Self::Graph) -> Self::Graph;

    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn prove_layers<'a>(
        graph: &Self::Graph,
        pub_inputs: &PublicInputs<
            <Self::AlphaHasher as Hasher>::Domain,
            <Self::BetaHasher as Hasher>::Domain,
        >,
        tau: &[PorepTau<Self::AlphaHasher, Self::BetaHasher>],
        aux: &'a [HybridMerkleTree<Self::AlphaHasher, Self::BetaHasher>],
        layer_challenges: &LayerChallenges,
        layers: usize,
        total_layers: usize,
        partition_count: usize,
        beta_heights: &[usize],
    ) -> Result<Vec<Vec<EncodingProof<Self::AlphaHasher, Self::BetaHasher>>>> {
        assert!(layers > 0);

        let mut new_graph = Some(graph.clone());

        (0..layers)
            .map(|layer| {
                // Convert the replica-id to the correct `HyrbidDomain` variant for this encoding
                // layer's beta height.
                let replica_id = if beta_heights[layer] == 0 {
                    pub_inputs.replica_id.convert_into_alpha()
                } else {
                    pub_inputs.replica_id.convert_into_beta()
                };

                let current_graph = new_graph.take().unwrap();
                let inner_layers = layers - layer;

                let new_priv_inputs = drgporep::PrivateInputs {
                    tree_d: &aux[layer],
                    tree_r: &aux[layer + 1],
                };
                let layer_diff = total_layers - inner_layers;
                let graph_size = current_graph.size();
                new_graph = Some(Self::transform(&current_graph));

                let prev_layer_beta_height = if layer == 0 {
                    usize::max_value()
                } else {
                    beta_heights[layer - 1]
                };

                let pp = drgporep::PublicParams::new(
                    current_graph,
                    true,
                    layer_challenges.challenges_for_layer(layer),
                    beta_heights[layer],
                    prev_layer_beta_height,
                );
                let partition_proofs: Vec<_> = (0..partition_count)
                    .into_par_iter()
                    .map(|k| {
                        let drgporep_pub_inputs = drgporep::PublicInputs {
                            replica_id: Some(replica_id),
                            challenges: pub_inputs.challenges(
                                layer_challenges,
                                graph_size,
                                layer_diff as u8,
                                Some(k),
                            ),
                            tau: Some(tau[layer]),
                        };

                        DrgPoRep::prove(&pp, &drgporep_pub_inputs, &new_priv_inputs)
                    })
                    .collect::<Result<Vec<_>>>()?;

                // Offload the data tree, we won't use it in the next iteration,
                // only `tree_r` is reused (as the new `tree_d`).
                aux[layer].try_offload_store();
                // Only if this is the last iteration also offload `tree_r`.
                if layer == layers - 1 {
                    aux[layer + 1].try_offload_store();
                }

                Ok(partition_proofs)
            })
            .collect::<Result<Vec<_>>>()
    }

    fn extract_and_invert_transform_layers<'a>(
        graph: &Self::Graph,
        layer_challenges: &LayerChallenges,
        beta_heights: &[usize],
        replica_id: &HybridDomain<
            <Self::AlphaHasher as Hasher>::Domain,
            <Self::BetaHasher as Hasher>::Domain,
        >,
        data: &'a mut [u8],
    ) -> Result<()> {
        let layers = layer_challenges.layers();
        assert!(layers > 0);

        (0..layers).fold(graph.clone(), |current_graph, layer| {
            let inverted = Self::invert_transform(&current_graph);

            // We pass in a `0`'s for beta height and the previous layer's beta height because those
            // public parameters are not used by `DrgPoRep::extract_all()`.
            let pp = drgporep::PublicParams::new(
                inverted.clone(),
                true,
                layer_challenges.challenges_for_layer(layer),
                0,
                0,
            );

            let replica_id = if beta_heights[layer] == 0 {
                replica_id.convert_into_alpha()
            } else {
                replica_id.convert_into_beta()
            };

            let mut res = DrgPoRep::extract_all(&pp, &replica_id, data)
                .expect("failed to extract data from PoRep");

            for (i, r) in res.iter_mut().enumerate() {
                data[i] = *r;
            }
            inverted
        });

        Ok(())
    }

    fn transform_and_replicate_layers(
        graph: &Self::Graph,
        layer_challenges: &LayerChallenges,
        replica_id: &HybridDomain<
            <Self::AlphaHasher as Hasher>::Domain,
            <Self::BetaHasher as Hasher>::Domain,
        >,
        data: &mut [u8],
        beta_heights: &[usize],
    ) -> Result<TransformedLayers<Self::AlphaHasher, Self::BetaHasher>> {
        let layers = layer_challenges.layers();
        assert!(layers > 0);
        let mut taus = Vec::with_capacity(layers);
        let mut auxs: Vec<HybridMerkleTree<Self::AlphaHasher, Self::BetaHasher>> =
            Vec::with_capacity(layers + 1);

        if !&settings::SETTINGS
            .lock()
            .unwrap()
            .generate_merkle_trees_in_parallel
        {
            let mut sorted_trees: Vec<_> = Vec::new();

            // We iterate over the number of encoding layers + 1 (`0..=layers`) to include the data
            // layer (the first iteration when `layer` is 0).
            (0..=layers).fold(graph.clone(), |current_graph, layer| {
                let is_data_layer = layer == 0;

                // We always use a beta height equal to Merkle tree height for the data layer to
                // ensure that only the beta hasher is used.
                let beta_height = if is_data_layer {
                    let n_leaves = graph.size();
                    (n_leaves as f32).log2().ceil() as usize + 1
                } else {
                    beta_heights[layer - 1]
                };

                let tree_d = Self::generate_data_tree(&current_graph, &data, beta_height, layer);

                info!("returning tree (layer: {})", layer);

                sorted_trees.push(tree_d);

                if layer < layers {
                    info!("encoding (layer: {})", layer);

                    // Change the replica-id variant for this encoding layer. The `replica_id`
                    // argument passed into this function is the data layer's replica-id.
                    if is_data_layer {
                        vde::encode(&current_graph, replica_id, data)
                            .expect("encoding failed in thread");
                    } else if beta_height == 0 {
                        vde::encode(&current_graph, &replica_id.convert_into_alpha(), data)
                            .expect("encoding failed in thread");
                    } else {
                        vde::encode(&current_graph, &replica_id.convert_into_beta(), data)
                            .expect("encoding failed in thread");
                    };
                }

                Self::transform(&current_graph)
            });

            sorted_trees
                .into_iter()
                .fold(None, |previous_comm_r: Option<_>, replica_tree| {
                    let comm_r = replica_tree.root();
                    // Each iteration's replica_tree becomes the next iteration's previous_tree (data_tree).
                    // The first iteration has no previous_tree.
                    if let Some(comm_d) = previous_comm_r {
                        let tau = porep::Tau { comm_r, comm_d };
                        // info!("setting tau/aux (layer: {})", i - 1);
                        // FIXME: Use `enumerate` if this log is worth it.
                        taus.push(tau);
                    };

                    auxs.push(replica_tree);

                    Some(comm_r)
                });
        } else {
            // The parallel case is more complicated but should produce the same results as the
            // serial case. Note that to make lifetimes work out, we have to inline and tease apart
            // the definition of DrgPoRep::replicate. This is because as implemented, it entangles
            // encoding and merkle tree generation too tightly to be used as a subcomponent.
            // Instead, we need to create a scope which encloses all the work, spawning threads
            // for merkle tree generation and sending the results back to a channel.
            // The received results need to be sorted by layer because ordering of the completed results
            // is not guaranteed. Misordered results will be seen in practice when trees are small.

            // The outer scope ensure that `tx` is dropped and closed before we read from `outer_rx`.
            // Otherwise, the read loop will block forever waiting for more input.
            let outer_rx = {
                let (tx, rx) = channel();

                let errf = |e| {
                    let err_string = format!("{:?}", e);
                    error!(
                        "MerkleTreeGenerationError: {} - {:?}",
                        &err_string,
                        failure::Backtrace::new()
                    );
                    Error::MerkleTreeGenerationError(err_string)
                };

                let _ = thread::scope(|scope| -> Result<()> {
                    let mut threads = Vec::with_capacity(layers + 1);
                    (0..=layers).fold(graph.clone(), |current_graph, layer| {
                        let is_data_layer = layer == 0;

                        // We always use a beta height equal to Merkle tree height for the data
                        // layer to ensure that only the beta hasher is used.
                        let beta_height = if is_data_layer {
                            let n_leaves = graph.size();
                            (n_leaves as f32).log2().ceil() as usize + 1
                        } else {
                            beta_heights[layer - 1]
                        };

                        let mut data_copy = anonymous_mmap(data.len());
                        data_copy[0..data.len()].clone_from_slice(data);

                        let return_channel = tx.clone();
                        let (transfer_tx, transfer_rx) = channel::<Self::Graph>();

                        transfer_tx
                            .send(current_graph.clone())
                            .expect("Failed to send value through channel");

                        let thread = scope.spawn(move |_| {
                            // If we panic anywhere in this closure, thread.join() below will receive an error —
                            // so it is safe to unwrap.
                            let graph = transfer_rx
                                .recv()
                                .expect("Failed to receive value through channel");

                            let tree_d =
                                Self::generate_data_tree(&graph, &data_copy, beta_height, layer);

                            info!("returning tree (layer: {})", layer);
                            return_channel
                                .send((layer, tree_d))
                                .expect("Failed to send value through channel");
                        });

                        threads.push(thread);

                        if layer < layers {
                            info!("encoding (layer: {})", layer);

                            // Change the replica-id variant for this encoding layer. The
                            // `replica_id` argument passed into this function is the data layer's
                            // replica-id.
                            if is_data_layer {
                                vde::encode(&current_graph, replica_id, data)
                                    .expect("encoding failed in thread");
                            } else if beta_height == 0 {
                                vde::encode(&current_graph, &replica_id.convert_into_alpha(), data)
                                    .expect("encoding failed in thread");
                            } else {
                                vde::encode(&current_graph, &replica_id.convert_into_beta(), data)
                                    .expect("encoding failed in thread");
                            };
                        }
                        Self::transform(&current_graph)
                    });

                    for thread in threads {
                        thread.join().map_err(errf)?;
                    }

                    Ok(())
                })
                .map_err(errf)?;

                rx
            };

            let mut sorted_trees = outer_rx.iter().collect::<Vec<_>>();
            sorted_trees.sort_unstable_by_key(|k| k.0);

            sorted_trees
                .into_iter()
                .fold(None, |previous_comm_r: Option<_>, (i, replica_tree)| {
                    let comm_r = replica_tree.root();
                    // Each iteration's replica_tree becomes the next iteration's previous_tree (data_tree).
                    // The first iteration has no previous_tree.
                    if let Some(comm_d) = previous_comm_r {
                        let tau = porep::Tau { comm_r, comm_d };
                        info!("setting tau/aux (layer: {})", i - 1);
                        taus.push(tau);
                    };

                    auxs.push(replica_tree);

                    Some(comm_r)
                });
        }

        Ok((taus, auxs))
    }

    fn generate_data_tree(
        graph: &Self::Graph,
        data: &[u8],
        beta_height: usize,
        _layer: usize,
    ) -> HybridMerkleTree<Self::AlphaHasher, Self::BetaHasher> {
        #[cfg(not(feature = "disk-trees"))]
        return graph.hybrid_merkle_tree(&data, beta_height).unwrap();

        #[cfg(feature = "disk-trees")]
        {
            let tree_dir = &settings::SETTINGS.lock().unwrap().replicated_trees_dir;
            // We should always be able to get this configuration
            // variable (at least as an empty string).

            if tree_dir.is_empty() {
                // Signal `merkle_tree_path` to create a temporary file.
                return graph
                    .hybrid_merkle_tree_path(&data, beta_height, None)
                    .unwrap();
            } else {
                // Try to create `tree_dir`, ignore the error if `AlreadyExists`.
                if let Some(create_error) = fs::create_dir(&tree_dir).err() {
                    if create_error.kind() != io::ErrorKind::AlreadyExists {
                        panic!(create_error);
                    }
                }

                let tree_d = graph
                    .hybrid_merkle_tree_path(
                        &data,
                        beta_height,
                        Some(&PathBuf::from(tree_dir).join(format!(
                            "tree-{}-{}",
                            _layer,
                            // FIXME: This argument is used only with `disk-trees`.
                            rand::random::<u32>()
                        ))),
                    )
                    .unwrap();
                // FIXME: The user of `REPLICATED_TREES_DIR` should figure out
                // how to manage this directory, for now we create every file with
                // a different random number; the problem being that tests now do
                // replications many times in the same run so they may end up
                // reusing the same files with invalid (old) data and failing.

                tree_d.try_offload_store();
                return tree_d;
            }
        }
    }
}

impl<'a, L> ProofScheme<'a> for L
where
    L: Layers,
{
    type PublicParams = PublicParams<L::AlphaHasher, L::BetaHasher, L::Graph>;
    type SetupParams = SetupParams;
    type PublicInputs =
        PublicInputs<<L::AlphaHasher as Hasher>::Domain, <L::BetaHasher as Hasher>::Domain>;
    type PrivateInputs = PrivateInputs<L::AlphaHasher, L::BetaHasher>;
    type Proof = Proof<L::AlphaHasher, L::BetaHasher>;
    type Requirements = ChallengeRequirements;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        let graph = L::Graph::new(
            sp.drg.nodes,
            sp.drg.degree,
            sp.drg.expansion_degree,
            sp.drg.seed,
        );

        Ok(PublicParams::new(
            graph,
            sp.layer_challenges.clone(),
            sp.beta_heights.clone(),
        ))
    }

    fn prove<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        let proofs = Self::prove_all_partitions(pub_params, pub_inputs, priv_inputs, 1)?;
        let k = match pub_inputs.k {
            None => 0,
            Some(k) => k,
        };

        Ok(proofs[k].to_owned())
    }

    fn prove_all_partitions<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
        partition_count: usize,
    ) -> Result<Vec<Self::Proof>> {
        assert!(partition_count > 0);

        let proofs = Self::prove_layers(
            &pub_params.graph,
            pub_inputs,
            &priv_inputs.tau,
            &priv_inputs.aux,
            &pub_params.layer_challenges,
            pub_params.layer_challenges.layers(),
            pub_params.layer_challenges.layers(),
            partition_count,
            &pub_params.beta_heights,
        )?;

        let mut proof_columns = vec![Vec::new(); partition_count];

        for partition_proofs in proofs.into_iter() {
            for (j, proof) in partition_proofs.into_iter().enumerate() {
                proof_columns[j].push(proof);
            }
        }

        let proofs = proof_columns
            .into_iter()
            .map(|p| Proof::new(p, priv_inputs.tau.clone()))
            .collect();

        Ok(proofs)
    }

    fn verify_all_partitions(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        partition_proofs: &[Self::Proof],
    ) -> Result<bool> {
        for (k, proof) in partition_proofs.iter().enumerate() {
            if proof.encoding_proofs.len() != pub_params.layer_challenges.layers() {
                return Ok(false);
            }

            // TODO: verification is broken for the first node, figure out how to unbreak
            // with permutations

            let mut comm_rs = Vec::new();
            let mut graph = Some(pub_params.graph.clone());

            for (layer, proof_layer) in proof.encoding_proofs.iter().enumerate() {
                comm_rs.push(proof.tau[layer].comm_r);

                let current_graph = graph.take().unwrap();
                let graph_size = current_graph.size();
                graph = Some(Self::transform(&current_graph));

                let beta_height = pub_params.beta_heights[layer];

                // If this is the first encoding layer (i.e if `layer` is 0), we don't have access to
                // the height of the data layer's tree, so we can just max out `usize`.
                let previous_layer_beta_height = if layer == 0 {
                    usize::max_value()
                } else {
                    pub_params.beta_heights[layer - 1]
                };

                let pp = drgporep::PublicParams::new(
                    current_graph,
                    true,
                    pub_params.layer_challenges.challenges_for_layer(layer),
                    pub_params.beta_heights[layer],
                    previous_layer_beta_height,
                );

                let replica_id = if beta_height == 0 {
                    pub_inputs.replica_id.convert_into_alpha()
                } else {
                    pub_inputs.replica_id.convert_into_beta()
                };

                let new_pub_inputs = drgporep::PublicInputs {
                    replica_id: Some(replica_id),
                    challenges: pub_inputs.challenges(
                        &pub_params.layer_challenges,
                        graph_size,
                        layer as u8,
                        Some(k),
                    ),
                    tau: Some(proof.tau[layer]),
                };

                let ep = &proof_layer;
                let res = DrgPoRep::verify(
                    &pp,
                    &new_pub_inputs,
                    &drgporep::Proof {
                        data_root: ep.data_root,
                        replica_root: ep.replica_root,
                        replica_nodes: ep.replica_nodes.clone(),
                        replica_parents: ep.replica_parents.clone(),
                        // TODO: investigate if clone can be avoided by using a reference in drgporep::DataProof
                        nodes: ep.nodes.clone(),
                    },
                )?;

                if !res {
                    return Ok(false);
                }
            }

            let last_layer_replica_id = if *pub_params.beta_heights.last().unwrap() == 0 {
                pub_inputs.replica_id.convert_into_alpha()
            } else {
                pub_inputs.replica_id.convert_into_beta()
            };

            let crs =
                comm_r_star::<L::AlphaHasher, L::BetaHasher>(&last_layer_replica_id, &comm_rs)?;

            if crs != pub_inputs.comm_r_star {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn with_partition(pub_in: Self::PublicInputs, k: Option<usize>) -> Self::PublicInputs {
        self::PublicInputs {
            replica_id: pub_in.replica_id,
            seed: None,
            tau: pub_in.tau,
            comm_r_star: pub_in.comm_r_star,
            k,
        }
    }

    fn satisfies_requirements(
        public_params: &Self::PublicParams,
        requirements: &ChallengeRequirements,
        partitions: usize,
    ) -> bool {
        let partition_challenges = public_params.layer_challenges.total_challenges();

        partition_challenges * partitions >= requirements.minimum_challenges
    }
}

// We need to calculate CommR* -- which is: H(replica_id|comm_r[0]|comm_r[1]|…comm_r[n])
fn comm_r_star<AH, BH>(
    replica_id: &HybridDomain<AH::Domain, BH::Domain>,
    comm_rs: &[HybridDomain<AH::Domain, BH::Domain>],
) -> Result<HybridDomain<AH::Domain, BH::Domain>>
where
    AH: Hasher,
    BH: Hasher,
{
    let l = (comm_rs.len() + 1) * 32;
    let mut bytes = vec![0; l];

    replica_id.write_bytes(&mut bytes[0..32])?;

    for (i, comm_r) in comm_rs.iter().enumerate() {
        comm_r.write_bytes(&mut bytes[(i + 1) * 32..(i + 2) * 32])?;
    }

    // `comm_r_star` will be the same variant of `HybridDomain` as the last `comm_r`.
    if comm_rs.last().unwrap().is_alpha() {
        let comm_r_star_alpha = AH::Function::hash(&bytes);
        Ok(HybridDomain::Alpha(comm_r_star_alpha))
    } else {
        let comm_r_star_beta = BH::Function::hash(&bytes);
        Ok(HybridDomain::Beta(comm_r_star_beta))
    }
}

impl<'a, 'c, L> PoRep<'a, L::AlphaHasher, L::BetaHasher> for L
where
    L: Layers,
{
    type Tau = Tau<<L::AlphaHasher as Hasher>::Domain, <L::BetaHasher as Hasher>::Domain>;
    type ProverAux = Vec<HybridMerkleTree<L::AlphaHasher, L::BetaHasher>>;

    fn replicate(
        pp: &'a PublicParams<L::AlphaHasher, L::BetaHasher, L::Graph>,
        replica_id: &HybridDomain<
            <L::AlphaHasher as Hasher>::Domain,
            <L::BetaHasher as Hasher>::Domain,
        >,
        data: &mut [u8],
        _data_tree: Option<HybridMerkleTree<L::AlphaHasher, L::BetaHasher>>,
    ) -> Result<(Self::Tau, Self::ProverAux)> {
        let (taus, auxs) = Self::transform_and_replicate_layers(
            &pp.graph,
            &pp.layer_challenges,
            replica_id,
            data,
            &pp.beta_heights,
        )?;

        let comm_rs: Vec<_> = taus.iter().map(|tau| tau.comm_r).collect();

        // The `replica_id` argument has a `HybridDomain` variant passed corresponding to the data
        // layer's beta height, to compute comm-r-star we need the last layer's replica-id.
        let last_layer_replica_id = if *pp.beta_heights.last().unwrap() == 0 {
            replica_id.convert_into_alpha()
        } else {
            replica_id.convert_into_beta()
        };

        let crs = comm_r_star::<L::AlphaHasher, L::BetaHasher>(&last_layer_replica_id, &comm_rs)?;

        let tau = Tau {
            layer_taus: taus,
            comm_r_star: crs,
        };
        Ok((tau, auxs))
    }

    fn extract_all<'b>(
        pp: &'a PublicParams<L::AlphaHasher, L::BetaHasher, L::Graph>,
        replica_id: &HybridDomain<
            <L::AlphaHasher as Hasher>::Domain,
            <L::BetaHasher as Hasher>::Domain,
        >,
        data: &'b [u8],
    ) -> Result<Vec<u8>> {
        let mut data = data.to_vec();

        Self::extract_and_invert_transform_layers(
            &pp.graph,
            &pp.layer_challenges,
            &pp.beta_heights,
            replica_id,
            &mut data,
        )?;

        Ok(data)
    }

    fn extract(
        _pp: &'a PublicParams<L::AlphaHasher, L::BetaHasher, L::Graph>,
        _replica_id: &HybridDomain<
            <L::AlphaHasher as Hasher>::Domain,
            <L::BetaHasher as Hasher>::Domain,
        >,
        _data: &[u8],
        _node: usize,
    ) -> Result<Vec<u8>> {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_taper_challenges() {
        let layer_challenges = LayerChallenges::new_tapered(10, 333, 7, 1.0 / 3.0);
        // Last layers should have most challenges.
        let expected: Vec<usize> = vec![20, 20, 20, 30, 44, 66, 99, 149, 223, 333];

        for (i, expected_count) in expected.iter().enumerate() {
            let calculated_count = layer_challenges.challenges_for_layer(i);
            assert_eq!(*expected_count as usize, calculated_count);
        }

        assert_eq!(expected, layer_challenges.all_challenges());
        assert_eq!(layer_challenges.total_challenges(), 1004);
        let live_challenges = LayerChallenges::new_tapered(4, 2, 2, 1.0 / 3.0);
        assert_eq!(live_challenges.total_challenges(), 6)
    }

    #[test]
    fn test_calculate_fixed_challenges() {
        let layer_challenges = LayerChallenges::new_fixed(10, 333);
        let expected = [333, 333, 333, 333, 333, 333, 333, 333, 333, 333];

        for (i, expected_count) in expected.iter().enumerate() {
            let calculated_count = layer_challenges.challenges_for_layer(i);
            assert_eq!(*expected_count as usize, calculated_count);
        }
    }
}
