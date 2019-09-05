use std::marker::PhantomData;

use blake2s_simd::Params as Blake2s;
use rayon::prelude::*;
use serde::de::Deserialize;
use serde::ser::Serialize;

use crate::challenge_derivation::derive_challenges;
use crate::drgporep::{self, DataProof, DrgPoRep};
use crate::drgraph::Graph;
use crate::error::Result;
use crate::hasher::{Domain, HashFunction, Hasher};
use crate::merkle::{next_pow2, populate_leaves, MerkleProof, MerkleStore, MerkleTree, Store};
use crate::parameter_cache::ParameterSetMetadata;
use crate::porep::{self, PoRep};
use crate::proof::ProofScheme;
use crate::util::{data_at_node, NODE_SIZE};
use crate::vde;
use crate::zigzag_graph::ZigZag;

type Tree<H> = MerkleTree<<H as Hasher>::Domain, <H as Hasher>::Function>;

#[derive(Debug, Clone, Serialize)]
pub struct LayerChallenges {
    layers: usize,
    count: usize,
}

impl LayerChallenges {
    pub const fn new_fixed(layers: usize, count: usize) -> Self {
        LayerChallenges { layers, count }
    }
    pub fn layers(&self) -> usize {
        self.layers
    }

    pub fn challenges(&self) -> usize {
        self.count
    }
}

#[derive(Debug)]
pub struct SetupParams {
    pub drg: drgporep::DrgParams,
    pub layer_challenges: LayerChallenges,
}

#[derive(Debug, Clone)]
pub struct PublicParams<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata,
{
    pub graph: G,
    pub layer_challenges: LayerChallenges,
    _h: PhantomData<H>,
}

#[derive(Debug, Clone)]
pub struct Tau<T: Domain> {
    pub layer_taus: Taus<T>,
    pub comm_r_star: T,
}

#[derive(Default)]
pub struct ChallengeRequirements {
    pub minimum_challenges: usize,
}

impl<T: Domain> Tau<T> {
    /// Return a single porep::Tau with the initial data and final replica commitments of layer_taus.
    pub fn simplify(&self) -> porep::Tau<T> {
        unimplemented!()
    }
}

impl<H, G> PublicParams<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata,
{
    pub fn new(graph: G, layer_challenges: LayerChallenges) -> Self {
        PublicParams {
            graph,
            layer_challenges,
            _h: PhantomData,
        }
    }
}

impl<H, G> ParameterSetMetadata for PublicParams<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata,
{
    fn identifier(&self) -> String {
        format!(
            "layered_drgporep::PublicParams{{ graph: {}, challenges: {:?} }}",
            self.graph.identifier(),
            self.layer_challenges,
        )
    }

    fn sector_size(&self) -> u64 {
        self.graph.sector_size()
    }
}

impl<'a, H, G> From<&'a PublicParams<H, G>> for PublicParams<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata,
{
    fn from(other: &PublicParams<H, G>) -> PublicParams<H, G> {
        PublicParams::new(other.graph.clone(), other.layer_challenges.clone())
    }
}

#[derive(Debug, Clone)]
pub struct PublicInputs<T: Domain> {
    pub replica_id: T,
    pub seed: Option<T>,
    pub tau: Option<porep::Tau<T>>,
    pub comm_r_star: T,
    pub k: Option<usize>,
}

impl<T: Domain> PublicInputs<T> {
    pub fn challenges(
        &self,
        layer_challenges: &LayerChallenges,
        leaves: usize,
        partition_k: Option<usize>,
    ) -> Vec<usize> {
        if let Some(ref seed) = self.seed {
            derive_challenges::<T>(
                layer_challenges,
                leaves,
                &self.replica_id,
                seed,
                partition_k.unwrap_or(0) as u8,
            )
        } else {
            derive_challenges::<T>(
                layer_challenges,
                leaves,
                &self.replica_id,
                &self.comm_r_star,
                partition_k.unwrap_or(0) as u8,
            )
        }
    }
}

pub struct PrivateInputs<H: Hasher> {
    pub tau: Taus<H::Domain>,
    pub aux: Aux<H>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<H: Hasher> {
    #[serde(bound(
        serialize = "DataProof<H>: Serialize",
        deserialize = "DataProof<H>: Deserialize<'de>"
    ))]
    pub comm_d_proofs: Vec<DataProof<H>>,
    #[serde(bound(
        serialize = "MerkleProof<H>: Serialize",
        deserialize = "MerkleProof<H>: Deserialize<'de>"
    ))]
    pub comm_c_proofs_even: Vec<MerkleProof<H>>,
    #[serde(bound(
        serialize = "MerkleProof<H>: Serialize",
        deserialize = "MerkleProof<H>: Deserialize<'de>"
    ))]
    pub comm_c_proofs_odd: Vec<MerkleProof<H>>,
    pub layer_labels: Vec<Vec<Vec<u8>>>,
    #[serde(bound(
        serialize = "DataProof<H>: Serialize",
        deserialize = "DataProof<H>: Deserialize<'de>"
    ))]
    pub comm_r_last_proofs: Vec<DataProof<H>>,
    #[serde(bound(
        serialize = "DrgParentsProof<H>: Serialize",
        deserialize = "DrgParentsProof<H>: Deserialize<'de>"
    ))]
    pub drg_parents_proofs: Vec<Vec<DrgParentsProof<H>>>,
    #[serde(bound(
        serialize = "ExpEvenParentsProof<H>: Serialize",
        deserialize = "ExpEvenParentsProof<H>: Deserialize<'de>"
    ))]
    pub exp_parents_even_proofs: Vec<Vec<ExpEvenParentsProof<H>>>,
    #[serde(bound(
        serialize = "ExpOddParentsProof<H>: Serialize",
        deserialize = "ExpOddParentsProof<H>: Deserialize<'de>"
    ))]
    pub exp_parents_odd_proofs: Vec<Vec<ExpOddParentsProof<H>>>,
    pub comm_r: H::Domain,
}

impl<H: Hasher> Proof<H> {
    pub fn serialize(&self) -> Vec<u8> {
        unimplemented!();
    }
}

pub type PartitionProofs<H> = Vec<Proof<H>>;

type PorepTau<H> = porep::Tau<<H as Hasher>::Domain>;
type TransformedLayers<H> = (Taus<<H as Hasher>::Domain>, Aux<H>);

#[derive(Debug, Clone)]
pub struct Taus<D: Domain> {
    /// The encoded nodes for 1..layers.
    encodings: Vec<Vec<u8>>,
    comm_r: D,
}

#[derive(Debug, Clone)]
pub struct Aux<H: Hasher> {
    tree_d: Tree<H>,
    tree_r_last: Tree<H>,
    tree_c: Tree<H>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrgParentsProof<H: Hasher> {
    pub labels: Vec<Vec<u8>>,
    #[serde(bound(
        serialize = "MerkleProof<H>: Serialize",
        deserialize = "MerkleProof<H>: Deserialize<'de>"
    ))]
    pub comm_c: MerkleProof<H>,
    #[serde(bound(
        serialize = "MerkleProof<H>: Serialize",
        deserialize = "MerkleProof<H>: Deserialize<'de>"
    ))]
    pub comm_r_last: MerkleProof<H>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpEvenParentsProof<H: Hasher> {
    pub labels: Vec<Vec<u8>>,
    pub value: Vec<u8>,
    #[serde(bound(
        serialize = "MerkleProof<H>: Serialize",
        deserialize = "MerkleProof<H>: Deserialize<'de>"
    ))]
    pub comm_c: MerkleProof<H>,
    #[serde(bound(
        serialize = "MerkleProof<H>: Serialize",
        deserialize = "MerkleProof<H>: Deserialize<'de>"
    ))]
    pub comm_r_last: MerkleProof<H>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpOddParentsProof<H: Hasher> {
    pub labels: Vec<Vec<u8>>,
    pub value: Vec<u8>,
    #[serde(bound(
        serialize = "MerkleProof<H>: Serialize",
        deserialize = "MerkleProof<H>: Deserialize<'de>"
    ))]
    pub comm_c: MerkleProof<H>,
}

/// Layers provides default implementations of methods required to handle proof and verification
/// of layered proofs of replication. Implementations must provide transform and invert_transform methods.
pub trait Layers {
    type Hasher: Hasher;
    type BaseGraph: Graph<Self::Hasher>;
    type Graph: ZigZag<BaseHasher = Self::Hasher, BaseGraph = Self::BaseGraph>
        + ParameterSetMetadata
        + Sync
        + Send;

    /// Transform a layer's public parameters, returning new public parameters corresponding to the next layer.
    /// Warning: This method will likely need to be extended for other implementations
    /// but because it is not clear what parameters they will need, only the ones needed
    /// for zizag are currently present (same applies to [invert_transform]).
    fn transform(graph: &Self::Graph) -> Self::Graph;

    /// Transform a layer's public parameters, returning new public parameters corresponding to the previous layer.
    fn invert_transform(graph: &Self::Graph) -> Self::Graph;

    #[allow(clippy::too_many_arguments)]
    fn prove_layers<'a>(
        graph: &Self::Graph,
        pub_inputs: &PublicInputs<<Self::Hasher as Hasher>::Domain>,
        tau: &Taus<<Self::Hasher as Hasher>::Domain>,
        aux: &'a Aux<Self::Hasher>,
        layer_challenges: &LayerChallenges,
        layers: usize,
        total_layers: usize,
        partition_count: usize,
    ) -> Result<Vec<Proof<Self::Hasher>>> {
        assert!(layers > 0);

        let graph_size = graph.size();

        // generate graphs for layer 1 and 2
        let graph_1 = Self::transform(graph);
        let graph_2 = Self::transform(&graph_1);

        (0..partition_count)
            .into_par_iter()
            .map(|k| {
                // Derive the set of challenges we are proving over.
                let challenges = pub_inputs.challenges(layer_challenges, graph_size, Some(k));

                let mut comm_d_proofs = Vec::with_capacity(challenges.len());
                let mut comm_r_last_proofs = Vec::with_capacity(challenges.len());
                let mut comm_c_proofs_even = Vec::with_capacity(challenges.len());
                let mut comm_c_proofs_odd = Vec::with_capacity(challenges.len());
                let mut layer_labels = Vec::with_capacity(challenges.len());
                let mut drg_parents_proofs = Vec::with_capacity(challenges.len());
                let mut exp_parents_even_proofs = Vec::with_capacity(challenges.len());
                let mut exp_parents_odd_proofs = Vec::with_capacity(challenges.len());

                // ZigZag commitment specifics
                for i in 0..challenges.len() {
                    let challenge = challenges[i] % graph.size();

                    // Initial data layer openings (D_X in Comm_D)
                    {
                        comm_d_proofs.push(DataProof {
                            data: aux.tree_d.read_at(challenge),
                            proof: MerkleProof::new_from_proof(&aux.tree_d.gen_proof(challenge)),
                        });
                    }

                    // C_n-X+1 in Comm_C
                    {
                        comm_c_proofs_even.push(MerkleProof::new_from_proof(
                            &aux.tree_c.gen_proof(NODE_SIZE - challenge + 1),
                        ));
                    }

                    // C_X in Comm_C
                    {
                        comm_c_proofs_odd.push(MerkleProof::new_from_proof(
                            &aux.tree_c.gen_proof(challenge),
                        ));
                    }

                    // e_X^(j) and e_n-X+1^(j)
                    {
                        let mut labels = Vec::with_capacity(2 * layers);
                        for layer in 1..layers {
                            // even
                            labels.push(
                                data_at_node(&tau.encodings[layer - 1], NODE_SIZE - challenge + 1)
                                    .unwrap()
                                    .to_vec(),
                            );
                            // odd
                            labels.push(
                                data_at_node(&tau.encodings[layer - 1], challenge)
                                    .unwrap()
                                    .to_vec(),
                            )
                        }
                        layer_labels.push(labels);
                    }

                    // Final replica layer openings (e_n-X-1^(l))
                    {
                        let challenge_inv = NODE_SIZE - challenge + 1;
                        comm_r_last_proofs.push(DataProof {
                            data: aux.tree_r_last.read_at(challenge_inv),
                            proof: MerkleProof::new_from_proof(
                                &aux.tree_r_last.gen_proof(challenge_inv),
                            ),
                        });
                    }

                    // DRG Parents
                    {
                        let base_degree = graph_1.base_graph().degree();

                        // DRG.Parents(X, 1)
                        let mut drg_parents = vec![0; base_degree];
                        graph_1.base_graph().parents(challenge, &mut drg_parents);

                        let mut proofs = Vec::with_capacity(base_degree);

                        for k in &drg_parents {
                            // labels e_k^(2j-1), e_n-k+1^(2j) for j=1..l/2
                            let mut labels = Vec::with_capacity(layers);
                            for j in 1..layers / 2 {
                                // -1 because encodings is zero indexed
                                labels.push(
                                    data_at_node(&tau.encodings[(2 * j - 1) - 1], *k)
                                        .unwrap()
                                        .to_vec(),
                                );
                                labels.push(
                                    data_at_node(&tau.encodings[(2 * j) - 1], NODE_SIZE - k + 1)
                                        .unwrap()
                                        .to_vec(),
                                );
                            }

                            // path for C_k to Comm_C
                            let comm_c = MerkleProof::new_from_proof(&aux.tree_c.gen_proof(*k));

                            // path for e_n-k+1^(l) to Comm_rlast
                            let comm_r_last = MerkleProof::new_from_proof(
                                &aux.tree_r_last.gen_proof(NODE_SIZE - k + 1),
                            );

                            proofs.push(DrgParentsProof {
                                labels,
                                comm_c,
                                comm_r_last,
                            });
                        }
                        drg_parents_proofs.push(proofs);
                    }

                    // Expander Parents - Even Layers
                    {
                        let exp_degree = graph_2.expansion_degree();

                        // EXP.Parents(n-X+1, 2)
                        let mut exp_parents = vec![0; exp_degree];
                        graph_2.expanded_parents(NODE_SIZE - challenge + 1, |p| {
                            exp_parents.copy_from_slice(&p[..]);
                        });

                        let mut proofs = Vec::with_capacity(exp_degree);

                        for k in &exp_parents {
                            // labels e_k^(2j) for j=1..l/2
                            let mut labels = Vec::with_capacity(layers / 2);
                            for j in 1..layers / 2 {
                                // -1 because encodings is zero indexed
                                labels.push(
                                    data_at_node(&tau.encodings[(2 * j) - 1], *k as usize)
                                        .unwrap()
                                        .to_vec(),
                                );
                            }

                            // O_n-k+1
                            let value = {
                                // H(e_i^(1) || e_i^(3) || .. || e_i^(l-1))
                                let mut hasher = Blake2s::new().hash_length(NODE_SIZE).to_state();
                                for layer in (1..layers).step_by(2) {
                                    hasher.update(
                                        data_at_node(
                                            &tau.encodings[layer],
                                            NODE_SIZE - (*k as usize) + 1,
                                        )
                                        .unwrap(),
                                    );
                                }
                                hasher.finalize().as_ref().to_vec()
                            };

                            // path for C_n-k+1 to Comm_C
                            let comm_c = MerkleProof::new_from_proof(
                                &aux.tree_c.gen_proof(NODE_SIZE - (*k as usize) + 1),
                            );

                            // path for e_k^(l) to Comm_rlast
                            let comm_r_last = MerkleProof::new_from_proof(
                                &aux.tree_r_last.gen_proof(*k as usize),
                            );

                            proofs.push(ExpEvenParentsProof {
                                labels,
                                value,
                                comm_c,
                                comm_r_last,
                            });
                        }
                        exp_parents_even_proofs.push(proofs);
                    }

                    // Expander Parents - Odd Layers
                    {
                        let exp_degree = graph_1.expansion_degree();

                        // EXP.Parents(X, 1)
                        let mut exp_parents = vec![0; exp_degree];
                        graph_1.expanded_parents(NODE_SIZE - challenge + 1, |p| {
                            exp_parents.copy_from_slice(&p[..]);
                        });

                        let mut proofs = Vec::with_capacity(exp_degree);

                        for k in &exp_parents {
                            // labels e_k^(2j-1) for j=1..l/2
                            let mut labels = Vec::with_capacity(layers / 2);
                            for j in 1..layers / 2 {
                                // -1 because encodings is zero indexed
                                labels.push(
                                    data_at_node(&tau.encodings[(2 * j - 1) - 1], *k as usize)
                                        .unwrap()
                                        .to_vec(),
                                );
                            }

                            // E_n-k+1
                            let value = {
                                // H(e_i^(2) || e_i^(4) || .. || e_i^(l-2))
                                let mut hasher = Blake2s::new().hash_length(NODE_SIZE).to_state();
                                for layer in (2..layers - 1).step_by(2) {
                                    hasher.update(
                                        data_at_node(
                                            &tau.encodings[layer],
                                            NODE_SIZE - (*k as usize) + 1,
                                        )
                                        .unwrap(),
                                    );
                                }
                                hasher.finalize().as_ref().to_vec()
                            };

                            // path for C_k to Comm_C
                            let comm_c =
                                MerkleProof::new_from_proof(&aux.tree_c.gen_proof(*k as usize));

                            proofs.push(ExpOddParentsProof {
                                labels,
                                value,
                                comm_c,
                            });
                        }
                        exp_parents_odd_proofs.push(proofs);
                    }
                }

                Ok(Proof {
                    comm_r: tau.comm_r.clone(),
                    comm_d_proofs,
                    comm_r_last_proofs,
                    comm_c_proofs_even,
                    comm_c_proofs_odd,
                    layer_labels,
                    drg_parents_proofs,
                    exp_parents_even_proofs,
                    exp_parents_odd_proofs,
                })
            })
            .collect()
    }

    fn extract_and_invert_transform_layers<'a>(
        graph: &Self::Graph,
        layer_challenges: &LayerChallenges,
        replica_id: &<Self::Hasher as Hasher>::Domain,
        data: &'a mut [u8],
    ) -> Result<()> {
        let layers = layer_challenges.layers();
        assert!(layers > 0);

        (0..layers).fold(graph.clone(), |current_graph, layer| {
            let inverted = Self::invert_transform(&current_graph);
            let pp =
                drgporep::PublicParams::new(inverted.clone(), true, layer_challenges.challenges());
            let mut res = DrgPoRep::extract_all(&pp, replica_id, data)
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
        replica_id: &<Self::Hasher as Hasher>::Domain,
        data: &mut [u8],
    ) -> Result<TransformedLayers<Self::Hasher>> {
        // TODO:
        // The implementation below is a memory hog, and very naive in terms of performance.
        // It also hardcodes the hash function.
        // This is done to get an initial version implemented and make sure it is correct.
        // After that we can improve on that.

        let layers = layer_challenges.layers();
        assert!(layers > 0);

        let build_tree = |tree_data: &[u8]| {
            let leafs = tree_data.len() / NODE_SIZE;
            assert_eq!(tree_data.len() % NODE_SIZE, 0);
            let pow = next_pow2(leafs);
            let mut leaves_store = MerkleStore::new(pow);
            populate_leaves::<_, <Self::Hasher as Hasher>::Function, _, std::iter::Map<_, _>>(
                &mut leaves_store,
                (0..leafs).map(|i| {
                    let d = data_at_node(tree_data, i).unwrap();
                    <Self::Hasher as Hasher>::Domain::try_from_bytes(d).unwrap()
                }),
            );

            graph.merkle_tree_from_leaves(leaves_store, leafs)
        };

        // 1. Build the MerkleTree over the original data
        let tree_d = build_tree(&data)?;

        // 2. Encode all layers
        let mut encoded_data: Vec<Vec<u8>> = Vec::with_capacity(layers);
        let mut current_graph = graph.clone();

        for layer in 0..layers {
            info!("encoding (layer: {})", layer);
            let mut to_encode = if layer == 0 {
                data.to_vec()
            } else {
                encoded_data[layer - 1].clone()
            };
            vde::encode(&current_graph, replica_id, &mut to_encode)?;
            current_graph = Self::transform(&current_graph);
            encoded_data.push(to_encode);
        }

        // 3. Construct Column Commitments
        // Split encoded layers into even, odd and the last one
        let r_last = encoded_data.pop().unwrap();

        let mut odd_partition = Vec::with_capacity(layers / 2);
        let mut even_partition = Vec::with_capacity(layers / 2);

        for (layer_num, layer) in encoded_data.iter().enumerate() {
            if layer_num % 2 == 0 {
                even_partition.push(layer);
            } else {
                odd_partition.push(layer);
            }
        }

        // build the columns
        let nodes_count = data.len() / NODE_SIZE;

        // odd columns
        let mut odd_columns = Vec::with_capacity(nodes_count);
        for i in 0..nodes_count {
            let mut hasher = Blake2s::new().hash_length(NODE_SIZE).to_state();
            for layer in 1..layers {
                let e = data_at_node(&odd_partition[layer], i).unwrap();
                hasher.update(e);
            }

            odd_columns.push(hasher.finalize());
        }

        // even columns
        let mut even_columns = Vec::with_capacity(nodes_count);
        for i in 0..nodes_count {
            let mut hasher = Blake2s::new().hash_length(NODE_SIZE).to_state();
            for layer in 1..layers {
                let e = data_at_node(&even_partition[layer], NODE_SIZE - i + 1).unwrap();
                hasher.update(e);
            }

            even_columns.push(hasher.finalize());
        }

        // combine odd and even
        let mut columns = Vec::with_capacity(data.len());
        for i in 0..nodes_count {
            let mut hasher = Blake2s::new().hash_length(NODE_SIZE).to_state();
            hasher.update(odd_columns[i].as_ref());
            hasher.update(even_columns[i].as_ref());
            columns.extend_from_slice(hasher.finalize().as_ref());
        }

        // Build the tree for CommC
        let tree_c = build_tree(&columns)?;

        // 4. Construct final replica commitment
        let tree_r_last = build_tree(&r_last)?;

        assert_eq!(encoded_data.len(), layers - 1);

        // comm_r = H(comm_c || comm_r_last)
        let comm_r = {
            let mut bytes = tree_c.root().as_ref().to_vec();
            bytes.extend_from_slice(tree_r_last.root().as_ref());
            <Self::Hasher as Hasher>::Function::hash(&bytes)
        };

        Ok((
            Taus {
                encodings: encoded_data,
                comm_r,
            },
            Aux {
                tree_c,
                tree_d,
                tree_r_last,
            },
        ))
    }
}

impl<'a, L: Layers> ProofScheme<'a> for L {
    type PublicParams = PublicParams<L::Hasher, L::Graph>;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<<L::Hasher as Hasher>::Domain>;
    type PrivateInputs = PrivateInputs<L::Hasher>;
    type Proof = Proof<L::Hasher>;
    type Requirements = ChallengeRequirements;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        let graph = L::Graph::new(
            sp.drg.nodes,
            sp.drg.degree,
            sp.drg.expansion_degree,
            sp.drg.seed,
        );

        Ok(PublicParams::new(graph, sp.layer_challenges.clone()))
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

        Self::prove_layers(
            &pub_params.graph,
            pub_inputs,
            &priv_inputs.tau,
            &priv_inputs.aux,
            &pub_params.layer_challenges,
            pub_params.layer_challenges.layers(),
            pub_params.layer_challenges.layers(),
            partition_count,
        )
    }

    fn verify_all_partitions(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        partition_proofs: &[Self::Proof],
    ) -> Result<bool> {
        // TODO: does comm_r go into the proof or not? if not we need to verify H(comm_c || com_r_last) = comm_r

        let graph = &pub_params.graph;
        // generate graphs for layer 1 and 2
        let graph_1 = Self::transform(graph);
        let graph_2 = Self::transform(&graph_1);

        for (k, proof) in partition_proofs.iter().enumerate() {
            let challenges =
                pub_inputs.challenges(&pub_params.layer_challenges, graph.size(), Some(k));
            for i in 0..challenges.len() {
                // Validate for this challenge
                let challenge = challenges[i] % graph.size();

                // 1. Verify inclusion proofs
                {
                    if !proof.comm_d_proofs[i].proves_challenge(challenge) {
                        return Ok(false);
                    }

                    if !proof.comm_c_proofs_even[i].proves_challenge(NODE_SIZE - challenge + 1) {
                        return Ok(false);
                    }

                    if !proof.comm_c_proofs_odd[i].proves_challenge(challenge) {
                        return Ok(false);
                    }

                    if !proof.comm_r_last_proofs[i].proves_challenge(NODE_SIZE - challenge + 1) {
                        return Ok(false);
                    }

                    // drg parents proofs
                    for proof in &proof.drg_parents_proofs[i] {
                        let base_degree = graph_1.base_graph().degree();

                        // DRG.Parents(X, 1)
                        let mut drg_parents = vec![0; base_degree];
                        graph_1.base_graph().parents(challenge, &mut drg_parents);

                        for k in &drg_parents {
                            if !proof.comm_c.proves_challenge(*k as usize) {
                                return Ok(false);
                            }
                            if !proof.comm_r_last.proves_challenge(NODE_SIZE - k + 1) {
                                return Ok(false);
                            }
                        }
                    }

                    // exp parents even
                    for proof in &proof.exp_parents_even_proofs[i] {
                        let exp_degree = graph_2.expansion_degree();

                        // EXP.Parents(n-X+1, 2)
                        let mut exp_parents = vec![0; exp_degree];
                        graph_2.expanded_parents(NODE_SIZE - challenge + 1, |p| {
                            exp_parents.copy_from_slice(&p[..]);
                        });

                        for k in &exp_parents {
                            if !proof.comm_c.proves_challenge(NODE_SIZE - (*k) as usize + 1) {
                                return Ok(false);
                            }
                            if !proof.comm_r_last.proves_challenge(*k as usize) {
                                return Ok(false);
                            }
                        }
                    }

                    // exp parents odd

                    // Expander Parents - Odd Layers
                    for proof in &proof.exp_parents_odd_proofs[i] {
                        let exp_degree = graph_1.expansion_degree();

                        // EXP.Parents(X, 1)
                        let mut exp_parents = vec![0; exp_degree];
                        graph_1.expanded_parents(NODE_SIZE - challenge + 1, |p| {
                            exp_parents.copy_from_slice(&p[..]);
                        });

                        for k in &exp_parents {
                            if !proof.comm_c.proves_challenge(*k as usize) {
                                return Ok(false);
                            }
                        }
                    }
                }

                // 2. D_X = e_x^(1) - H(tau || Parents_0(x))

                // 3. for 2..l-1
                // if j = 0 % 2 => e_n-x+1^(j-1) = e_n-x+1^(j) - H(tau || Parents_j(n-x+1))
                // else => e_x^(j-1) = e_x^(j) - H(tau || Parents_j(x))

                // TODO:
            }

            // 4. verify comm_r_star
            // TODO: is this still relevant
            let comm_rs = vec![proof.comm_r.clone()];
            let crs = comm_r_star::<L::Hasher>(&pub_inputs.replica_id, &comm_rs)?;

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
        public_params: &PublicParams<L::Hasher, L::Graph>,
        requirements: &ChallengeRequirements,
        partitions: usize,
    ) -> bool {
        let partition_challenges = public_params.layer_challenges.challenges();

        partition_challenges * partitions >= requirements.minimum_challenges
    }
}

// We need to calculate CommR* -- which is: H(replica_id|comm_r[0]|comm_r[1]|…comm_r[n])
fn comm_r_star<H: Hasher>(replica_id: &H::Domain, comm_rs: &[H::Domain]) -> Result<H::Domain> {
    let l = (comm_rs.len() + 1) * 32;
    let mut bytes = vec![0; l];

    replica_id.write_bytes(&mut bytes[0..32])?;

    for (i, comm_r) in comm_rs.iter().enumerate() {
        comm_r.write_bytes(&mut bytes[(i + 1) * 32..(i + 2) * 32])?;
    }

    Ok(H::Function::hash(&bytes))
}

impl<'a, 'c, L: Layers> PoRep<'a, L::Hasher> for L {
    type Tau = Tau<<L::Hasher as Hasher>::Domain>;
    type ProverAux = Aux<L::Hasher>;

    fn replicate(
        pp: &'a PublicParams<L::Hasher, L::Graph>,
        replica_id: &<L::Hasher as Hasher>::Domain,
        data: &mut [u8],
        _data_tree: Option<Tree<L::Hasher>>,
    ) -> Result<(Self::Tau, Self::ProverAux)> {
        let (taus, aux) = Self::transform_and_replicate_layers(
            &pp.graph,
            &pp.layer_challenges,
            replica_id,
            data,
        )?;
        // TODO: solidify this.
        let comm_rs = vec![taus.comm_r];
        let crs = comm_r_star::<L::Hasher>(replica_id, &comm_rs)?;
        let tau = Tau {
            layer_taus: taus,
            comm_r_star: crs,
        };
        Ok((tau, aux))
    }

    fn extract_all<'b>(
        pp: &'b PublicParams<L::Hasher, L::Graph>,
        replica_id: &'b <L::Hasher as Hasher>::Domain,
        data: &'b [u8],
    ) -> Result<Vec<u8>> {
        let mut data = data.to_vec();

        Self::extract_and_invert_transform_layers(
            &pp.graph,
            &pp.layer_challenges,
            replica_id,
            &mut data,
        )?;

        Ok(data)
    }

    fn extract(
        _pp: &PublicParams<L::Hasher, L::Graph>,
        _replica_id: &<L::Hasher as Hasher>::Domain,
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
    fn test_calculate_fixed_challenges() {
        let layer_challenges = LayerChallenges::new_fixed(10, 333);
        let expected = 333;

        let calculated_count = layer_challenges.challenges();
        assert_eq!(expected as usize, calculated_count);
    }
}
