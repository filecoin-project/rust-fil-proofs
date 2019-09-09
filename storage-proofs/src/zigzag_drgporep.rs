//! ZigZagDrgPorep is a layered PoRep which replicates layer by layer.
//! Between layers, the graph is 'reversed' in such a way that the dependencies expand with each iteration.
//! This reversal is not a straightforward inversion -- so we coin the term 'zigzag' to describe the transformation.
//! Each graph can be divided into base and expansion components.
//! The 'base' component is an ordinary DRG. The expansion component attempts to add a target (expansion_degree) number of connections
//! between nodes in a reversible way. Expansion connections are therefore simply inverted at each layer.
//! Because of how DRG-sampled parents are calculated on demand, the base components are not. Instead, a same-degree
//! DRG with connections in the opposite direction (and using the same random seed) is used when calculating parents on demand.
//! For the algorithm to have the desired properties, it is important that the expansion components are directly inverted at each layer.
//! However, it is fortunately not necessary that the base DRG components also have this property.

use std::marker::PhantomData;

use blake2s_simd::Params as Blake2s;
use rayon::prelude::*;
use serde::de::Deserialize;
use serde::ser::Serialize;

use crate::challenge_derivation::derive_challenges;
use crate::drgporep::{self, DrgPoRep};
use crate::drgraph::Graph;
use crate::error::Result;
use crate::fr32::bytes_into_fr_repr_safe;
use crate::hasher::{Domain, HashFunction, Hasher};
use crate::merkle::{next_pow2, populate_leaves, MerkleProof, MerkleStore, MerkleTree, Store};
use crate::parameter_cache::ParameterSetMetadata;
use crate::porep::PoRep;
use crate::proof::ProofScheme;
use crate::util::{data_at_node, NODE_SIZE};
use crate::vde;
use crate::zigzag_graph::ZigZagBucketGraph;

type Tree<H> = MerkleTree<<H as Hasher>::Domain, <H as Hasher>::Function>;

#[derive(Debug)]
pub struct ZigZagDrgPoRep<'a, H: 'a + Hasher> {
    _a: PhantomData<&'a H>,
}

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

#[derive(Default)]
pub struct ChallengeRequirements {
    pub minimum_challenges: usize,
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
    pub tau: Tau<T>,
    pub k: Option<usize>,
}

impl<T: Domain> PublicInputs<T> {
    pub fn challenges(
        &self,
        layer_challenges: &LayerChallenges,
        leaves: usize,
        partition_k: Option<usize>,
    ) -> Vec<usize> {
        let k = partition_k.unwrap_or(0);

        if let Some(ref seed) = self.seed {
            derive_challenges::<T>(layer_challenges, leaves, &self.replica_id, seed, k as u8)
        } else {
            derive_challenges::<T>(
                layer_challenges,
                leaves,
                &self.replica_id,
                &self.tau.comm_r,
                k as u8,
            )
        }
    }
}

pub struct PrivateInputs<H: Hasher> {
    pub aux: Aux<H>,
}

// TODO: what should be actually in this?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<H: Hasher> {
    #[serde(bound(
        serialize = "MerkleProof<H>: Serialize",
        deserialize = "MerkleProof<H>: Deserialize<'de>"
    ))]
    pub comm_d_proofs: Vec<MerkleProof<H>>,
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
    #[serde(bound(
        serialize = "MerkleProof<H>: Serialize",
        deserialize = "MerkleProof<H>: Deserialize<'de>"
    ))]
    pub comm_r_last_proofs: Vec<MerkleProof<H>>,
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
    #[serde(bound(
        serialize = "EncodingProof<H>: Serialize",
        deserialize = "EncodingProof<H>: Deserialize<'de>"
    ))]
    /// Indexed by challenge. The encoding proof for layer 1.
    pub encoding_proof_1: Vec<EncodingProof<H>>,
    #[serde(bound(
        serialize = "EncodingProof<H>: Serialize",
        deserialize = "EncodingProof<H>: Deserialize<'de>"
    ))]
    /// Indexed first by challenge then by layer in 2..layers - 1.
    pub encoding_proofs: Vec<Vec<EncodingProof<H>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodingProof<H: Hasher> {
    encoded_node: H::Domain,
    decoded_node: H::Domain,
    parents: Vec<Vec<u8>>,
    #[serde(skip)]
    _h: PhantomData<H>,
}

impl<H: Hasher> EncodingProof<H> {
    pub fn new(encoded_node: H::Domain, decoded_node: H::Domain, parents: Vec<Vec<u8>>) -> Self {
        EncodingProof {
            encoded_node,
            decoded_node,
            parents,
            _h: PhantomData,
        }
    }

    pub fn verify(&self, replica_id: &H::Domain) -> bool {
        // create the key = H(tau || (e_k^(j))_{k in Parents(x, 1)})
        let key = {
            let mut hasher = Blake2s::new().hash_length(32).to_state();
            hasher.update(replica_id.as_ref());
            for parent in &self.parents {
                hasher.update(parent);
            }

            let hash = hasher.finalize();
            bytes_into_fr_repr_safe(hash.as_ref()).into()
        };

        // decode:
        let unsealed = H::sloth_decode(&key, &self.encoded_node);

        // assert equality
        unsealed == self.decoded_node
    }
}

impl<H: Hasher> Proof<H> {
    pub fn serialize(&self) -> Vec<u8> {
        unimplemented!();
    }
}

pub type PartitionProofs<H> = Vec<Proof<H>>;

type TransformedLayers<H> = (Tau<<H as Hasher>::Domain>, Aux<H>);

/// Tau for a single parition.
#[derive(Debug, Clone)]
pub struct Tau<D: Domain> {
    comm_d: D,
    comm_c: D,
    comm_r: D,
    comm_r_last: D,
}

#[derive(Debug, Clone)]
pub struct Aux<H: Hasher> {
    /// The encoded nodes for 1..layers.
    encodings: Vec<Vec<u8>>,
    tree_d: Tree<H>,
    tree_r_last: Tree<H>,
    tree_c: Tree<H>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrgParentsProof<H: Hasher> {
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
    pub value: H::Domain,
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
    pub value: H::Domain,
    #[serde(bound(
        serialize = "MerkleProof<H>: Serialize",
        deserialize = "MerkleProof<H>: Deserialize<'de>"
    ))]
    pub comm_c: MerkleProof<H>,
}

fn get_node<H: Hasher>(data: &[u8], index: usize) -> Result<H::Domain> {
    H::Domain::try_from_bytes(data_at_node(data, index).expect("invalid node math"))
}

impl<'a, H: 'static + Hasher> ZigZagDrgPoRep<'a, H> {
    /// Transform a layer's public parameters, returning new public parameters corresponding to the next layer.
    /// Warning: This method will likely need to be extended for other implementations
    /// but because it is not clear what parameters they will need, only the ones needed
    /// for zizag are currently present (same applies to [invert_transform]).
    fn transform(graph: &ZigZagBucketGraph<H>) -> ZigZagBucketGraph<H> {
        graph.zigzag()
    }

    /// Transform a layer's public parameters, returning new public parameters corresponding to the previous layer.
    fn invert_transform(graph: &ZigZagBucketGraph<H>) -> ZigZagBucketGraph<H> {
        graph.zigzag()
    }

    #[allow(clippy::too_many_arguments)]
    fn prove_layers(
        graph_0: &ZigZagBucketGraph<H>,
        pub_inputs: &PublicInputs<<H as Hasher>::Domain>,
        aux: &Aux<H>,
        layer_challenges: &LayerChallenges,
        layers: usize,
        _total_layers: usize,
        partition_count: usize,
    ) -> Result<Vec<Proof<H>>> {
        assert!(layers > 0);

        let graph_size = graph_0.size();
        let graph_1 = Self::transform(&graph_0);
        let graph_2 = Self::transform(&graph_1);

        assert_eq!(graph_0.layer(), 0);
        assert_eq!(graph_1.layer(), 1);
        assert_eq!(graph_2.layer(), 2);

        (0..partition_count)
            .into_par_iter()
            .map(|k| {
                trace!("proving partition {}/{}", k, partition_count);

                // Derive the set of challenges we are proving over.
                let challenges = pub_inputs.challenges(layer_challenges, graph_size, Some(k));

                let mut comm_d_proofs = Vec::with_capacity(challenges.len());
                let mut comm_r_last_proofs = Vec::with_capacity(challenges.len());
                let mut comm_c_proofs_even = Vec::with_capacity(challenges.len());
                let mut comm_c_proofs_odd = Vec::with_capacity(challenges.len());
                let mut drg_parents_proofs = Vec::with_capacity(challenges.len());
                let mut exp_parents_even_proofs = Vec::with_capacity(challenges.len());
                let mut exp_parents_odd_proofs = Vec::with_capacity(challenges.len());

                let mut encoding_proof_1 = Vec::with_capacity(challenges.len());
                let mut encoding_proofs = Vec::with_capacity(challenges.len());

                // ZigZag commitment specifics
                for raw_challenge in challenges {
                    let challenge = raw_challenge % graph_0.size();

                    // Initial data layer openings (D_X in Comm_D)
                    {
                        comm_d_proofs.push(MerkleProof::new_from_proof(
                            &aux.tree_d.gen_proof(challenge),
                        ));
                    }

                    // C_n-X+1 in Comm_C
                    {
                        comm_c_proofs_even.push(MerkleProof::new_from_proof(
                            &aux.tree_c.gen_proof(graph_0.inv_index(challenge)),
                        ));
                    }

                    // C_X in Comm_C
                    {
                        comm_c_proofs_odd.push(MerkleProof::new_from_proof(
                            &aux.tree_c.gen_proof(challenge),
                        ));
                    }

                    // Final replica layer openings (e_n-X-1^(l))
                    {
                        let challenge_inv = graph_0.inv_index(challenge);
                        comm_r_last_proofs.push(MerkleProof::new_from_proof(
                            &aux.tree_r_last.gen_proof(challenge_inv),
                        ));
                    }

                    // Encoding Proof layer 1
                    {
                        let encoded_node = get_node::<H>(&aux.encodings[0], challenge)?;
                        let decoded_node = aux.tree_d.read_at(challenge);

                        let mut parents = vec![0; graph_0.degree()];
                        graph_0.parents(challenge, &mut parents);

                        let parents_data = parents
                            .into_iter()
                            .map(|parent| {
                                data_at_node(&aux.encodings[0], parent).map(|v| v.to_vec())
                            })
                            .collect::<Result<_>>()?;

                        encoding_proof_1.push(EncodingProof::<H>::new(
                            encoded_node,
                            decoded_node,
                            parents_data,
                        ));
                    }

                    // Encoding Proof Layer 2..l-1
                    {
                        let mut proofs = Vec::with_capacity(layers - 2);

                        for layer in 2..layers {
                            let (graph, challenge) = if layer % 2 == 0 {
                                (&graph_1, graph_1.inv_index(challenge))
                            } else {
                                (&graph_2, challenge)
                            };

                            let encoded_data = &aux.encodings[layer - 1];
                            let decoded_data = &aux.encodings[layer - 2];

                            let encoded_node = get_node::<H>(&encoded_data, challenge)?;
                            let decoded_node = get_node::<H>(&decoded_data, challenge)?;

                            let mut parents = vec![0; graph.degree()];
                            graph.parents(challenge, &mut parents);

                            let parents_data = parents
                                .into_iter()
                                .map(|parent| {
                                    data_at_node(&encoded_data, parent).map(|v| v.to_vec())
                                })
                                .collect::<Result<_>>()?;

                            proofs.push(EncodingProof::<H>::new(
                                encoded_node,
                                decoded_node,
                                parents_data,
                            ));
                        }

                        encoding_proofs.push(proofs);
                    }

                    // DRG Parents
                    {
                        let base_degree = graph_0.base_graph().degree();

                        // DRG.Parents(X, 1)
                        let mut drg_parents = vec![0; base_degree];
                        graph_0.base_parents(challenge, &mut drg_parents);
                        let mut proofs = Vec::with_capacity(base_degree);

                        for k in &drg_parents {
                            // path for C_k to Comm_C
                            let comm_c = MerkleProof::new_from_proof(&aux.tree_c.gen_proof(*k));

                            // path for e_n-k+1^(l) to Comm_rlast
                            let comm_r_last = MerkleProof::new_from_proof(
                                &aux.tree_r_last.gen_proof(graph_0.inv_index(*k)),
                            );

                            proofs.push(DrgParentsProof {
                                comm_c,
                                comm_r_last,
                            });
                        }
                        drg_parents_proofs.push(proofs);
                    }

                    // Expander Parents - Even Layers
                    {
                        let exp_degree = graph_1.expansion_degree();

                        // EXP.Parents(n-X+1, 0)
                        let mut exp_parents = vec![0; exp_degree];
                        graph_1.expanded_parents(graph_1.inv_index(challenge), |p| {
                            exp_parents[..p.len()].copy_from_slice(&p[..]);
                        });

                        let mut proofs = Vec::with_capacity(exp_degree);

                        for k in &exp_parents {
                            // O_n-k+1
                            let value: Result<H::Domain> = {
                                // H(e_i^(1) || e_i^(3) || .. || e_i^(l-1))
                                let mut hasher = Blake2s::new().hash_length(NODE_SIZE).to_state();
                                for layer in (1..layers).step_by(2) {
                                    hasher.update(data_at_node(
                                        // -1 because encodings is zero indexed
                                        &aux.encodings[layer - 1],
                                        graph_1.inv_index(*k as usize),
                                    )?);
                                }
                                let hash = hasher.finalize();
                                Ok(bytes_into_fr_repr_safe(hash.as_ref()).into())
                            };

                            // path for C_n-k+1 to Comm_C
                            let comm_c = MerkleProof::new_from_proof(
                                &aux.tree_c.gen_proof(graph_1.inv_index(*k as usize)),
                            );

                            // path for e_k^(l) to Comm_rlast
                            let comm_r_last = MerkleProof::new_from_proof(
                                &aux.tree_r_last.gen_proof(*k as usize),
                            );

                            proofs.push(ExpEvenParentsProof {
                                value: value?,
                                comm_c,
                                comm_r_last,
                            });
                        }
                        exp_parents_even_proofs.push(proofs);
                    }

                    // Expander Parents - Odd Layers
                    {
                        let exp_degree = graph_2.expansion_degree();

                        // EXP.Parents(X, 1)
                        let mut exp_parents = vec![0; exp_degree];
                        graph_2.expanded_parents(challenge, |p| {
                            exp_parents[..p.len()].copy_from_slice(&p[..]);
                        });

                        let mut proofs = Vec::with_capacity(exp_degree);

                        for k in &exp_parents {
                            // E_n-k+1
                            let value: Result<H::Domain> = {
                                // H(e_i^(2) || e_i^(4) || .. || e_i^(l-2))
                                let mut hasher = Blake2s::new().hash_length(NODE_SIZE).to_state();
                                for layer in (2..layers - 1).step_by(2) {
                                    hasher.update(data_at_node(
                                        // -1 because encodings is zero indexed
                                        &aux.encodings[layer - 1],
                                        graph_2.inv_index(*k as usize),
                                    )?);
                                }

                                let hash = hasher.finalize();
                                Ok(bytes_into_fr_repr_safe(hash.as_ref()).into())
                            };

                            // path for C_k to Comm_C
                            let comm_c =
                                MerkleProof::new_from_proof(&aux.tree_c.gen_proof(*k as usize));

                            proofs.push(ExpOddParentsProof {
                                value: value?,
                                comm_c,
                            });
                        }
                        exp_parents_odd_proofs.push(proofs);
                    }
                }

                Ok(Proof {
                    comm_d_proofs,
                    comm_r_last_proofs,
                    comm_c_proofs_even,
                    comm_c_proofs_odd,
                    drg_parents_proofs,
                    exp_parents_even_proofs,
                    exp_parents_odd_proofs,
                    encoding_proof_1,
                    encoding_proofs,
                })
            })
            .collect()
    }

    fn extract_and_invert_transform_layers(
        graph: &ZigZagBucketGraph<H>,
        layer_challenges: &LayerChallenges,
        replica_id: &<H as Hasher>::Domain,
        data: &mut [u8],
    ) -> Result<()> {
        trace!("extract_and_invert_transform_layers");

        let layers = layer_challenges.layers();
        assert!(layers > 0);

        (0..layers).fold(graph.clone(), |current_graph, _layer| {
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
        graph: &ZigZagBucketGraph<H>,
        layer_challenges: &LayerChallenges,
        replica_id: &<H as Hasher>::Domain,
        data: &mut [u8],
        data_tree: Option<Tree<H>>,
    ) -> Result<TransformedLayers<H>> {
        trace!("transform_and_replicate_layers");
        let nodes_count = graph.size();

        assert_eq!(data.len(), nodes_count * NODE_SIZE);

        // TODO:
        // The implementation below is a memory hog, and very naive in terms of performance.
        // It also hardcodes the hash function.
        // This is done to get an initial version implemented and make sure it is correct.
        // After that we can improve on that.

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
        let mut encoded_data: Vec<Vec<u8>> = Vec::with_capacity(layers);
        let mut current_graph = graph.clone();

        for layer in 0..layers {
            trace!("encoding (layer: {})", layer);
            let mut to_encode = if layer == 0 {
                data.to_vec()
            } else {
                encoded_data[layer - 1].clone()
            };
            vde::encode(&current_graph, replica_id, &mut to_encode)?;
            current_graph = Self::transform(&current_graph);
            assert_eq!(to_encode.len(), NODE_SIZE * nodes_count);
            encoded_data.push(to_encode);
        }

        // Split encoded layers into even, odd and the last one
        let r_last = encoded_data.pop().unwrap();

        // store the last layer in the original data
        data[..NODE_SIZE * nodes_count].copy_from_slice(&r_last);

        // 3. Construct Column Commitments

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
        let columns: Vec<u8> = (0..nodes_count)
            .into_par_iter()
            .map(|i| {
                // odd
                let mut hasher = Blake2s::new().hash_length(NODE_SIZE).to_state();
                for partition in &odd_partition {
                    let e = data_at_node(partition, i).unwrap();
                    hasher.update(e);
                }

                let odd_hash = hasher.finalize();
                // even
                let mut hasher = Blake2s::new().hash_length(NODE_SIZE).to_state();
                for partition in &even_partition {
                    let e = data_at_node(partition, graph.inv_index(i)).unwrap();
                    hasher.update(e);
                }

                let even_hash = hasher.finalize();

                // combine
                let mut hasher = Blake2s::new().hash_length(NODE_SIZE).to_state();
                hasher.update(odd_hash.as_ref());
                hasher.update(even_hash.as_ref());

                hasher.finalize().as_ref().to_vec()
            })
            .flatten()
            .collect();

        // Build the tree for CommC
        let tree_c = build_tree(&columns)?;

        // 4. Construct final replica commitment
        let tree_r_last = build_tree(&r_last)?;

        assert_eq!(encoded_data.len(), layers - 1);

        // comm_r = H(comm_c || comm_r_last)
        let comm_r = {
            let mut bytes = tree_c.root().as_ref().to_vec();
            bytes.extend_from_slice(tree_r_last.root().as_ref());
            <H as Hasher>::Function::hash(&bytes)
        };

        Ok((
            Tau {
                comm_c: tree_c.root(),
                comm_d: tree_d.root(),
                comm_r,
                comm_r_last: tree_r_last.root(),
            },
            Aux {
                encodings: encoded_data,
                tree_c,
                tree_d,
                tree_r_last,
            },
        ))
    }
}

impl<'a, 'c, H: 'static + Hasher> ProofScheme<'a> for ZigZagDrgPoRep<'c, H> {
    type PublicParams = PublicParams<H, ZigZagBucketGraph<H>>;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<<H as Hasher>::Domain>;
    type PrivateInputs = PrivateInputs<H>;
    type Proof = Proof<H>;
    type Requirements = ChallengeRequirements;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        let graph = ZigZagBucketGraph::<H>::new_zigzag(
            sp.drg.nodes,
            sp.drg.degree,
            sp.drg.expansion_degree,
            0,
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
        trace!("prove_all_partitions");
        assert!(partition_count > 0);

        Self::prove_layers(
            &pub_params.graph,
            pub_inputs,
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
        // generate graphs
        let graph_0 = &pub_params.graph;
        let graph_1 = Self::transform(graph_0);
        let graph_2 = Self::transform(&graph_1);

        assert_eq!(graph_0.layer(), 0);
        assert_eq!(graph_1.layer(), 1);
        assert_eq!(graph_2.layer(), 2);

        let nodes_count = graph_0.size();
        let replica_id = &pub_inputs.replica_id;
        let layers = pub_params.layer_challenges.layers();

        trace!("verify_all_partitions ({})", nodes_count);

        for (k, proof) in partition_proofs.iter().enumerate() {
            trace!(
                "verify partition proof {}/{}",
                k + 1,
                partition_proofs.len()
            );

            let challenges =
                pub_inputs.challenges(&pub_params.layer_challenges, graph_0.size(), Some(k));
            for i in 0..challenges.len() {
                trace!("verify challenge {}/{}", i, challenges.len());
                // Validate for this challenge
                let challenge = challenges[i] % graph_0.size();

                // 1. Verify inclusion proofs
                {
                    trace!("verify inclusion");

                    if !proof.comm_d_proofs[i].proves_challenge(challenge) {
                        return Ok(false);
                    }

                    if !proof.comm_c_proofs_even[i].proves_challenge(graph_0.inv_index(challenge)) {
                        return Ok(false);
                    }

                    if !proof.comm_c_proofs_odd[i].proves_challenge(challenge) {
                        return Ok(false);
                    }

                    if !proof.comm_r_last_proofs[i].proves_challenge(graph_0.inv_index(challenge)) {
                        return Ok(false);
                    }

                    trace!("verify drg parents");
                    // DRG Parents
                    {
                        let base_degree = graph_0.base_graph().degree();

                        // DRG.Parents(X, 1)
                        let mut drg_parents = vec![0; base_degree];
                        graph_0.base_parents(challenge, &mut drg_parents);

                        assert_eq!(drg_parents.len(), proof.drg_parents_proofs[i].len());
                        for (k, proof) in drg_parents.iter().zip(&proof.drg_parents_proofs[i]) {
                            if !proof.comm_c.proves_challenge(*k as usize) {
                                return Ok(false);
                            }
                            if !proof.comm_r_last.proves_challenge(graph_0.inv_index(*k)) {
                                return Ok(false);
                            }
                        }
                    }

                    // Expander Parents - Even Layers
                    trace!("verify exp parents even");
                    {
                        let exp_degree = graph_1.expansion_degree();

                        // EXP.Parents(n-X+1, 0)
                        let mut exp_parents = vec![0; exp_degree];
                        graph_1.expanded_parents(graph_1.inv_index(challenge), |p| {
                            exp_parents[..p.len()].copy_from_slice(&p[..]);
                        });

                        assert_eq!(exp_parents.len(), proof.exp_parents_even_proofs[i].len());
                        for (k, proof) in exp_parents.iter().zip(&proof.exp_parents_even_proofs[i])
                        {
                            if !proof
                                .comm_c
                                .proves_challenge(graph_1.inv_index(*k as usize))
                            {
                                return Ok(false);
                            }
                            if !proof.comm_r_last.proves_challenge(*k as usize) {
                                return Ok(false);
                            }
                        }
                    }

                    // Expander Parents - Odd Layers
                    {
                        let exp_degree = graph_2.expansion_degree();

                        // EXP.Parents(X, 1)
                        let mut exp_parents = vec![0; exp_degree];
                        graph_2.expanded_parents(challenge, |p| {
                            exp_parents[..p.len()].copy_from_slice(&p[..]);
                        });

                        assert_eq!(exp_parents.len(), proof.exp_parents_odd_proofs[i].len());
                        for (k, proof) in exp_parents.iter().zip(&proof.exp_parents_odd_proofs[i]) {
                            if !proof.comm_c.proves_challenge(*k as usize) {
                                return Ok(false);
                            }
                        }
                    }
                }

                // 2. Verify Encoding Layer 1
                trace!("verify encoding (layer: 1)");
                if !proof.encoding_proof_1[i].verify(replica_id) {
                    return Ok(false);
                }

                // 3. Verify Encoding Layer 2..layers - 1
                assert_eq!(proof.encoding_proofs[i].len(), layers - 2);

                let mut invalid = 0;
                for (j, encoding_proof) in proof.encoding_proofs[i].iter().enumerate() {
                    trace!("verify encoding (layer: {})", j + 2);

                    if !encoding_proof.verify(replica_id) {
                        trace!("invalid proof");
                        // return Ok(false);
                        invalid += 1;
                    }
                }

                if invalid > 0 {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    fn with_partition(pub_in: Self::PublicInputs, k: Option<usize>) -> Self::PublicInputs {
        self::PublicInputs {
            replica_id: pub_in.replica_id,
            seed: None,
            tau: pub_in.tau,
            k,
        }
    }

    fn satisfies_requirements(
        public_params: &PublicParams<H, ZigZagBucketGraph<H>>,
        requirements: &ChallengeRequirements,
        partitions: usize,
    ) -> bool {
        let partition_challenges = public_params.layer_challenges.challenges();

        partition_challenges * partitions >= requirements.minimum_challenges
    }
}

impl<'a, 'c, H: 'static + Hasher> PoRep<'a, H> for ZigZagDrgPoRep<'a, H> {
    type Tau = Tau<<H as Hasher>::Domain>;
    type ProverAux = Aux<H>;

    fn replicate(
        pp: &'a PublicParams<H, ZigZagBucketGraph<H>>,
        replica_id: &<H as Hasher>::Domain,
        data: &mut [u8],
        data_tree: Option<Tree<H>>,
    ) -> Result<(Self::Tau, Self::ProverAux)> {
        let (tau, aux) = Self::transform_and_replicate_layers(
            &pp.graph,
            &pp.layer_challenges,
            replica_id,
            data,
            data_tree,
        )?;

        Ok((tau, aux))
    }

    fn extract_all<'b>(
        pp: &'b PublicParams<H, ZigZagBucketGraph<H>>,
        replica_id: &'b <H as Hasher>::Domain,
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
        _pp: &PublicParams<H, ZigZagBucketGraph<H>>,
        _replica_id: &<H as Hasher>::Domain,
        _data: &[u8],
        _node: usize,
    ) -> Result<Vec<u8>> {
        unimplemented!();
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
    use crate::zigzag_drgporep::{
        LayerChallenges, PrivateInputs, PublicInputs, PublicParams, SetupParams,
    };
    use crate::zigzag_graph::EXP_DEGREE;

    const DEFAULT_ZIGZAG_LAYERS: usize = 10;

    #[test]
    fn test_calculate_fixed_challenges() {
        let layer_challenges = LayerChallenges::new_fixed(10, 333);
        let expected = 333;

        let calculated_count = layer_challenges.challenges();
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
        let data = vec![2u8; 32 * 3];
        let challenges = LayerChallenges::new_fixed(DEFAULT_ZIGZAG_LAYERS, 5);

        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();

        let sp = SetupParams {
            drg: drgporep::DrgParams {
                nodes: data.len() / 32,
                degree: BASE_DEGREE,
                expansion_degree: EXP_DEGREE,
                seed: new_seed(),
            },
            layer_challenges: challenges.clone(),
        };

        let mut pp = ZigZagDrgPoRep::<H>::setup(&sp).expect("setup failed");
        // Get the graph for the last layer.
        // In reality, this is a no-op with an even number of layers.
        for _ in 0..pp.layer_challenges.layers() {
            pp.graph = pp.graph.zigzag();
        }

        ZigZagDrgPoRep::<H>::replicate(&pp, &replica_id, data_copy.as_mut_slice(), None)
            .expect("replication failed");

        let transformed_params = PublicParams::new(pp.graph, challenges.clone());

        assert_ne!(data, data_copy);

        let decoded_data = ZigZagDrgPoRep::<H>::extract_all(
            &transformed_params,
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
        // pretty_env_logger::init();
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
        let (tau, aux) =
            ZigZagDrgPoRep::<H>::replicate(&pp, &replica_id, data_copy.as_mut_slice(), None)
                .expect("replication failed");
        assert_ne!(data, data_copy);

        let pub_inputs = PublicInputs::<H::Domain> {
            replica_id,
            seed: None,
            tau,
            k: None,
        };

        let priv_inputs = PrivateInputs { aux };

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
}
