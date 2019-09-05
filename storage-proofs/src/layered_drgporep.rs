use std::cmp::{max, min};
use std::marker::PhantomData;
use std::sync::mpsc::channel;

use blake2s_simd::Params as Blake2s;
use crossbeam_utils::thread;
use rayon::prelude::*;
use serde::de::Deserialize;
use serde::ser::Serialize;

use crate::challenge_derivation::derive_challenges;
use crate::drgporep::{self, DrgPoRep};
use crate::drgraph::Graph;
use crate::error::{Error, Result};
use crate::hasher::{Domain, HashFunction, Hasher};
use crate::merkle::{next_pow2, populate_leaves, MerkleStore, MerkleTree, Store};
use crate::parameter_cache::ParameterSetMetadata;
use crate::porep::{self, PoRep};
use crate::proof::ProofScheme;
use crate::util::{data_at_node, NODE_SIZE};
use crate::vde;

type Tree<H> = MerkleTree<<H as Hasher>::Domain, <H as Hasher>::Function>;

#[derive(Debug, Clone, Serialize)]
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
    pub layer_taus: Vec<porep::Tau<T>>,
    pub comm_r_star: T,
}

#[derive(Default)]
pub struct ChallengeRequirements {
    pub minimum_challenges: usize,
}

impl<T: Domain> Tau<T> {
    /// Return a single porep::Tau with the initial data and final replica commitments of layer_taus.
    pub fn simplify(&self) -> porep::Tau<T> {
        porep::Tau {
            comm_r: self.layer_taus[self.layer_taus.len() - 1].comm_r,
            comm_d: self.layer_taus[0].comm_d,
        }
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

pub type EncodingProof<H> = drgporep::Proof<H>;

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
        layer: u8,
        partition_k: Option<usize>,
    ) -> Vec<usize> {
        if let Some(ref seed) = self.seed {
            derive_challenges::<T>(
                layer_challenges,
                layer,
                leaves,
                &self.replica_id,
                seed,
                partition_k.unwrap_or(0) as u8,
            )
        } else {
            derive_challenges::<T>(
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

pub struct PrivateInputs<H: Hasher> {
    /// MerkleTree for the last replication layer.
    pub tree_r_last: Tree<H>,
    /// The aggregated columns.
    pub columns: Vec<u8>,
    /// MerkleTree for the columns.
    pub tree_c: Tree<H>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<H: Hasher> {
    #[serde(bound(
        serialize = "EncodingProof<H>: Serialize",
        deserialize = "EncodingProof<H>: Deserialize<'de>"
    ))]
    pub encoding_proofs: Vec<EncodingProof<H>>,
    pub tau: Vec<porep::Tau<H::Domain>>,
}

impl<H: Hasher> Proof<H> {
    pub fn serialize(&self) -> Vec<u8> {
        unimplemented!();
    }
}

pub type PartitionProofs<H> = Vec<Proof<H>>;

impl<H: Hasher> Proof<H> {
    pub fn new(
        encoding_proofs: Vec<EncodingProof<H>>,
        tau: Vec<porep::Tau<H::Domain>>,
    ) -> Proof<H> {
        Proof {
            encoding_proofs,
            tau,
        }
    }
}

pub trait Layerable<H: Hasher>: Graph<H> {}

type PorepTau<H> = porep::Tau<<H as Hasher>::Domain>;
type TransformedLayers<H> = (Vec<PorepTau<H>>, Vec<Tree<H>>);

/// Layers provides default implementations of methods required to handle proof and verification
/// of layered proofs of replication. Implementations must provide transform and invert_transform methods.
pub trait Layers {
    type Hasher: Hasher;
    type Graph: Layerable<Self::Hasher> + ParameterSetMetadata + Sync + Send;

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
        tau: &[PorepTau<Self::Hasher>],
        aux: &'a [Tree<Self::Hasher>],
        layer_challenges: &LayerChallenges,
        layers: usize,
        total_layers: usize,
        partition_count: usize,
    ) -> Result<Vec<Vec<EncodingProof<Self::Hasher>>>> {
        assert!(layers > 0);

        let mut new_graph = Some(graph.clone());

        (0..layers)
            .map(|layer| {
                let current_graph = new_graph.take().unwrap();
                let inner_layers = layers - layer;

                let new_priv_inputs = drgporep::PrivateInputs {
                    tree_d: &aux[layer],
                    tree_r: &aux[layer + 1],
                };
                let layer_diff = total_layers - inner_layers;
                let graph_size = current_graph.size();
                new_graph = Some(Self::transform(&current_graph));

                let pp = drgporep::PublicParams::new(
                    current_graph,
                    true,
                    layer_challenges.challenges_for_layer(layer),
                );
                let partition_proofs: Vec<_> = (0..partition_count)
                    .into_par_iter()
                    .map(|k| {
                        let drgporep_pub_inputs = drgporep::PublicInputs {
                            replica_id: Some(pub_inputs.replica_id),
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

                Ok(partition_proofs)
            })
            .collect::<Result<Vec<_>>>()
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
            let pp = drgporep::PublicParams::new(
                inverted.clone(),
                true,
                layer_challenges.challenges_for_layer(layer),
            );
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
        let tree_d = build_tree(&data);

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

        for (layer_num, layer) in encoded_data.into_iter().enumerate() {
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

        unimplemented!()
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

        let proofs = Self::prove_layers(
            &pub_params.graph,
            pub_inputs,
            &priv_inputs.tau,
            &priv_inputs.aux,
            &pub_params.layer_challenges,
            pub_params.layer_challenges.layers(),
            pub_params.layer_challenges.layers(),
            partition_count,
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

                let pp = drgporep::PublicParams::new(
                    current_graph,
                    true,
                    pub_params.layer_challenges.challenges_for_layer(layer),
                );
                let new_pub_inputs = drgporep::PublicInputs {
                    replica_id: Some(pub_inputs.replica_id),
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
        let partition_challenges = public_params.layer_challenges.total_challenges();

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
    type ProverAux = Vec<Tree<L::Hasher>>;

    fn replicate(
        pp: &'a PublicParams<L::Hasher, L::Graph>,
        replica_id: &<L::Hasher as Hasher>::Domain,
        data: &mut [u8],
        _data_tree: Option<Tree<L::Hasher>>,
    ) -> Result<(Self::Tau, Self::ProverAux)> {
        let (taus, auxs) = Self::transform_and_replicate_layers(
            &pp.graph,
            &pp.layer_challenges,
            replica_id,
            data,
        )?;

        let comm_rs: Vec<_> = taus.iter().map(|tau| tau.comm_r).collect();
        let crs = comm_r_star::<L::Hasher>(replica_id, &comm_rs)?;
        let tau = Tau {
            layer_taus: taus,
            comm_r_star: crs,
        };
        Ok((tau, auxs))
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
