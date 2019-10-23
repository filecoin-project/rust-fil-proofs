use std::marker::PhantomData;

use merkletree::store::DiskStore;
use merkletree::store::Store;
use paired::bls12_381::Fr;
use serde::{Deserialize, Serialize};

use crate::drgraph::Graph;
use crate::error::Result;
use crate::fr32::bytes_into_fr_repr_safe;
use crate::hasher::{Domain, Hasher};
use crate::merkle::{MerkleProof, MerkleTree};
use crate::parameter_cache::ParameterSetMetadata;
use crate::stacked::{
    column::Column, column_proof::ColumnProof, encoding_proof::EncodingProof,
    graph::StackedBucketGraph, hash::hash2, LayerChallenges,
};
use crate::util::{data_at_node, NODE_SIZE};

pub type Tree<H> = MerkleTree<<H as Hasher>::Domain, <H as Hasher>::Function>;

#[derive(Debug)]
pub struct SetupParams {
    // Number of nodes
    pub nodes: usize,

    // Base degree of DRG
    pub degree: usize,

    pub expansion_degree: usize,

    // Random seed
    pub seed: [u32; 7],

    pub layer_challenges: LayerChallenges,
}

#[derive(Debug, Clone)]
pub struct PublicParams<H>
where
    H: 'static + Hasher,
{
    pub graph: StackedBucketGraph<H>,
    pub layer_challenges: LayerChallenges,
    _h: PhantomData<H>,
}

impl<H> PublicParams<H>
where
    H: Hasher,
{
    pub fn new(graph: StackedBucketGraph<H>, layer_challenges: LayerChallenges) -> Self {
        PublicParams {
            graph,
            layer_challenges,
            _h: PhantomData,
        }
    }
}

impl<H> ParameterSetMetadata for PublicParams<H>
where
    H: Hasher,
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

impl<'a, H> From<&'a PublicParams<H>> for PublicParams<H>
where
    H: Hasher,
{
    fn from(other: &PublicParams<H>) -> PublicParams<H> {
        PublicParams::new(other.graph.clone(), other.layer_challenges.clone())
    }
}

#[derive(Debug, Clone)]
pub struct PublicInputs<T: Domain> {
    pub replica_id: T,
    pub seed: Option<T>,
    pub tau: Option<Tau<T>>,
    pub k: Option<usize>,
}

impl<T: Domain> PublicInputs<T> {
    pub fn challenges(
        &self,
        layer_challenges: &LayerChallenges,
        layer: usize,
        leaves: usize,
        partition_k: Option<usize>,
    ) -> Vec<usize> {
        let k = partition_k.unwrap_or(0);

        if let Some(ref seed) = self.seed {
            layer_challenges.derive::<T>(layer, leaves, &self.replica_id, seed, k as u8)
        } else {
            layer_challenges.derive::<T>(
                layer,
                leaves,
                &self.replica_id,
                &self.tau.as_ref().expect("missing comm_r").comm_r,
                k as u8,
            )
        }
    }

    pub fn all_challenges(
        &self,
        layer_challenges: &LayerChallenges,
        leaves: usize,
        partition_k: Option<usize>,
    ) -> Vec<usize> {
        let k = partition_k.unwrap_or(0);

        if let Some(ref seed) = self.seed {
            layer_challenges.derive_all::<T>(leaves, &self.replica_id, seed, k as u8)
        } else {
            layer_challenges.derive_all::<T>(
                leaves,
                &self.replica_id,
                &self.tau.as_ref().expect("missing comm_r").comm_r,
                k as u8,
            )
        }
    }
}

#[derive(Debug)]
pub struct PrivateInputs<H: Hasher> {
    pub p_aux: PersistentAux<H::Domain>,
    pub t_aux: TemporaryAux<H>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<H: Hasher> {
    #[serde(bound(
        serialize = "MerkleProof<H>: Serialize",
        deserialize = "MerkleProof<H>: Deserialize<'de>"
    ))]
    pub comm_d_proofs: MerkleProof<H>,
    #[serde(bound(
        serialize = "MerkleProof<H>: Serialize, ColumnProof<H>: Serialize",
        deserialize = "MerkleProof<H>: Deserialize<'de>, ColumnProof<H>: Deserialize<'de>"
    ))]
    pub comm_r_last_proof: MerkleProof<H>,
    #[serde(bound(
        serialize = "ReplicaColumnProof<H>: Serialize",
        deserialize = "ReplicaColumnProof<H>: Deserialize<'de>"
    ))]
    pub replica_column_proofs: ReplicaColumnProof<H>,
    #[serde(bound(
        serialize = "EncodingProof<H>: Serialize",
        deserialize = "EncodingProof<H>: Deserialize<'de>"
    ))]
    /// Indexed by layer in 1..layers.
    pub encoding_proofs: Vec<EncodingProof<H>>,
}

impl<H: Hasher> Proof<H> {
    pub fn comm_r_last(&self) -> &H::Domain {
        self.comm_r_last_proof.root()
    }

    pub fn comm_c(&self) -> &H::Domain {
        self.replica_column_proofs.c_x.root()
    }

    fn comm_r(&self) -> H::Domain {
        Fr::from(hash2(self.comm_c(), self.comm_r_last())).into()
    }

    /// Verify the full proof.
    pub fn verify(
        &self,
        pub_params: &PublicParams<H>,
        pub_inputs: &PublicInputs<<H as Hasher>::Domain>,
        challenge: usize,
        challenge_index: usize,
        graph: &StackedBucketGraph<H>,
    ) -> bool {
        let replica_id = &pub_inputs.replica_id;

        check!(challenge < graph.size());
        check!(pub_inputs.tau.is_some());

        // just grabbing the first one
        let actual_comm_r = self.comm_r();
        let expected_comm_r = if let Some(ref tau) = pub_inputs.tau {
            &tau.comm_r
        } else {
            return false;
        };

        check_eq!(expected_comm_r, &actual_comm_r);

        // Verify initial data layer
        trace!("verify initial data layer");

        check!(self.comm_d_proofs.proves_challenge(challenge));
        if let Some(ref tau) = pub_inputs.tau {
            check_eq!(self.comm_d_proofs.root(), &tau.comm_d);
        } else {
            return false;
        }

        // Verify replica column openings
        trace!("verify replica column openings");
        check!(self.replica_column_proofs.verify());

        check!(self.verify_final_replica_layer(challenge));

        check!(self.verify_encodings(replica_id, &pub_params.layer_challenges, challenge_index));

        true
    }

    /// Verify all encodings.
    fn verify_encodings(
        &self,
        replica_id: &H::Domain,
        layer_challenges: &LayerChallenges,
        challenge_index: usize,
    ) -> bool {
        // Verify Encoding Layer 1..layers
        for layer in 1..=layer_challenges.layers() {
            let expect_challenge =
                layer_challenges.include_challenge_at_layer(layer, challenge_index);
            trace!(
                "verify encoding (layer: {} - expect_challenge: {})",
                layer,
                expect_challenge
            );

            let (encoded_node, decoded_node) = if layer == layer_challenges.layers() {
                (
                    self.comm_r_last_proof.leaf(),
                    Some(self.comm_d_proofs.leaf()),
                )
            } else {
                (
                    self.replica_column_proofs.c_x.get_node_at_layer(layer),
                    None,
                )
            };

            if expect_challenge {
                check!(self.encoding_proofs.get(layer - 1).is_some());
                let encoding_proof = &self.encoding_proofs[layer - 1];
                check!(encoding_proof.verify(replica_id, encoded_node, decoded_node));
            } else {
                check!(self.encoding_proofs.get(layer - 1).is_none());
            }
        }

        true
    }

    /// Verify final replica layer openings
    fn verify_final_replica_layer(&self, challenge: usize) -> bool {
        trace!("verify final replica layer openings");
        check!(self.comm_r_last_proof.proves_challenge(challenge));

        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaColumnProof<H: Hasher> {
    #[serde(bound(
        serialize = "ColumnProof<H>: Serialize",
        deserialize = "ColumnProof<H>: Deserialize<'de>"
    ))]
    pub c_x: ColumnProof<H>,
    #[serde(bound(
        serialize = "ColumnProof<H>: Serialize",
        deserialize = "ColumnProof<H>: Deserialize<'de>"
    ))]
    pub drg_parents: Vec<ColumnProof<H>>,
    #[serde(bound(
        serialize = "ColumnProof<H>: Serialize",
        deserialize = "ColumnProof<H>: Deserialize<'de>"
    ))]
    pub exp_parents: Vec<ColumnProof<H>>,
}

impl<H: Hasher> ReplicaColumnProof<H> {
    pub fn verify(&self) -> bool {
        let expected_comm_c = self.c_x.root();

        trace!("  verify c_x");
        check!(self.c_x.verify());

        trace!("  verify drg_parents");
        for proof in &self.drg_parents {
            check!(proof.verify());
            check_eq!(expected_comm_c, proof.root());
        }

        trace!("  verify exp_parents");
        for proof in &self.exp_parents {
            check!(proof.verify());
            check_eq!(expected_comm_c, proof.root());
        }

        true
    }
}

impl<H: Hasher> Proof<H> {
    pub fn serialize(&self) -> Vec<u8> {
        unimplemented!();
    }
}

pub type TransformedLayers<H> = (
    Tau<<H as Hasher>::Domain>,
    PersistentAux<<H as Hasher>::Domain>,
    TemporaryAux<H>,
);

/// Tau for a single parition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tau<D: Domain> {
    pub comm_d: D,
    pub comm_r: D,
}

/// Stored along side the sector on disk.
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PersistentAux<D> {
    pub comm_c: D,
    pub comm_r_last: D,
}

#[derive(Debug)]
pub struct TemporaryAux<H: Hasher> {
    /// The encoded nodes for 1..layers.
    pub encodings: Encodings<H>,
    pub tree_d: Tree<H>,
    pub tree_r_last: Tree<H>,
    pub tree_c: Tree<H>,
}

impl<H: Hasher> TemporaryAux<H> {
    pub fn encoding_at_layer(&self, layer: usize) -> &DiskStore<H::Domain> {
        self.encodings.encoding_at_layer(layer)
    }

    pub fn domain_node_at_layer(&self, layer: usize, node_index: u32) -> Result<H::Domain> {
        Ok(self.encoding_at_layer(layer).read_at(node_index as usize))
    }

    pub fn column(&self, column_index: u32) -> Result<Column<H>> {
        self.encodings.column(column_index)
    }
}

#[derive(Debug)]
pub struct Encodings<H: Hasher> {
    encodings: Vec<DiskStore<H::Domain>>,
    _h: PhantomData<H>,
}

impl<H: Hasher> Encodings<H> {
    pub fn new(encodings: Vec<DiskStore<H::Domain>>) -> Self {
        Encodings {
            encodings,
            _h: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.encodings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.encodings.is_empty()
    }

    pub fn encoding_at_layer(&self, layer: usize) -> &DiskStore<H::Domain> {
        assert!(layer != 0, "Layer cannot be 0");
        assert!(
            layer <= self.layers(),
            "Layer {} is not available (only {} layers available)",
            layer,
            self.layers()
        );

        let row_index = layer - 1;
        &self.encodings[row_index]
    }

    /// Returns encoding on the last layer.
    pub fn encoding_at_last_layer(&self) -> &DiskStore<H::Domain> {
        &self.encodings[self.encodings.len() - 1]
    }

    /// How many layers are available.
    fn layers(&self) -> usize {
        self.encodings.len()
    }

    /// Build the column for the given node.
    pub fn column(&self, node: u32) -> Result<Column<H>> {
        let rows = self
            .encodings
            .iter()
            .map(|encoding| encoding.read_at(node as usize))
            .collect();

        Ok(Column::new(node, rows))
    }
}

pub fn get_node<H: Hasher>(data: &[u8], index: usize) -> Result<H::Domain> {
    H::Domain::try_from_bytes(data_at_node(data, index).expect("invalid node math"))
}

/// Generate the replica id as expected for Stacked DRG.
pub fn generate_replica_id<H: Hasher>(
    prover_id: &[u8; 32],
    sector_id: u64,
    ticket: &[u8; 32],
    comm_d: H::Domain,
) -> H::Domain {
    use blake2s_simd::Params as Blake2s;

    let mut hasher = Blake2s::new().hash_length(NODE_SIZE).to_state();

    hasher.update(prover_id);
    hasher.update(&sector_id.to_le_bytes()[..]);
    hasher.update(ticket);
    hasher.update(AsRef::<[u8]>::as_ref(&comm_d));

    bytes_into_fr_repr_safe(hasher.finalize().as_ref()).into()
}
