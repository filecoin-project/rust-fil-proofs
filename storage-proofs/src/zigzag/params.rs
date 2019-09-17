use std::marker::PhantomData;

use paired::bls12_381::Fr;
use serde::{Deserialize, Serialize};

use crate::drgporep;
use crate::drgraph::Graph;
use crate::error::Result;
use crate::hasher::{Domain, Hasher};
use crate::merkle::{MerkleProof, MerkleTree};
use crate::parameter_cache::ParameterSetMetadata;
use crate::util::data_at_node;
use crate::zigzag::{
    column::Column, column_proof::ColumnProof, encoding_proof::EncodingProof,
    graph::ZigZagBucketGraph, hash::hash2, LayerChallenges,
};

pub type Tree<H> = MerkleTree<<H as Hasher>::Domain, <H as Hasher>::Function>;

#[derive(Debug)]
pub struct SetupParams {
    pub drg: drgporep::DrgParams,
    pub layer_challenges: LayerChallenges,
}

#[derive(Debug, Clone)]
pub struct PublicParams<H>
where
    H: 'static + Hasher,
{
    pub graph: ZigZagBucketGraph<H>,
    pub layer_challenges: LayerChallenges,
    _h: PhantomData<H>,
}

impl<H> PublicParams<H>
where
    H: Hasher,
{
    pub fn new(graph: ZigZagBucketGraph<H>, layer_challenges: LayerChallenges) -> Self {
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
        leaves: usize,
        partition_k: Option<usize>,
    ) -> Vec<usize> {
        let k = partition_k.unwrap_or(0);

        if let Some(ref seed) = self.seed {
            layer_challenges.derive::<T>(leaves, &self.replica_id, seed, k as u8)
        } else {
            layer_challenges.derive::<T>(
                leaves,
                &self.replica_id,
                &self.tau.as_ref().expect("missing comm_r").comm_r,
                k as u8,
            )
        }
    }
}

#[derive(Debug, Clone)]
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
    pub comm_r_last_proofs: (MerkleProof<H>, Vec<MerkleProof<H>>),
    #[serde(bound(
        serialize = "ReplicaColumnProof<H>: Serialize",
        deserialize = "ReplicaColumnProof<H>: Deserialize<'de>"
    ))]
    pub replica_column_proofs: ReplicaColumnProof<H>,
    #[serde(bound(
        serialize = "EncodingProof<H>: Serialize",
        deserialize = "EncodingProof<H>: Deserialize<'de>"
    ))]
    /// Indexed by challenge. The encoding proof for layer 1.
    pub encoding_proof_1: EncodingProof<H>,
    #[serde(bound(
        serialize = "EncodingProof<H>: Serialize",
        deserialize = "EncodingProof<H>: Deserialize<'de>"
    ))]
    /// Indexed first by challenge then by layer in 2..layers - 1.
    pub encoding_proofs: Vec<EncodingProof<H>>,
}

impl<H: Hasher> Proof<H> {
    pub fn comm_r_last(&self) -> &H::Domain {
        self.comm_r_last_proofs.0.root()
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
        graph_0: &ZigZagBucketGraph<H>,
        graph_1: &ZigZagBucketGraph<H>,
    ) -> bool {
        let replica_id = &pub_inputs.replica_id;
        let layers = pub_params.layer_challenges.layers();

        check!(challenge < graph_0.size());

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

        check!(self.verify_final_replica_layer(challenge, graph_1));

        check!(self.verify_encodings(replica_id, layers));

        true
    }

    /// Verify all encodings.
    fn verify_encodings(&self, replica_id: &H::Domain, layers: usize) -> bool {
        let rpc = &self.replica_column_proofs;
        let comm_d = &self.comm_d_proofs;

        // Verify Encoding layer 1
        trace!("verify encoding (layer: 1)");
        check!(self.encoding_proof_1.verify(
            replica_id,
            rpc.c_x.get_node_at_layer(1),
            comm_d.leaf()
        ));

        // Verify Encoding Layer 2..layers - 1
        check_eq!(self.encoding_proofs.len(), layers - 2);

        for (j, encoding_proof) in self.encoding_proofs.iter().enumerate() {
            let layer = j + 2;
            trace!("verify encoding (layer: {})", layer);;

            let encoded_node = rpc.c_x.get_node_at_layer(layer);
            let decoded_node = rpc.c_inv_x.get_node_at_layer(layer - 1);

            check!(encoding_proof.verify(replica_id, encoded_node, decoded_node));
        }

        true
    }

    /// Verify final replica layer openings
    fn verify_final_replica_layer(&self, challenge: usize, graph_1: &ZigZagBucketGraph<H>) -> bool {
        trace!("verify final replica layer openings");
        let inv_challenge = graph_1.inv_index(challenge);

        check!(self.comm_r_last_proofs.0.proves_challenge(inv_challenge));

        let mut parents = vec![0; graph_1.degree()];
        graph_1.parents(inv_challenge, &mut parents);

        check_eq!(parents.len(), self.comm_r_last_proofs.1.len());

        for (p, parent) in self.comm_r_last_proofs.1.iter().zip(parents.into_iter()) {
            check!(p.proves_challenge(parent));
            check_eq!(self.comm_r_last(), p.root());
        }

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
    pub c_inv_x: ColumnProof<H>,
    #[serde(bound(
        serialize = "ColumnProof<H>: Serialize",
        deserialize = "ColumnProof<H>: Deserialize<'de>"
    ))]
    pub drg_parents: Vec<ColumnProof<H>>,
    #[serde(bound(
        serialize = "ColumnProof<H>: Serialize",
        deserialize = "ColumnProof<H>: Deserialize<'de>"
    ))]
    pub exp_parents_even: Vec<ColumnProof<H>>,
    #[serde(bound(
        serialize = "ColumnProof<H>: Serialize",
        deserialize = "ColumnProof<H>: Deserialize<'de>"
    ))]
    pub exp_parents_odd: Vec<ColumnProof<H>>,
}

impl<H: Hasher> ReplicaColumnProof<H> {
    pub fn verify(&self) -> bool {
        let expected_comm_c = self.c_x.root();

        trace!("  verify c_x");
        check!(self.c_x.verify());

        trace!("  verify c_inv_x");
        check!(self.c_inv_x.verify());
        check_eq!(expected_comm_c, self.c_inv_x.root());

        trace!("  verify drg_parents");
        for proof in &self.drg_parents {
            check!(proof.verify());
            check_eq!(expected_comm_c, proof.root());
        }

        trace!("  verify exp_parents_even");
        for proof in &self.exp_parents_even {
            check!(proof.verify());
            check_eq!(expected_comm_c, proof.root());
        }

        trace!("  verify exp_parents_odd");
        for proof in &self.exp_parents_odd {
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PersistentAux<D> {
    pub comm_c: D,
    pub comm_r_last: D,
}

#[derive(Debug, Clone)]
pub struct TemporaryAux<H: Hasher> {
    /// The encoded nodes for 1..layers.
    pub encodings: Encodings<H>,
    pub tree_d: Tree<H>,
    pub tree_r_last: Tree<H>,
    pub tree_c: Tree<H>,
    /// E_i
    pub es: Vec<H::Domain>,
    /// O_i
    pub os: Vec<H::Domain>,
}

impl<H: Hasher> TemporaryAux<H> {
    pub fn encoding_at_layer(&self, layer: usize) -> &[u8] {
        self.encodings.encoding_at_layer(layer)
    }

    pub fn node_at_layer(&self, layer: usize, node_index: usize) -> Result<&[u8]> {
        self.encodings.node_at_layer(layer, node_index)
    }

    pub fn domain_node_at_layer(&self, layer: usize, node_index: usize) -> Result<H::Domain> {
        self.node_at_layer(layer, node_index)
            .and_then(H::Domain::try_from_bytes)
    }

    pub fn even_column(&self, column_index: usize) -> Result<Column<H>> {
        self.encodings.even_column(column_index)
    }

    pub fn odd_column(&self, column_index: usize) -> Result<Column<H>> {
        self.encodings.odd_column(column_index)
    }

    pub fn full_column(
        &self,
        graph: &ZigZagBucketGraph<H>,
        column_index: usize,
    ) -> Result<Column<H>> {
        self.encodings.full_column(graph, column_index)
    }
}

#[derive(Debug, Clone)]
pub struct Encodings<H: Hasher> {
    encodings: Vec<Vec<u8>>,
    _h: PhantomData<H>,
}

impl<H: Hasher> Encodings<H> {
    pub fn new(encodings: Vec<Vec<u8>>) -> Self {
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

    pub fn encoding_at_layer(&self, layer: usize) -> &[u8] {
        assert!(layer != 0, "Layer cannot be 0");
        assert!(
            layer < self.layers(),
            "Layer {} is not available (only {} layers available)",
            layer,
            self.layers()
        );

        let row_index = layer - 1;
        &self.encodings[row_index][..]
    }

    /// How many layers are available.
    fn layers(&self) -> usize {
        self.encodings.len() + 1
    }

    pub fn node_at_layer(&self, layer: usize, node_index: usize) -> Result<&[u8]> {
        let encoding = self.encoding_at_layer(layer);
        data_at_node(encoding, node_index)
    }

    pub fn even_column(&self, column_index: usize) -> Result<Column<H>> {
        let rows = (2..self.layers())
            .step_by(2)
            .map(|layer| H::Domain::try_from_bytes(self.node_at_layer(layer, column_index)?))
            .collect::<Result<_>>()?;

        Ok(Column::new_even(column_index, rows))
    }

    pub fn odd_column(&self, column_index: usize) -> Result<Column<H>> {
        let rows = (1..self.layers())
            .step_by(2)
            .map(|layer| H::Domain::try_from_bytes(self.node_at_layer(layer, column_index)?))
            .collect::<Result<_>>()?;

        Ok(Column::new_odd(column_index, rows))
    }

    pub fn full_column(
        &self,
        graph: &ZigZagBucketGraph<H>,
        column_index: usize,
    ) -> Result<Column<H>> {
        let inv_index = graph.inv_index(column_index);

        let rows = (1..self.layers())
            .map(|layer| {
                let x = if layer % 2 == 0 {
                    inv_index
                } else {
                    column_index
                };

                H::Domain::try_from_bytes(self.node_at_layer(layer, x)?)
            })
            .collect::<Result<_>>()?;

        Ok(Column::new_all(column_index, rows))
    }
}

pub fn get_node<H: Hasher>(data: &[u8], index: usize) -> Result<H::Domain> {
    H::Domain::try_from_bytes(data_at_node(data, index).expect("invalid node math"))
}
