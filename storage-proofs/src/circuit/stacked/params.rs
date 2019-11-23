use std::marker::PhantomData;

use bellperson::gadgets::{boolean::Boolean, num};
use bellperson::{ConstraintSystem, SynthesisError};
use fil_sapling_crypto::jubjub::JubjubEngine;
use paired::bls12_381::{Bls12, Fr};

use crate::circuit::stacked::{
    column_proof::ColumnProof, encoding_proof::EncodingProof, labeling_proof::LabelingProof,
};
use crate::circuit::{por::PoRCircuit, variables::Root};
use crate::drgraph::Graph;
use crate::hasher::Hasher;
use crate::merkle::MerkleProof;
use crate::stacked::{
    Proof as VanillaProof, PublicParams, ReplicaColumnProof as VanillaReplicaColumnProof,
};

#[derive(Debug, Clone)]
pub struct Proof<H: Hasher, G: Hasher> {
    pub comm_d_proof: InclusionPath<G>,
    pub comm_r_last_proof: InclusionPath<H>,
    pub replica_column_proof: ReplicaColumnProof<H>,
    pub labeling_proofs: Vec<(usize, LabelingProof)>,
    pub encoding_proof: EncodingProof,
}

impl<H: Hasher, G: Hasher> Proof<H, G> {
    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty(params: &PublicParams<H>, challenge_index: usize) -> Self {
        let layers = params.layer_challenges.layers();

        let mut labeling_proofs = Vec::with_capacity(layers);
        for layer in 1..=layers {
            let include_challenge = params
                .layer_challenges
                .include_challenge_at_layer(layer, challenge_index);

            if !include_challenge {
                continue;
            }

            labeling_proofs.push((layer, LabelingProof::empty(params, layer)));
        }

        Proof {
            comm_d_proof: InclusionPath::empty(&params.window_graph),
            comm_r_last_proof: InclusionPath::empty(&params.window_graph),
            replica_column_proof: ReplicaColumnProof::empty(params),
            labeling_proofs,
            encoding_proof: EncodingProof::empty(params),
        }
    }

    /// Circuit synthesis.
    #[allow(clippy::too_many_arguments)]
    pub fn synthesize<CS: ConstraintSystem<Bls12>>(
        self,
        mut cs: CS,
        params: &<Bls12 as JubjubEngine>::Params,
        layers: usize,
        comm_d: &num::AllocatedNum<Bls12>,
        comm_c: &num::AllocatedNum<Bls12>,
        comm_r_last: &num::AllocatedNum<Bls12>,
        replica_id: &[Boolean],
    ) -> Result<(), SynthesisError> {
        let Proof {
            comm_d_proof,
            comm_r_last_proof,
            replica_column_proof,
            labeling_proofs,
            encoding_proof,
        } = self;

        // verify initial data layer
        let comm_d_leaf = comm_d_proof.alloc_value(cs.namespace(|| "comm_d_leaf"))?;
        comm_d_proof.synthesize(
            cs.namespace(|| "comm_d_inclusion"),
            params,
            comm_d.clone(),
            comm_d_leaf.clone(),
        )?;

        let comm_r_last_data_leaf =
            comm_r_last_proof.alloc_value(cs.namespace(|| "comm_r_last_data_leaf"))?;

        // verify encodings
        for (layer, proof) in labeling_proofs.into_iter() {
            let raw = replica_column_proof.c_x.get_node_at_layer(layer);
            let labeled_node =
                num::AllocatedNum::alloc(cs.namespace(|| format!("label_node_{}", layer)), || {
                    raw.map(Into::into)
                        .ok_or_else(|| SynthesisError::AssignmentMissing)
                })?;

            proof.synthesize(
                cs.namespace(|| format!("labeling_proof_{}", layer)),
                params,
                replica_id,
                &labeled_node,
            )?;
        }

        encoding_proof.synthesize(
            cs.namespace(|| format!("encoding_proof_{}", layers)),
            params,
            replica_id,
            &comm_r_last_data_leaf,
            &comm_d_leaf,
        )?;

        // verify replica column openings
        replica_column_proof.synthesize(cs.namespace(|| "replica_column_proof"), params, comm_c)?;

        // verify final replica layer
        comm_r_last_proof.synthesize(
            cs.namespace(|| "comm_r_last_data_inclusion"),
            params,
            comm_r_last.clone(),
            comm_r_last_data_leaf,
        )?;

        Ok(())
    }
}

impl<H: Hasher, G: Hasher> From<VanillaProof<H, G>> for Proof<H, G> {
    fn from(vanilla_proof: VanillaProof<H, G>) -> Self {
        let VanillaProof {
            comm_d_proofs,
            comm_r_last_proof,
            replica_column_proofs,
            labeling_proofs,
            encoding_proof,
        } = vanilla_proof;

        let mut labeling_proofs: Vec<_> = labeling_proofs
            .into_iter()
            .map(|(layer, p)| (layer, p.into()))
            .collect();

        labeling_proofs.sort_by_cached_key(|(k, _)| *k);

        Proof {
            comm_d_proof: comm_d_proofs.into(),
            comm_r_last_proof: comm_r_last_proof.into(),
            replica_column_proof: replica_column_proofs.into(),
            labeling_proofs,
            encoding_proof: encoding_proof.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct InclusionPath<H: Hasher> {
    value: Option<Fr>,
    auth_path: Vec<Option<(Fr, bool)>>,
    _h: PhantomData<H>,
}

impl<H: Hasher> InclusionPath<H> {
    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty<G: Hasher>(graph: &impl Graph<G>) -> Self {
        InclusionPath {
            value: None,
            auth_path: vec![None; graph.merkle_tree_depth() as usize],
            _h: PhantomData,
        }
    }

    pub fn alloc_value<CS: ConstraintSystem<Bls12>>(
        &self,
        cs: CS,
    ) -> Result<num::AllocatedNum<Bls12>, SynthesisError> {
        num::AllocatedNum::alloc(cs, || {
            self.value
                .map(Into::into)
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })
    }

    pub fn synthesize<CS: ConstraintSystem<Bls12>>(
        self,
        cs: CS,
        params: &<Bls12 as JubjubEngine>::Params,
        root: num::AllocatedNum<Bls12>,
        leaf: num::AllocatedNum<Bls12>,
    ) -> Result<(), SynthesisError> {
        let InclusionPath { auth_path, .. } = self;

        let root = Root::from_allocated::<CS>(root);
        let value = Root::from_allocated::<CS>(leaf);
        PoRCircuit::<Bls12, H>::synthesize(cs, params, value, auth_path, root, true)
    }
}

impl<H: Hasher> From<MerkleProof<H>> for InclusionPath<H> {
    fn from(other: MerkleProof<H>) -> Self {
        let (value, auth_path) = other.into_options_with_leaf();

        InclusionPath {
            value,
            auth_path,
            _h: PhantomData,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReplicaColumnProof<H: Hasher> {
    c_x: ColumnProof<H>,
    drg_parents: Vec<ColumnProof<H>>,
    exp_parents: Vec<ColumnProof<H>>,
}

impl<H: Hasher> ReplicaColumnProof<H> {
    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty(params: &PublicParams<H>) -> Self {
        ReplicaColumnProof {
            c_x: ColumnProof::empty(params),
            drg_parents: vec![
                ColumnProof::empty(params);
                params.window_graph.base_graph().degree()
            ],
            exp_parents: vec![ColumnProof::empty(params); params.window_graph.expansion_degree()],
        }
    }

    pub fn synthesize<CS: ConstraintSystem<Bls12>>(
        self,
        mut cs: CS,
        params: &<Bls12 as JubjubEngine>::Params,
        comm_c: &num::AllocatedNum<Bls12>,
    ) -> Result<(), SynthesisError> {
        let ReplicaColumnProof {
            c_x,
            drg_parents,
            exp_parents,
        } = self;

        // c_x
        c_x.synthesize(cs.namespace(|| "c_x"), params, comm_c)?;

        // drg parents
        for (i, parent) in drg_parents.into_iter().enumerate() {
            parent.synthesize(cs.namespace(|| format!("drg_parent_{}", i)), params, comm_c)?;
        }

        // exp parents
        for (i, parent) in exp_parents.into_iter().enumerate() {
            parent.synthesize(cs.namespace(|| format!("exp_parent_{}", i)), params, comm_c)?;
        }

        Ok(())
    }
}

impl<H: Hasher> From<VanillaReplicaColumnProof<H>> for ReplicaColumnProof<H> {
    fn from(vanilla_proof: VanillaReplicaColumnProof<H>) -> Self {
        let VanillaReplicaColumnProof {
            c_x,
            drg_parents,
            exp_parents,
        } = vanilla_proof;

        ReplicaColumnProof {
            c_x: c_x.into(),
            drg_parents: drg_parents.into_iter().map(|p| p.into()).collect(),
            exp_parents: exp_parents.into_iter().map(|p| p.into()).collect(),
        }
    }
}
