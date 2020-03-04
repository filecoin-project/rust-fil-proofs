use std::marker::PhantomData;

use bellperson::gadgets::{boolean::Boolean, num};
use bellperson::{ConstraintSystem, SynthesisError};
use fil_sapling_crypto::jubjub::JubjubEngine;
use generic_array::typenum;
use paired::bls12_381::{Bls12, Fr};
use paired::Engine;

use super::{
    column_proof::ColumnProof, encoding_proof::EncodingProof, labeling_proof::LabelingProof,
};
use crate::drgraph::Graph;
use crate::gadgets::por::PoRCircuit;
use crate::gadgets::variables::Root;
use crate::hasher::{Hasher, PoseidonArity, PoseidonEngine};
use crate::merkle::MerkleProof;
use crate::porep::stacked::{
    Proof as VanillaProof, PublicParams, ReplicaColumnProof as VanillaReplicaColumnProof,
};

#[derive(Debug, Clone)]
pub struct Proof<H: Hasher, G: Hasher> {
    pub comm_d_proof: InclusionPath<Bls12, G, typenum::U2>,
    pub comm_r_last_proof: InclusionPath<Bls12, H, typenum::U8>,
    pub replica_column_proof: ReplicaColumnProof<H>,
    pub labeling_proofs: Vec<(usize, LabelingProof)>,
    pub encoding_proof: EncodingProof,
}

impl<H: Hasher, G: Hasher> Proof<H, G> {
    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty(params: &PublicParams<H>) -> Self {
        let layers = params.layer_challenges.layers();

        let mut labeling_proofs = Vec::with_capacity(layers);
        for layer in 1..=layers {
            labeling_proofs.push((layer, LabelingProof::empty(params, layer)));
        }

        Proof {
            comm_d_proof: InclusionPath::empty(&params.graph),
            comm_r_last_proof: InclusionPath::empty(&params.graph),
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
pub struct InclusionPath<E: Engine, H: Hasher, U>
where
    U: PoseidonArity<E>,
    typenum::Add1<U>: generic_array::ArrayLength<E::Fr>,
{
    value: Option<Fr>,
    auth_path: Vec<(Vec<Option<Fr>>, Option<usize>)>,
    _e: PhantomData<E>,
    _h: PhantomData<H>,
    _u: PhantomData<U>,
}

impl<U, H: Hasher> InclusionPath<Bls12, H, U>
where
    U: 'static + PoseidonArity<Bls12>,
    Bls12: PoseidonEngine<U>,
    typenum::Add1<U>: generic_array::ArrayLength<Fr>,
{
    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty<G: Hasher>(graph: &impl Graph<G>) -> Self {
        InclusionPath {
            value: None,
            auth_path: vec![
                (vec![None; U::to_usize() - 1], None);
                graph.merkle_tree_depth::<U>() as usize - 1
            ],
            _e: PhantomData,
            _h: PhantomData,
            _u: PhantomData,
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
        PoRCircuit::<U, Bls12, H>::synthesize(cs, params, value, auth_path, root, true)
    }
}

impl<E: Engine, H: Hasher, U: PoseidonArity<E>> From<MerkleProof<H, U>> for InclusionPath<E, H, U>
where
    typenum::Add1<U>: generic_array::ArrayLength<E::Fr>,
{
    fn from(other: MerkleProof<H, U>) -> Self {
        let (value, auth_path) = other.into_options_with_leaf();

        InclusionPath {
            value,
            auth_path,
            _e: PhantomData,
            _h: PhantomData,
            _u: PhantomData,
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
            drg_parents: vec![ColumnProof::empty(params); params.graph.base_graph().degree()],
            exp_parents: vec![ColumnProof::empty(params); params.graph.expansion_degree()],
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
