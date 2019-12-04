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
    WindowProof as VanillaWindowProof, WrapperProof as VanillaWrapperProof, OPENINGS_PER_WINDOW,
};

#[derive(Debug, Clone)]
pub struct Proof<H: Hasher, G: Hasher> {
    pub window_proofs: Vec<WindowProof<H, G>>,
    pub wrapper_proofs: Vec<WrapperProof<H>>,
    pub comm_c: Option<Fr>,
    pub comm_q: Option<Fr>,
    pub comm_r_last: Option<Fr>,
}

#[derive(Debug, Clone)]
pub struct WindowProof<H: Hasher, G: Hasher> {
    pub comm_d_proofs: Vec<InclusionPath<G>>,
    pub comm_q_proofs: Vec<InclusionPath<H>>,
    pub replica_column_proof: ReplicaColumnProof<H>,
    pub labeling_proofs: Vec<Vec<(usize, LabelingProof)>>,
    pub encoding_proofs: Vec<EncodingProof>,
}

#[derive(Debug, Clone)]
pub struct WrapperProof<H: Hasher> {
    pub comm_r_last_proof: InclusionPath<H>,
    pub comm_q_parents_proofs: Vec<InclusionPath<H>>,
    pub labeling_proof: LabelingProof,
}

impl<H: Hasher, G: Hasher> WindowProof<H, G> {
    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty(params: &PublicParams<H>, _challenge_index: usize) -> Self {
        let layers = params.config.window_challenges.layers();

        let labeling_proofs = (0..OPENINGS_PER_WINDOW)
            .map(|_| {
                (1..layers)
                    .map(|layer| (layer, LabelingProof::empty(params, layer)))
                    .collect()
            })
            .collect();

        WindowProof {
            comm_d_proofs: vec![InclusionPath::empty(&params.wrapper_graph); OPENINGS_PER_WINDOW],
            comm_q_proofs: vec![InclusionPath::empty(&params.wrapper_graph); OPENINGS_PER_WINDOW],
            replica_column_proof: ReplicaColumnProof::empty(params),
            labeling_proofs,
            encoding_proofs: vec![EncodingProof::empty(params); OPENINGS_PER_WINDOW],
        }
    }

    /// Circuit synthesis.
    #[allow(clippy::too_many_arguments)]
    pub fn synthesize<CS: ConstraintSystem<Bls12>>(
        self,
        mut cs: CS,
        params: &<Bls12 as JubjubEngine>::Params,
        comm_d: &num::AllocatedNum<Bls12>,
        comm_c: &num::AllocatedNum<Bls12>,
        comm_q: &num::AllocatedNum<Bls12>,
        replica_id: &[Boolean],
        layers: usize,
    ) -> Result<(), SynthesisError> {
        let WindowProof {
            comm_d_proofs,
            comm_q_proofs,
            replica_column_proof,
            labeling_proofs,
            encoding_proofs,
        } = self;

        // verify initial data layer
        let mut comm_d_leafs = Vec::new();
        for (i, comm_d_proof) in comm_d_proofs.into_iter().enumerate() {
            let comm_d_leaf =
                comm_d_proof.alloc_value(cs.namespace(|| format!("comm_d_leaf_{}", i)))?;
            comm_d_proof.synthesize(
                cs.namespace(|| format!("comm_d_inclusion_{}", i)),
                params,
                comm_d.clone(),
                comm_d_leaf.clone(),
            )?;
            comm_d_leafs.push(comm_d_leaf);
        }

        // verify q data layer
        let mut comm_q_leafs = Vec::new();
        for (i, comm_q_proof) in comm_q_proofs.into_iter().enumerate() {
            let comm_q_leaf =
                comm_q_proof.alloc_value(cs.namespace(|| format!("comm_q_leaf_{}", i)))?;
            comm_q_proof.synthesize(
                cs.namespace(|| format!("comm_q_inclusion_{}", i)),
                params,
                comm_q.clone(),
                comm_q_leaf.clone(),
            )?;
            comm_q_leafs.push(comm_q_leaf);
        }

        // verify labels
        for (window_index, labeling_proofs) in labeling_proofs.into_iter().enumerate() {
            let mut cs = cs.namespace(|| format!("labeling_proof_{}", window_index));
            assert_eq!(labeling_proofs.len(), layers - 1);

            for (layer, proof) in labeling_proofs.into_iter() {
                let raw = replica_column_proof
                    .c_x
                    .get_node_at_layer(window_index, layer);

                let labeled_node = num::AllocatedNum::alloc(
                    cs.namespace(|| format!("label_node_{}", layer)),
                    || {
                        raw.map(Into::into)
                            .ok_or_else(|| SynthesisError::AssignmentMissing)
                    },
                )?;

                proof.synthesize(
                    cs.namespace(|| format!("labeling_proof_{}", layer)),
                    params,
                    replica_id,
                    &labeled_node,
                )?;
            }
        }

        for (i, (encoding_proof, (comm_q_leaf, comm_d_leaf))) in encoding_proofs
            .into_iter()
            .zip(comm_q_leafs.iter().zip(comm_d_leafs.iter()))
            .enumerate()
        {
            encoding_proof.synthesize(
                cs.namespace(|| format!("encoding_proof_{}", i)),
                params,
                replica_id,
                comm_q_leaf,
                comm_d_leaf,
            )?;
        }

        // verify replica column openings
        replica_column_proof.synthesize(cs.namespace(|| "replica_column_proof"), params, comm_c)?;

        Ok(())
    }
}

impl<H: Hasher> WrapperProof<H> {
    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty(params: &PublicParams<H>, _challenge_index: usize) -> Self {
        let degree = params.wrapper_graph.expansion_degree();
        let comm_q_parents_proofs: Vec<_> = (0..degree)
            .map(|_| InclusionPath::empty(&params.wrapper_graph))
            .collect();

        WrapperProof {
            comm_r_last_proof: InclusionPath::empty(&params.wrapper_graph),
            comm_q_parents_proofs,
            labeling_proof: LabelingProof::empty_expansion(params),
        }
    }

    /// Circuit synthesis.
    #[allow(clippy::too_many_arguments)]
    pub fn synthesize<CS: ConstraintSystem<Bls12>>(
        self,
        mut cs: CS,
        params: &<Bls12 as JubjubEngine>::Params,
        comm_q: &num::AllocatedNum<Bls12>,
        comm_r_last: num::AllocatedNum<Bls12>,
        replica_id: &[Boolean],
    ) -> Result<(), SynthesisError> {
        let WrapperProof {
            comm_r_last_proof,
            comm_q_parents_proofs,
            labeling_proof,
        } = self;

        let comm_r_last_data_leaf =
            comm_r_last_proof.alloc_value(cs.namespace(|| "comm_r_last_data_leaf"))?;

        comm_r_last_proof.synthesize(
            cs.namespace(|| "comm_r_last_proof"),
            params,
            comm_r_last,
            comm_r_last_data_leaf.clone(),
        )?;

        // verify comm_q_parents
        for (i, proof) in comm_q_parents_proofs.into_iter().enumerate() {
            let comm_q_leaf = proof.alloc_value(cs.namespace(|| format!("comm_q_leaf_{}", i)))?;

            proof.synthesize(
                cs.namespace(|| format!("comm_q_parent_{}_inclusion", i)),
                params,
                comm_q.clone(),
                comm_q_leaf.clone(),
            )?;
        }

        // verify labeling
        labeling_proof.synthesize(
            cs.namespace(|| "labeling_proof"),
            params,
            replica_id,
            &comm_r_last_data_leaf,
        )?;

        Ok(())
    }
}

impl<H: Hasher, G: Hasher> From<VanillaProof<H, G>> for Proof<H, G> {
    fn from(vanilla_proof: VanillaProof<H, G>) -> Self {
        let VanillaProof {
            window_proofs,
            wrapper_proofs,
            comm_q,
            comm_c,
            comm_r_last,
        } = vanilla_proof;

        Proof {
            window_proofs: window_proofs.into_iter().map(Into::into).collect(),
            wrapper_proofs: wrapper_proofs.into_iter().map(Into::into).collect(),
            comm_q: Some(comm_q.into()),
            comm_c: Some(comm_c.into()),
            comm_r_last: Some(comm_r_last.into()),
        }
    }
}

impl<H: Hasher, G: Hasher> From<VanillaWindowProof<H, G>> for WindowProof<H, G> {
    fn from(vanilla_proof: VanillaWindowProof<H, G>) -> Self {
        let VanillaWindowProof {
            comm_d_proofs,
            comm_q_proofs,
            replica_column_proof,
            labeling_proofs,
            encoding_proofs,
        } = vanilla_proof;

        let labeling_proofs: Vec<_> = labeling_proofs
            .into_iter()
            .map(|proof| {
                let mut p = proof
                    .into_iter()
                    .map(|(layer, p)| (layer, p.into()))
                    .collect::<Vec<(_, _)>>();
                p.sort_by_cached_key(|(k, _)| *k);
                p
            })
            .collect();

        WindowProof {
            comm_d_proofs: comm_d_proofs.into_iter().map(Into::into).collect(),
            comm_q_proofs: comm_q_proofs.into_iter().map(Into::into).collect(),
            replica_column_proof: replica_column_proof.into(),
            labeling_proofs,
            encoding_proofs: encoding_proofs.into_iter().map(Into::into).collect(),
        }
    }
}

impl<H: Hasher> From<VanillaWrapperProof<H>> for WrapperProof<H> {
    fn from(vanilla_proof: VanillaWrapperProof<H>) -> Self {
        let VanillaWrapperProof {
            comm_r_last_proof,
            comm_q_parents_proofs,
            labeling_proof,
        } = vanilla_proof;

        let comm_q_parents_proofs: Vec<_> =
            comm_q_parents_proofs.into_iter().map(Into::into).collect();

        WrapperProof {
            comm_r_last_proof: comm_r_last_proof.into(),
            comm_q_parents_proofs,
            labeling_proof: labeling_proof.into(),
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
