use bellperson::{ConstraintSystem, SynthesisError};
use fil_sapling_crypto::circuit::num;
use paired::bls12_381::{Bls12, Fr};

use crate::circuit::zigzag::column_proof::ColumnProof;
use crate::circuit::zigzag::encoding_proof::EncodingProof;
use crate::drgraph::Graph;
use crate::hasher::Hasher;
use crate::zigzag::{
    Proof as VanillaProof, PublicParams, ReplicaColumnProof as VanillaReplicaColumnProof,
};

#[derive(Debug, Clone)]
pub struct Proof {
    pub comm_d_proof: InclusionPath,
    pub comm_r_last_proofs: (InclusionPath, Vec<InclusionPath>),
    pub replica_column_proof: ReplicaColumnProof,
    pub encoding_proof_1: EncodingProof,
    pub encoding_proofs: Vec<EncodingProof>,
}

impl Proof {
    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty<H: Hasher>(params: &PublicParams<H>) -> Self {
        let degree = params.graph.degree();
        let challenges_count = params.layer_challenges.challenges_count();
        let layers = params.layer_challenges.layers();

        Proof {
            comm_d_proof: InclusionPath::empty(degree),
            comm_r_last_proofs: (
                InclusionPath::empty(degree),
                vec![InclusionPath::empty(degree); challenges_count],
            ),
            replica_column_proof: ReplicaColumnProof::empty(params),
            encoding_proof_1: EncodingProof::empty(params),
            encoding_proofs: vec![EncodingProof::empty(params); layers - 2],
        }
    }

    /// Circuit synthesis.
    pub fn synthesize<CS: ConstraintSystem<Bls12>>(
        self,
        cs: &mut CS,
        comm_r_last_0: &num::AllocatedNum<Bls12>,
        comm_c_0: &num::AllocatedNum<Bls12>,
    ) -> Result<(), SynthesisError> {
        let Proof {
            comm_d_proof,
            comm_r_last_proofs,
            replica_column_proof,
            encoding_proof_1,
            encoding_proofs,
        } = self;

        // verify initial data layer

        // verify replica column openings

        // verify final replica layer

        // verify encodings

        Ok(())
    }
}

impl<H: Hasher> From<VanillaProof<H>> for Proof {
    fn from(vanilla_proof: VanillaProof<H>) -> Self {
        let VanillaProof {
            comm_d_proofs,
            comm_r_last_proofs,
            replica_column_proofs,
            encoding_proof_1,
            encoding_proofs,
        } = vanilla_proof;

        Proof {
            comm_d_proof: comm_d_proofs.as_options().into(),
            comm_r_last_proofs: (
                comm_r_last_proofs.0.as_options().into(),
                comm_r_last_proofs
                    .1
                    .into_iter()
                    .map(|p| p.as_options().into())
                    .collect(),
            ),
            replica_column_proof: replica_column_proofs.into(),
            encoding_proof_1: encoding_proof_1.into(),
            encoding_proofs: encoding_proofs.into_iter().map(|p| p.into()).collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct InclusionPath(Vec<Option<(Fr, bool)>>);

impl InclusionPath {
    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty(degree: usize) -> Self {
        InclusionPath(vec![None; degree])
    }
}

impl From<Vec<Option<(Fr, bool)>>> for InclusionPath {
    fn from(other: Vec<Option<(Fr, bool)>>) -> Self {
        InclusionPath(other)
    }
}

#[derive(Debug, Clone)]
pub struct ReplicaColumnProof {
    c_x: ColumnProof,
    c_inv_x: ColumnProof,
    drg_parents: Vec<ColumnProof>,
    exp_parents_even: Vec<ColumnProof>,
    exp_parents_odd: Vec<ColumnProof>,
}

impl ReplicaColumnProof {
    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty<H: Hasher>(params: &PublicParams<H>) -> Self {
        ReplicaColumnProof {
            c_x: ColumnProof::empty_all(params),
            c_inv_x: ColumnProof::empty_all(params),
            drg_parents: vec![ColumnProof::empty_all(params); params.graph.base_graph().degree()],
            exp_parents_even: vec![
                ColumnProof::empty_even(params);
                params.graph.expansion_degree()
            ],
            exp_parents_odd: vec![ColumnProof::empty_odd(params); params.graph.expansion_degree()],
        }
    }
}

impl<H: Hasher> From<VanillaReplicaColumnProof<H>> for ReplicaColumnProof {
    fn from(vanilla_proof: VanillaReplicaColumnProof<H>) -> Self {
        let VanillaReplicaColumnProof {
            c_x,
            c_inv_x,
            drg_parents,
            exp_parents_even,
            exp_parents_odd,
        } = vanilla_proof;

        ReplicaColumnProof {
            c_x: c_x.into(),
            c_inv_x: c_inv_x.into(),
            drg_parents: drg_parents.into_iter().map(|p| p.into()).collect(),
            exp_parents_even: exp_parents_even.into_iter().map(|p| p.into()).collect(),
            exp_parents_odd: exp_parents_odd.into_iter().map(|p| p.into()).collect(),
        }
    }
}
