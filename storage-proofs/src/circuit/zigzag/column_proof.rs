use paired::bls12_381::Fr;

use crate::circuit::zigzag::{column::Column, params::InclusionPath};
use crate::drgraph::Graph;
use crate::hasher::Hasher;
use crate::zigzag::{ColumnProof as VanillaColumnProof, PublicParams};

#[derive(Debug, Clone)]
pub enum ColumnProof<H: Hasher> {
    All {
        column: Column,
        inclusion_path: InclusionPath<H>,
    },
    Even {
        column: Column,
        inclusion_path: InclusionPath<H>,
        o_i: Option<Fr>,
    },
    Odd {
        column: Column,
        inclusion_path: InclusionPath<H>,
        e_i: Option<Fr>,
    },
}

impl<H: Hasher> ColumnProof<H> {
    /// Create an empty `ColumnProof::All`, used in `blank_circuit`s.
    pub fn empty_all(params: &PublicParams<H>) -> Self {
        ColumnProof::All {
            column: Column::empty_all(params),
            inclusion_path: InclusionPath::empty(params.graph.degree()),
        }
    }

    /// Create an empty `ColumnProof::Even`, used in `blank_circuit`s.
    pub fn empty_even(params: &PublicParams<H>) -> Self {
        ColumnProof::Even {
            column: Column::empty_even(params),
            inclusion_path: InclusionPath::empty(params.graph.degree()),
            o_i: None,
        }
    }

    /// Create an empty `ColumnProof::Odd`, used in `blank_circuit`s.
    pub fn empty_odd(params: &PublicParams<H>) -> Self {
        ColumnProof::Odd {
            column: Column::empty_odd(params),
            inclusion_path: InclusionPath::empty(params.graph.degree()),
            e_i: None,
        }
    }
}

impl<H: Hasher> From<VanillaColumnProof<H>> for ColumnProof<H> {
    fn from(vanilla_proof: VanillaColumnProof<H>) -> Self {
        match vanilla_proof {
            VanillaColumnProof::All {
                column,
                inclusion_proof,
            } => ColumnProof::All {
                column: column.into(),
                inclusion_path: inclusion_proof.into(),
            },
            VanillaColumnProof::Odd {
                column,
                inclusion_proof,
                e_i,
            } => ColumnProof::Odd {
                column: column.into(),
                inclusion_path: inclusion_proof.into(),
                e_i: Some(e_i.into()),
            },
            VanillaColumnProof::Even {
                column,
                inclusion_proof,
                o_i,
            } => ColumnProof::Even {
                column: column.into(),
                inclusion_path: inclusion_proof.into(),
                o_i: Some(o_i.into()),
            },
        }
    }
}
