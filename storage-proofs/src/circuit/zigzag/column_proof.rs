use paired::bls12_381::Fr;

use crate::circuit::zigzag::{column::Column, params::InclusionPath};
use crate::drgraph::Graph;
use crate::hasher::Hasher;
use crate::zigzag::{ColumnProof as VanillaColumnProof, PublicParams};

#[derive(Debug, Clone)]
pub enum ColumnProof {
    All {
        column: Column,
        inclusion_path: InclusionPath,
    },
    Even {
        column: Column,
        inclusion_path: InclusionPath,
        o_i: Option<Fr>,
    },
    Odd {
        column: Column,
        inclusion_path: InclusionPath,
        e_i: Option<Fr>,
    },
}

impl ColumnProof {
    /// Create an empty `ColumnProof::All`, used in `blank_circuit`s.
    pub fn empty_all<H: Hasher>(params: &PublicParams<H>) -> Self {
        ColumnProof::All {
            column: Column::empty_all(params),
            inclusion_path: InclusionPath::empty(params.graph.degree()),
        }
    }

    /// Create an empty `ColumnProof::Even`, used in `blank_circuit`s.
    pub fn empty_even<H: Hasher>(params: &PublicParams<H>) -> Self {
        ColumnProof::Even {
            column: Column::empty_even(params),
            inclusion_path: InclusionPath::empty(params.graph.degree()),
            o_i: None,
        }
    }

    /// Create an empty `ColumnProof::Odd`, used in `blank_circuit`s.
    pub fn empty_odd<H: Hasher>(params: &PublicParams<H>) -> Self {
        ColumnProof::Odd {
            column: Column::empty_odd(params),
            inclusion_path: InclusionPath::empty(params.graph.degree()),
            e_i: None,
        }
    }
}

impl<H: Hasher> From<VanillaColumnProof<H>> for ColumnProof {
    fn from(vanilla_proof: VanillaColumnProof<H>) -> Self {
        match vanilla_proof {
            VanillaColumnProof::All {
                column,
                inclusion_proof,
            } => ColumnProof::All {
                column: column.into(),
                inclusion_path: inclusion_proof.as_options().into(),
            },
            VanillaColumnProof::Odd {
                column,
                inclusion_proof,
                e_i,
            } => ColumnProof::Odd {
                column: column.into(),
                inclusion_path: inclusion_proof.as_options().into(),
                e_i: Some(e_i.into()),
            },
            VanillaColumnProof::Even {
                column,
                inclusion_proof,
                o_i,
            } => ColumnProof::Even {
                column: column.into(),
                inclusion_path: inclusion_proof.as_options().into(),
                o_i: Some(o_i.into()),
            },
        }
    }
}
