use bellperson::{ConstraintSystem, SynthesisError};
use fil_sapling_crypto::circuit::num;
use fil_sapling_crypto::jubjub::JubjubEngine;
use paired::bls12_381::{Bls12, Fr};

use crate::circuit::{
    constraint,
    zigzag::{column::Column, hash::hash2, params::InclusionPath},
};
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

    pub fn column(&self) -> &Column {
        match self {
            ColumnProof::All { ref column, .. } => column,
            ColumnProof::Even { ref column, .. } => column,
            ColumnProof::Odd { ref column, .. } => column,
        }
    }

    pub fn alloc_node_at_layer<CS: ConstraintSystem<Bls12>>(
        &self,
        cs: CS,
        layer: usize,
    ) -> Result<num::AllocatedNum<Bls12>, SynthesisError> {
        let value = self.column().get_node_at_layer(layer);
        num::AllocatedNum::alloc(cs, || {
            value
                .map(Into::into)
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })
    }

    pub fn synthesize<CS: ConstraintSystem<Bls12>>(
        self,
        mut cs: CS,
        params: &<Bls12 as JubjubEngine>::Params,
        comm_c: &num::AllocatedNum<Bls12>,
    ) -> Result<(), SynthesisError> {
        match self {
            ColumnProof::All {
                inclusion_path,
                column,
            } => {
                let c_i = column.hash(cs.namespace(|| "column_hash"), params)?;

                let leaf_num = inclusion_path.alloc_value(cs.namespace(|| "leaf"))?;

                constraint::equal(&mut cs, || "enforce column_hash = leaf", &c_i, &leaf_num);

                // TODO: currently allocating the leaf twice, inclusion path should take the already allocated leaf.
                inclusion_path.synthesize(
                    cs.namespace(|| "column_proof_all_inclusion"),
                    params,
                    comm_c.clone(),
                    leaf_num,
                )?;
            }
            ColumnProof::Even {
                inclusion_path,
                o_i,
                column,
            } => {
                let e_i = column.hash(cs.namespace(|| "column_hash"), params)?;
                let e_i_bits = e_i.into_bits_le(cs.namespace(|| "e_i_bits"))?;
                let o_i_num = num::AllocatedNum::alloc(cs.namespace(|| "o_i"), || {
                    o_i.map(Into::into)
                        .ok_or_else(|| SynthesisError::AssignmentMissing)
                })?;
                let o_i_bits = o_i_num.into_bits_le(cs.namespace(|| "o_i_bits"))?;

                let c_i = hash2(cs.namespace(|| "h(o_i, e_i)"), &o_i_bits, &e_i_bits)?;

                let leaf_num = inclusion_path.alloc_value(cs.namespace(|| "leaf"))?;
                constraint::equal(&mut cs, || "enforce h(o_i, e_i) = leaf", &c_i, &leaf_num);

                // TODO: currently allocating the leaf twice, inclusion path should take the already allocated leaf.
                inclusion_path.synthesize(
                    cs.namespace(|| "column_proof_even_inclusion"),
                    params,
                    comm_c.clone(),
                    leaf_num,
                )?;
            }
            ColumnProof::Odd {
                inclusion_path,
                e_i,
                column,
            } => {
                let o_i = column.hash(cs.namespace(|| "column_hash"), params)?;
                let o_i_bits = o_i.into_bits_le(cs.namespace(|| "o_i_bits"))?;
                let e_i_num = num::AllocatedNum::alloc(cs.namespace(|| "e_i"), || {
                    e_i.map(Into::into)
                        .ok_or_else(|| SynthesisError::AssignmentMissing)
                })?;
                let e_i_bits = e_i_num.into_bits_le(cs.namespace(|| "e_i_bits"))?;

                let c_i = hash2(cs.namespace(|| "h(o_i, e_i)"), &o_i_bits, &e_i_bits)?;

                let leaf_num = inclusion_path.alloc_value(cs.namespace(|| "leaf"))?;

                constraint::equal(&mut cs, || "enforce h(o_i, e_i) = leaf", &c_i, &leaf_num);

                inclusion_path.synthesize(
                    cs.namespace(|| "column_proof_odd_inclusion"),
                    params,
                    comm_c.clone(),
                    leaf_num,
                )?;
            }
        }

        Ok(())
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
