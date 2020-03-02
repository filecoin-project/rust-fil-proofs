use bellperson::gadgets::num;
use bellperson::{ConstraintSystem, SynthesisError};
use fil_sapling_crypto::jubjub::JubjubEngine;
use generic_array::typenum;
use paired::bls12_381::{Bls12, Fr};

use super::{column::Column, params::InclusionPath};

use crate::gadgets::constraint;
use crate::hasher::Hasher;
use crate::porep::stacked::{ColumnProof as VanillaColumnProof, PublicParams};

#[derive(Debug, Clone)]
pub struct ColumnProof<H: Hasher> {
    column: Column,
    inclusion_path: InclusionPath<Bls12, H, typenum::U8>,
}

impl<H: Hasher> ColumnProof<H> {
    /// Create an empty `ColumnProof`, used in `blank_circuit`s.
    pub fn empty(params: &PublicParams<H>) -> Self {
        ColumnProof {
            column: Column::empty(params),
            inclusion_path: InclusionPath::empty(&params.graph),
        }
    }

    pub fn get_node_at_layer(&self, layer: usize) -> &Option<Fr> {
        self.column.get_node_at_layer(layer)
    }

    pub fn synthesize<CS: ConstraintSystem<Bls12>>(
        self,
        mut cs: CS,
        params: &<Bls12 as JubjubEngine>::Params,
        comm_c: &num::AllocatedNum<Bls12>,
    ) -> Result<(), SynthesisError> {
        let ColumnProof {
            inclusion_path,
            column,
        } = self;

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

        Ok(())
    }
}

impl<H: Hasher> From<VanillaColumnProof<H>> for ColumnProof<H> {
    fn from(vanilla_proof: VanillaColumnProof<H>) -> Self {
        let VanillaColumnProof {
            column,
            inclusion_proof,
        } = vanilla_proof;

        ColumnProof {
            column: column.into(),
            inclusion_path: inclusion_proof.into(),
        }
    }
}
