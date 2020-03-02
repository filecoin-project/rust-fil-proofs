use bellperson::gadgets::num;
use bellperson::{ConstraintSystem, SynthesisError};
use fil_sapling_crypto::jubjub::JubjubEngine;
use paired::bls12_381::{Bls12, Fr};

use super::hash::hash_single_column;

use crate::hasher::Hasher;
use crate::porep::stacked::{Column as VanillaColumn, PublicParams};

#[derive(Debug, Clone)]
pub struct Column {
    index: Option<u32>,
    rows: Vec<Option<Fr>>,
}

impl<H: Hasher> From<VanillaColumn<H>> for Column {
    fn from(other: VanillaColumn<H>) -> Self {
        let VanillaColumn { index, rows, .. } = other;

        Column {
            index: Some(index),
            rows: rows.into_iter().map(|r| Some(r.into())).collect(),
        }
    }
}

impl Column {
    /// Create an empty `Column`, used in `blank_circuit`s.
    pub fn empty<H: Hasher>(params: &PublicParams<H>) -> Self {
        Column {
            index: None,
            rows: vec![None; params.layer_challenges.layers()],
        }
    }

    pub fn get_node_at_layer(&self, layer: usize) -> &Option<Fr> {
        assert!(layer > 0, "layer must be greater than 0");
        let row_index = layer - 1;
        &self.rows[row_index]
    }

    pub fn hash<CS: ConstraintSystem<Bls12>>(
        self,
        mut cs: CS,
        _params: &<Bls12 as JubjubEngine>::Params,
    ) -> Result<num::AllocatedNum<Bls12>, SynthesisError> {
        hash_single_column(cs.namespace(|| "column_hash"), &self.rows)
    }
}
