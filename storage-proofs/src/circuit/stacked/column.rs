use bellperson::gadgets::num;
use bellperson::{ConstraintSystem, SynthesisError};
use fil_sapling_crypto::jubjub::JubjubEngine;
use paired::bls12_381::{Bls12, Fr};

use crate::circuit::stacked::hash::hash_single_column;
use crate::hasher::Hasher;
use crate::parameter_cache::ParameterSetMetadata;
use crate::stacked::{Column as VanillaColumn, PublicParams, WINDOW_SIZE_BYTES};

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
        let num_windows = params.sector_size() as usize / WINDOW_SIZE_BYTES;
        let num_rows = params.layer_challenges.layers() - 1 * num_windows;

        Column {
            index: None,
            rows: vec![None; num_rows],
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
        params: &<Bls12 as JubjubEngine>::Params,
    ) -> Result<num::AllocatedNum<Bls12>, SynthesisError> {
        hash_single_column(cs.namespace(|| "column_hash"), params, &self.rows)
    }
}
