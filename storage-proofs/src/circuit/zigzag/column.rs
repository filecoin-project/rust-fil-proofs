use bellperson::{ConstraintSystem, SynthesisError};
use fil_sapling_crypto::circuit::{boolean::Boolean, num};
use fil_sapling_crypto::jubjub::JubjubEngine;
use paired::bls12_381::{Bls12, Fr};

use crate::circuit::zigzag::hash::{hash1, hash2, hash_single_column};
use crate::hasher::Hasher;
use crate::zigzag::{Column as VanillaColumn, PublicParams, RawColumn as VanillaRawColumn};

#[derive(Debug, Clone)]
pub enum Column {
    All(RawColumn),
    Odd(RawColumn),
    Even(RawColumn),
}

#[derive(Debug, Clone)]
pub struct RawColumn {
    index: Option<usize>,
    rows: Vec<Option<Fr>>,
}

impl<H: Hasher> From<VanillaColumn<H>> for Column {
    fn from(other: VanillaColumn<H>) -> Self {
        match other {
            VanillaColumn::All(raw) => Column::All(raw.into()),
            VanillaColumn::Odd(raw) => Column::Odd(raw.into()),
            VanillaColumn::Even(raw) => Column::Even(raw.into()),
        }
    }
}

impl<H: Hasher> From<VanillaRawColumn<H>> for RawColumn {
    fn from(other: VanillaRawColumn<H>) -> Self {
        let VanillaRawColumn { index, rows, .. } = other;

        RawColumn {
            index: Some(index),
            rows: rows.into_iter().map(|r| Some(r.into())).collect(),
        }
    }
}

impl Column {
    /// Create an empty `Column::All`, used in `blank_circuit`s.
    pub fn empty_all<H: Hasher>(params: &PublicParams<H>) -> Self {
        Column::All(RawColumn {
            index: None,
            rows: vec![None; params.layer_challenges.layers()],
        })
    }

    /// Create an empty `Column::Even`, used in `blank_circuit`s.
    pub fn empty_even<H: Hasher>(params: &PublicParams<H>) -> Self {
        Column::Even(RawColumn {
            index: None,
            rows: vec![None; (params.layer_challenges.layers() / 2) - 1],
        })
    }

    /// Create an empty `Column::Odd`, used in `blank_circuit`s.
    pub fn empty_odd<H: Hasher>(params: &PublicParams<H>) -> Self {
        Column::Odd(RawColumn {
            index: None,
            rows: vec![None; params.layer_challenges.layers() / 2],
        })
    }

    pub fn hash<CS: ConstraintSystem<Bls12>>(
        self,
        mut cs: CS,
        _params: &<Bls12 as JubjubEngine>::Params,
    ) -> Result<num::AllocatedNum<Bls12>, SynthesisError> {
        match self {
            Column::All(RawColumn { rows, .. }) => {
                let mut even_bits = Vec::new();
                let mut odd_bits = Vec::new();
                for (i, row) in rows.into_iter().enumerate() {
                    let row_num = num::AllocatedNum::alloc(
                        cs.namespace(|| format!("all_row_{}_num", i)),
                        || {
                            row.map(Into::into)
                                .ok_or_else(|| SynthesisError::AssignmentMissing)
                        },
                    )?;
                    let mut row_bits =
                        row_num.into_bits_le(cs.namespace(|| format!("all_row_{}_bits", i)))?;
                    // pad to full bytes
                    while row_bits.len() % 8 > 0 {
                        row_bits.push(Boolean::Constant(false));
                    }

                    // adjust index, as the column stored at index 0 is layer 1 => odd
                    if (i + 1) % 2 == 0 {
                        even_bits.extend(row_bits);
                    } else {
                        odd_bits.extend(row_bits);
                    }
                }

                // calculate hashes
                let e_i = hash1(cs.namespace(|| "hash_even"), &even_bits)?;
                let o_i = hash1(cs.namespace(|| "hash_odd"), &odd_bits)?;

                let e_i_bits = e_i.into_bits_le(cs.namespace(|| "e_i_bits"))?;
                let o_i_bits = o_i.into_bits_le(cs.namespace(|| "o_i_bits"))?;

                hash2(cs.namespace(|| "h(o_i, e_i)"), &o_i_bits, &e_i_bits)
            }
            Column::Even(RawColumn { rows, .. }) => {
                hash_single_column(cs.namespace(|| "even_column_hash"), &rows)
            }
            Column::Odd(RawColumn { rows, .. }) => {
                hash_single_column(cs.namespace(|| "odd_column_hash"), &rows)
            }
        }
    }
}
