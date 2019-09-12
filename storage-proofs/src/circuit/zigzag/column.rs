use paired::bls12_381::Fr;

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
}
