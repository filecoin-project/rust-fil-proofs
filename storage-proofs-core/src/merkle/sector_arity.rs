use ff::PrimeField;
use filecoin_hashers::PoseidonArity;
use generic_array::typenum::{Unsigned, U0, U2, U4, U8};

use crate::{
    SECTOR_NODES_16_KIB, SECTOR_NODES_16_MIB, SECTOR_NODES_1_KIB, SECTOR_NODES_2_KIB,
    SECTOR_NODES_32_GIB, SECTOR_NODES_32_KIB, SECTOR_NODES_4_KIB, SECTOR_NODES_512_MIB,
    SECTOR_NODES_64_GIB, SECTOR_NODES_8_KIB, SECTOR_NODES_8_MIB,
};

pub trait Arity<F: PrimeField>: Clone + Send + Sync {
    const SECTOR_NODES: usize;

    type U: PoseidonArity<F>;
    type V: PoseidonArity<F>;
    type W: PoseidonArity<F>;

    #[inline]
    fn base_arity() -> usize {
        Self::U::to_usize()
    }

    #[inline]
    fn sub_arity() -> usize {
        Self::V::to_usize()
    }

    #[inline]
    fn top_arity() -> usize {
        Self::W::to_usize()
    }

    #[inline]
    fn arities() -> (usize, usize, usize) {
        (Self::base_arity(), Self::sub_arity(), Self::top_arity())
    }

    fn heights() -> (usize, usize, usize) {
        let (base_arity, sub_arity, top_arity) = Self::arities();

        let mut base_height = Self::SECTOR_NODES.trailing_zeros() as usize;
        let (mut sub_height, mut top_height) = (0, 0);

        if sub_arity != 0 {
            base_height -= sub_arity.trailing_zeros() as usize;
            sub_height = 1;
        }
        if top_arity != 0 {
            base_height -= top_arity.trailing_zeros() as usize;
            top_height = 1;
        }
        base_height /= base_arity.trailing_zeros() as usize;

        (base_height, sub_height, top_height)
    }

    // A blank R1CS merkle path for the given sector size.
    #[inline]
    fn blank_merkle_path() -> Vec<Vec<Option<F>>> {
        let (base_arity, sub_arity, top_arity) = Self::arities();
        let (base_height, sub_height, top_height) = Self::heights();
        let mut path = Vec::with_capacity(base_height + sub_height + top_height);
        for _ in 0..base_height {
            path.push(vec![None; base_arity - 1]);
        }
        if sub_height == 1 {
            path.push(vec![None; sub_arity - 1]);
        }
        if top_height == 1 {
            path.push(vec![None; top_arity - 1]);
        }
        path
    }
}

#[derive(Clone, Copy)]
pub struct Arity1K;
#[derive(Clone, Copy)]
pub struct Arity2K;
#[derive(Clone, Copy)]
pub struct Arity4K;
#[derive(Clone, Copy)]
pub struct Arity8K;
#[derive(Clone, Copy)]
pub struct Arity16K;
#[derive(Clone, Copy)]
pub struct Arity32K;
#[derive(Clone, Copy)]
pub struct Arity8M;
#[derive(Clone, Copy)]
pub struct Arity16M;
#[derive(Clone, Copy)]
pub struct Arity512M;
#[derive(Clone, Copy)]
pub struct Arity32G;
#[derive(Clone, Copy)]
pub struct Arity64G;

impl<F: PrimeField> Arity<F> for Arity1K {
    const SECTOR_NODES: usize = SECTOR_NODES_1_KIB;
    type U = U8;
    type V = U4;
    type W = U0;
}

impl<F: PrimeField> Arity<F> for Arity2K {
    const SECTOR_NODES: usize = SECTOR_NODES_2_KIB;
    type U = U8;
    type V = U0;
    type W = U0;
}

impl<F: PrimeField> Arity<F> for Arity4K {
    const SECTOR_NODES: usize = SECTOR_NODES_4_KIB;
    type U = U8;
    type V = U2;
    type W = U0;
}

impl<F: PrimeField> Arity<F> for Arity8K {
    const SECTOR_NODES: usize = SECTOR_NODES_8_KIB;
    type U = U8;
    type V = U4;
    type W = U0;
}

impl<F: PrimeField> Arity<F> for Arity16K {
    const SECTOR_NODES: usize = SECTOR_NODES_16_KIB;
    type U = U8;
    type V = U8;
    type W = U0;
}

impl<F: PrimeField> Arity<F> for Arity32K {
    const SECTOR_NODES: usize = SECTOR_NODES_32_KIB;
    type U = U8;
    type V = U8;
    type W = U2;
}

impl<F: PrimeField> Arity<F> for Arity8M {
    const SECTOR_NODES: usize = SECTOR_NODES_8_MIB;
    type U = U8;
    type V = U0;
    type W = U0;
}

impl<F: PrimeField> Arity<F> for Arity16M {
    const SECTOR_NODES: usize = SECTOR_NODES_16_MIB;
    type U = U8;
    type V = U2;
    type W = U0;
}

impl<F: PrimeField> Arity<F> for Arity512M {
    const SECTOR_NODES: usize = SECTOR_NODES_512_MIB;
    type U = U8;
    type V = U0;
    type W = U0;
}

impl<F: PrimeField> Arity<F> for Arity32G {
    const SECTOR_NODES: usize = SECTOR_NODES_32_GIB;
    type U = U8;
    type V = U8;
    type W = U0;
}

impl<F: PrimeField> Arity<F> for Arity64G {
    const SECTOR_NODES: usize = SECTOR_NODES_64_GIB;
    type U = U8;
    type V = U8;
    type W = U2;
}
