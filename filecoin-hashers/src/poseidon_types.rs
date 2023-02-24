use std::any::TypeId;
use std::fmt::Debug;
use std::marker::PhantomData;

use blstrs::Scalar as Fr;
use ff::PrimeField;
use generic_array::typenum::{U0, U11, U2, U36, U4, U8};
#[cfg(feature = "halo2")]
use halo2_proofs::pasta::{Fp, Fq};
use lazy_static::lazy_static;
use neptune::{poseidon::PoseidonConstants, Arity, Strength};
#[cfg(feature = "nova")]
use pasta_curves::{Fp, Fq};
use typemap::ShareMap;

/// Arity to use by default for `hash_md` with poseidon.
pub type PoseidonMDArity = U36;

/// Poseidon strengths used in each proof system.
pub const GROTH16_STRENGTH: Strength = Strength::Standard;
pub const NOVA_STRENGTH: Strength = Strength::Standard;
pub const HALO2_STRENGTH: Strength = Strength::EvenPartial;

/// Returns `true` if Halo2 uses standard strength Poseidon.
pub const HALO2_STRENGTH_IS_STD: bool = match HALO2_STRENGTH {
    Strength::Standard => true,
    Strength::EvenPartial => false,
    _ => panic!("halo2 strength must be `Standard` or `EvenPartial`"),
};

/// Returns the Poseidon strength configured for the given field.
pub fn poseidon_strength<F: PrimeField>() -> Strength {
    if TypeId::of::<F>() == TypeId::of::<Fr>() {
        GROTH16_STRENGTH
    } else if cfg!(feature = "halo2") {
        HALO2_STRENGTH
    } else {
        NOVA_STRENGTH
    }
}

lazy_static! {
    pub static ref POSEIDON_CONSTANTS_2: PoseidonConstants::<Fr, U2> = PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_4: PoseidonConstants::<Fr, U4> = PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_8: PoseidonConstants::<Fr, U8> = PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_11: PoseidonConstants::<Fr, U11> = PoseidonConstants::new();
    pub static ref POSEIDON_MD_CONSTANTS: PoseidonConstants::<Fr, PoseidonMDArity> =
        PoseidonConstants::new();
}

#[cfg(feature = "halo2")]
lazy_static! {
    pub static ref POSEIDON_CONSTANTS_2_PALLAS: PoseidonConstants::<Fp, U2> =
        PoseidonConstants::new_with_strength(HALO2_STRENGTH);
    pub static ref POSEIDON_CONSTANTS_4_PALLAS: PoseidonConstants::<Fp, U4> =
        PoseidonConstants::new_with_strength(HALO2_STRENGTH);
    pub static ref POSEIDON_CONSTANTS_8_PALLAS: PoseidonConstants::<Fp, U8> =
        PoseidonConstants::new_with_strength(HALO2_STRENGTH);
    pub static ref POSEIDON_CONSTANTS_11_PALLAS: PoseidonConstants::<Fp, U11> =
        PoseidonConstants::new_with_strength(HALO2_STRENGTH);
    pub static ref POSEIDON_MD_CONSTANTS_PALLAS: PoseidonConstants::<Fp, PoseidonMDArity> =
        PoseidonConstants::new_with_strength(HALO2_STRENGTH);
    pub static ref POSEIDON_CONSTANTS_2_VESTA: PoseidonConstants::<Fq, U2> =
        PoseidonConstants::new_with_strength(HALO2_STRENGTH);
    pub static ref POSEIDON_CONSTANTS_4_VESTA: PoseidonConstants::<Fq, U4> =
        PoseidonConstants::new_with_strength(HALO2_STRENGTH);
    pub static ref POSEIDON_CONSTANTS_8_VESTA: PoseidonConstants::<Fq, U8> =
        PoseidonConstants::new_with_strength(HALO2_STRENGTH);
    pub static ref POSEIDON_CONSTANTS_11_VESTA: PoseidonConstants::<Fq, U11> =
        PoseidonConstants::new_with_strength(HALO2_STRENGTH);
    pub static ref POSEIDON_MD_CONSTANTS_VESTA: PoseidonConstants::<Fq, PoseidonMDArity> =
        PoseidonConstants::new_with_strength(HALO2_STRENGTH);
}

#[cfg(feature = "nova")]
lazy_static! {
    pub static ref POSEIDON_CONSTANTS_2_PALLAS: PoseidonConstants::<Fp, U2> =
        PoseidonConstants::new_with_strength(NOVA_STRENGTH);
    pub static ref POSEIDON_CONSTANTS_4_PALLAS: PoseidonConstants::<Fp, U4> =
        PoseidonConstants::new_with_strength(NOVA_STRENGTH);
    pub static ref POSEIDON_CONSTANTS_8_PALLAS: PoseidonConstants::<Fp, U8> =
        PoseidonConstants::new_with_strength(NOVA_STRENGTH);
    pub static ref POSEIDON_CONSTANTS_11_PALLAS: PoseidonConstants::<Fp, U11> =
        PoseidonConstants::new_with_strength(NOVA_STRENGTH);
    pub static ref POSEIDON_MD_CONSTANTS_PALLAS: PoseidonConstants::<Fp, PoseidonMDArity> =
        PoseidonConstants::new_with_strength(NOVA_STRENGTH);
    pub static ref POSEIDON_CONSTANTS_2_VESTA: PoseidonConstants::<Fq, U2> =
        PoseidonConstants::new_with_strength(NOVA_STRENGTH);
    pub static ref POSEIDON_CONSTANTS_4_VESTA: PoseidonConstants::<Fq, U4> =
        PoseidonConstants::new_with_strength(NOVA_STRENGTH);
    pub static ref POSEIDON_CONSTANTS_8_VESTA: PoseidonConstants::<Fq, U8> =
        PoseidonConstants::new_with_strength(NOVA_STRENGTH);
    pub static ref POSEIDON_CONSTANTS_11_VESTA: PoseidonConstants::<Fq, U11> =
        PoseidonConstants::new_with_strength(NOVA_STRENGTH);
    pub static ref POSEIDON_MD_CONSTANTS_VESTA: PoseidonConstants::<Fq, PoseidonMDArity> =
        PoseidonConstants::new_with_strength(NOVA_STRENGTH);
}

#[cfg(not(any(feature = "halo2", feature = "nova")))]
lazy_static! {
    pub static ref POSEIDON_CONSTANTS: ShareMap = {
        let mut tm = ShareMap::custom();

        tm.insert::<PoseidonLookup<Fr, U2>>(&*POSEIDON_CONSTANTS_2);
        tm.insert::<PoseidonLookup<Fr, U4>>(&*POSEIDON_CONSTANTS_4);
        tm.insert::<PoseidonLookup<Fr, U8>>(&*POSEIDON_CONSTANTS_8);
        tm.insert::<PoseidonLookup<Fr, U11>>(&*POSEIDON_CONSTANTS_11);

        tm
    };
}

#[cfg(any(feature = "halo2", feature = "nova"))]
lazy_static! {
    pub static ref POSEIDON_CONSTANTS: ShareMap = {
        let mut tm = ShareMap::custom();

        tm.insert::<PoseidonLookup<Fr, U2>>(&*POSEIDON_CONSTANTS_2);
        tm.insert::<PoseidonLookup<Fr, U4>>(&*POSEIDON_CONSTANTS_4);
        tm.insert::<PoseidonLookup<Fr, U8>>(&*POSEIDON_CONSTANTS_8);
        tm.insert::<PoseidonLookup<Fr, U11>>(&*POSEIDON_CONSTANTS_11);

        tm.insert::<PoseidonLookup<Fp, U2>>(&*POSEIDON_CONSTANTS_2_PALLAS);
        tm.insert::<PoseidonLookup<Fp, U4>>(&*POSEIDON_CONSTANTS_4_PALLAS);
        tm.insert::<PoseidonLookup<Fp, U8>>(&*POSEIDON_CONSTANTS_8_PALLAS);
        tm.insert::<PoseidonLookup<Fp, U11>>(&*POSEIDON_CONSTANTS_11_PALLAS);

        tm.insert::<PoseidonLookup<Fq, U2>>(&*POSEIDON_CONSTANTS_2_VESTA);
        tm.insert::<PoseidonLookup<Fq, U4>>(&*POSEIDON_CONSTANTS_4_VESTA);
        tm.insert::<PoseidonLookup<Fq, U8>>(&*POSEIDON_CONSTANTS_8_VESTA);
        tm.insert::<PoseidonLookup<Fq, U11>>(&*POSEIDON_CONSTANTS_11_VESTA);

        tm
    };
}

// Used as the key to lookup Poseidon constants for a field `F` and arity `A`.
pub struct PoseidonLookup<F, A>(PhantomData<(F, A)>)
where
    F: PrimeField,
    A: PoseidonArity<F>;

impl<F, A> typemap::Key for PoseidonLookup<F, A>
where
    F: PrimeField,
    A: PoseidonArity<F>,
{
    type Value = &'static PoseidonConstants<F, A>;
}

#[inline]
pub fn get_poseidon_constants<F, A>() -> &'static PoseidonConstants<F, A>
where
    F: PrimeField,
    A: PoseidonArity<F>,
{
    *POSEIDON_CONSTANTS
        .get::<PoseidonLookup<F, A>>()
        .unwrap_or_else(|| {
            panic!(
                "arity-{} Poseidon constants not found for field",
                A::to_usize()
            )
        })
}

// A marker trait for arities which are in `POSEIDON_CONSTANTS`; we require that 'PoseidonArity<F>`
// implements `Send + Sync` because those traits are required by `lazy_static`.
pub trait PoseidonArity<F: PrimeField>: Arity<F> + Send + Sync + Clone + Debug {}

// We must implement `PoseidonArity<F> for U0` because the `U0` arity is used in compound trees
// (each compound tree arity must implement `PoseidonArity`).
impl<F: PrimeField> PoseidonArity<F> for U0 {}
impl<F: PrimeField> PoseidonArity<F> for U2 {}
impl<F: PrimeField> PoseidonArity<F> for U4 {}
impl<F: PrimeField> PoseidonArity<F> for U8 {}
impl<F: PrimeField> PoseidonArity<F> for U11 {}
impl<F: PrimeField> PoseidonArity<F> for PoseidonMDArity {}
