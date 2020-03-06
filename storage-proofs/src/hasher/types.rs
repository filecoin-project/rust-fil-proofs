use lazy_static::lazy_static;

use crate::error::Result;
use bellperson::gadgets::{boolean, num};
use bellperson::{ConstraintSystem, SynthesisError};
use fil_sapling_crypto::jubjub::JubjubEngine;
use generic_array::typenum;
use generic_array::typenum::{U1, U11, U16, U2, U24, U36, U4, U8};
use merkletree::hash::{Algorithm as LightAlgorithm, Hashable as LightHashable};
use merkletree::merkle::Element;
use neptune::poseidon::PoseidonConstants;
use paired::bls12_381::{Bls12, Fr, FrRepr};
use paired::Engine;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;

pub type PoseidonBinaryArity = U2;
pub type PoseidonQuadArity = U4;
pub type PoseidonOctArity = U8;

/// Arity to use by default for `hash_md` with poseidon.
pub type PoseidonMDArity = U36;

/// Arity to use for hasher implementations (Poseidon) which are specialized at compile time.
/// Must match PoseidonArity
pub const MERKLE_TREE_ARITY: usize = 2;

lazy_static! {
    pub static ref POSEIDON_CONSTANTS_1: PoseidonConstants::<Bls12, U1> = PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_2: PoseidonConstants::<Bls12, U2> = PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_4: PoseidonConstants::<Bls12, U4> = PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_8: PoseidonConstants::<Bls12, U8> = PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_16: PoseidonConstants::<Bls12, U16> =
        PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_24: PoseidonConstants::<Bls12, U24> =
        PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_36: PoseidonConstants::<Bls12, U36> =
        PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_11: PoseidonConstants::<Bls12, U11> =
        PoseidonConstants::new();
    pub static ref POSEIDON_MD_CONSTANTS: PoseidonConstants::<Bls12, PoseidonMDArity> =
        PoseidonConstants::new();
}

pub trait PoseidonArity<E: Engine>:
    typenum::Unsigned
    + Send
    + Sync
    + Clone
    + std::ops::Add<typenum::B1>
    + std::ops::Add<typenum::UInt<typenum::UTerm, typenum::B1>>
where
    typenum::Add1<Self>: generic_array::ArrayLength<E::Fr>,
{
    #[allow(non_snake_case)]
    fn PARAMETERS() -> &'static PoseidonConstants<E, Self>;
}

impl PoseidonArity<Bls12> for U1 {
    fn PARAMETERS() -> &'static PoseidonConstants<Bls12, Self> {
        &*POSEIDON_CONSTANTS_1
    }
}
impl PoseidonArity<Bls12> for U2 {
    fn PARAMETERS() -> &'static PoseidonConstants<Bls12, Self> {
        &*POSEIDON_CONSTANTS_2
    }
}

impl PoseidonArity<Bls12> for U4 {
    fn PARAMETERS() -> &'static PoseidonConstants<Bls12, Self> {
        &*POSEIDON_CONSTANTS_4
    }
}

impl PoseidonArity<Bls12> for U8 {
    fn PARAMETERS() -> &'static PoseidonConstants<Bls12, Self> {
        &*POSEIDON_CONSTANTS_8
    }
}

impl PoseidonArity<Bls12> for U11 {
    fn PARAMETERS() -> &'static PoseidonConstants<Bls12, Self> {
        &*POSEIDON_CONSTANTS_11
    }
}

impl PoseidonArity<Bls12> for U16 {
    fn PARAMETERS() -> &'static PoseidonConstants<Bls12, Self> {
        &*POSEIDON_CONSTANTS_16
    }
}
impl PoseidonArity<Bls12> for U24 {
    fn PARAMETERS() -> &'static PoseidonConstants<Bls12, Self> {
        &*POSEIDON_CONSTANTS_24
    }
}
impl PoseidonArity<Bls12> for U36 {
    fn PARAMETERS() -> &'static PoseidonConstants<Bls12, Self> {
        &*POSEIDON_CONSTANTS_36
    }
}

pub trait PoseidonEngine<Arity>: Engine
where
    Arity: 'static
        + typenum::Unsigned
        + std::ops::Add<typenum::B1>
        + std::ops::Add<typenum::UInt<typenum::UTerm, typenum::B1>>,
    typenum::Add1<Arity>: generic_array::ArrayLength<Self::Fr>,
{
    #[allow(non_snake_case)]
    fn PARAMETERS() -> &'static PoseidonConstants<Self, Arity>;
}

impl<E: Engine, U: 'static + PoseidonArity<E>> PoseidonEngine<U> for E
where
    typenum::Add1<U>: generic_array::ArrayLength<E::Fr>,
{
    fn PARAMETERS() -> &'static PoseidonConstants<Self, U> {
        PoseidonArity::PARAMETERS()
    }
}

pub trait Domain:
    Ord
    + Copy
    + Clone
    + AsRef<[u8]>
    + Default
    + ::std::fmt::Debug
    + Eq
    + Send
    + Sync
    + From<Fr>
    + From<FrRepr>
    + Into<Fr>
    + Serialize
    + DeserializeOwned
    + Element
    + std::hash::Hash
{
    fn serialize(&self) -> Vec<u8>;
    fn into_bytes(&self) -> Vec<u8>;
    fn try_from_bytes(raw: &[u8]) -> Result<Self>;
    /// Write itself into the given slice, LittleEndian bytes.
    fn write_bytes(&self, _: &mut [u8]) -> Result<()>;

    fn random<R: rand::RngCore>(rng: &mut R) -> Self;
}

pub trait HashFunction<T: Domain>:
    Clone + ::std::fmt::Debug + Send + Sync + LightAlgorithm<T>
{
    fn hash(data: &[u8]) -> T;
    fn hash2(a: &T, b: &T) -> T;
    fn hash_md(input: &[T]) -> T {
        // Default to binary.
        assert!(input.len() > 1, "hash_md needs more than one element.");
        input
            .iter()
            .skip(1)
            .fold(input[0], |acc, elt| Self::hash2(&acc, elt))
    }

    fn hash_leaf(data: &dyn LightHashable<Self>) -> T {
        let mut a = Self::default();
        data.hash(&mut a);
        let item_hash = a.hash();
        a.leaf(item_hash)
    }

    fn hash_single_node(data: &dyn LightHashable<Self>) -> T {
        let mut a = Self::default();
        data.hash(&mut a);
        a.hash()
    }

    fn hash_leaf_circuit<E: JubjubEngine + PoseidonEngine<typenum::U2>, CS: ConstraintSystem<E>>(
        mut cs: CS,
        left: &num::AllocatedNum<E>,
        right: &num::AllocatedNum<E>,
        height: usize,
        params: &E::Params,
    ) -> std::result::Result<num::AllocatedNum<E>, SynthesisError> {
        let left_bits = left.to_bits_le(cs.namespace(|| "left num into bits"))?;
        let right_bits = right.to_bits_le(cs.namespace(|| "right num into bits"))?;

        Self::hash_leaf_bits_circuit(cs, &left_bits, &right_bits, height, params)
    }

    fn hash_multi_leaf_circuit<
        Arity: 'static + PoseidonArity<E>,
        E: JubjubEngine + PoseidonEngine<Arity>,
        CS: ConstraintSystem<E>,
    >(
        cs: CS,
        leaves: &[num::AllocatedNum<E>],
        height: usize,
        params: &E::Params,
    ) -> std::result::Result<num::AllocatedNum<E>, SynthesisError>
    where
        typenum::Add1<Arity>: generic_array::ArrayLength<E::Fr>;

    fn hash_md_circuit<
        E: JubjubEngine + PoseidonEngine<PoseidonMDArity>,
        CS: ConstraintSystem<E>,
    >(
        _cs: &mut CS,
        _elements: &[num::AllocatedNum<E>],
    ) -> std::result::Result<num::AllocatedNum<E>, SynthesisError> {
        unimplemented!();
    }

    fn hash_leaf_bits_circuit<E: JubjubEngine, CS: ConstraintSystem<E>>(
        _cs: CS,
        _left: &[boolean::Boolean],
        _right: &[boolean::Boolean],
        _height: usize,
        _params: &E::Params,
    ) -> std::result::Result<num::AllocatedNum<E>, SynthesisError> {
        unimplemented!();
    }

    fn hash_circuit<E: JubjubEngine, CS: ConstraintSystem<E>>(
        cs: CS,
        bits: &[boolean::Boolean],
        params: &E::Params,
    ) -> std::result::Result<num::AllocatedNum<E>, SynthesisError>;

    fn hash2_circuit<E, CS>(
        cs: CS,
        a: &num::AllocatedNum<E>,
        b: &num::AllocatedNum<E>,
        params: &E::Params,
    ) -> std::result::Result<num::AllocatedNum<E>, SynthesisError>
    where
        E: JubjubEngine + PoseidonEngine<typenum::U2>,
        CS: ConstraintSystem<E>;
}

pub trait Hasher: Clone + ::std::fmt::Debug + Eq + Default + Send + Sync {
    type Domain: Domain + LightHashable<Self::Function> + AsRef<Self::Domain>;
    type Function: HashFunction<Self::Domain>;

    fn sloth_encode(key: &Self::Domain, ciphertext: &Self::Domain) -> Result<Self::Domain>;
    fn sloth_decode(key: &Self::Domain, ciphertext: &Self::Domain) -> Result<Self::Domain>;

    fn name() -> String;
}
