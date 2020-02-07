use lazy_static::lazy_static;

use bellperson::gadgets::{boolean, num};
use bellperson::{ConstraintSystem, SynthesisError};
use fil_sapling_crypto::jubjub::JubjubEngine;
use generic_array::typenum::{U2, U4, U8};
use merkletree::hash::{Algorithm as LightAlgorithm, Hashable as LightHashable};
use merkletree::merkle::Element;
use neptune::poseidon::PoseidonConstants;
use paired::bls12_381::{Bls12, Fr, FrRepr};
use paired::Engine;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;

use crate::error::Result;

pub type PoseidonBinaryArity = U2;
pub type PoseidonQuadArity = U4;
pub type PoseidonOctArity = U8;

pub type PoseidonArity = PoseidonBinaryArity;

/// Arity to use for hasher implementations (Poseidon) which are specialized at compile time.
/// Must match PoseidonArity
pub const MERKLE_TREE_ARITY: usize = 2;

lazy_static! {
    pub static ref POSEIDON_CONSTANTS: PoseidonConstants<Bls12, PoseidonArity> =
        PoseidonConstants::new();
}

pub trait PoseidonEngine: Engine {
    #[allow(non_snake_case)]
    fn PARAMETERS(arity: usize) -> &'static PoseidonConstants<Self, PoseidonArity>;
}

impl PoseidonEngine for Bls12 {
    fn PARAMETERS(arity: usize) -> &'static PoseidonConstants<Self, PoseidonArity> {
        assert_eq!(arity, MERKLE_TREE_ARITY);
        &*POSEIDON_CONSTANTS
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

    fn hash_leaf_circuit<E: JubjubEngine + PoseidonEngine, CS: ConstraintSystem<E>>(
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
        E: JubjubEngine + PoseidonEngine,
        CS: ConstraintSystem<E>;
}

pub trait Hasher: Clone + ::std::fmt::Debug + Eq + Default + Send + Sync {
    type Domain: Domain + LightHashable<Self::Function> + AsRef<Self::Domain>;
    type Function: HashFunction<Self::Domain>;

    fn create_label(data: &[u8], m: usize) -> Result<Self::Domain>;
    fn sloth_encode(key: &Self::Domain, ciphertext: &Self::Domain) -> Result<Self::Domain>;
    fn sloth_decode(key: &Self::Domain, ciphertext: &Self::Domain) -> Result<Self::Domain>;

    fn name() -> String;
}
