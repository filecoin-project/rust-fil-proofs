use lazy_static::lazy_static;

use bellperson::gadgets::{boolean, num};
use bellperson::{ConstraintSystem, SynthesisError};
use fil_sapling_crypto::jubjub::JubjubEngine;
use generic_array::typenum::{U3, U5, U9};
use merkletree::hash::{Algorithm as LightAlgorithm, Hashable as LightHashable};
use merkletree::merkle::Element;
use neptune::poseidon::PoseidonConstants;
use paired::bls12_381::{Bls12, Fr, FrRepr};
use paired::Engine;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;

use crate::error::Result;

/// PoseidonWidth must be 1 + the desired arity.
pub type PoseidonBinaryWidth = U3;
pub type PoseidonQuadWidth = U5;
pub type PoseidonOctWidth = U9;

pub type PoseidonWidth = PoseidonBinaryWidth;

/// Arity to use for hasher implementations (Poseidon) which are specialized at compile time.
/// Must match PoseidonWidth
pub const MERKLE_TREE_ARITY: usize = 2;

lazy_static! {
    pub static ref POSEIDON_CONSTANTS: PoseidonConstants<Bls12, PoseidonWidth> =
        PoseidonConstants::new(MERKLE_TREE_ARITY);
}

pub trait PoseidonEngine: Engine {
    #[allow(non_snake_case)]
    fn PARAMETERS(arity: usize) -> &'static PoseidonConstants<Self, PoseidonWidth>;
}

impl PoseidonEngine for Bls12 {
    fn PARAMETERS(arity: usize) -> &'static PoseidonConstants<Self, PoseidonWidth> {
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

    fn hash2<S: AsRef<[u8]>, U: AsRef<[u8]>>(a: S, b: U) -> T;

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
        params: &E::Params,
        height: Option<usize>,
        left: &num::AllocatedNum<E>,
        right: &num::AllocatedNum<E>,
    ) -> std::result::Result<num::AllocatedNum<E>, SynthesisError> {
        let left_bits = left.to_bits_le(cs.namespace(|| "left num into bits"))?;
        let right_bits = right.to_bits_le(cs.namespace(|| "right num into bits"))?;

        Self::hash_leaf_bits_circuit(cs, &left_bits, &right_bits, height, params)
    }

    fn hash_leaf_bits_circuit<E: JubjubEngine, CS: ConstraintSystem<E>>(
        _cs: CS,
        _left: &[boolean::Boolean],
        _right: &[boolean::Boolean],
        _height: Option<usize>,
        _params: &E::Params,
    ) -> std::result::Result<num::AllocatedNum<E>, SynthesisError> {
        unimplemented!();
    }
}

pub trait Hasher: Clone + ::std::fmt::Debug + Eq + Default + Send + Sync {
    type Domain: Domain + LightHashable<Self::Function> + AsRef<Self::Domain>;
    type Function: HashFunction<Self::Domain>;

    fn create_label(data: &[u8], m: usize) -> Result<Self::Domain>;
    fn sloth_encode(key: &Self::Domain, ciphertext: &Self::Domain) -> Result<Self::Domain>;
    fn sloth_decode(key: &Self::Domain, ciphertext: &Self::Domain) -> Result<Self::Domain>;

    fn name() -> String;
}
