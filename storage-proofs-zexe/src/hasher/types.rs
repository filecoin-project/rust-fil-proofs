use algebra::biginteger::BigInteger256 as FrRepr;
use algebra::fields::bls12_381::Fr;

use algebra::PairingEngine as Engine;
use dpc::crypto_primitives::crh::pedersen::PedersenWindow;
use snark_gadgets::bits::boolean;
use snark_gadgets::fields::fp::FpGadget;
use snark::{ConstraintSystem, SynthesisError};

use merkletree::hash::{Algorithm as LightAlgorithm, Hashable as LightHashable};
use merkletree::merkle::Element;
use rand::Rand;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;

use crate::error::Result;

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
    + Rand
    + Serialize
    + DeserializeOwned
    + Element
{
    fn serialize(&self) -> Vec<u8>;
    fn into_bytes(&self) -> Vec<u8>;
    fn try_from_bytes(raw: &[u8]) -> Result<Self>;
    /// Write itself into the given slice, LittleEndian bytes.
    fn write_bytes(&self, _: &mut [u8]) -> Result<()>;
}

pub trait HashFunction<T: Domain>:
    Clone + ::std::fmt::Debug + Eq + Send + Sync + LightAlgorithm<T>
{
    fn hash(data: &[u8]) -> T;

    fn hash_leaf(data: &LightHashable<Self>) -> T {
        let mut a = Self::default();
        data.hash(&mut a);
        let item_hash = a.hash();
        a.leaf(item_hash)
    }

    fn hash_single_node(data: &LightHashable<Self>) -> T {
        let mut a = Self::default();
        data.hash(&mut a);
        a.hash()
    }

    fn hash_leaf_circuit<E: Engine, CS: ConstraintSystem<E>>(
        cs: CS,
        left: &[boolean::Boolean],
        right: &[boolean::Boolean],
        height: usize,
    ) -> std::result::Result<FpGadget<E>, SynthesisError>;

    fn hash_circuit<E: Engine, CS: ConstraintSystem<E>>(
        cs: CS,
        bits: &[boolean::Boolean],
    ) -> std::result::Result<FpGadget<E>, SynthesisError>;
}

pub trait Hasher: Clone + ::std::fmt::Debug + Eq + Default + Send + Sync {
    type Domain: Domain + LightHashable<Self::Function>;
    type Function: HashFunction<Self::Domain>;

    fn kdf(data: &[u8], m: usize) -> Self::Domain;
    fn sloth_encode(key: &Self::Domain, ciphertext: &Self::Domain, rounds: usize) -> Self::Domain;
    fn sloth_decode(key: &Self::Domain, ciphertext: &Self::Domain, rounds: usize) -> Self::Domain;

    fn name() -> String;
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Window;

impl PedersenWindow for Window {
    const WINDOW_SIZE: usize = 1;
    const NUM_WINDOWS: usize = 2016;
}

