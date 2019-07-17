use algebra::biginteger::BigInteger256 as FrRepr;
use algebra::curves::bls12_381::Bls12_381;
use algebra::curves::jubjub::JubJubProjective as JubJub;
use algebra::fields::bls12_381::Fr;

use dpc::crypto_primitives::crh::pedersen::PedersenWindow;
use snark::{ConstraintSystem, SynthesisError};
use snark_gadgets::bits::boolean;
use snark_gadgets::fields::fp::FpGadget;

use merkletree::hash::{Algorithm as LightAlgorithm, Hashable as LightHashable};
use merkletree::merkle::Element;
use rand::Rand;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;

use crate::error::Result;
use dpc::crypto_primitives::crh::pedersen::PedersenParameters;

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

    fn hash_leaf_circuit<CS: ConstraintSystem<Bls12_381>>(
        cs: CS,
        left: &[boolean::Boolean],
        right: &[boolean::Boolean],
        height: usize,
        params: &PedersenParameters<JubJub>,
    ) -> std::result::Result<FpGadget<Bls12_381>, SynthesisError>;

    fn hash_circuit<CS: ConstraintSystem<Bls12_381>>(
        cs: CS,
        bits: &[boolean::Boolean],
        params: &PedersenParameters<JubJub>,
    ) -> std::result::Result<FpGadget<Bls12_381>, SynthesisError>;
}

pub trait Hasher: Clone + ::std::fmt::Debug + Eq + Default + Send + Sync {
    type Domain: Domain + LightHashable<Self::Function>;
    type Function: HashFunction<Self::Domain>;

    fn kdf(data: &[u8], m: usize) -> Self::Domain;
    fn sloth_encode(key: &Self::Domain, ciphertext: &Self::Domain, rounds: usize) -> Self::Domain;
    fn sloth_decode(key: &Self::Domain, ciphertext: &Self::Domain, rounds: usize) -> Self::Domain;

    fn name() -> String;
}
