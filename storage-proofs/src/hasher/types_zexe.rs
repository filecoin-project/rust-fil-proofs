use zexe_algebra::fields::bls12_381::Fr;
use zexe_algebra::PairingEngine as Engine;
use zexe_algebra::groups::Group;
use zexe_algebra::biginteger::BigInteger256 as FrRepr;
use zexe_gadgets::bits::boolean;
use zexe_gadgets::fields::fp::FpGadget;
use zexe_gadgets::groups::GroupGadget;
use zexe_snark::{ConstraintSystem, SynthesisError};

use merkletree::hash::{Algorithm as LightAlgorithm, Hashable as LightHashable};
use merkletree::merkle::Element;
use rand::Rand;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;

use crate::error::Result;

pub trait DomainZexe:
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

pub trait HashFunctionZexe<T: DomainZexe>:
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

    fn hash_leaf_circuit<G: Group, E: Engine, GG: GroupGadget<G, E>, CS: ConstraintSystem<E>>(
        cs: CS,
        left: &[boolean::Boolean],
        right: &[boolean::Boolean],
        height: usize
    ) -> std::result::Result<FpGadget<E>, SynthesisError>;

    fn hash_circuit<G: Group, E: Engine, GG: GroupGadget<G, E>, CS: ConstraintSystem<E>>(
        cs: CS,
        bits: &[boolean::Boolean]
    ) -> std::result::Result<FpGadget<E>, SynthesisError>;
}

pub trait HasherZexe: Clone + ::std::fmt::Debug + Eq + Default + Send + Sync {
    type DomainZexe: DomainZexe + LightHashable<Self::FunctionZexe>;
    type FunctionZexe: HashFunctionZexe<Self::DomainZexe>;

    fn kdf(data: &[u8], m: usize) -> Self::DomainZexe;
    fn sloth_encode(key: &Self::DomainZexe, ciphertext: &Self::DomainZexe, rounds: usize) -> Self::DomainZexe;
    fn sloth_decode(key: &Self::DomainZexe, ciphertext: &Self::DomainZexe, rounds: usize) -> Self::DomainZexe;

    fn name() -> String;
}
