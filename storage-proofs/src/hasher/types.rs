use crate::error::Result;
use merkle_light::hash::{Algorithm as LightAlgorithm, Hashable as LightHashable};
use pairing::bls12_381::{Fr, FrRepr};
use rand::Rand;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;

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
}

pub trait Hasher: Clone + ::std::fmt::Debug + Eq + Default + Send + Sync {
    type Domain: Domain + LightHashable<Self::Function>;
    type Function: HashFunction<Self::Domain>;

    fn kdf(data: &[u8], m: usize) -> Self::Domain;
    fn sloth_encode(key: &Self::Domain, ciphertext: &Self::Domain, rounds: usize) -> Self::Domain;
    fn sloth_decode(key: &Self::Domain, ciphertext: &Self::Domain, rounds: usize) -> Self::Domain;
}
