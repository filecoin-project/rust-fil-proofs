use std::fmt;
use std::hash::Hasher as StdHasher;
use std::marker::PhantomData;

use bellman::{ConstraintSystem, SynthesisError};
use merkle_light::hash::{Algorithm, Hashable};
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use pairing::{PrimeField, PrimeFieldRepr};
use rand::{Rand, Rng};
use sapling_crypto::circuit::{boolean, num};
use sapling_crypto::jubjub::JubjubEngine;
use sha2::Digest;

use super::{Domain, HashFunction, Hasher};
use crate::crypto::sloth;
use crate::error::*;

pub trait Digester: Digest + Clone + Default + ::std::fmt::Debug + Send + Sync {
    fn name() -> String;
}

#[derive(Default, Copy, Clone, Debug)]
pub struct DigestHasher<D: Digester> {
    _d: PhantomData<D>,
}

impl<D: Digester> PartialEq for DigestHasher<D> {
    fn eq(&self, other: &Self) -> bool {
        self._d == other._d
    }
}

impl<D: Digester> Eq for DigestHasher<D> {}

impl<D: Digester> Hasher for DigestHasher<D> {
    type Domain = DigestDomain;
    type Function = DigestFunction<D>;

    fn name() -> String {
        format!("DigestHasher<{}>", D::name())
    }

    fn kdf(data: &[u8], m: usize) -> Self::Domain {
        assert_eq!(
            data.len(),
            32 * (1 + m),
            "invalid input length: data.len(): {} m: {}",
            data.len(),
            m
        );

        <Self::Function as HashFunction<Self::Domain>>::hash(data)
    }

    fn sloth_encode(key: &Self::Domain, ciphertext: &Self::Domain, rounds: usize) -> Self::Domain {
        // TODO: validate this is how sloth should work in this case
        let k = (*key).into();
        let c = (*ciphertext).into();

        sloth::encode::<Bls12>(&k, &c, rounds).into()
    }

    fn sloth_decode(key: &Self::Domain, ciphertext: &Self::Domain, rounds: usize) -> Self::Domain {
        // TODO: validate this is how sloth should work in this case
        sloth::decode::<Bls12>(&(*key).into(), &(*ciphertext).into(), rounds).into()
    }
}

#[derive(Default, Clone)]
pub struct DigestFunction<D: Digester>(D);

impl<D: Digester> PartialEq for DigestFunction<D> {
    fn eq(&self, other: &Self) -> bool {
        format!("{:?}", self) == format!("{:?}", other)
    }
}

impl<D: Digester> Eq for DigestFunction<D> {}

impl<D: Digester> fmt::Debug for DigestFunction<D> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DigestFunction({:?})", self.0)
    }
}

impl<D: Digester> StdHasher for DigestFunction<D> {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0.input(msg)
    }

    #[inline]
    fn finish(&self) -> u64 {
        unreachable!("unused by Function -- should never be called")
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct DigestDomain(pub [u8; 32]);

impl DigestDomain {
    fn trim_to_fr32(&mut self) {
        // strip last two bits, to ensure result is in Fr.
        self.0[31] &= 0b0011_1111;
    }
}

impl Rand for DigestDomain {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        // generating an Fr and converting it, to ensure we stay in the field
        rng.gen::<Fr>().into()
    }
}

impl AsRef<[u8]> for DigestDomain {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl<D: Digester> Hashable<DigestFunction<D>> for DigestDomain {
    fn hash(&self, state: &mut DigestFunction<D>) {
        state.write(self.as_ref())
    }
}

impl From<Fr> for DigestDomain {
    fn from(val: Fr) -> Self {
        let mut res = Self::default();
        val.into_repr().write_le(&mut res.0[0..32]).unwrap();

        res
    }
}

impl From<FrRepr> for DigestDomain {
    fn from(val: FrRepr) -> Self {
        let mut res = Self::default();
        val.write_le(&mut res.0[0..32]).unwrap();

        res
    }
}

impl From<DigestDomain> for Fr {
    fn from(val: DigestDomain) -> Self {
        let mut res = FrRepr::default();
        res.read_le(&val.0[0..32]).unwrap();

        Fr::from_repr(res).unwrap()
    }
}

impl Domain for DigestDomain {
    fn serialize(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn into_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn try_from_bytes(raw: &[u8]) -> Result<Self> {
        if raw.len() != 32 {
            return Err(Error::InvalidInputSize);
        }
        let mut res = DigestDomain::default();
        res.0.copy_from_slice(&raw[0..32]);
        Ok(res)
    }

    fn write_bytes(&self, dest: &mut [u8]) -> Result<()> {
        if dest.len() < 32 {
            return Err(Error::InvalidInputSize);
        }
        dest[0..32].copy_from_slice(&self.0[..]);
        Ok(())
    }
}

impl<D: Digester> HashFunction<DigestDomain> for DigestFunction<D> {
    fn hash(data: &[u8]) -> DigestDomain {
        let hashed = D::digest(data);
        let mut res = DigestDomain::default();
        res.0.copy_from_slice(&hashed[..]);
        res.trim_to_fr32();
        res
    }
    fn hash_leaf_circuit<E: JubjubEngine, CS: ConstraintSystem<E>>(
        _cs: CS,
        _left: &[boolean::Boolean],
        _right: &[boolean::Boolean],
        _height: usize,
        _params: &E::Params,
    ) -> std::result::Result<num::AllocatedNum<E>, SynthesisError> {
        unimplemented!("circuit leaf hash");
    }
    fn hash_circuit<E: JubjubEngine, CS: ConstraintSystem<E>>(
        _cs: CS,
        _bits: &[boolean::Boolean],
        _params: &E::Params,
    ) -> std::result::Result<num::AllocatedNum<E>, SynthesisError> {
        unimplemented!("circuit hash");
    }
}

impl<D: Digester> Algorithm<DigestDomain> for DigestFunction<D> {
    #[inline]
    fn hash(&mut self) -> DigestDomain {
        let mut h = [0u8; 32];
        h.copy_from_slice(self.0.clone().result().as_ref());
        let mut dd = DigestDomain::from(h);
        dd.trim_to_fr32();
        dd
    }

    #[inline]
    fn reset(&mut self) {
        self.0.reset();
    }

    fn leaf(&mut self, leaf: DigestDomain) -> DigestDomain {
        leaf
    }

    fn node(&mut self, left: DigestDomain, right: DigestDomain, height: usize) -> DigestDomain {
        height.hash(self);

        left.hash(self);
        right.hash(self);
        self.hash()
    }
}

impl From<[u8; 32]> for DigestDomain {
    #[inline]
    fn from(val: [u8; 32]) -> Self {
        DigestDomain(val)
    }
}

impl From<DigestDomain> for [u8; 32] {
    #[inline]
    fn from(val: DigestDomain) -> Self {
        val.0
    }
}
