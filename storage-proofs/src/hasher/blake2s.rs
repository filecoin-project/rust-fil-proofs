use std::fmt;
use std::hash::Hasher as StdHasher;

use bellman::{ConstraintSystem, SynthesisError};
use blake2s_simd::{Hash as Blake2sHash, Params as Blake2s, State};
use byteorder::{LittleEndian, WriteBytesExt};
use merkle_light::hash::{Algorithm, Hashable};
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use pairing::{PrimeField, PrimeFieldRepr};
use rand::{Rand, Rng};
use sapling_crypto::circuit::{blake2s as blake2s_circuit, boolean, multipack, num};
use sapling_crypto::jubjub::JubjubEngine;

use super::{Domain, HashFunction, Hasher};
use crate::crypto::sloth;
use crate::error::*;

#[derive(Default, Copy, Clone, PartialEq, Eq, Debug)]
pub struct Blake2sHasher {}

impl Hasher for Blake2sHasher {
    type Domain = Blake2sDomain;
    type Function = Blake2sFunction;

    fn name() -> String {
        "Blake2sHasher".into()
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

#[derive(Clone)]
pub struct Blake2sFunction(State);

impl Default for Blake2sFunction {
    fn default() -> Self {
        Blake2sFunction(Blake2s::new().hash_length(32).to_state())
    }
}

impl PartialEq for Blake2sFunction {
    fn eq(&self, other: &Self) -> bool {
        format!("{:?}", self) == format!("{:?}", other)
    }
}

impl Eq for Blake2sFunction {}

impl fmt::Debug for Blake2sFunction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Blake2sFunction({:?})", self.0)
    }
}

impl StdHasher for Blake2sFunction {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0.update(msg);
    }

    #[inline]
    fn finish(&self) -> u64 {
        unreachable!("unused by Function -- should never be called")
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct Blake2sDomain(pub [u8; 32]);

impl Blake2sDomain {
    fn trim_to_fr32(&mut self) {
        // strip last two bits, to ensure result is in Fr.
        self.0[31] &= 0b0011_1111;
    }
}

impl Rand for Blake2sDomain {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        // generating an Fr and converting it, to ensure we stay in the field
        rng.gen::<Fr>().into()
    }
}

impl AsRef<[u8]> for Blake2sDomain {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl Hashable<Blake2sFunction> for Blake2sDomain {
    fn hash(&self, state: &mut Blake2sFunction) {
        state.write(self.as_ref())
    }
}

impl From<Fr> for Blake2sDomain {
    fn from(val: Fr) -> Self {
        let mut res = Self::default();
        val.into_repr().write_le(&mut res.0[0..32]).unwrap();

        res
    }
}

impl From<FrRepr> for Blake2sDomain {
    fn from(val: FrRepr) -> Self {
        let mut res = Self::default();
        val.write_le(&mut res.0[0..32]).unwrap();

        res
    }
}

impl From<Blake2sDomain> for Fr {
    fn from(val: Blake2sDomain) -> Self {
        let mut res = FrRepr::default();
        res.read_le(&val.0[0..32]).unwrap();

        Fr::from_repr(res).unwrap()
    }
}

impl Domain for Blake2sDomain {
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
        let mut res = Blake2sDomain::default();
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

impl Into<Blake2sDomain> for Blake2sHash {
    fn into(self) -> Blake2sDomain {
        let mut res = Blake2sDomain::default();
        res.0[..].copy_from_slice(self.as_ref());
        res.trim_to_fr32();

        res
    }
}

impl HashFunction<Blake2sDomain> for Blake2sFunction {
    fn hash(data: &[u8]) -> Blake2sDomain {
        Blake2s::new()
            .hash_length(32)
            .to_state()
            .update(data)
            .finalize()
            .into()
    }

    fn hash_leaf_circuit<E: JubjubEngine, CS: ConstraintSystem<E>>(
        mut cs: CS,
        left: &[boolean::Boolean],
        right: &[boolean::Boolean],
        height: usize,
        params: &E::Params,
    ) -> std::result::Result<num::AllocatedNum<E>, SynthesisError> {
        let mut preimage: Vec<boolean::Boolean> = vec![];
        let mut height_bytes = vec![];
        height_bytes
            .write_u64::<LittleEndian>(height as u64)
            .expect("failed to write height");

        preimage.extend(
            multipack::bytes_to_bits_le(&height_bytes)
                .iter()
                .enumerate()
                .map(|(i, b)| {
                    boolean::AllocatedBit::alloc(
                        cs.namespace(|| format!("height_bit {}", i)),
                        Some(*b),
                    )
                    .map(boolean::Boolean::Is)
                })
                .collect::<::std::result::Result<Vec<boolean::Boolean>, _>>()?,
        );
        preimage.extend_from_slice(left);
        while preimage.len() % 8 != 0 {
            preimage.push(boolean::Boolean::Constant(false));
        }

        preimage.extend_from_slice(right);
        while preimage.len() % 8 != 0 {
            preimage.push(boolean::Boolean::Constant(false));
        }

        Self::hash_circuit(cs, &preimage[..], params)
    }

    fn hash_circuit<E: JubjubEngine, CS: ConstraintSystem<E>>(
        mut cs: CS,
        bits: &[boolean::Boolean],
        _params: &E::Params,
    ) -> std::result::Result<num::AllocatedNum<E>, SynthesisError> {
        let personalization = vec![0u8; 8];
        let alloc_bits =
            blake2s_circuit::blake2s(cs.namespace(|| "hash"), &bits[..], &personalization)?;
        let fr = match alloc_bits[0].get_value() {
            Some(_) => {
                let bits = alloc_bits
                    .iter()
                    .map(|v| v.get_value().unwrap())
                    .collect::<Vec<bool>>();
                // TODO: figure out if we can avoid this
                let frs = multipack::compute_multipacking::<E>(&bits);
                Ok(frs[0])
            }
            None => Err(SynthesisError::AssignmentMissing),
        };

        num::AllocatedNum::<E>::alloc(cs.namespace(|| "num"), || fr)
    }
}

impl Algorithm<Blake2sDomain> for Blake2sFunction {
    #[inline]
    fn hash(&mut self) -> Blake2sDomain {
        self.0.clone().finalize().into()
    }

    #[inline]
    fn reset(&mut self) {
        self.0 = Blake2s::new().hash_length(32).to_state()
    }

    fn leaf(&mut self, leaf: Blake2sDomain) -> Blake2sDomain {
        leaf
    }

    fn node(&mut self, left: Blake2sDomain, right: Blake2sDomain, height: usize) -> Blake2sDomain {
        height.hash(self);

        left.hash(self);
        right.hash(self);
        self.hash()
    }
}

impl From<[u8; 32]> for Blake2sDomain {
    #[inline]
    fn from(val: [u8; 32]) -> Self {
        Blake2sDomain(val)
    }
}

impl From<Blake2sDomain> for [u8; 32] {
    #[inline]
    fn from(val: Blake2sDomain) -> Self {
        val.0
    }
}
