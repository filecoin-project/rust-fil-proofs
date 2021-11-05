use std::fmt::{self, Debug, Formatter};
use std::hash::Hasher as StdHasher;
use std::panic::panic_any;

use anyhow::ensure;
use bellperson::{
    bls::{Bls12, Fr, FrRepr},
    gadgets::{boolean::Boolean, multipack, num::AllocatedNum, sha256::sha256 as sha256_circuit},
    ConstraintSystem, SynthesisError,
};
use ff::{Field, PrimeField, PrimeFieldRepr};
use merkletree::{
    hash::{Algorithm, Hashable},
    merkle::Element,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::types::{Domain, HashFunction, Hasher};

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
pub struct Sha256Hasher {}

impl Hasher for Sha256Hasher {
    type Domain = Sha256Domain;
    type Function = Sha256Function;

    fn name() -> String {
        "sha256_hasher".into()
    }
}

#[derive(Default, Clone, Debug)]
pub struct Sha256Function(Sha256);

impl StdHasher for Sha256Function {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0.update(msg)
    }

    #[inline]
    fn finish(&self) -> u64 {
        unreachable!("unused by Function -- should never be called")
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize, Hash)]
pub struct Sha256Domain(pub [u8; 32]);

impl Debug for Sha256Domain {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Domain({})", hex::encode(&self.0))
    }
}

impl AsRef<Sha256Domain> for Sha256Domain {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl Sha256Domain {
    fn trim_to_fr32(&mut self) {
        // strip last two bits, to ensure result is in Fr.
        self.0[31] &= 0b0011_1111;
    }
}

impl AsRef<[u8]> for Sha256Domain {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl Hashable<Sha256Function> for Sha256Domain {
    fn hash(&self, state: &mut Sha256Function) {
        state.write(self.as_ref())
    }
}

impl From<Fr> for Sha256Domain {
    fn from(val: Fr) -> Self {
        let mut res = Self::default();
        val.into_repr()
            .write_le(&mut res.0[0..32])
            .expect("write_le failure");

        res
    }
}

impl From<FrRepr> for Sha256Domain {
    fn from(val: FrRepr) -> Self {
        let mut res = Self::default();
        val.write_le(&mut res.0[0..32]).expect("write_le failure");

        res
    }
}

impl From<Sha256Domain> for Fr {
    fn from(val: Sha256Domain) -> Self {
        let mut res = FrRepr::default();
        res.read_le(&val.0[0..32]).expect("read_le failure");

        Fr::from_repr(res).expect("from_repr failure")
    }
}

impl Domain for Sha256Domain {
    fn into_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn try_from_bytes(raw: &[u8]) -> anyhow::Result<Self> {
        ensure!(
            raw.len() == Sha256Domain::byte_len(),
            "invalid number of bytes"
        );

        let mut res = Sha256Domain::default();
        res.0.copy_from_slice(&raw[0..Sha256Domain::byte_len()]);
        Ok(res)
    }

    fn write_bytes(&self, dest: &mut [u8]) -> anyhow::Result<()> {
        ensure!(
            dest.len() >= Sha256Domain::byte_len(),
            "invalid number of bytes"
        );

        dest[0..Sha256Domain::byte_len()].copy_from_slice(&self.0[..]);
        Ok(())
    }

    fn random<R: RngCore>(rng: &mut R) -> Self {
        // generating an Fr and converting it, to ensure we stay in the field
        Fr::random(rng).into()
    }
}

impl Element for Sha256Domain {
    fn byte_len() -> usize {
        32
    }

    fn from_slice(bytes: &[u8]) -> Self {
        match Sha256Domain::try_from_bytes(bytes) {
            Ok(res) => res,
            Err(err) => panic_any(err),
        }
    }

    fn copy_to_slice(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(&self.0);
    }
}

impl HashFunction<Sha256Domain> for Sha256Function {
    fn hash(data: &[u8]) -> Sha256Domain {
        let hashed = Sha256::digest(data);
        let mut res = Sha256Domain::default();
        res.0.copy_from_slice(&hashed[..]);
        res.trim_to_fr32();
        res
    }

    fn hash2(a: &Sha256Domain, b: &Sha256Domain) -> Sha256Domain {
        let hashed = Sha256::new()
            .chain(AsRef::<[u8]>::as_ref(a))
            .chain(AsRef::<[u8]>::as_ref(b))
            .finalize();
        let mut res = Sha256Domain::default();
        res.0.copy_from_slice(&hashed[..]);
        res.trim_to_fr32();
        res
    }

    fn hash_multi_leaf_circuit<Arity, CS: ConstraintSystem<Bls12>>(
        mut cs: CS,
        leaves: &[AllocatedNum<Bls12>],
        _height: usize,
    ) -> Result<AllocatedNum<Bls12>, SynthesisError> {
        let mut bits = Vec::with_capacity(leaves.len() * Fr::CAPACITY as usize);
        for (i, leaf) in leaves.iter().enumerate() {
            let mut padded = leaf.to_bits_le(cs.namespace(|| format!("{}_num_into_bits", i)))?;
            while padded.len() % 8 != 0 {
                padded.push(Boolean::Constant(false));
            }

            bits.extend(
                padded
                    .chunks_exact(8)
                    .flat_map(|chunk| chunk.iter().rev())
                    .cloned(),
            );
        }
        Self::hash_circuit(cs, &bits)
    }

    fn hash_leaf_bits_circuit<CS: ConstraintSystem<Bls12>>(
        cs: CS,
        left: &[Boolean],
        right: &[Boolean],
        _height: usize,
    ) -> Result<AllocatedNum<Bls12>, SynthesisError> {
        let mut preimage: Vec<Boolean> = vec![];

        let mut left_padded = left.to_vec();
        while left_padded.len() % 8 != 0 {
            left_padded.push(Boolean::Constant(false));
        }

        preimage.extend(
            left_padded
                .chunks_exact(8)
                .flat_map(|chunk| chunk.iter().rev())
                .cloned(),
        );

        let mut right_padded = right.to_vec();
        while right_padded.len() % 8 != 0 {
            right_padded.push(Boolean::Constant(false));
        }

        preimage.extend(
            right_padded
                .chunks_exact(8)
                .flat_map(|chunk| chunk.iter().rev())
                .cloned(),
        );

        Self::hash_circuit(cs, &preimage[..])
    }

    fn hash_circuit<CS: ConstraintSystem<Bls12>>(
        mut cs: CS,
        bits: &[Boolean],
    ) -> Result<AllocatedNum<Bls12>, SynthesisError> {
        let be_bits = sha256_circuit(cs.namespace(|| "hash"), bits)?;
        let le_bits = be_bits
            .chunks(8)
            .flat_map(|chunk| chunk.iter().rev())
            .cloned()
            .take(Fr::CAPACITY as usize)
            .collect::<Vec<_>>();
        multipack::pack_bits(cs.namespace(|| "pack_le"), &le_bits)
    }

    fn hash2_circuit<CS>(
        mut cs: CS,
        a_num: &AllocatedNum<Bls12>,
        b_num: &AllocatedNum<Bls12>,
    ) -> Result<AllocatedNum<Bls12>, SynthesisError>
    where
        CS: ConstraintSystem<Bls12>,
    {
        // Allocate as booleans
        let a = a_num.to_bits_le(cs.namespace(|| "a_bits"))?;
        let b = b_num.to_bits_le(cs.namespace(|| "b_bits"))?;

        let mut preimage: Vec<Boolean> = vec![];

        let mut a_padded = a.to_vec();
        while a_padded.len() % 8 != 0 {
            a_padded.push(Boolean::Constant(false));
        }

        preimage.extend(
            a_padded
                .chunks_exact(8)
                .flat_map(|chunk| chunk.iter().rev())
                .cloned(),
        );

        let mut b_padded = b.to_vec();
        while b_padded.len() % 8 != 0 {
            b_padded.push(Boolean::Constant(false));
        }

        preimage.extend(
            b_padded
                .chunks_exact(8)
                .flat_map(|chunk| chunk.iter().rev())
                .cloned(),
        );

        Self::hash_circuit(cs, &preimage[..])
    }
}

impl Algorithm<Sha256Domain> for Sha256Function {
    #[inline]
    fn hash(&mut self) -> Sha256Domain {
        let mut h = [0u8; 32];
        h.copy_from_slice(self.0.clone().finalize().as_ref());
        let mut dd = Sha256Domain::from(h);
        dd.trim_to_fr32();
        dd
    }

    #[inline]
    fn reset(&mut self) {
        self.0.reset();
    }

    fn leaf(&mut self, leaf: Sha256Domain) -> Sha256Domain {
        leaf
    }

    fn node(&mut self, left: Sha256Domain, right: Sha256Domain, _height: usize) -> Sha256Domain {
        left.hash(self);
        right.hash(self);
        self.hash()
    }

    fn multi_node(&mut self, parts: &[Sha256Domain], _height: usize) -> Sha256Domain {
        for part in parts {
            part.hash(self)
        }
        self.hash()
    }
}

impl From<[u8; 32]> for Sha256Domain {
    #[inline]
    fn from(val: [u8; 32]) -> Self {
        Sha256Domain(val)
    }
}

impl From<Sha256Domain> for [u8; 32] {
    #[inline]
    fn from(val: Sha256Domain) -> Self {
        val.0
    }
}
