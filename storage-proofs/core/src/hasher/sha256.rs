use std::hash::Hasher as StdHasher;

use anyhow::ensure;
use bellperson::gadgets::{boolean, num, sha256::sha256 as sha256_circuit};
use bellperson::{ConstraintSystem, SynthesisError};
use ff::{Field, PrimeField, PrimeFieldRepr};
use merkletree::hash::{Algorithm, Hashable};
use merkletree::merkle::Element;
use paired::bls12_381::{Bls12, Fr, FrRepr};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{Domain, HashFunction, Hasher};
use crate::crypto::sloth;
use crate::error::*;
use crate::gadgets::multipack;

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
pub struct Sha256Hasher {}

impl Hasher for Sha256Hasher {
    type Domain = Sha256Domain;
    type Function = Sha256Function;

    fn name() -> String {
        "sha256_hasher".into()
    }

    fn sloth_encode(key: &Self::Domain, ciphertext: &Self::Domain) -> Result<Self::Domain> {
        // TODO: validate this is how sloth should work in this case
        let k = (*key).into();
        let c = (*ciphertext).into();

        Ok(sloth::encode(&k, &c).into())
    }

    fn sloth_decode(key: &Self::Domain, ciphertext: &Self::Domain) -> Result<Self::Domain> {
        // TODO: validate this is how sloth should work in this case
        Ok(sloth::decode(&(*key).into(), &(*ciphertext).into()).into())
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

impl std::fmt::Debug for Sha256Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

    fn try_from_bytes(raw: &[u8]) -> Result<Self> {
        ensure!(
            raw.len() == Sha256Domain::byte_len(),
            Error::InvalidInputSize
        );

        let mut res = Sha256Domain::default();
        res.0.copy_from_slice(&raw[0..Sha256Domain::byte_len()]);
        Ok(res)
    }

    fn write_bytes(&self, dest: &mut [u8]) -> Result<()> {
        ensure!(
            dest.len() >= Sha256Domain::byte_len(),
            Error::InvalidInputSize
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
            Err(err) => panic!(err),
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
        leaves: &[num::AllocatedNum<Bls12>],
        _height: usize,
    ) -> std::result::Result<num::AllocatedNum<Bls12>, SynthesisError> {
        let mut bits = Vec::with_capacity(leaves.len() * Fr::CAPACITY as usize);
        for (i, leaf) in leaves.iter().enumerate() {
            let mut padded = leaf.to_bits_le(cs.namespace(|| format!("{}_num_into_bits", i)))?;
            while padded.len() % 8 != 0 {
                padded.push(boolean::Boolean::Constant(false));
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
        left: &[boolean::Boolean],
        right: &[boolean::Boolean],
        _height: usize,
    ) -> std::result::Result<num::AllocatedNum<Bls12>, SynthesisError> {
        let mut preimage: Vec<boolean::Boolean> = vec![];

        let mut left_padded = left.to_vec();
        while left_padded.len() % 8 != 0 {
            left_padded.push(boolean::Boolean::Constant(false));
        }

        preimage.extend(
            left_padded
                .chunks_exact(8)
                .flat_map(|chunk| chunk.iter().rev())
                .cloned(),
        );

        let mut right_padded = right.to_vec();
        while right_padded.len() % 8 != 0 {
            right_padded.push(boolean::Boolean::Constant(false));
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
        bits: &[boolean::Boolean],
    ) -> std::result::Result<num::AllocatedNum<Bls12>, SynthesisError> {
        let be_bits = sha256_circuit(cs.namespace(|| "hash"), &bits[..])?;
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
        a_num: &num::AllocatedNum<Bls12>,
        b_num: &num::AllocatedNum<Bls12>,
    ) -> std::result::Result<num::AllocatedNum<Bls12>, SynthesisError>
    where
        CS: ConstraintSystem<Bls12>,
    {
        // Allocate as booleans
        let a = a_num.to_bits_le(cs.namespace(|| "a_bits"))?;
        let b = b_num.to_bits_le(cs.namespace(|| "b_bits"))?;

        let mut preimage: Vec<boolean::Boolean> = vec![];

        let mut a_padded = a.to_vec();
        while a_padded.len() % 8 != 0 {
            a_padded.push(boolean::Boolean::Constant(false));
        }

        preimage.extend(
            a_padded
                .chunks_exact(8)
                .flat_map(|chunk| chunk.iter().rev())
                .cloned(),
        );

        let mut b_padded = b.to_vec();
        while b_padded.len() % 8 != 0 {
            b_padded.push(boolean::Boolean::Constant(false));
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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::fr32::fr_into_bytes;
    use crate::util::bytes_into_boolean_vec;
    use bellperson::util_cs::test_cs::TestConstraintSystem;

    use bellperson::gadgets::boolean::Boolean;
    use bellperson::ConstraintSystem;
    use ff::Field;
    use merkletree::hash::Algorithm;
    use paired::bls12_381::{Bls12, Fr};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    #[test]
    fn hash_leaf_bits_circuit() {
        let mut cs = TestConstraintSystem::<Bls12>::new();
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let left_fr = Fr::random(rng);
        let right_fr = Fr::random(rng);
        let left: Vec<u8> = fr_into_bytes(&left_fr);
        let right: Vec<u8> = fr_into_bytes(&right_fr);
        let height = 1;

        let left_bits: Vec<Boolean> = {
            let mut cs = cs.namespace(|| "left");
            bytes_into_boolean_vec(&mut cs, Some(left.as_slice()), 256).expect("left bits failure")
        };

        let right_bits: Vec<Boolean> = {
            let mut cs = cs.namespace(|| "right");
            bytes_into_boolean_vec(&mut cs, Some(right.as_slice()), 256)
                .expect("right bits failure")
        };

        let out = Sha256Function::hash_leaf_bits_circuit(
            cs.namespace(|| "hash_leaf_circuit"),
            &left_bits,
            &right_bits,
            height,
        )
        .expect("key derivation function failed");

        assert!(cs.is_satisfied(), "constraints not satisfied");
        assert_eq!(cs.num_constraints(), 45_387);

        let expected: Fr = Sha256Function::default()
            .node(left_fr.into(), right_fr.into(), height)
            .into();

        assert_eq!(
            expected,
            out.get_value().expect("get_value failure"),
            "circuit and non circuit do not match"
        );
    }
}
