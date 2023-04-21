use std::cmp::Ordering;
use std::fmt::{self, Debug, Formatter};
use std::hash::Hasher as StdHasher;
use std::marker::PhantomData;
use std::panic::panic_any;

use bellperson::{
    gadgets::{boolean::Boolean, multipack, num::AllocatedNum, sha256::sha256 as sha256_circuit},
    ConstraintSystem, SynthesisError,
};
use blstrs::Scalar as Fr;
use ff::{PrimeField, PrimeFieldBits};
use merkletree::{
    hash::{Algorithm, Hashable},
    merkle::Element,
};
#[cfg(feature = "nova")]
use pasta_curves::{Fp, Fq};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::types::{impl_hasher_for_field, Domain, HashFunction, Hasher};

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
pub struct Sha256Hasher<F = Fr> {
    _f: PhantomData<F>,
}

#[derive(Default, Clone, Debug)]
pub struct Sha256Function<F = Fr> {
    hasher: Sha256,
    _f: PhantomData<F>,
}

impl<F> StdHasher for Sha256Function<F> {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.hasher.update(msg);
    }

    #[inline]
    fn finish(&self) -> u64 {
        unreachable!("unused by Function -- should never be called")
    }
}

#[derive(Copy, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Sha256Domain<F = Fr> {
    pub state: [u8; 32],
    #[serde(skip)]
    _f: PhantomData<F>,
}

impl<F> Debug for Sha256Domain<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Sha256Domain<{}>({})",
            std::any::type_name::<F>(),
            hex::encode(&self.state),
        )
    }
}

impl<F> AsRef<Sha256Domain<F>> for Sha256Domain<F> {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<F> Sha256Domain<F> {
    fn trim_to_fr32(&mut self) {
        // strip two most significant bits, to ensure result is a valid 255-bit field element.
        self.state[31] &= 0b0011_1111;
    }
}

impl<F> AsRef<[u8]> for Sha256Domain<F> {
    fn as_ref(&self) -> &[u8] {
        &self.state
    }
}

impl<F> PartialEq for Sha256Domain<F> {
    fn eq(&self, other: &Self) -> bool {
        self.state == other.state
    }
}

impl<F> Eq for Sha256Domain<F> {}

impl<F> PartialOrd for Sha256Domain<F> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.state.partial_cmp(&other.state)
    }
}

impl<F> Ord for Sha256Domain<F> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.state.cmp(&other.state)
    }
}

impl<F> std::hash::Hash for Sha256Domain<F> {
    fn hash<H: StdHasher>(&self, hasher: &mut H) {
        std::hash::Hash::hash(&self.state, hasher);
    }
}

impl<F> Hashable<Sha256Function<F>> for Sha256Domain<F> {
    fn hash(&self, state: &mut Sha256Function<F>) {
        state.write(self.as_ref())
    }
}

impl<F> Element for Sha256Domain<F>
where
    F: PrimeField,
    Self: Domain<Field = F>,
{
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
        bytes.copy_from_slice(&self.state);
    }
}

impl<F> HashFunction<Sha256Domain<F>> for Sha256Function<F>
where
    F: PrimeFieldBits,
    Sha256Domain<F>: Domain<Field = F>,
{
    fn hash(data: &[u8]) -> Sha256Domain<F> {
        let hashed = Sha256::digest(data);
        let mut res = Sha256Domain::default();
        res.state.copy_from_slice(&hashed[..]);
        res.trim_to_fr32();
        res
    }

    fn hash2(a: &Sha256Domain<F>, b: &Sha256Domain<F>) -> Sha256Domain<F> {
        let hashed = Sha256::new().chain_update(a).chain_update(b).finalize();
        let mut res = Sha256Domain::default();
        res.state.copy_from_slice(&hashed[..]);
        res.trim_to_fr32();
        res
    }

    fn hash_leaf_circuit<CS: ConstraintSystem<F>>(
        mut cs: CS,
        left: &AllocatedNum<F>,
        right: &AllocatedNum<F>,
        height: usize,
    ) -> Result<AllocatedNum<F>, SynthesisError> {
        let left_bits = left.to_bits_le(cs.namespace(|| "left num into bits"))?;
        let right_bits = right.to_bits_le(cs.namespace(|| "right num into bits"))?;

        Self::hash_leaf_bits_circuit(cs, &left_bits, &right_bits, height)
    }

    fn hash_multi_leaf_circuit<Arity, CS: ConstraintSystem<F>>(
        mut cs: CS,
        leaves: &[AllocatedNum<F>],
        _height: usize,
    ) -> Result<AllocatedNum<F>, SynthesisError> {
        let mut bits = Vec::with_capacity(leaves.len() * F::CAPACITY as usize);
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

    fn hash_leaf_bits_circuit<CS: ConstraintSystem<F>>(
        cs: CS,
        left: &[Boolean],
        right: &[Boolean],
        _height: usize,
    ) -> Result<AllocatedNum<F>, SynthesisError> {
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

    fn hash_circuit<CS: ConstraintSystem<F>>(
        mut cs: CS,
        bits: &[Boolean],
    ) -> Result<AllocatedNum<F>, SynthesisError> {
        let be_bits = sha256_circuit(cs.namespace(|| "hash"), bits)?;
        let le_bits = be_bits
            .chunks(8)
            .flat_map(|chunk| chunk.iter().rev())
            .take(F::CAPACITY as usize)
            .cloned()
            .collect::<Vec<_>>();
        multipack::pack_bits(cs.namespace(|| "pack_le"), &le_bits)
    }

    fn hash2_circuit<CS>(
        mut cs: CS,
        a_num: &AllocatedNum<F>,
        b_num: &AllocatedNum<F>,
    ) -> Result<AllocatedNum<F>, SynthesisError>
    where
        CS: ConstraintSystem<F>,
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

impl<F> Algorithm<Sha256Domain<F>> for Sha256Function<F>
where
    F: PrimeField,
    Sha256Domain<F>: Domain<Field = F>,
{
    #[inline]
    fn hash(&mut self) -> Sha256Domain<F> {
        let mut h = [0u8; 32];
        h.copy_from_slice(self.hasher.clone().finalize().as_ref());
        let mut dd = Sha256Domain::from(h);
        dd.trim_to_fr32();
        dd
    }

    #[inline]
    fn reset(&mut self) {
        self.hasher.reset();
    }

    fn leaf(&mut self, leaf: Sha256Domain<F>) -> Sha256Domain<F> {
        leaf
    }

    fn node(
        &mut self,
        left: Sha256Domain<F>,
        right: Sha256Domain<F>,
        _height: usize,
    ) -> Sha256Domain<F> {
        left.hash(self);
        right.hash(self);
        self.hash()
    }

    fn multi_node(&mut self, parts: &[Sha256Domain<F>], _height: usize) -> Sha256Domain<F> {
        for part in parts {
            part.hash(self)
        }
        self.hash()
    }
}

impl<F> From<[u8; 32]> for Sha256Domain<F> {
    #[inline]
    fn from(val: [u8; 32]) -> Self {
        Sha256Domain {
            state: val,
            _f: PhantomData,
        }
    }
}

impl<F> From<Sha256Domain<F>> for [u8; 32] {
    #[inline]
    fn from(val: Sha256Domain<F>) -> Self {
        val.state
    }
}

impl_hasher_for_field!(Sha256Hasher, Sha256Domain, Sha256Function, "sha256_hasher", Fr);

#[cfg(feature = "nova")]
impl_hasher_for_field!(Sha256Hasher, Sha256Domain, Sha256Function, "sha256_hasher", Fp, Fq);

#[cfg(all(test, feature = "nova"))]
mod tests {
    use super::*;

    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use ff::Field;
    use generic_array::typenum::U0;

    #[test]
    fn test_sha256_vanilla_all_fields() {
        // Test two one-block and two two-block preimages.
        let preimages = [vec![1u8], vec![0, 55, 0, 0], vec![1; 64], vec![1; 100]];
        for preimage in &preimages {
            let digest_fr: [u8; 32] =
                <Sha256Function<Fr> as HashFunction<_>>::hash(preimage).into();
            let digest_fp: [u8; 32] =
                <Sha256Function<Fp> as HashFunction<_>>::hash(preimage).into();
            let digest_fq: [u8; 32] =
                <Sha256Function<Fq> as HashFunction<_>>::hash(preimage).into();
            assert_eq!(digest_fr, digest_fp);
            assert_eq!(digest_fr, digest_fq);
        }
    }

    #[test]
    fn test_sha256_r1cs_circuit_all_fields() {
        // Choose an arbitrary arity type because it is ignored by the sha256 circuit.
        type A = U0;

        let digest_fr: Fr = {
            let mut cs = TestConstraintSystem::new();
            let preimage =
                [AllocatedNum::alloc(&mut cs, || Ok(Fr::one()))
                    .expect("allocation should not fail")];
            Sha256Function::<Fr>::hash_multi_leaf_circuit::<A, _>(&mut cs, &preimage, 0)
                .expect("sha256 failed")
                .get_value()
                .expect("digest should be allocated")
        };
        let digest_fp: Fp = {
            let mut cs = TestConstraintSystem::new();
            let preimage =
                [AllocatedNum::alloc(&mut cs, || Ok(Fp::one()))
                    .expect("allocation should not fail")];
            Sha256Function::<Fp>::hash_multi_leaf_circuit::<A, _>(&mut cs, &preimage, 0)
                .expect("sha256 failed")
                .get_value()
                .expect("digest should be allocated")
        };
        let digest_fq: Fq = {
            let mut cs = TestConstraintSystem::new();
            let preimage =
                [AllocatedNum::alloc(&mut cs, || Ok(Fq::one()))
                    .expect("allocation should not fail")];
            Sha256Function::<Fq>::hash_multi_leaf_circuit::<A, _>(&mut cs, &preimage, 0)
                .expect("sha256 failed")
                .get_value()
                .expect("digest should be allocated")
        };

        for ((byte_1, byte_2), byte_3) in digest_fr
            .to_repr()
            .as_ref()
            .iter()
            .zip(digest_fp.to_repr().as_ref())
            .zip(digest_fq.to_repr().as_ref())
        {
            assert_eq!(byte_1, byte_2);
            assert_eq!(byte_1, byte_3);
        }
    }
}
