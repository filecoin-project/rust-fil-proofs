use std::hash::Hasher as StdHasher;

use anyhow::ensure;
use bellperson::gadgets::{boolean, num};
use bellperson::{ConstraintSystem, SynthesisError};
use ff::{Field, PrimeField, PrimeFieldRepr};
use fil_sapling_crypto::circuit::pedersen_hash as pedersen_hash_circuit;
use fil_sapling_crypto::pedersen_hash::Personalization;
use merkletree::hash::{Algorithm as LightAlgorithm, Hashable};
use merkletree::merkle::Element;
use paired::bls12_381::{Bls12, Fr, FrRepr};
use serde::{Deserialize, Serialize};

use crate::crypto::{pedersen, sloth};
use crate::error::{Error, Result};
use crate::gadgets::pedersen::{pedersen_compression_num, pedersen_md_no_padding};
use crate::hasher::{Domain, HashFunction, Hasher};

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PedersenHasher {}

impl Hasher for PedersenHasher {
    type Domain = PedersenDomain;
    type Function = PedersenFunction;

    fn name() -> String {
        "PedersenHasher".into()
    }

    #[inline]
    fn sloth_encode(key: &Self::Domain, ciphertext: &Self::Domain) -> Result<Self::Domain> {
        // Unrapping here is safe; `Fr` elements and hash domain elements are the same byte length.
        let key = Fr::from_repr(key.0)?;
        let ciphertext = Fr::from_repr(ciphertext.0)?;
        Ok(sloth::encode(&key, &ciphertext).into())
    }

    #[inline]
    fn sloth_decode(key: &Self::Domain, ciphertext: &Self::Domain) -> Result<Self::Domain> {
        // Unrapping here is safe; `Fr` elements and hash domain elements are the same byte length.
        let key = Fr::from_repr(key.0)?;
        let ciphertext = Fr::from_repr(ciphertext.0)?;

        Ok(sloth::decode(&key, &ciphertext).into())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PedersenFunction(Fr);

impl Default for PedersenFunction {
    fn default() -> PedersenFunction {
        PedersenFunction(Fr::from_repr(FrRepr::default()).expect("failed default"))
    }
}

impl Hashable<PedersenFunction> for Fr {
    fn hash(&self, state: &mut PedersenFunction) {
        let mut bytes = Vec::with_capacity(32);
        self.into_repr()
            .write_le(&mut bytes)
            .expect("write_le failure");
        state.write(&bytes);
    }
}

impl Hashable<PedersenFunction> for PedersenDomain {
    fn hash(&self, state: &mut PedersenFunction) {
        let mut bytes = Vec::with_capacity(32);
        self.0
            .write_le(&mut bytes)
            .expect("Failed to write `FrRepr`");
        state.write(&bytes);
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct PedersenDomain(pub FrRepr);

impl AsRef<PedersenDomain> for PedersenDomain {
    fn as_ref(&self) -> &PedersenDomain {
        self
    }
}

impl std::hash::Hash for PedersenDomain {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let raw: &[u64] = self.0.as_ref();
        std::hash::Hash::hash(raw, state);
    }
}

impl PartialEq for PedersenDomain {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}

impl Eq for PedersenDomain {}

impl Default for PedersenDomain {
    fn default() -> PedersenDomain {
        PedersenDomain(FrRepr::default())
    }
}

impl Ord for PedersenDomain {
    #[inline(always)]
    fn cmp(&self, other: &PedersenDomain) -> ::std::cmp::Ordering {
        (self.0).cmp(&other.0)
    }
}

impl PartialOrd for PedersenDomain {
    #[inline(always)]
    fn partial_cmp(&self, other: &PedersenDomain) -> Option<::std::cmp::Ordering> {
        Some((self.0).cmp(&other.0))
    }
}

impl AsRef<[u8]> for PedersenDomain {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        as_ref(&(self.0).0)
    }
}

// This is unsafe, and I wish it wasn't here, but I really need AsRef<[u8]> to work, without allocating.
// https://internals.rust-lang.org/t/safe-trasnsmute-for-slices-e-g-u64-u32-particularly-simd-types/2871
// https://github.com/briansmith/ring/blob/abb3fdfc08562f3f02e95fb551604a871fd4195e/src/polyfill.rs#L93-L110
#[inline(always)]
#[allow(clippy::needless_lifetimes)]
fn as_ref<'a>(src: &'a [u64; 4]) -> &'a [u8] {
    unsafe {
        std::slice::from_raw_parts(
            src.as_ptr() as *const u8,
            src.len() * std::mem::size_of::<u64>(),
        )
    }
}

impl Domain for PedersenDomain {
    fn into_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PedersenDomain::byte_len());
        self.0.write_le(&mut out).expect("write_le failure");

        out
    }

    fn try_from_bytes(raw: &[u8]) -> Result<Self> {
        ensure!(raw.len() == PedersenDomain::byte_len(), Error::BadFrBytes);
        let mut res: FrRepr = Default::default();
        res.read_le(raw)?;

        Ok(PedersenDomain(res))
    }

    fn write_bytes(&self, dest: &mut [u8]) -> Result<()> {
        self.0.write_le(dest)?;
        Ok(())
    }

    fn random<R: rand::RngCore>(rng: &mut R) -> Self {
        // generating an Fr and converting it, to ensure we stay in the field
        Fr::random(rng).into()
    }
}

impl Element for PedersenDomain {
    fn byte_len() -> usize {
        32
    }

    fn from_slice(bytes: &[u8]) -> Self {
        PedersenDomain::try_from_bytes(bytes).expect("invalid bytes")
    }

    fn copy_to_slice(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(&self.into_bytes());
    }
}

impl StdHasher for PedersenFunction {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0 = pedersen::pedersen(msg);
    }

    #[inline]
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

pub fn pedersen_hash<I: IntoIterator<Item = bool>>(
    node_bits: I,
) -> fil_sapling_crypto::jubjub::edwards::Point<Bls12, fil_sapling_crypto::jubjub::PrimeOrder> {
    #[cfg(target_arch = "x86_64")]
    {
        use fil_sapling_crypto::pedersen_hash::pedersen_hash_bls12_381_with_precomp;
        pedersen_hash_bls12_381_with_precomp::<_>(
            Personalization::None,
            node_bits,
            &pedersen::JJ_PARAMS,
        )
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        use fil_sapling_crypto::pedersen_hash::pedersen_hash;
        pedersen_hash::<Bls12, _>(Personalization::None, node_bits, &pedersen::JJ_PARAMS)
    }
}

impl HashFunction<PedersenDomain> for PedersenFunction {
    fn hash(data: &[u8]) -> PedersenDomain {
        pedersen::pedersen_md_no_padding(data).into()
    }

    fn hash2(a: &PedersenDomain, b: &PedersenDomain) -> PedersenDomain {
        let data = NodeBits::new(&(a.0).0[..], &(b.0).0[..]);
        let digest = pedersen_hash(data);
        digest.into_xy().0.into()
    }

    fn hash_multi_leaf_circuit<Arity, CS: ConstraintSystem<Bls12>>(
        mut cs: CS,
        leaves: &[num::AllocatedNum<Bls12>],
        _height: usize,
    ) -> std::result::Result<num::AllocatedNum<Bls12>, SynthesisError> {
        let is_binary = leaves.len() == 2;

        let mut bits = Vec::with_capacity(leaves.len() * Fr::CAPACITY as usize);
        for (i, leaf) in leaves.iter().enumerate() {
            bits.extend_from_slice(
                &leaf.to_bits_le(cs.namespace(|| format!("{}_num_into_bits", i)))?,
            );
            if !is_binary {
                while bits.len() % 8 != 0 {
                    bits.push(boolean::Boolean::Constant(false));
                }
            }
        }

        if is_binary {
            Ok(pedersen_hash_circuit::pedersen_hash(
                cs,
                Personalization::None,
                &bits,
                &*pedersen::JJ_PARAMS,
            )?
            .get_x()
            .clone())
        } else {
            Self::hash_circuit(cs, &bits)
        }
    }

    fn hash_leaf_bits_circuit<CS: ConstraintSystem<Bls12>>(
        cs: CS,
        left: &[boolean::Boolean],
        right: &[boolean::Boolean],
        _height: usize,
    ) -> ::std::result::Result<num::AllocatedNum<Bls12>, SynthesisError> {
        let mut preimage: Vec<boolean::Boolean> = vec![];
        preimage.extend_from_slice(left);
        preimage.extend_from_slice(right);

        Ok(pedersen_hash_circuit::pedersen_hash(
            cs,
            Personalization::None,
            &preimage,
            &*pedersen::JJ_PARAMS,
        )?
        .get_x()
        .clone())
    }

    fn hash_circuit<CS: ConstraintSystem<Bls12>>(
        cs: CS,
        bits: &[boolean::Boolean],
    ) -> std::result::Result<num::AllocatedNum<Bls12>, SynthesisError> {
        pedersen_md_no_padding(cs, bits)
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

        let mut values = Vec::new();
        values.extend_from_slice(&a);
        values.extend_from_slice(&b);

        if values.is_empty() {
            // can happen with small layers
            num::AllocatedNum::alloc(cs.namespace(|| "pedersen_hash1"), || Ok(Fr::zero()))
        } else {
            pedersen_compression_num(cs.namespace(|| "pedersen_hash1"), &values)
        }
    }
}

impl LightAlgorithm<PedersenDomain> for PedersenFunction {
    #[inline]
    fn hash(&mut self) -> PedersenDomain {
        self.0.into()
    }

    #[inline]
    fn reset(&mut self) {
        self.0 = Fr::from_repr(FrRepr::from(0)).expect("failed 0");
    }

    fn leaf(&mut self, leaf: PedersenDomain) -> PedersenDomain {
        leaf
    }

    fn node(
        &mut self,
        left: PedersenDomain,
        right: PedersenDomain,
        _height: usize,
    ) -> PedersenDomain {
        let node_bits = NodeBits::new(&(left.0).0[..], &(right.0).0[..]);
        let digest = pedersen_hash(node_bits);

        digest.into_xy().0.into()
    }

    fn multi_node(&mut self, parts: &[PedersenDomain], height: usize) -> PedersenDomain {
        match parts.len() {
            2 => self.node(parts[0], parts[1], height),
            _ => {
                use crate::crypto::pedersen::*;

                pedersen_md_no_padding_bits(Bits::new_many(parts.iter())).into()
            }
        }
    }
}

/// Helper to iterate over a pair of `Fr`.
struct NodeBits<'a> {
    // 256 bits
    lhs: &'a [u64],
    // 256 bits
    rhs: &'a [u64],
    index: usize,
}

impl<'a> NodeBits<'a> {
    pub fn new(lhs: &'a [u64], rhs: &'a [u64]) -> Self {
        NodeBits { lhs, rhs, index: 0 }
    }
}

impl<'a> Iterator for NodeBits<'a> {
    type Item = bool;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.index < 255 {
            // return lhs
            let a = self.index / 64;
            let b = self.index % 64;
            let res = (self.lhs[a] & (1 << b)) != 0;
            self.index += 1;
            return Some(res);
        }

        if self.index < 2 * 255 {
            // return rhs
            let a = (self.index - 255) / 64;
            let b = (self.index - 255) % 64;
            let res = (self.rhs[a] & (1 << b)) != 0;
            self.index += 1;
            return Some(res);
        }

        None
    }
}

impl From<Fr> for PedersenDomain {
    #[inline]
    fn from(val: Fr) -> Self {
        PedersenDomain(val.into_repr())
    }
}

impl From<FrRepr> for PedersenDomain {
    #[inline]
    fn from(val: FrRepr) -> Self {
        PedersenDomain(val)
    }
}

impl From<PedersenDomain> for Fr {
    #[inline]
    fn from(val: PedersenDomain) -> Self {
        Fr::from_repr(val.0).expect("from_repr failure")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    // use merkletree::hash::Hashable;

    // use crate::merkle::BinaryMerkleTree;

    // These two tests need to be rewritten not to use from_data, or from_data needs to be fixed to not hash its contents
    // before it is restored to MerkleTreeTrait.
    // #[test]
    // fn test_path() {
    //     let values = ["hello", "world", "you", "two"];
    //     let t = BinaryMerkleTree::<PedersenHasher>::from_data(values.iter()).unwrap();

    //     let p = t.gen_proof(0).unwrap(); // create a proof for the first value = "hello"
    //     assert_eq!(*p.path(), vec![0, 0]);
    //     assert_eq!(
    //         p.validate::<PedersenFunction>()
    //             .expect("failed to validate"),
    //         true
    //     );
    // }

    // #[test]
    // fn test_pedersen_hasher() {
    //     let values = ["hello", "world", "you", "two"];

    //     let t = BinaryMerkleTree::<PedersenHasher>::from_data(values.iter()).unwrap();

    //     assert_eq!(t.leafs(), 4);

    //     let mut a = PedersenFunction::default();
    //     let leaves: Vec<PedersenDomain> = values
    //         .iter()
    //         .map(|v| {
    //             v.hash(&mut a);
    //             let h = a.hash();
    //             a.reset();
    //             h
    //         })
    //         .collect();

    //     assert_eq!(t.read_at(0).unwrap(), leaves[0]);
    //     assert_eq!(t.read_at(1).unwrap(), leaves[1]);
    //     assert_eq!(t.read_at(2).unwrap(), leaves[2]);
    //     assert_eq!(t.read_at(3).unwrap(), leaves[3]);

    //     let i1 = a.node(leaves[0], leaves[1], 0);
    //     a.reset();
    //     let i2 = a.node(leaves[2], leaves[3], 0);
    //     a.reset();

    //     assert_eq!(t.read_at(4).unwrap(), i1);
    //     assert_eq!(t.read_at(5).unwrap(), i2);

    //     let root = a.node(i1, i2, 1);
    //     a.reset();

    //     assert_eq!(
    //         t.read_at(0).unwrap().0,
    //         FrRepr([
    //             8141980337328041169,
    //             4041086031096096197,
    //             4135265344031344584,
    //             7650472305044950055
    //         ])
    //     );

    //     let expected = FrRepr([
    //         11371136130239400769,
    //         4290566175630177573,
    //         11576422143286805197,
    //         2687080719931344767,
    //     ]);
    //     let actual = t.read_at(6).unwrap().0;

    //     assert_eq!(actual, expected);
    //     assert_eq!(t.read_at(6).unwrap(), root);
    // }

    #[test]
    fn test_as_ref() {
        let cases: Vec<[u64; 4]> = vec![
            [0, 0, 0, 0],
            [
                14963070332212552755,
                2414807501862983188,
                16116531553419129213,
                6357427774790868134,
            ],
        ];

        for case in cases.into_iter() {
            let repr = FrRepr(case);
            let val = PedersenDomain(repr);

            for _ in 0..100 {
                assert_eq!(val.into_bytes(), val.into_bytes());
            }

            let raw: &[u8] = val.as_ref();

            for i in 0..4 {
                assert_eq!(case[i], unsafe {
                    let mut val = [0u8; 8];
                    val.clone_from_slice(&raw[i * 8..(i + 1) * 8]);
                    mem::transmute::<[u8; 8], u64>(val)
                });
            }
        }
    }

    #[test]
    fn test_serialize() {
        let repr = FrRepr([1, 2, 3, 4]);
        let val = PedersenDomain(repr);

        let ser = serde_json::to_string(&val)
            .expect("Failed to serialize `PedersenDomain` element to JSON string");
        let val_back = serde_json::from_str(&ser)
            .expect("Failed to deserialize JSON string to `PedersenDomain`");

        assert_eq!(val, val_back);
    }
}
