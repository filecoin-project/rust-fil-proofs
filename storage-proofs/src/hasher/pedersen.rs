use std::hash::Hasher as StdHasher;

use bellman::{ConstraintSystem, SynthesisError};
use bitvec::{self, BitVec};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use merkle_light::hash::{Algorithm as LightAlgorithm, Hashable};
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use pairing::{PrimeField, PrimeFieldRepr};
use rand::{Rand, Rng};
use sapling_crypto::circuit::{boolean, num, pedersen_hash as pedersen_hash_circuit};
use sapling_crypto::jubjub::JubjubEngine;
use sapling_crypto::pedersen_hash::{pedersen_hash, Personalization};
use serde::de::{Deserialize, Deserializer};
use serde::ser::Serializer;

use crate::circuit::pedersen::pedersen_md_no_padding;
use crate::crypto::{kdf, pedersen, sloth};
use crate::error::{Error, Result};
use crate::hasher::{Domain, HashFunction, Hasher};

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
pub struct PedersenHasher {}

impl Hasher for PedersenHasher {
    type Domain = PedersenDomain;
    type Function = PedersenFunction;

    fn name() -> String {
        "PedersenHasher".into()
    }

    fn kdf(data: &[u8], m: usize) -> Self::Domain {
        kdf::kdf(data, m).into()
    }

    #[inline]
    fn sloth_encode(key: &Self::Domain, ciphertext: &Self::Domain, rounds: usize) -> Self::Domain {
        let key = Fr::from_repr(key.0).unwrap();
        let ciphertext = Fr::from_repr(ciphertext.0).unwrap();
        sloth::encode::<Bls12>(&key, &ciphertext, rounds).into()
    }

    #[inline]
    fn sloth_decode(key: &Self::Domain, ciphertext: &Self::Domain, rounds: usize) -> Self::Domain {
        let key = Fr::from_repr(key.0).unwrap();
        let ciphertext = Fr::from_repr(ciphertext.0).unwrap();

        sloth::decode::<Bls12>(&key, &ciphertext, rounds).into()
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
        self.into_repr().write_le(&mut bytes).unwrap();
        state.write(&bytes);
    }
}

impl Hashable<PedersenFunction> for PedersenDomain {
    fn hash(&self, state: &mut PedersenFunction) {
        let mut bytes = Vec::with_capacity(32);
        self.0.write_le(&mut bytes).unwrap();
        state.write(&bytes);
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PedersenDomain(#[serde(with = "FrReprDef")] pub FrRepr);

pub struct FrReprDef(pub [u64; 4]);

impl FrReprDef {
    fn serialize<S>(__self: &FrRepr, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut writer = Vec::with_capacity(32);

        for digit in __self.0.as_ref().iter() {
            writer.write_u64::<LittleEndian>(*digit).unwrap();
        }

        if serializer.is_human_readable() {
            serializer.collect_str(&base64::display::Base64Display::with_config(
                &writer,
                base64::STANDARD,
            ))
        } else {
            serializer.serialize_bytes(&writer)
        }
    }

    fn deserialize<'de, D>(deserializer: D) -> ::std::result::Result<FrRepr, D::Error>
    where
        D: Deserializer<'de>,
    {
        let arr: Vec<u8> = if deserializer.is_human_readable() {
            let raw = String::deserialize(deserializer)?;
            base64::decode(&raw).unwrap()
        } else {
            Vec::deserialize(deserializer)?
        };

        let mut digits = [0u64; 4];
        let mut source = ::std::io::Cursor::new(arr);
        for digit in digits.iter_mut() {
            *digit = source.read_u64::<LittleEndian>().unwrap();
        }

        Ok(FrRepr(digits))
    }
}

impl Default for PedersenDomain {
    fn default() -> PedersenDomain {
        PedersenDomain(FrRepr::default())
    }
}

impl Rand for PedersenDomain {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        let fr: Fr = rng.gen();
        PedersenDomain(fr.into_repr())
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
    // QUESTION: When, if ever, should serialize and into_bytes return different results?
    // The definitions here at least are equivalent.
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32);
        self.0.write_le(&mut bytes).unwrap();
        bytes
    }

    fn into_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        self.0.write_le(&mut out).unwrap();

        out
    }

    fn try_from_bytes(raw: &[u8]) -> Result<Self> {
        if raw.len() != 32 {
            return Err(Error::BadFrBytes);
        }
        let mut res: FrRepr = Default::default();
        res.read_le(raw).map_err(|_| Error::BadFrBytes)?;

        Ok(PedersenDomain(res))
    }

    fn write_bytes(&self, dest: &mut [u8]) -> Result<()> {
        self.0.write_le(dest)?;
        Ok(())
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

impl HashFunction<PedersenDomain> for PedersenFunction {
    fn hash(data: &[u8]) -> PedersenDomain {
        pedersen::pedersen_md_no_padding(data).into()
    }

    fn hash_leaf_circuit<E: JubjubEngine, CS: ConstraintSystem<E>>(
        cs: CS,
        left: &[boolean::Boolean],
        right: &[boolean::Boolean],
        height: usize,
        params: &E::Params,
    ) -> ::std::result::Result<num::AllocatedNum<E>, SynthesisError> {
        let mut preimage: Vec<boolean::Boolean> = vec![];
        preimage.extend_from_slice(left);
        preimage.extend_from_slice(right);

        Ok(pedersen_hash_circuit::pedersen_hash(
            cs,
            Personalization::MerkleTree(height),
            &preimage,
            params,
        )?
        .get_x()
        .clone())
    }

    fn hash_circuit<E: JubjubEngine, CS: ConstraintSystem<E>>(
        cs: CS,
        bits: &[boolean::Boolean],
        params: &E::Params,
    ) -> std::result::Result<num::AllocatedNum<E>, SynthesisError> {
        pedersen_md_no_padding(cs, params, bits)
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
        height: usize,
    ) -> PedersenDomain {
        let lhs = BitVec::<bitvec::LittleEndian, u64>::from(&(left.0).0[..]);
        let rhs = BitVec::<bitvec::LittleEndian, u64>::from(&(right.0).0[..]);

        let bits = lhs
            .iter()
            .take(Fr::NUM_BITS as usize)
            .chain(rhs.iter().take(Fr::NUM_BITS as usize));

        pedersen_hash::<Bls12, _>(
            Personalization::MerkleTree(height),
            bits,
            &pedersen::JJ_PARAMS,
        )
        .into_xy()
        .0
        .into()
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
        Fr::from_repr(val.0).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    use merkle_light::hash::Hashable;

    use crate::merkle::MerkleTree;

    #[test]
    fn test_path() {
        let values = ["hello", "world", "you", "two"];
        let t = MerkleTree::<PedersenDomain, PedersenFunction>::from_data(values.iter());

        let p = t.gen_proof(0); // create a proof for the first value = "hello"
        assert_eq!(*p.path(), vec![true, true]);
        assert_eq!(p.validate::<PedersenFunction>(), true);
    }

    #[test]
    fn test_pedersen_hasher() {
        let values = ["hello", "world", "you", "two"];

        let t = MerkleTree::<PedersenDomain, PedersenFunction>::from_data(values.iter());

        assert_eq!(t.leafs(), 4);

        let mut a = PedersenFunction::default();
        let leaves: Vec<PedersenDomain> = values
            .iter()
            .map(|v| {
                v.hash(&mut a);
                let h = a.hash();
                a.reset();
                h
            })
            .collect();

        assert_eq!(t[0], leaves[0]);
        assert_eq!(t[1], leaves[1]);
        assert_eq!(t[2], leaves[2]);
        assert_eq!(t[3], leaves[3]);

        let i1 = a.node(leaves[0], leaves[1], 0);
        a.reset();
        let i2 = a.node(leaves[2], leaves[3], 0);
        a.reset();

        assert_eq!(t[4], i1);
        assert_eq!(t[5], i2);

        let root = a.node(i1, i2, 1);
        a.reset();

        assert_eq!(
            t[0].0,
            FrRepr([
                5516429847681692214,
                1363403528947283679,
                5429691745410183571,
                7730413689037971367
            ])
        );

        let expected = FrRepr([
            14963070332212552755,
            2414807501862983188,
            16116531553419129213,
            6357427774790868134,
        ]);
        let actual = t[6].0;

        assert_eq!(actual, expected);

        assert_eq!(t[6], root);
    }

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
                assert_eq!(val.as_ref().to_vec(), val.as_ref().to_vec());
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

        let ser = serde_json::to_string(&val).unwrap();
        let val_back = serde_json::from_str(&ser).unwrap();

        assert_eq!(val, val_back);
    }
}
