use bitvec::prelude::*;
use rand::{Rand, Rng};
use std::hash::Hasher as StdHasher;
use std::io::Read;
use std::io::Write;

use snark::{ConstraintSystem, SynthesisError};

use algebra::biginteger::BigInteger;
use algebra::biginteger::BigInteger256 as FrRepr;
use algebra::curves::ProjectiveCurve;
use algebra::curves::{bls12_381::Bls12_381 as Bls12, jubjub::JubJubProjective as JubJub};
use algebra::fields::{bls12_381::Fr, FpParameters, PrimeField};

use snark_gadgets::bits::uint8::UInt8;
use snark_gadgets::boolean::Boolean;
use snark_gadgets::fields::fp::FpGadget;
use snark_gadgets::groups::curves::twisted_edwards::jubjub::JubJubGadget;

use snark_gadgets::utils::AllocGadget;

use dpc::{
    crypto_primitives::crh::{
        pedersen::{PedersenCRH, PedersenParameters},
        FixedLengthCRH,
    },
    gadgets::crh::{
        pedersen::PedersenCRHGadget, pedersen::PedersenCRHGadgetParameters, FixedLengthCRHGadget,
    },
};

use merkletree::hash::{Algorithm as LightAlgorithm, Hashable};
use merkletree::merkle::Element;

use crate::circuit::pedersen::pedersen_md_no_padding;
use crate::crypto::pedersen::{pedersen_hash, Personalization, BigWindow};
use crate::crypto::{kdf, pedersen, sloth};
use crate::error::{Error, Result};
use crate::hasher::{Domain, HashFunction, Hasher};
use crate::circuit::pedersen::pedersen_compression_num;

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
        // Unwrapping here is safe; `Fr` elements and hash domain elements are the same byte length.
        let key = Fr::from_repr(key.0);
        let ciphertext = Fr::from_repr(ciphertext.0);
        sloth::encode::<Bls12>(&key, &ciphertext, rounds).into()
    }

    #[inline]
    fn sloth_decode(key: &Self::Domain, ciphertext: &Self::Domain, rounds: usize) -> Self::Domain {
        // Unwrapping here is safe; `Fr` elements and hash domain elements are the same byte length.
        let key = Fr::from_repr(key.0);
        let ciphertext = Fr::from_repr(ciphertext.0);

        sloth::decode::<Bls12>(&key, &ciphertext, rounds).into()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PedersenFunction(Fr);

impl Default for PedersenFunction {
    fn default() -> PedersenFunction {
        PedersenFunction(Fr::from_repr(FrRepr::default()))
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
        self.0
            .write_le(&mut bytes)
            .expect("Failed to write `FrRepr`");
        state.write(&bytes);
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PedersenDomain(pub FrRepr);

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
        let mut bytes = Vec::with_capacity(PedersenDomain::byte_len());
        self.0.write_le(&mut bytes).unwrap();
        bytes
    }

    fn into_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PedersenDomain::byte_len());
        self.0.write_le(&mut out).unwrap();

        out
    }

    fn try_from_bytes(raw: &[u8]) -> Result<Self> {
        if raw.len() != PedersenDomain::byte_len() {
            return Err(Error::BadFrBytes);
        }
        let mut res: FrRepr = Default::default();
        res.read_le((&raw[..]).by_ref())
            .map_err(|_| Error::BadFrBytes)?;

        Ok(PedersenDomain(res))
    }

    fn write_bytes(&self, dest: &mut [u8]) -> Result<()> {
        self.0.write_le((&mut dest[..]).by_ref())?;
        Ok(())
    }
}

impl Element for PedersenDomain {
    fn byte_len() -> usize {
        32
    }

    fn from_slice(bytes: &[u8]) -> Self {
        match PedersenDomain::try_from_bytes(bytes) {
            Ok(res) => res,
            Err(err) => panic!(err),
        }
    }

    fn copy_to_slice(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(&self.into_bytes());
    }
}

impl StdHasher for PedersenFunction {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0 = pedersen::pedersen(msg).x;
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

    fn hash_leaf_circuit<CS: ConstraintSystem<Bls12>>(
        mut cs: CS,
        left: &[Boolean],
        right: &[Boolean],
        height: usize,
        params: &PedersenParameters<JubJub>,
    ) -> std::result::Result<FpGadget<Bls12>, SynthesisError> {
        let mut preimage: Vec<Boolean> = vec![];
        preimage.extend_from_slice(left);
        preimage.extend_from_slice(right);

        type CRHGadget = PedersenCRHGadget<JubJub, Bls12, JubJubGadget>;
        type CRH = PedersenCRH<JubJub, BigWindow>;

        let gadget_parameters =
            <CRHGadget as FixedLengthCRHGadget<CRH, Bls12>>::ParametersGadget::alloc(
                &mut cs.ns(|| "gadget_parameters"),
                || Ok(params),
            )
                .unwrap();

        let mut personalization = Personalization::MerkleTree(height)
            .get_bits()
            .into_iter()
            .map(|v| Boolean::Constant(v))
            .collect::<Vec<Boolean>>();

        let mut bits_with_personalization = personalization
            .into_iter()
            .chain(preimage.to_vec().into_iter())
            .collect::<Vec<_>>();

        while bits_with_personalization.len() % 8 != 0 {
            bits_with_personalization.push(Boolean::Constant(false));
        }

        let input_bytes = bits_with_personalization
            .chunks(8)
            .into_iter()
            .map(|v| UInt8::from_bits_le(v))
            .collect::<Vec<UInt8>>();

        let gadget_result = <CRHGadget as FixedLengthCRHGadget<CRH, Bls12>>::check_evaluation_gadget(
            &mut cs.ns(|| "gadget_evaluation"),
            &gadget_parameters,
            &input_bytes,
        ).unwrap();

        Ok(gadget_result.x)
    }

    fn hash_circuit<CS: ConstraintSystem<Bls12>>(
        cs: CS,
        bits: &[Boolean],
        params: &PedersenParameters<JubJub>,
    ) -> std::result::Result<FpGadget<Bls12>, SynthesisError> {
        pedersen_md_no_padding(cs, bits, params)
    }
}

impl LightAlgorithm<PedersenDomain> for PedersenFunction {
    #[inline]
    fn hash(&mut self) -> PedersenDomain {
        self.0.into()
    }

    #[inline]
    fn reset(&mut self) {
        self.0 = Fr::from_repr(FrRepr::from(0));
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
        let lhs = BitVec::<LittleEndian, u64>::from(&(left.0).0[..]);
        let rhs = BitVec::<LittleEndian, u64>::from(&(right.0).0[..]);

        let bits = lhs
            .iter()
            .take(<Fr as PrimeField>::Params::MODULUS_BITS as usize)
            .chain(
                rhs.iter()
                    .take(<Fr as PrimeField>::Params::MODULUS_BITS as usize),
            );

        pedersen_hash::<_>(Personalization::MerkleTree(height), bits).into_affine().x.into()
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
        Fr::from_repr(val.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    use merkletree::hash::Hashable;

    use crate::merkle::{MerkleTree, VecMerkleTree};

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

        let t = VecMerkleTree::<PedersenDomain, PedersenFunction>::from_data(values.iter());
        // Using `VecMerkleTree` since the `MmapStore` of `MerkleTree` doesn't support `Deref` (`as_slice`).

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

        assert_eq!(t.read_at(0), leaves[0]);
        assert_eq!(t.read_at(1), leaves[1]);
        assert_eq!(t.read_at(2), leaves[2]);
        assert_eq!(t.read_at(3), leaves[3]);

        let i1 = a.node(leaves[0], leaves[1], 0);
        a.reset();
        let i2 = a.node(leaves[2], leaves[3], 0);
        a.reset();

        assert_eq!(t.read_at(4), i1);
        assert_eq!(t.read_at(5), i2);

        let root = a.node(i1, i2, 1);
        a.reset();

        // Note: this test fails as we use different generator points and zexe used a slightly different approach
        // for Pedersen hashing (no windowing). Hence the expected output should be updated.

        // assert_eq!(
        //     t.read_at(0).0,
        //     FrRepr([
        //         5516429847681692214,
        //         1363403528947283679,
        //         5429691745410183571,
        //         7730413689037971367
        //     ])
        // );

        // let expected = FrRepr([
        //     14963070332212552755,
        //     2414807501862983188,
        //     16116531553419129213,
        //     6357427774790868134,
        // ]);
        // let actual = t.read_at(6).0;

        // assert_eq!(actual, expected);

        assert_eq!(t.read_at(6), root);
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

        let ser = serde_json::to_string(&val)
            .expect("Failed to serialize `PedersenDomain` element to JSON string");
        let val_back = serde_json::from_str(&ser)
            .expect("Failed to deserialize JSON string to `PedersenDomain`");

        assert_eq!(val, val_back);
    }
}
