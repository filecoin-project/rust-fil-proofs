use std::cmp::Ordering;
use std::hash::{Hash as StdHash, Hasher as StdHasher};
use std::panic::panic_any;

use anyhow::ensure;
use bellperson::{
    gadgets::{boolean::Boolean, num::AllocatedNum},
    ConstraintSystem, SynthesisError,
};
use blstrs::Scalar as Fr;
use ff::{Field, PrimeField};
use generic_array::typenum::{marker_traits::Unsigned, U2};
use merkletree::{
    hash::{Algorithm as LightAlgorithm, Hashable},
    merkle::Element,
};
use neptune::{circuit::poseidon_hash, poseidon::Poseidon};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::types::{
    Domain, HashFunction, Hasher, PoseidonArity, PoseidonMDArity, POSEIDON_CONSTANTS_16,
    POSEIDON_CONSTANTS_2, POSEIDON_CONSTANTS_4, POSEIDON_CONSTANTS_8, POSEIDON_MD_CONSTANTS,
};

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoseidonHasher {}

impl Hasher for PoseidonHasher {
    type Domain = PoseidonDomain;
    type Function = PoseidonFunction;

    fn name() -> String {
        "poseidon_hasher".into()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PoseidonFunction(Fr);

impl Default for PoseidonFunction {
    fn default() -> PoseidonFunction {
        PoseidonFunction(Fr::zero())
    }
}

impl Hashable<PoseidonFunction> for Fr {
    fn hash(&self, state: &mut PoseidonFunction) {
        state.write(&self.to_repr());
    }
}

impl Hashable<PoseidonFunction> for PoseidonDomain {
    fn hash(&self, state: &mut PoseidonFunction) {
        state.write(&self.0);
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct PoseidonDomain(pub <Fr as PrimeField>::Repr);

impl AsRef<PoseidonDomain> for PoseidonDomain {
    fn as_ref(&self) -> &PoseidonDomain {
        self
    }
}

impl StdHash for PoseidonDomain {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        StdHash::hash(&self.0, state);
    }
}

impl PartialEq for PoseidonDomain {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for PoseidonDomain {}

impl Default for PoseidonDomain {
    fn default() -> PoseidonDomain {
        PoseidonDomain(<Fr as PrimeField>::Repr::default())
    }
}

impl Ord for PoseidonDomain {
    #[inline(always)]
    fn cmp(&self, other: &PoseidonDomain) -> Ordering {
        (self.0).cmp(&other.0)
    }
}

impl PartialOrd for PoseidonDomain {
    #[inline(always)]
    fn partial_cmp(&self, other: &PoseidonDomain) -> Option<Ordering> {
        Some((self.0).cmp(&other.0))
    }
}

impl AsRef<[u8]> for PoseidonDomain {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Domain for PoseidonDomain {
    fn into_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn try_from_bytes(raw: &[u8]) -> anyhow::Result<Self> {
        ensure!(
            raw.len() == PoseidonDomain::byte_len(),
            "invalid amount of bytes"
        );
        let mut repr = <Fr as PrimeField>::Repr::default();
        repr.copy_from_slice(&raw);
        Ok(PoseidonDomain(repr))
    }

    fn write_bytes(&self, dest: &mut [u8]) -> anyhow::Result<()> {
        ensure!(
            dest.len() == PoseidonDomain::byte_len(),
            "invalid amount of bytes"
        );
        dest.copy_from_slice(&self.0);
        Ok(())
    }

    fn random<R: RngCore>(rng: &mut R) -> Self {
        // generating an Fr and converting it, to ensure we stay in the field
        Fr::random(rng).into()
    }
}

impl Element for PoseidonDomain {
    fn byte_len() -> usize {
        32
    }

    fn from_slice(bytes: &[u8]) -> Self {
        match PoseidonDomain::try_from_bytes(bytes) {
            Ok(res) => res,
            Err(err) => panic_any(err),
        }
    }

    fn copy_to_slice(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(&self.0);
    }
}

impl StdHasher for PoseidonFunction {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0 = Fr::from_repr_vartime(shared_hash(msg).0).expect("from_repr failure");
    }

    #[inline]
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

fn shared_hash(data: &[u8]) -> PoseidonDomain {
    // FIXME: We shouldn't unwrap here, but doing otherwise will require an interface change.
    // We could truncate so `bytes_into_frs` cannot fail, then ensure `data` is always `fr_safe`.
    let preimage = data
        .chunks(32)
        .map(|ref chunk| {
            Fr::from_repr_vartime(PoseidonDomain::from_slice(chunk).0).expect("from_repr failure")
        })
        .collect::<Vec<_>>();

    shared_hash_frs(&preimage).into()
}

fn shared_hash_frs(preimage: &[Fr]) -> Fr {
    match preimage.len() {
        2 => {
            let mut p = Poseidon::new_with_preimage(&preimage, &POSEIDON_CONSTANTS_2);
            p.hash()
        }
        4 => {
            let mut p = Poseidon::new_with_preimage(&preimage, &POSEIDON_CONSTANTS_4);
            p.hash()
        }
        8 => {
            let mut p = Poseidon::new_with_preimage(&preimage, &POSEIDON_CONSTANTS_8);
            p.hash()
        }
        16 => {
            let mut p = Poseidon::new_with_preimage(&preimage, &POSEIDON_CONSTANTS_16);
            p.hash()
        }

        _ => panic_any(format!(
            "Unsupported arity for Poseidon hasher: {}",
            preimage.len()
        )),
    }
}

impl HashFunction<PoseidonDomain> for PoseidonFunction {
    fn hash(data: &[u8]) -> PoseidonDomain {
        shared_hash(data)
    }

    fn hash2(a: &PoseidonDomain, b: &PoseidonDomain) -> PoseidonDomain {
        let mut p =
            Poseidon::new_with_preimage(&[(*a).into(), (*b).into()][..], &*POSEIDON_CONSTANTS_2);
        let fr: Fr = p.hash();
        fr.into()
    }

    fn hash_md(input: &[PoseidonDomain]) -> PoseidonDomain {
        assert!(input.len() > 1, "hash_md needs more than one element.");
        let arity = PoseidonMDArity::to_usize();

        let mut p = Poseidon::new(&*POSEIDON_MD_CONSTANTS);

        let fr_input = input
            .iter()
            .map(|x| Fr::from_repr_vartime(x.0).expect("from_repr failure"))
            .collect::<Vec<_>>();

        fr_input[1..]
            .chunks(arity - 1)
            .fold(fr_input[0], |acc, elts| {
                p.reset();
                p.input(acc).expect("input failure"); // These unwraps will panic iff arity is incorrect, but it was checked above.
                elts.iter().for_each(|elt| {
                    let _ = p.input(*elt).expect("input failure");
                });
                p.hash()
            })
            .into()
    }

    fn hash_leaf_circuit<CS: ConstraintSystem<Fr>>(
        cs: CS,
        left: &AllocatedNum<Fr>,
        right: &AllocatedNum<Fr>,
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        let preimage = vec![left.clone(), right.clone()];

        poseidon_hash::<CS, Fr, U2>(cs, preimage, U2::PARAMETERS())
    }

    fn hash_multi_leaf_circuit<Arity: 'static + PoseidonArity, CS: ConstraintSystem<Fr>>(
        cs: CS,
        leaves: &[AllocatedNum<Fr>],
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        let params = Arity::PARAMETERS();
        poseidon_hash::<CS, Fr, Arity>(cs, leaves.to_vec(), params)
    }

    fn hash_md_circuit<CS: ConstraintSystem<Fr>>(
        cs: &mut CS,
        elements: &[AllocatedNum<Fr>],
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        let params = PoseidonMDArity::PARAMETERS();
        let arity = PoseidonMDArity::to_usize();

        let mut hash = elements[0].clone();
        let mut preimage = vec![hash.clone(); arity]; // Allocate. This will be overwritten.
        for (hash_num, elts) in elements[1..].chunks(arity - 1).enumerate() {
            preimage[0] = hash;
            for (i, elt) in elts.iter().enumerate() {
                preimage[i + 1] = elt.clone();
            }
            // any terminal padding
            #[allow(clippy::needless_range_loop)]
            for i in (elts.len() + 1)..arity {
                preimage[i] =
                    AllocatedNum::alloc(cs.namespace(|| format!("padding {}", i)), || {
                        Ok(Fr::zero())
                    })
                    .expect("alloc failure");
            }
            let cs = cs.namespace(|| format!("hash md {}", hash_num));
            hash = poseidon_hash::<_, Fr, PoseidonMDArity>(cs, preimage.clone(), params)?.clone();
        }

        Ok(hash)
    }

    fn hash_circuit<CS: ConstraintSystem<Fr>>(
        _cs: CS,
        _bits: &[Boolean],
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!();
    }

    fn hash2_circuit<CS>(
        cs: CS,
        a: &AllocatedNum<Fr>,
        b: &AllocatedNum<Fr>,
    ) -> Result<AllocatedNum<Fr>, SynthesisError>
    where
        CS: ConstraintSystem<Fr>,
    {
        let preimage = vec![a.clone(), b.clone()];
        poseidon_hash::<CS, Fr, U2>(cs, preimage, U2::PARAMETERS())
    }
}

impl LightAlgorithm<PoseidonDomain> for PoseidonFunction {
    #[inline]
    fn hash(&mut self) -> PoseidonDomain {
        self.0.into()
    }

    #[inline]
    fn reset(&mut self) {
        self.0 = Fr::zero();
    }

    fn leaf(&mut self, leaf: PoseidonDomain) -> PoseidonDomain {
        leaf
    }

    fn node(
        &mut self,
        left: PoseidonDomain,
        right: PoseidonDomain,
        _height: usize,
    ) -> PoseidonDomain {
        shared_hash_frs(&[
            Fr::from_repr_vartime(left.0).expect("from_repr failure"),
            Fr::from_repr_vartime(right.0).expect("from_repr failure"),
        ])
        .into()
    }

    fn multi_node(&mut self, parts: &[PoseidonDomain], _height: usize) -> PoseidonDomain {
        match parts.len() {
            1 | 2 | 4 | 8 | 16 => shared_hash_frs(
                &parts
                    .iter()
                    .enumerate()
                    .map(|(i, x)| {
                        if let Some(fr) = Fr::from_repr_vartime(x.0) {
                            fr
                        } else {
                            panic_any(format!("from_repr failure at {}", i));
                        }
                    })
                    .collect::<Vec<_>>(),
            )
            .into(),
            arity => panic_any(format!("unsupported arity {}", arity)),
        }
    }
}

impl From<Fr> for PoseidonDomain {
    #[inline]
    fn from(val: Fr) -> Self {
        PoseidonDomain(val.to_repr())
    }
}

impl From<[u8; 32]> for PoseidonDomain {
    #[inline]
    fn from(val: [u8; 32]) -> Self {
        PoseidonDomain(val)
    }
}

impl From<PoseidonDomain> for Fr {
    #[inline]
    fn from(val: PoseidonDomain) -> Self {
        Fr::from_repr_vartime(val.0).expect("from_repr failure")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use merkletree::{merkle::MerkleTree, store::VecStore};

    fn u64s_to_u8s(u64s: [u64; 4]) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&u64s[0].to_le_bytes());
        bytes[8..16].copy_from_slice(&u64s[1].to_le_bytes());
        bytes[16..24].copy_from_slice(&u64s[2].to_le_bytes());
        bytes[24..].copy_from_slice(&u64s[3].to_le_bytes());
        bytes
    }

    #[test]
    fn test_path() {
        let values = [
            PoseidonDomain(Fr::one().to_repr()),
            PoseidonDomain(Fr::one().to_repr()),
            PoseidonDomain(Fr::one().to_repr()),
            PoseidonDomain(Fr::one().to_repr()),
        ];

        let t = MerkleTree::<PoseidonDomain, PoseidonFunction, VecStore<_>, U2>::new(
            values.iter().copied(),
        )
        .expect("merkle tree new failure");

        let p = t.gen_proof(0).expect("gen_proof failure"); // create a proof for the first value =k Fr::one()

        assert_eq!(*p.path(), vec![0, 0]);
        assert_eq!(
            p.validate::<PoseidonFunction>()
                .expect("failed to validate"),
            true
        );
    }

    // #[test]
    // fn test_poseidon_quad() {
    //     let leaves = [Fr::one(), Fr::zero(), Fr::zero(), Fr::one()];

    //     assert_eq!(Fr::zero().to_repr(), shared_hash_frs(&leaves[..]).0);
    // }

    #[test]
    fn test_poseidon_hasher() {
        let leaves = [
            PoseidonDomain(Fr::one().to_repr()),
            PoseidonDomain(Fr::zero().to_repr()),
            PoseidonDomain(Fr::zero().to_repr()),
            PoseidonDomain(Fr::one().to_repr()),
        ];

        let t = MerkleTree::<PoseidonDomain, PoseidonFunction, VecStore<_>, U2>::new(
            leaves.iter().copied(),
        )
        .expect("merkle tree new failure");

        assert_eq!(t.leafs(), 4);

        let mut a = PoseidonFunction::default();

        assert_eq!(t.read_at(0).expect("read_at failure"), leaves[0]);
        assert_eq!(t.read_at(1).expect("read_at failure"), leaves[1]);
        assert_eq!(t.read_at(2).expect("read_at failure"), leaves[2]);
        assert_eq!(t.read_at(3).expect("read_at failure"), leaves[3]);

        let i1 = a.node(leaves[0], leaves[1], 0);
        a.reset();
        let i2 = a.node(leaves[2], leaves[3], 0);
        a.reset();

        assert_eq!(t.read_at(4).expect("read_at failure"), i1);
        assert_eq!(t.read_at(5).expect("read_at failure"), i2);

        let root = a.node(i1, i2, 1);
        a.reset();

        assert_eq!(
            t.read_at(4).expect("read_at failure").0,
            u64s_to_u8s([
                0xb339ff6079800b5e,
                0xec5907b3dc3094af,
                0x93c003cc74a24f26,
                0x042f94ffbe786bc3,
            ]),
        );

        let expected = u64s_to_u8s([
            0xefbb8be3e291e671,
            0x77cc72b8cb2b5ad2,
            0x30eb6385ae6b74ae,
            0x1effebb7b26ad9eb,
        ]);
        let actual = t.read_at(6).expect("read_at failure").0;

        assert_eq!(actual, expected);
        assert_eq!(t.read_at(6).expect("read_at failure"), root);
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
            let val = PoseidonDomain(u64s_to_u8s(case));

            for _ in 0..100 {
                assert_eq!(val.into_bytes(), val.into_bytes());
            }

            let raw: &[u8] = val.as_ref();

            for (limb, bytes) in case.iter().zip(raw.chunks(8)) {
                assert_eq!(&limb.to_le_bytes(), bytes);
            }
        }
    }

    #[test]
    fn test_serialize() {
        let val = PoseidonDomain(u64s_to_u8s([1, 2, 3, 4]));

        let ser = serde_json::to_string(&val)
            .expect("Failed to serialize `PoseidonDomain` element to JSON string");
        let val_back = serde_json::from_str(&ser)
            .expect("Failed to deserialize JSON string to `PoseidonnDomain`");

        assert_eq!(val, val_back);
    }

    #[test]
    fn test_hash_md() {
        // let arity = PoseidonMDArity::to_usize();
        let n = 71;
        let data = vec![PoseidonDomain(Fr::one().to_repr()); n];
        let hashed = PoseidonFunction::hash_md(&data);

        assert_eq!(
            hashed,
            PoseidonDomain(u64s_to_u8s([
                0x351c54133b332c90,
                0xc26f6d625f4e8195,
                0x5fd9623643ed9622,
                0x59f42220e09ff6f7,
            ]))
        );
    }
    #[test]
    fn test_hash_md_circuit() {
        // let arity = PoseidonMDArity::to_usize();
        let n = 71;
        let data = vec![PoseidonDomain(Fr::one().to_repr()); n];

        let mut cs = TestConstraintSystem::<Fr>::new();
        let circuit_data = (0..n)
            .map(|n| {
                AllocatedNum::alloc(cs.namespace(|| format!("input {}", n)), || Ok(Fr::one()))
                    .expect("alloc failure")
            })
            .collect::<Vec<_>>();

        let hashed = PoseidonFunction::hash_md(&data);
        let hashed_fr = Fr::from_repr_vartime(hashed.0).expect("from_repr failure");

        let circuit_hashed = PoseidonFunction::hash_md_circuit(&mut cs, circuit_data.as_slice())
            .expect("hash_md_circuit failure");

        assert!(cs.is_satisfied());
        let expected_constraints = 2_770;
        let actual_constraints = cs.num_constraints();

        assert_eq!(expected_constraints, actual_constraints);

        assert_eq!(
            hashed_fr,
            circuit_hashed.get_value().expect("get_value failure")
        );
    }
}
