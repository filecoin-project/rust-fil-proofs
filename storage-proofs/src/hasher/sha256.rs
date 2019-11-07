use sha2::{Digest, Sha256};

use std::hash::Hasher as StdHasher;

use bellperson::{ConstraintSystem, SynthesisError};
use ff::{PrimeField, PrimeFieldRepr};
use fil_sapling_crypto::circuit::{boolean, multipack, num, sha256::sha256 as sha256_circuit};
use fil_sapling_crypto::jubjub::JubjubEngine;
use merkletree::hash::{Algorithm, Hashable};
use merkletree::merkle::Element;
use paired::bls12_381::{Bls12, Fr, FrRepr};
use rand::{Rand, Rng};

use super::{Domain, HashFunction, Hasher};
use crate::crypto::sloth;
use crate::error::*;

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
pub struct Sha256Hasher {}

impl Hasher for Sha256Hasher {
    type Domain = Sha256Domain;
    type Function = Sha256Function;

    fn name() -> String {
        "Sha256Hasher".into()
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

    fn sloth_encode(key: &Self::Domain, ciphertext: &Self::Domain) -> Self::Domain {
        // TODO: validate this is how sloth should work in this case
        let k = (*key).into();
        let c = (*ciphertext).into();

        sloth::encode::<Bls12>(&k, &c).into()
    }

    fn sloth_decode(key: &Self::Domain, ciphertext: &Self::Domain) -> Self::Domain {
        // TODO: validate this is how sloth should work in this case
        sloth::decode::<Bls12>(&(*key).into(), &(*ciphertext).into()).into()
    }
}

#[derive(Default, Clone, Debug)]
pub struct Sha256Function(Sha256);

impl StdHasher for Sha256Function {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0.input(msg)
    }

    #[inline]
    fn finish(&self) -> u64 {
        unreachable!("unused by Function -- should never be called")
    }
}

#[derive(
    Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Default, Serialize, Deserialize, Hash,
)]
pub struct Sha256Domain(pub [u8; 32]);

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

impl Rand for Sha256Domain {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        // generating an Fr and converting it, to ensure we stay in the field
        rng.gen::<Fr>().into()
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
        val.into_repr().write_le(&mut res.0[0..32]).unwrap();

        res
    }
}

impl From<FrRepr> for Sha256Domain {
    fn from(val: FrRepr) -> Self {
        let mut res = Self::default();
        val.write_le(&mut res.0[0..32]).unwrap();

        res
    }
}

impl From<Sha256Domain> for Fr {
    fn from(val: Sha256Domain) -> Self {
        let mut res = FrRepr::default();
        res.read_le(&val.0[0..32]).unwrap();

        Fr::from_repr(res).unwrap()
    }
}

impl Domain for Sha256Domain {
    fn serialize(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn into_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn try_from_bytes(raw: &[u8]) -> Result<Self> {
        if raw.len() != Sha256Domain::byte_len() {
            return Err(Error::InvalidInputSize);
        }
        let mut res = Sha256Domain::default();
        res.0.copy_from_slice(&raw[0..Sha256Domain::byte_len()]);
        Ok(res)
    }

    fn write_bytes(&self, dest: &mut [u8]) -> Result<()> {
        if dest.len() < Sha256Domain::byte_len() {
            return Err(Error::InvalidInputSize);
        }
        dest[0..Sha256Domain::byte_len()].copy_from_slice(&self.0[..]);
        Ok(())
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

    fn hash_leaf_circuit<E: JubjubEngine, CS: ConstraintSystem<E>>(
        cs: CS,
        left: &[boolean::Boolean],
        right: &[boolean::Boolean],
        _height: usize,
        params: &E::Params,
    ) -> std::result::Result<num::AllocatedNum<E>, SynthesisError> {
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

        Self::hash_circuit(cs, &preimage[..], params)
    }

    fn hash_circuit<E: JubjubEngine, CS: ConstraintSystem<E>>(
        mut cs: CS,
        bits: &[boolean::Boolean],
        _params: &E::Params,
    ) -> std::result::Result<num::AllocatedNum<E>, SynthesisError> {
        let alloc_bits = sha256_circuit(cs.namespace(|| "hash"), &bits[..])?;
        let fr = if alloc_bits[0].get_value().is_some() {
            let be_bits = alloc_bits
                .iter()
                .map(|v| v.get_value().unwrap())
                .collect::<Vec<bool>>();

            let le_bits = be_bits
                .chunks(8)
                .flat_map(|chunk| chunk.iter().rev())
                .copied()
                .take(E::Fr::CAPACITY as usize)
                .collect::<Vec<bool>>();

            Ok(multipack::compute_multipacking::<E>(&le_bits)[0])
        } else {
            Err(SynthesisError::AssignmentMissing)
        };

        num::AllocatedNum::<E>::alloc(cs.namespace(|| "result_num"), || fr)
    }
}

impl Algorithm<Sha256Domain> for Sha256Function {
    #[inline]
    fn hash(&mut self) -> Sha256Domain {
        let mut h = [0u8; 32];
        h.copy_from_slice(self.0.clone().result().as_ref());
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

    use std::fmt;
    use std::iter::FromIterator;

    use crate::circuit::test::TestConstraintSystem;
    use crate::crypto;
    use crate::fr32::fr_into_bytes;
    use crate::merkle::MerkleTree;
    use crate::util::bytes_into_boolean_vec;
    use bellperson::ConstraintSystem;
    use fil_sapling_crypto::circuit::boolean::Boolean;
    use merkletree::hash::{Algorithm, Hashable};
    use paired::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};

    struct HexSlice<'a>(&'a [u8]);

    impl<'a> HexSlice<'a> {
        fn new<T>(data: &'a T) -> HexSlice<'a>
        where
            T: ?Sized + AsRef<[u8]> + 'a,
        {
            HexSlice(data.as_ref())
        }
    }

    /// reverse order
    impl<'a> fmt::Display for HexSlice<'a> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let len = self.0.len();
            for i in 0..len {
                let byte = self.0[len - 1 - i];
                write!(f, "{:x}{:x}", byte >> 4, byte & 0xf)?;
            }
            Ok(())
        }
    }

    #[test]
    fn test_sha256_hash() {
        let mut a = <Sha256Hasher as Hasher>::Function::default();
        "hello".hash(&mut a);
        let h1 = a.hash();
        assert_eq!(
            format!("{}", HexSlice::new(AsRef::<[u8]>::as_ref(&h1))),
            "24988b93623304735e42a71f5c1e161b9ee2b9c52a3be8260ea3b05fba4df22c"
        );
    }

    #[test]
    fn test_sha256_node() {
        let mut h1 = [0u8; 32];
        let mut h2 = [0u8; 32];
        let mut h3 = [0u8; 32];
        h1[0] = 0x00;
        h2[0] = 0x11;
        h3[0] = 0x22;

        let mut a = <Sha256Hasher as Hasher>::Function::default();
        let h11 = h1;
        let h12 = h2;
        let h13 = h3;
        let h21 = a.node(h11.into(), h12.into(), 0);
        a.reset();
        let h22 = a.node(h13.into(), h13.into(), 0);
        a.reset();
        let _h31 = a.node(h21.into(), h22.into(), 1);
        a.reset();

        let l1 = a.leaf(h1.into());
        a.reset();

        let l2 = a.leaf(h2.into());
        a.reset();

        // let mut s = vec![0x00];
        // s.extend(h1.to_vec());
        // println!(
        //     "1: {}",
        //     HexSlice::new(sha256_digest(s.as_slice()).as_slice())
        // );

        // assert_eq!(
        //     format!("{}", HexSlice::new(l1.as_ref())),
        //     "e96c39a7e54a9ac9d54330a0f2686f7dbc2d26df8385252fca5682ac319e9c7f"
        // );

        // assert_eq!(
        //     format!("{}", HexSlice::new(h21.as_ref())),
        //     "f820fce7caf5f38f47d4893692c90ea92af47f10cdd3facd1b9e4642e5dfa84f"
        // );
        // assert_eq!(
        //     format!("{}", HexSlice::new(h22.as_ref())),
        //     "888ee00d8142c7c7ca5635c1f175e11f3aa811c00ad3a200cd36584ce2a75384"
        // );
        // assert_eq!(
        //     format!("{}", HexSlice::new(h31.as_ref())),
        //     "e6a6b12f6147ce9ce87c9f2a7f41ddd9587f6ea59ccbfb33fba08e3740d96200"
        // );

        let v: Vec<Sha256Domain> = vec![h1.into(), h2.into(), h3.into()];
        let v2: Vec<Sha256Domain> = vec![h1.into(), h2.into()];
        let t = MerkleTree::<<Sha256Hasher as Hasher>::Domain, <Sha256Hasher as Hasher>::Function>::from_iter(v);
        let t2 = MerkleTree::<
            <Sha256Hasher as Hasher>::Domain,
            <Sha256Hasher as Hasher>::Function,
        >::from_iter(v2);
        // Using `VecMerkleTree` since the `MmapStore` of `MerkleTree` doesn't support `Deref` (`as_slice`).

        assert_eq!(
            AsRef::<[u8]>::as_ref(&t2.read_at(0)),
            AsRef::<[u8]>::as_ref(&l1)
        );
        assert_eq!(
            AsRef::<[u8]>::as_ref(&t2.read_at(1)),
            AsRef::<[u8]>::as_ref(&l2)
        );
        assert_eq!(
            AsRef::<[u8]>::as_ref(&t2.read_at(2)),
            AsRef::<[u8]>::as_ref(&h21)
        );

        // TODO: Verify this is the right hash — bearing in mind that the two most significant bits must be cleared after each hash.
        assert_eq!(
            format!("{}", HexSlice::new(AsRef::<[u8]>::as_ref(&t.root()))),
            "1c1afe57ff6efa4204cf4e17e20bf4d7f6ebf3a4c27391f93993291560107f88"
        );
    }

    #[test]
    fn hash_leaf_circuit() {
        let mut cs = TestConstraintSystem::<Bls12>::new();
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let left_fr = rng.gen();
        let right_fr = rng.gen();
        let left: Vec<u8> = fr_into_bytes::<Bls12>(&left_fr);
        let right: Vec<u8> = fr_into_bytes::<Bls12>(&right_fr);
        let height = 1;

        let left_bits: Vec<Boolean> = {
            let mut cs = cs.namespace(|| "left");
            bytes_into_boolean_vec(&mut cs, Some(left.as_slice()), 256).unwrap()
        };

        let right_bits: Vec<Boolean> = {
            let mut cs = cs.namespace(|| "right");
            bytes_into_boolean_vec(&mut cs, Some(right.as_slice()), 256).unwrap()
        };

        let out = Sha256Function::hash_leaf_circuit(
            cs.namespace(|| "hash_leaf_circuit"),
            &left_bits,
            &right_bits,
            height,
            &crypto::pedersen::JJ_PARAMS,
        )
        .expect("key derivation function failed");

        assert!(cs.is_satisfied(), "constraints not satisfied");
        assert_eq!(cs.num_constraints(), 45386);

        let expected: Fr = Sha256Function::default()
            .node(left_fr.into(), right_fr.into(), height)
            .into();

        assert_eq!(
            expected,
            out.get_value().unwrap(),
            "circuit and non circuit do not match"
        );
    }
}
