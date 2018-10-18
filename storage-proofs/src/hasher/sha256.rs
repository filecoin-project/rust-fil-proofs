use std::fmt;
use std::hash::Hasher as StdHasher;

use merkle_light::hash::{Algorithm, Hashable};
use pairing::bls12_381::Fr;
use rand::{Rand, Rng};
use sha2::{Digest, Sha256};

use super::{Domain, HashFunction, Hasher};
use error::Result;

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
pub struct Sha256Hasher {}

impl Hasher for Sha256Hasher {
    type Domain = Sha256Domain;
    type Function = Sha256Function;

    fn kdf(_data: &[u8], _m: usize) -> Self::Domain {
        unimplemented!()
    }

    fn sloth_encode(
        _key: &Self::Domain,
        _ciphertext: &Self::Domain,
        _rounds: usize,
    ) -> Self::Domain {
        unimplemented!()
    }

    fn sloth_decode(
        _key: &Self::Domain,
        _ciphertext: &Self::Domain,
        _rounds: usize,
    ) -> Self::Domain {
        unimplemented!()
    }
}

#[derive(Clone)]
pub struct Sha256Function(Sha256);

impl Default for Sha256Function {
    fn default() -> Sha256Function {
        Sha256Function(Sha256::new())
    }
}

impl fmt::Debug for Sha256Function {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Sha256Function")
    }
}

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

#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Default)]
pub struct Sha256Domain(pub [u8; 32]);

impl Rand for Sha256Domain {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        Sha256Domain(rng.gen())
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
    fn from(_val: Fr) -> Self {
        unimplemented!()
    }
}
impl From<Sha256Domain> for Fr {
    fn from(_val: Sha256Domain) -> Self {
        unimplemented!()
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
        if raw.len() != 32 {
            return Err(format_err!("invalid byte length"));
        }
        let mut res = Sha256Domain::default();
        res.0.copy_from_slice(&raw[0..32]);
        Ok(res)
    }

    fn write_bytes(&self, dest: &mut [u8]) -> Result<()> {
        if dest.len() < 32 {
            return Err(format_err!("destination too short"));
        }
        dest[0..32].copy_from_slice(&self.0[..]);
        Ok(())
    }
}

impl HashFunction<Sha256Domain> for Sha256Function {
    fn hash(data: &[u8]) -> Sha256Domain {
        let mut hasher = Sha256::new();
        hasher.input(data);
        let mut res = Sha256Domain::default();
        res.0.copy_from_slice(&hasher.result()[..]);

        res
    }
}

impl Algorithm<Sha256Domain> for Sha256Function {
    #[inline]
    fn hash(&mut self) -> Sha256Domain {
        let mut h = [0u8; 32];
        h.copy_from_slice(self.0.clone().result().as_ref());
        h.into()
    }

    #[inline]
    fn reset(&mut self) {
        self.0 = Sha256::new();
    }

    fn leaf(&mut self, leaf: Sha256Domain) -> Sha256Domain {
        leaf
    }

    fn node(&mut self, left: Sha256Domain, right: Sha256Domain, _height: usize) -> Sha256Domain {
        // TODO: second preimage attack fix
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
    use merkle_light::merkle::MerkleTree;
    use std::iter::FromIterator;

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
        let mut a = Sha256Function::default();
        "hello".hash(&mut a);
        let h1 = a.hash();
        assert_eq!(
            format!("{}", HexSlice::new(h1.as_ref())),
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

        let mut a = Sha256Function::default();
        let h11 = h1;
        let h12 = h2;
        let h13 = h3;
        let h21 = a.node(h11.into(), h12.into(), 1);
        a.reset();
        let h22 = a.node(h13.into(), h13.into(), 1);
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
        let t = MerkleTree::<Sha256Domain, Sha256Function>::from_iter(v);
        let t2 = MerkleTree::<Sha256Domain, Sha256Function>::from_iter(v2);

        assert_eq!(t2.as_slice()[0].as_ref(), l1.as_ref());
        assert_eq!(t2.as_slice()[1].as_ref(), l2.as_ref());
        assert_eq!(t2.as_slice()[2].as_ref(), h21.as_ref());

        // TODO: Verify this is the right hash
        assert_eq!(
            format!("{}", HexSlice::new(t.root().as_ref())),
            "e24f0cd2064e5b756515d6977d2b27629f4c8d1b86675f49f5124fea25827b6a"
        );
    }
}
