use merkle_light::hash::{Algorithm, Hashable};
use sha2::{Digest, Sha256};
use std::fmt;
use std::hash::Hasher;

#[derive(Clone)]
pub struct SHA256Algorithm(Sha256);

impl SHA256Algorithm {
    fn new() -> SHA256Algorithm {
        SHA256Algorithm(Sha256::new())
    }
}

impl Default for SHA256Algorithm {
    fn default() -> SHA256Algorithm {
        SHA256Algorithm::new()
    }
}

impl fmt::Debug for SHA256Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SHA256Algorithm")
    }
}

impl Hasher for SHA256Algorithm {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0.input(msg)
    }

    #[inline]
    fn finish(&self) -> u64 {
        unreachable!("unused by Algorithm -- should never be called")
    }
}

pub type SHA256Hash = [u8; 32];

impl Algorithm<SHA256Hash> for SHA256Algorithm {
    #[inline]
    fn hash(&mut self) -> SHA256Hash {
        let mut h = [0u8; 32];
        h.copy_from_slice(self.0.clone().result().as_ref());
        h
    }

    #[inline]
    fn reset(&mut self) {
        self.0 = Sha256::new();
    }

    fn leaf(&mut self, leaf: SHA256Hash) -> SHA256Hash {
        leaf
    }

    fn node(&mut self, left: SHA256Hash, right: SHA256Hash, _height: usize) -> SHA256Hash {
        // TODO: second preimage attack fix
        left.hash(self);
        right.hash(self);
        self.hash()
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
        let mut a = SHA256Algorithm::new();
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

        let mut a = SHA256Algorithm::new();
        let h11 = h1;
        let h12 = h2;
        let h13 = h3;
        let h21 = a.node(h11, h12, 1);
        a.reset();
        let h22 = a.node(h13, h13, 1);
        a.reset();
        let _h31 = a.node(h21, h22, 1);
        a.reset();

        let l1 = a.leaf(h1);
        a.reset();

        let l2 = a.leaf(h2);
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

        let t: MerkleTree<SHA256Hash, SHA256Algorithm> = MerkleTree::from_iter(vec![h1, h2, h3]);
        let t2: MerkleTree<SHA256Hash, SHA256Algorithm> = MerkleTree::from_iter(vec![h1, h2]);

        assert_eq!(t2.as_slice()[0], l1.as_ref());
        assert_eq!(t2.as_slice()[1], l2.as_ref());
        assert_eq!(t2.as_slice()[2], h21.as_ref());

        // TODO: Verify this is the right hash
        assert_eq!(
            format!("{}", HexSlice::new(t.root().as_ref())),
            "e24f0cd2064e5b756515d6977d2b27629f4c8d1b86675f49f5124fea25827b6a"
        );
    }
}
