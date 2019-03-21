use sha2::Sha256;

use super::{DigestHasher, Digester};

impl Digester for Sha256 {
    fn name() -> String {
        "Sha256".into()
    }
}

pub type Sha256Hasher = DigestHasher<Sha256>;

#[cfg(test)]
mod tests {
    use super::*;

    use std::fmt;
    use std::iter::FromIterator;

    use merkle_light::hash::{Algorithm, Hashable};
    use merkle_light::merkle::MerkleTree;

    use super::super::{DigestDomain, Hasher};

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

        let v: Vec<DigestDomain> = vec![h1.into(), h2.into(), h3.into()];
        let v2: Vec<DigestDomain> = vec![h1.into(), h2.into()];
        let t = MerkleTree::<<Sha256Hasher as Hasher>::Domain, <Sha256Hasher as Hasher>::Function>::from_iter(v);
        let t2 = MerkleTree::<<Sha256Hasher as Hasher>::Domain, <Sha256Hasher as Hasher>::Function>::from_iter(v2);

        assert_eq!(t2.as_slice()[0].as_ref(), l1.as_ref());
        assert_eq!(t2.as_slice()[1].as_ref(), l2.as_ref());
        assert_eq!(t2.as_slice()[2].as_ref(), h21.as_ref());

        // TODO: Verify this is the right hash — bearing in mind that the two most significant bits must be cleared after each hash.
        assert_eq!(
            format!("{}", HexSlice::new(t.root().as_ref())),
            "1c1afe57ff6efa4204cf4e17e20bf4d7f6ebf3a4c27391f93993291560107f88"
        );
    }
}
