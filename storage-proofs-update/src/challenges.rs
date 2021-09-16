use std::marker::PhantomData;

use blstrs::{Bls12, Scalar as Fr};
use ff::{PrimeField, PrimeFieldBits};
use filecoin_hashers::{HashFunction, Hasher};
use storage_proofs_core::merkle::MerkleTreeTrait;

pub struct Challenges<TreeR: MerkleTreeTrait> {
    challenge_bits: usize,
    challenges_per_digest: usize,
    comm_r_new: <TreeR::Hasher as Hasher>::Domain,
    j: u64,
    i: usize,
    digest_j_bits: Vec<bool>,
    _tree_r: PhantomData<TreeR>,
}

impl<TreeR: MerkleTreeTrait> Challenges<TreeR> {
    pub fn new(sector_nodes: usize, comm_r_new: <TreeR::Hasher as Hasher>::Domain) -> Self {
        // TODO: change to `trailing_zeros()`
        let challenge_bits = (sector_nodes as f32).log2() as usize;
        let challenges_per_digest = Fr::CAPACITY as usize / challenge_bits;
        Challenges {
            challenge_bits,
            challenges_per_digest,
            comm_r_new,
            j: 0,
            i: 0,
            digest_j_bits: Vec::with_capacity(Fr::NUM_BITS as usize),
            _tree_r: PhantomData,
        }
    }
}

impl<TreeR: MerkleTreeTrait> Iterator for Challenges<TreeR> {
    // Return a `usize` (as opposed to something smaller like `u32`) because
    // `MerkleTreeTrait::gen_proof()` takes a `usize` challenge.
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if self.i == 0 {
            let digest_j: Fr = <TreeR::Hasher as Hasher>::Function::hash2(
                &self.comm_r_new,
                &Fr::from(self.j).into(),
            )
            .into();
            /*
            self.digest_j_bits = BitIterator::new(digest_j)
                .into_iter()
                .collect::<Vec<bool>>()
                .into_iter()
                // make little-endian
                .rev()
                .collect();
             */
            self.digest_j_bits = digest_j.to_le_bits().into_iter().collect::<Vec<bool>>();
        }

        let c_bits =
            &self.digest_j_bits[self.i * self.challenge_bits..(self.i + 1) * self.challenge_bits];

        let mut c: usize = 0;
        let mut pow2: usize = 1;
        for bit in c_bits {
            c += *bit as usize * pow2;
            pow2 <<= 1;
        }

        self.i += 1;
        if self.i == self.challenges_per_digest {
            self.i = 0;
            self.j += 1;
        }

        Some(c)
    }
}
