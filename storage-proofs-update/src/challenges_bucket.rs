use std::marker::PhantomData;

use blstrs::{Bls12, Scalar as Fr};
use ff::{Field, PrimeField, PrimeFieldBits};
use filecoin_hashers::{HashFunction, Hasher};
use storage_proofs_core::merkle::MerkleTreeTrait;

use crate::PARTITION_CHALLENGES;

// The number of partitions for this sector-size.
#[inline]
fn partitions(sector_nodes: usize) -> usize {
    if sector_nodes == 1 << 5 {
        1
    } else {
        16
    }
}

pub struct Challenges<TreeRHasher: Hasher> {
    challenge_bit_len: usize,
    challenge_bits_from_digest: usize,
    challenges_per_digest: usize,
    comm_r_new: TreeRHasher::Domain,
    // A bit-mask used to add the partition-index `k` (as little-endian bits) to each generated
    // challenge's bits.
    partition_bits: usize,
    // The index of the current digest.
    j: usize,
    // The index of the current challenge in the `j`-th digest.
    i: usize,
    // The number of challenges which have yet to be generated for this partition.
    challenges_remaining: usize,
    digest_j_bits: Vec<bool>,
    _h: PhantomData<TreeRHasher>,
}

impl<TreeRHasher: Hasher> Challenges<TreeRHasher> {
    pub fn new(sector_nodes: usize, comm_r_new: TreeRHasher::Domain, k: usize) -> Self {
        let partitions = partitions(sector_nodes);
        assert!(k < partitions);
        let partition_bit_len = partitions.trailing_zeros() as usize;

        let challenge_bit_len = sector_nodes.trailing_zeros() as usize;
        let challenge_bits_from_digest = challenge_bit_len - partition_bit_len;
        let challenges_per_digest = Fr::CAPACITY as usize / challenge_bits_from_digest;

        // let partition_bits: Vec<bool> = (0..partition_bit_len).map(|i| (k >> i) & 1 == 1).collect();
        let partition_bits: usize = k << challenge_bits_from_digest;

        Challenges {
            challenge_bit_len,
            challenge_bits_from_digest,
            challenges_per_digest,
            comm_r_new,
            partition_bits,
            j: 0,
            i: 0,
            digest_j_bits: Vec::with_capacity(Fr::NUM_BITS as usize),
            challenges_remaining: PARTITION_CHALLENGES,
            _h: PhantomData,
        }
    }
}

impl<TreeRHasher: Hasher> Iterator for Challenges<TreeRHasher> {
    // Return a `usize` (as opposed to something smaller like `u32`) because
    // `MerkleTreeTrait::gen_proof()` takes `usize` challenges.
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if self.challenges_remaining == 0 {
            return None;
        }

        // Generate the `j`-th digest.
        if self.i == 0 {
            let j: TreeRHasher::Domain = Fr::from(self.j as u64).into();
            let digest_j: Fr = TreeRHasher::Function::hash2(&self.comm_r_new, &j).into();
            /*self.digest_j_bits = BitIterator::new(digest_j)
                .into_iter()
                .collect::<Vec<bool>>()
                .into_iter()
                // make little-endian
                .rev()
            .collect();*/
            self.digest_j_bits = digest_j.to_le_bits().into_iter().collect::<Vec<bool>>();
        }

        // Derive the `i`-th challenge `c` from `digest_j`.
        let c_bits = {
            let start = self.i * self.challenge_bits_from_digest;
            let stop = start + self.challenge_bits_from_digest;
            &self.digest_j_bits[start..stop]
        };

        let mut c: usize = 0;
        let mut pow2: usize = 1;
        for bit in c_bits {
            c += *bit as usize * pow2;
            pow2 <<= 1;
        }
        // Append the partition-index bits onto the most-significant end of `c`.
        c |= self.partition_bits;

        self.i += 1;
        if self.i == self.challenges_per_digest {
            self.i = 0;
            self.j += 1;
        }
        self.challenges_remaining -= 1;
        Some(c)
    }
}
