use std::marker::PhantomData;

use blstrs::Scalar as Fr;
use ff::{PrimeField, PrimeFieldBits};
use filecoin_hashers::{HashFunction, Hasher};

use crate::constants::{challenge_count, partition_count};

pub struct Challenges<TreeRHasher: Hasher> {
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
        let partitions = partition_count(sector_nodes);
        assert!(k < partitions);
        // The number of partitions is guaranteed to be a power of two.
        let partition_bit_len = partitions.trailing_zeros() as usize;

        let challenge_bit_len = sector_nodes.trailing_zeros() as usize;
        let challenge_bits_from_digest = challenge_bit_len - partition_bit_len;
        // `challenge_bit_len` will likely not divide `Fr::CAPACITY`, thus we must round down here.
        let challenges_per_digest = Fr::CAPACITY as usize / challenge_bits_from_digest;

        // let partition_bits: Vec<bool> = (0..partition_bit_len).map(|i| (k >> i) & 1 == 1).collect();
        let partition_bits: usize = k << challenge_bits_from_digest;

        Challenges {
            challenge_bits_from_digest,
            challenges_per_digest,
            comm_r_new,
            partition_bits,
            j: 0,
            i: 0,
            digest_j_bits: Vec::with_capacity(Fr::NUM_BITS as usize),
            challenges_remaining: challenge_count(sector_nodes),
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
            let j = Fr::from(self.j as u64);
            let digest_j: Fr = TreeRHasher::Function::hash2(&self.comm_r_new, &j.into()).into();
            self.digest_j_bits = digest_j.to_le_bits().into_iter().collect();
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

#[cfg(test)]
mod tests {
    use super::*;

    use filecoin_hashers::{
        poseidon::{PoseidonDomain, PoseidonHasher},
        Domain,
    };
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::TEST_SEED;

    use crate::constants::ALLOWED_SECTOR_SIZES;

    #[test]
    fn test_challenges() {
        let mut rng = &mut XorShiftRng::from_seed(TEST_SEED);
        let comm_r_new = PoseidonDomain::random(&mut rng);

        for sector_nodes in ALLOWED_SECTOR_SIZES.iter().copied() {
            let partitions = partition_count(sector_nodes);
            let partition_nodes = sector_nodes / partitions;
            let partition_challenges = challenge_count(sector_nodes);

            // Right shift each challenge `c` by `get_partition_shr` to get the partition-index `k`.
            let get_partition_shr =
                (sector_nodes.trailing_zeros() - partitions.trailing_zeros()) as usize;

            for k in 0..partitions {
                let first_partition_node = k * partition_nodes;
                let last_partition_node = first_partition_node + partition_nodes - 1;

                let challenges: Vec<usize> =
                    Challenges::<PoseidonHasher>::new(sector_nodes, comm_r_new.clone(), k)
                        .collect();

                assert_eq!(challenges.len(), partition_challenges);

                for c in challenges.into_iter() {
                    assert!(c >= first_partition_node);
                    assert!(c <= last_partition_node);
                    // This is redundant with the above range check, but let's sanity check anyway.
                    assert_eq!(c >> get_partition_shr, k);
                }
            }
        }
    }
}
