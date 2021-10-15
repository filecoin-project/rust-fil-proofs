use blstrs::Scalar as Fr;
use ff::{PrimeField, PrimeFieldBits};
use filecoin_hashers::{poseidon::PoseidonHasher, HashFunction, Hasher};

use crate::constants::{challenge_count, partition_count, TreeRDomain};

// Generates the challenges for partition `k` of an `EmptySectorUpdate` proof. All challenges
// returned for partition `k` are guaranteed to lie within the `k`-th chunk of sector nodes.
//
// `challenge_count(sector_nodes)` number of challenges are generated for each partition;
// challenges are returned one at a time via the `Iterator` interface.
//
// `random_bits_per_challenge` number of random bits are generated per challenge, the
// partition-index (`partition_bits`) is appended onto the most-significant end of the random bits.
// Random bits are generated using the Poseidon hash function; each digest generates the random bits
// for `challenges_per_digest` number challenges.
pub struct Challenges {
    comm_r_new: TreeRDomain,
    // The partition-index bits which are appended onto each challenges random bits.
    partition_bits: u32,
    // The number of bits to generate per challenge.
    random_bits_per_challenge: usize,
    // The number of challenges derived per generated digest.
    challenges_per_digest: usize,
    // The index of the current digest across all partitions of this proof.
    digest_index_all_partitions: usize,
    // The index of the current challenge in the current digest.
    i: usize,
    digest_bits: Vec<bool>,
    // The number of challenges to be generated for this partition.
    challenges_remaining: usize,
}

impl Challenges {
    pub fn new(sector_nodes: usize, comm_r_new: TreeRDomain, k: usize) -> Self {
        let partitions = partition_count(sector_nodes);
        assert!(k < partitions);

        let challenge_bit_len = sector_nodes.trailing_zeros() as usize;
        let partition_bit_len = partitions.trailing_zeros() as usize;
        let random_bits_per_challenge = challenge_bit_len - partition_bit_len;
        let challenges_per_digest = Fr::CAPACITY as usize / random_bits_per_challenge;

        let partition_bits = (k << random_bits_per_challenge) as u32;

        let challenge_count = challenge_count(sector_nodes);
        let digests_per_partition =
            (challenge_count as f32 / challenges_per_digest as f32).ceil() as usize;
        let digest_index_all_partitions = k * digests_per_partition;

        Challenges {
            comm_r_new,
            partition_bits,
            random_bits_per_challenge,
            challenges_per_digest,
            digest_index_all_partitions,
            i: 0,
            digest_bits: Vec::with_capacity(Fr::NUM_BITS as usize),
            challenges_remaining: challenge_count,
        }
    }
}

impl Iterator for Challenges {
    // All sector-sizes have challenges that fit within 32 bits.
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        if self.challenges_remaining == 0 {
            return None;
        }

        // `digest = H(comm_r_new || digest_index)` where `digest_index` is across all partitions.
        if self.i == 0 {
            let digest_index = Fr::from(self.digest_index_all_partitions as u64);
            let digest: Fr =
                <PoseidonHasher as Hasher>::Function::hash2(&self.comm_r_new, &digest_index.into())
                    .into();
            self.digest_bits = digest.to_le_bits().into_iter().collect();
        }

        // Derive the `i`-th challenge `c` from `digest`.
        let c_bits = {
            let start = self.i * self.random_bits_per_challenge;
            let stop = start + self.random_bits_per_challenge;
            &self.digest_bits[start..stop]
        };

        let mut c = 0;
        for (i, bit) in c_bits.iter().enumerate() {
            if *bit {
                c |= 1 << i;
            }
        }
        // Append the partition-index bits onto the most-significant end of `c`.
        c |= self.partition_bits;

        self.i += 1;
        if self.i == self.challenges_per_digest {
            self.i = 0;
            self.digest_index_all_partitions += 1;
        }
        self.challenges_remaining -= 1;
        Some(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use filecoin_hashers::Domain;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::TEST_SEED;

    use crate::constants::{TreeRDomain, ALLOWED_SECTOR_SIZES};

    #[test]
    fn test_challenge_bucketing() {
        let mut rng = XorShiftRng::from_seed(TEST_SEED);

        for sector_nodes in ALLOWED_SECTOR_SIZES.iter().copied() {
            let comm_r_new = TreeRDomain::random(&mut rng);

            let partitions = partition_count(sector_nodes);
            let partition_challenges = challenge_count(sector_nodes);
            let partition_nodes = (sector_nodes / partitions) as u32;

            // Right shift each challenge `c` by `get_partition_shr` to get the partition-index `k`.
            let get_partition_shr = sector_nodes.trailing_zeros() - partitions.trailing_zeros();

            for k in 0..partitions {
                let challenges: Vec<u32> = Challenges::new(sector_nodes, comm_r_new, k).collect();
                assert_eq!(challenges.len(), partition_challenges);

                let k = k as u32;
                let first_partition_node = k * partition_nodes;
                let last_partition_node = first_partition_node + partition_nodes - 1;

                for c in challenges.into_iter() {
                    assert!(first_partition_node <= c && c <= last_partition_node);
                    // This check is redundant given the above range check, but let's sanity check
                    // it anyway.
                    assert_eq!(c >> get_partition_shr, k);
                }
            }
        }
    }
}
