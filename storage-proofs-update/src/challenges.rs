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

    use std::collections::HashMap;

    use filecoin_hashers::Domain;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::TEST_SEED;

    use crate::constants::{
        TreeRDomain, ALLOWED_SECTOR_SIZES, SECTOR_SIZE_16_KIB, SECTOR_SIZE_16_MIB,
        SECTOR_SIZE_1_KIB, SECTOR_SIZE_2_KIB, SECTOR_SIZE_32_GIB, SECTOR_SIZE_32_KIB,
        SECTOR_SIZE_4_KIB, SECTOR_SIZE_512_MIB, SECTOR_SIZE_64_GIB, SECTOR_SIZE_8_KIB,
        SECTOR_SIZE_8_MIB,
    };

    #[test]
    fn test_challenges_against_hardcoded() {
        type SectorNodes = usize;
        type PartitionIndex = usize;

        let mut rng = XorShiftRng::from_seed(TEST_SEED);
        let comm_r_new = TreeRDomain::random(&mut rng);

        let test_vectors: HashMap<(SectorNodes, PartitionIndex), [u32; 5]> = {
            let mut hm = HashMap::new();
            hm.insert((SECTOR_SIZE_1_KIB, 0), [5, 9, 2, 0, 31]);
            hm.insert((SECTOR_SIZE_2_KIB, 0), [37, 36, 0, 60, 37]);
            hm.insert((SECTOR_SIZE_4_KIB, 0), [37, 18, 64, 47, 26]);
            hm.insert((SECTOR_SIZE_8_KIB, 0), [37, 9, 240, 165, 89]);

            hm.insert((SECTOR_SIZE_16_KIB, 0), [37, 9, 240, 165, 89]);
            hm.insert((SECTOR_SIZE_16_KIB, 1), [342, 390, 338, 407, 380]);

            hm.insert((SECTOR_SIZE_32_KIB, 0), [293, 4, 380, 308, 53]);
            hm.insert((SECTOR_SIZE_32_KIB, 1), [598, 835, 980, 914, 727]);

            hm.insert((SECTOR_SIZE_8_MIB, 0), [2341, 42480, 17241, 30407, 23862]);
            hm.insert(
                (SECTOR_SIZE_8_MIB, 1),
                [99926, 104274, 93564, 74241, 116856],
            );

            hm.insert((SECTOR_SIZE_16_MIB, 0), [2341, 54008, 118998, 52952, 1491]);
            hm.insert(
                (SECTOR_SIZE_16_MIB, 1),
                [165462, 150441, 154463, 197696, 220295],
            );

            hm.insert(
                (SECTOR_SIZE_512_MIB, 0),
                [2341, 367199, 444227, 381799, 419584],
            );
            hm.insert(
                (SECTOR_SIZE_512_MIB, 1),
                [1063656, 1540079, 1357979, 1644364, 1394127],
            );
            hm.insert(
                (SECTOR_SIZE_512_MIB, 14),
                [14789866, 14735953, 15532418, 15676174, 14783566],
            );
            hm.insert(
                (SECTOR_SIZE_512_MIB, 15),
                [16366137, 15746672, 16416779, 16186611, 16210584],
            );

            hm.insert(
                (SECTOR_SIZE_32_GIB, 0),
                [32508197, 30463593, 30631788, 22649857, 15398760],
            );
            hm.insert(
                (SECTOR_SIZE_32_GIB, 1),
                [85580133, 87841529, 85791345, 80308353, 101474256],
            );
            hm.insert(
                (SECTOR_SIZE_32_GIB, 14),
                [979516080, 944706378, 994431438, 945426651, 1005867799],
            );
            hm.insert(
                (SECTOR_SIZE_32_GIB, 15),
                [1034257159, 1057076592, 1042443489, 1059045736, 1025565787],
            );

            hm.insert(
                (SECTOR_SIZE_64_GIB, 0),
                [99617061, 15231796, 24435163, 69940096, 101625718],
            );
            hm.insert(
                (SECTOR_SIZE_64_GIB, 1),
                [219797861, 178138492, 155665564, 135867664, 195085821],
            );
            hm.insert(
                (SECTOR_SIZE_64_GIB, 14),
                [1919040176, 1948748197, 1943106675, 1938506267, 1950303537],
            );
            hm.insert(
                (SECTOR_SIZE_64_GIB, 15),
                [2040890119, 2072042168, 2022218552, 2112092205, 2031226437],
            );

            hm
        };

        for ((sector_nodes, k), challenges_expected) in test_vectors.into_iter() {
            assert_eq!(
                Challenges::new(sector_nodes, comm_r_new, k)
                    .take(5)
                    .collect::<Vec<u32>>(),
                challenges_expected,
            );
        }
    }

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
