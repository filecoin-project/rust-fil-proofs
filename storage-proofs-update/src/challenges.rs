use blstrs::Scalar as Fr;
use ff::{PrimeField, PrimeFieldBits};
use neptune::poseidon::Poseidon;

use crate::constants::{
    challenge_count, partition_count, TreeRDomain, POSEIDON_CONSTANTS_GEN_RANDOMNESS,
};

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

    pub fn new_poseidon(sector_nodes: usize, comm_r_new: TreeRDomain) -> Self {
        let repeats = partition_count(sector_nodes);

        let challenge_bit_len = sector_nodes.trailing_zeros() as usize;
        let random_bits_per_challenge = challenge_bit_len;
        let challenges_per_digest = Fr::CAPACITY as usize / random_bits_per_challenge;

        let challenge_count = challenge_count(sector_nodes) * repeats;
        let digest_index_all_partitions = 0;

        Challenges {
            comm_r_new,
            partition_bits: 0,
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
            let digest = Poseidon::new_with_preimage(
                &[self.comm_r_new.into(), digest_index],
                &POSEIDON_CONSTANTS_GEN_RANDOMNESS,
            )
            .hash();
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
            hm.insert((SECTOR_SIZE_1_KIB, 0), [21, 7, 3, 31, 0]);
            hm.insert((SECTOR_SIZE_2_KIB, 0), [53, 51, 56, 3, 0]);
            hm.insert((SECTOR_SIZE_4_KIB, 0), [117, 25, 62, 0, 72]);
            hm.insert((SECTOR_SIZE_8_KIB, 0), [245, 140, 15, 128, 28]);

            hm.insert((SECTOR_SIZE_16_KIB, 0), [245, 140, 15, 128, 28]);
            hm.insert((SECTOR_SIZE_16_KIB, 1), [286, 308, 493, 510, 508]);

            hm.insert((SECTOR_SIZE_32_KIB, 0), [245, 454, 3, 400, 193]);
            hm.insert((SECTOR_SIZE_32_KIB, 1), [542, 666, 955, 927, 911]);

            hm.insert((SECTOR_SIZE_8_MIB, 0), [36085, 32783, 44060, 10950, 3731]);
            hm.insert(
                (SECTOR_SIZE_8_MIB, 1),
                [78878, 130797, 112892, 93994, 78379],
            );

            hm.insert(
                (SECTOR_SIZE_16_MIB, 0),
                [101621, 16391, 109319, 25944, 41193],
            );
            hm.insert(
                (SECTOR_SIZE_16_MIB, 1),
                [209950, 163702, 175679, 224741, 197410],
            );

            hm.insert(
                (SECTOR_SIZE_512_MIB, 0),
                [1019125, 116736, 706220, 59698, 799498],
            );
            hm.insert(
                (SECTOR_SIZE_512_MIB, 1),
                [2092548, 1213276, 1185483, 1164598, 1095197],
            );
            hm.insert(
                (SECTOR_SIZE_512_MIB, 14),
                [15212432, 15665918, 15015423, 15012912, 15495223],
            );
            hm.insert(
                (SECTOR_SIZE_512_MIB, 15),
                [16388544, 15794686, 16637142, 16319148, 16328348],
            );

            hm.insert(
                (SECTOR_SIZE_32_GIB, 0),
                [1019125, 27985696, 15282860, 11586600, 44651330],
            );
            hm.insert(
                (SECTOR_SIZE_32_GIB, 1),
                [109168525, 127316247, 80331041, 97065716, 72310052],
            );
            hm.insert(
                (SECTOR_SIZE_32_GIB, 14),
                [990420169, 955146989, 968005601, 976863263, 944650706],
            );
            hm.insert(
                (SECTOR_SIZE_32_GIB, 15),
                [1038629497, 1053983614, 1030421316, 1027373887, 1068685433],
            );

            hm.insert(
                (SECTOR_SIZE_64_GIB, 0),
                [1019125, 13992848, 3820715, 18225541, 57316660],
            );
            hm.insert(
                (SECTOR_SIZE_64_GIB, 1),
                [243386253, 197875851, 204632136, 171516766, 247789010],
            );
            hm.insert(
                (SECTOR_SIZE_64_GIB, 14),
                [1997053129, 1920414070, 2003609080, 1900492803, 1963254685],
            );
            hm.insert(
                (SECTOR_SIZE_64_GIB, 15),
                [2045262457, 2036941247, 2136653521, 2091356007, 2147167623],
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
