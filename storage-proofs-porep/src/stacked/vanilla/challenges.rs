use blstrs::Scalar as Fr;
use log::trace;
use num_bigint::BigUint;

use filecoin_hashers::Domain;
use sha2::{Digest, Sha256};

#[inline]
fn bigint_to_challenge(bigint: BigUint, sector_nodes: usize) -> usize {
    debug_assert!(sector_nodes < 1 << 32);
    // Ensure that we don't challenge the first node.
    let non_zero_node = (bigint % (sector_nodes - 1)) + 1usize;
    non_zero_node.to_u32_digits()[0] as usize
}

#[derive(Clone, Debug)]
pub struct InteractiveChallenges {
    challenges_per_partition: usize,
}

impl InteractiveChallenges {
    pub const fn new(challenges_per_partition: usize) -> Self {
        Self {
            challenges_per_partition,
        }
    }

    pub const fn new_synthetic(challenges_per_partition: usize) -> Self {
        Self {
            challenges_per_partition,
        }
    }

    /// Returns the porep challenges for partition `k`.
    pub fn derive<D: Domain>(
        &self,
        sector_nodes: usize,
        replica_id: &D,
        seed: &[u8; 32],
        k: u8,
    ) -> Vec<usize> {
        (0..self.challenges_per_partition)
            .map(|i| {
                let j: u32 = ((self.challenges_per_partition * k as usize) + i) as u32;

                let hash = Sha256::new()
                    .chain_update(replica_id.into_bytes())
                    .chain_update(seed)
                    .chain_update(j.to_le_bytes())
                    .finalize();

                let bigint = BigUint::from_bytes_le(hash.as_ref());
                bigint_to_challenge(bigint, sector_nodes)
            })
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct SynthChallenges {
    challenges_per_partition: usize,
}

impl SynthChallenges {
    pub const fn new(challenges_per_partition: usize) -> Self {
        Self {
            challenges_per_partition,
        }
    }

    /// Returns the porep challenges for partition `k` taken from the synthetic challenges.
    pub fn derive<D: Domain>(
        &self,
        sector_nodes: usize,
        replica_id: &D,
        comm_r: &D,
        seed: &[u8; 32],
        k: u8,
    ) -> Vec<usize> {
        let replica_id: Fr = (*replica_id).into();
        let comm_r: Fr = (*comm_r).into();
        SynthChallengeGenerator::default(sector_nodes, &replica_id, &comm_r)
            .gen_porep_partition_challenges(self.challenges_per_partition, seed, k as usize)
    }

    /// Returns the synthetic challenge indexes of the porep challenges for partition `k`.
    pub fn derive_indexes<D: Domain>(
        &self,
        sector_nodes: usize,
        replica_id: &D,
        comm_r: &D,
        seed: &[u8; 32],
        k: u8,
    ) -> Vec<usize> {
        trace!(
            "generating porep partition synthetic challenge indexes (k = {})",
            k,
        );
        let replica_id: Fr = (*replica_id).into();
        let comm_r: Fr = (*comm_r).into();
        SynthChallengeGenerator::default(sector_nodes, &replica_id, &comm_r)
            .gen_partition_synth_indexes(self.challenges_per_partition, seed, k as usize)
    }

    /// Returns the entire synthetic challenge set.
    pub fn derive_synthetic<D: Domain>(
        sector_nodes: usize,
        replica_id: &D,
        comm_r: &D,
    ) -> Vec<usize> {
        let replica_id: Fr = (*replica_id).into();
        let comm_r: Fr = (*comm_r).into();
        let synth = SynthChallengeGenerator::default(sector_nodes, &replica_id, &comm_r);
        trace!(
            "generating entire synthetic challenge set (num_synth_challenges = {})",
            synth.num_synth_challenges,
        );
        synth.collect()
    }
}

#[derive(Clone, Debug)]
pub struct NiChallenges {
    challenges_per_partition: usize,
}

impl NiChallenges {
    pub const fn new(challenges_per_partition: usize) -> Self {
        Self {
            challenges_per_partition,
        }
    }

    pub fn derive<D: Domain>(
        &self,
        sector_nodes: usize,
        replica_id: &D,
        comm_r: &D,
        k: u8,
    ) -> Vec<usize> {
        const TAG: &[u8] = b"filecoin.io|PoRep|1|NonInteractive|1";
        let hash_init = Sha256::new()
            .chain_update(TAG)
            .chain_update(replica_id.into_bytes())
            .chain_update(comm_r);
        (0..self.challenges_per_partition)
            .map(|i| {
                let j: u32 = ((self.challenges_per_partition * k as usize) + i) as u32;

                let hash = hash_init.clone().chain_update(j.to_le_bytes()).finalize();

                let bigint = BigUint::from_bytes_le(hash.as_ref());
                bigint_to_challenge(bigint, sector_nodes)
            })
            .collect()
    }
}

#[derive(Clone, Debug)]
pub enum Challenges {
    Interactive(InteractiveChallenges),
    Synth(SynthChallenges),
    Ni(NiChallenges),
}

impl Challenges {
    pub const fn new_interactive(challenges_per_partition: usize) -> Self {
        Self::Interactive(InteractiveChallenges::new(challenges_per_partition))
    }

    pub const fn new_synthetic(challenges_per_partition: usize) -> Self {
        Self::Synth(SynthChallenges::new(challenges_per_partition))
    }

    pub const fn new_non_interactive(challenges_per_partition: usize) -> Self {
        Self::Ni(NiChallenges::new(challenges_per_partition))
    }

    pub fn num_challenges_per_partition(&self) -> usize {
        match self {
            Self::Interactive(InteractiveChallenges {
                challenges_per_partition,
            })
            | Self::Synth(SynthChallenges {
                challenges_per_partition,
            })
            | Self::Ni(NiChallenges {
                challenges_per_partition,
            }) => *challenges_per_partition,
        }
    }
}

#[derive(Debug, Default)]
pub struct ChallengeRequirements {
    pub minimum_challenges: usize,
}

pub(crate) mod synthetic {
    use super::*;

    use std::cmp::min;
    use std::convert::TryInto;

    use blake2b_simd::Params as Blake2b;
    use chacha20::{
        cipher::{KeyIvInit, StreamCipher, StreamCipherSeek},
        ChaCha20,
    };
    use ff::PrimeField;

    pub const SYNTHETIC_POREP_VANILLA_PROOFS_KEY: &str = "syn-porep-vanilla-proofs";
    pub const SYNTHETIC_POREP_VANILLA_PROOFS_EXT: &str = "dat";

    // Default synthetic challenge count for production sector sizes.
    #[cfg_attr(feature = "tooling", visibility::make(pub))]
    const DEFAULT_SYNTH_CHALLENGE_COUNT: usize = 1 << 18;
    const SYNTH_CHALLENGE_SIZE: usize = 32;
    const SYNTH_INDEX_SIZE: usize = 4;
    const CHACHA20_KEY_SIZE: usize = 32;
    const CHACHA20_NONCE: &[u8; 12] = b"synth-porep\x00";

    // The prf used to generate synthetic challenges.
    fn chacha20_gen(replica_id: &[u8; 32], comm_r: &[u8; 32]) -> ChaCha20 {
        let key = Blake2b::new()
            .hash_length(CHACHA20_KEY_SIZE)
            .key(b"filecoin.io|PoRep|1|Synthetic|1|Generation")
            .to_state()
            .update(replica_id)
            .update(comm_r)
            .finalize();
        ChaCha20::new(key.as_bytes().into(), CHACHA20_NONCE.into())
    }

    // The prf used to select the synthetic challenges used as porep challenge (i.e. the prf used to
    // generate synthetic challenge indices).
    fn chacha20_select(replica_id: &[u8; 32], rand: &[u8; 32]) -> ChaCha20 {
        let key = Blake2b::new()
            .hash_length(CHACHA20_KEY_SIZE)
            .key(b"filecoin.io|PoRep|1|Synthetic|1|Selection")
            .to_state()
            .update(replica_id)
            .update(rand)
            .finalize();
        ChaCha20::new(key.as_bytes().into(), CHACHA20_NONCE.into())
    }

    #[cfg_attr(feature = "tooling", visibility::make(pub))]
    pub(crate) struct SynthChallengeGenerator {
        sector_nodes: usize,
        replica_id: [u8; 32],
        comm_r: [u8; 32],
        // The number of synthetic challenges to generate; the porep challenge set will be a subset of
        // these generated synthetic challenges.
        pub(crate) num_synth_challenges: usize,
        // The prf used to generate synthetic challenges (not the synthetic challenge indices
        // selected for porep challenges).
        chacha20: ChaCha20,
        // The index `0 <= i < num_synth_challenges` of the next synthetic challenge to generate.
        i: usize,
    }

    impl Clone for SynthChallengeGenerator {
        fn clone(&self) -> Self {
            let mut synth = Self {
                sector_nodes: self.sector_nodes,
                replica_id: self.replica_id,
                comm_r: self.comm_r,
                num_synth_challenges: self.num_synth_challenges,
                chacha20: chacha20_gen(&self.replica_id, &self.comm_r),
                i: 0,
            };
            synth.seek(self.i);
            synth
        }
    }

    impl Iterator for SynthChallengeGenerator {
        type Item = usize;

        // Generates and returns the next synthetic challenge.
        fn next(&mut self) -> Option<Self::Item> {
            if self.i >= self.num_synth_challenges {
                return None;
            }
            let mut rand_bytes = [0u8; SYNTH_CHALLENGE_SIZE];
            self.chacha20.apply_keystream(&mut rand_bytes);
            let bigint = BigUint::from_bytes_le(&rand_bytes);
            let challenge = bigint_to_challenge(bigint, self.sector_nodes);
            self.i += 1;
            Some(challenge)
        }
    }

    impl SynthChallengeGenerator {
        pub fn new(
            sector_nodes: usize,
            replica_id: &Fr,
            comm_r: &Fr,
            num_synth_challenges: usize,
        ) -> Self {
            assert!(
                num_synth_challenges < 1 << 32,
                "num_synth_challenges must not exceed u32",
            );
            let replica_id = replica_id.to_repr();
            let comm_r = comm_r.to_repr();
            let chacha20 = chacha20_gen(&replica_id, &comm_r);
            Self {
                sector_nodes,
                replica_id,
                comm_r,
                num_synth_challenges,
                chacha20,
                i: 0,
            }
        }

        pub fn default(sector_nodes: usize, replica_id: &Fr, comm_r: &Fr) -> Self {
            let num_synth_challenges = min(sector_nodes, DEFAULT_SYNTH_CHALLENGE_COUNT);
            Self::new(sector_nodes, replica_id, comm_r, num_synth_challenges)
        }

        /// Seeks to the `i`-th synthetic challenge; seeking to `i` results in the next call to
        /// `SynthChallengeGenerator::next` returning the `i`-th synthetic challenge.
        pub(super) fn seek(&mut self, i: usize) {
            self.chacha20
                .try_seek((i * SYNTH_CHALLENGE_SIZE) as u32)
                .expect("seeking should not exceed keystream length");
            self.i = i;
        }

        /// Returns the `i`-th synthetic challenge.
        pub fn gen_synth_challenge(&mut self, i: usize) -> usize {
            assert!(i < self.num_synth_challenges);
            self.seek(i);
            self.next()
                .expect("challenge iterator should not be finished")
        }

        /// Returns the synthetic challenge indexes that select the porep partition's challenges.
        pub fn gen_partition_synth_indexes(
            &self,
            num_partition_challenges: usize,
            rand: &[u8; 32],
            k: usize,
        ) -> Vec<usize> {
            let first_porep_challenge = k * num_partition_challenges;

            let mut chacha20 = chacha20_select(&self.replica_id, rand);
            chacha20
                .try_seek((first_porep_challenge * SYNTH_INDEX_SIZE) as u32)
                .expect("seeking should not exceed keystream length");

            let mut rand_bytes = vec![0u8; num_partition_challenges * SYNTH_INDEX_SIZE];
            chacha20.apply_keystream(&mut rand_bytes);

            rand_bytes
                .chunks(SYNTH_INDEX_SIZE)
                .map(|index_bytes| {
                    let index_bytes: [u8; SYNTH_INDEX_SIZE] =
                        index_bytes.try_into().expect("conversion should not fail");
                    let synth_index = u32::from_le_bytes(index_bytes) as usize;
                    synth_index % self.num_synth_challenges
                })
                .collect()
        }

        /// Returns the porep challenges for partition `k` selected from the synthetic challenges.
        pub fn gen_porep_partition_challenges(
            &self,
            num_partition_challenges: usize,
            rand: &[u8; 32],
            k: usize,
        ) -> Vec<usize> {
            let mut synth = self.clone();
            self.gen_partition_synth_indexes(num_partition_challenges, rand, k)
                .into_iter()
                .map(|i| synth.gen_synth_challenge(i))
                .collect()
        }

        /// Returns all porep challenges selected from the synthetic challenges.
        #[inline]
        #[cfg(test)]
        pub fn gen_porep_challenges(
            &self,
            num_porep_challenges: usize,
            rand: &[u8; 32],
        ) -> Vec<usize> {
            self.gen_porep_partition_challenges(num_porep_challenges, rand, 0)
        }
    }
}

use synthetic::SynthChallengeGenerator;

#[cfg(test)]
mod test {
    use super::*;

    use std::collections::HashMap;

    use filecoin_hashers::sha256::Sha256Domain;
    use rand::{thread_rng, Rng, RngCore};

    #[test]
    fn test_calculate_fixed_challenges() {
        let layer_challenges = Challenges::new_interactive(333);
        let expected = 333;

        let calculated_count = layer_challenges.num_challenges_per_partition();
        assert_eq!(expected as usize, calculated_count);
    }

    #[test]
    fn challenge_derivation() {
        let n = 200;
        let layers = 100;

        let challenges = InteractiveChallenges::new(n);
        let leaves = 1 << 30;
        let rng = &mut thread_rng();
        let replica_id: Sha256Domain = Sha256Domain::random(rng);
        let seed: [u8; 32] = rng.gen();
        let partitions = 5;
        let total_challenges = partitions * n;

        let mut layers_with_duplicates = 0;

        for _layer in 1..=layers {
            let mut histogram = HashMap::new();
            for k in 0..partitions {
                let challenges = challenges.derive(leaves, &replica_id, &seed, k as u8);

                for challenge in challenges {
                    let counter = histogram.entry(challenge).or_insert(0);
                    *counter += 1;
                }
            }
            let unique_challenges = histogram.len();
            if unique_challenges < total_challenges {
                layers_with_duplicates += 1;
            }
        }

        // If we generate 100 layers with 1,000 challenges in each, at most two layers can contain
        // any duplicates for this assertion to succeed.
        //
        // This test could randomly fail (anything's possible), but if it happens regularly something is wrong.
        assert!(layers_with_duplicates < 3);
    }

    #[test]
    // This test shows that partitioning (k = 0..partitions) generates the same challenges as
    // generating the same number of challenges with only one partition (k = 0).
    fn challenge_partition_equivalence() {
        let n = 40;
        let leaves = 1 << 30;
        let rng = &mut thread_rng();
        let replica_id: Sha256Domain = Sha256Domain::random(rng);
        let seed: [u8; 32] = rng.gen();
        let partitions = 5;
        let layers = 100;
        let total_challenges = n * partitions;

        for _layer in 1..=layers {
            let one_partition_challenges =
                InteractiveChallenges::new(total_challenges).derive(leaves, &replica_id, &seed, 0);
            let many_partition_challenges = (0..partitions)
                .flat_map(|k| {
                    InteractiveChallenges::new(n).derive(leaves, &replica_id, &seed, k as u8)
                })
                .collect::<Vec<_>>();

            assert_eq!(one_partition_challenges, many_partition_challenges);
        }
    }

    #[test]
    fn test_synth_challenges_32gib() {
        let sector_nodes = 1 << 30;
        let replica_id = Fr::from(thread_rng().next_u64());
        let comm_r = Fr::from(thread_rng().next_u64());

        let mut synth = SynthChallengeGenerator::default(sector_nodes, &replica_id, &comm_r);

        // Test synthetic challenge generation.
        let synth_challenges: Vec<usize> = synth.clone().collect();
        for (i, challenge) in synth_challenges.into_iter().enumerate() {
            assert!(challenge < sector_nodes);
            assert_eq!(synth.gen_synth_challenge(i), challenge);
        }

        // Test porep challenge generation.
        let partition_challenge_count = 18;
        let partition_count = 10;
        let total_porep_challenges = partition_challenge_count * partition_count;
        let rand = [1u8; 32];

        let all_porep_challenges = synth.gen_porep_challenges(total_porep_challenges, &rand);
        for (k, partition_challenges) in all_porep_challenges
            .chunks(partition_challenge_count)
            .enumerate()
        {
            assert_eq!(
                synth.gen_porep_partition_challenges(partition_challenge_count, &rand, k),
                partition_challenges,
            );
        }
    }

    #[test]
    fn test_synth_challenges_against_hardcoded() {
        let sector_nodes = 1 << 10;
        let replica_id = Fr::from(55);
        let comm_r = Fr::from(101);
        let num_synth_challenges = 21;
        let num_porep_challenges = 10;
        let porep_challenge_randomness = [1u8; 32];

        // Expected challenges for `sector_nodes = 2^10`, `replica_id = 55`, `comm_r = 101`, and
        // `rand = [1; 32]`.
        let expected_synth_challenges: [usize; 21] = [
            178, 297, 869, 211, 875, 477, 94, 781, 124, 332, 856, 801, 176, 692, 429, 691, 290,
            204, 986, 210, 973,
        ];
        let expected_porep_challenges: [usize; 10] =
            [176, 781, 801, 986, 290, 211, 692, 856, 986, 332];

        let mut synth =
            SynthChallengeGenerator::new(sector_nodes, &replica_id, &comm_r, num_synth_challenges);

        // Test synthetic challenge generation against hardcoded challenges.
        let synth_challenges: Vec<usize> = synth.clone().collect();
        assert!(synth_challenges.iter().all(|c| c < &sector_nodes));
        assert_eq!(synth_challenges, expected_synth_challenges);

        // Test generation of individual synthetic challenges.
        for i in (0..num_synth_challenges).rev() {
            assert_eq!(synth.gen_synth_challenge(i), synth_challenges[i]);
        }
        // Test seeking.
        synth.seek(num_synth_challenges);
        assert!(synth.next().is_none());

        // Test porep challenge generation against hardcoded challenges.
        let porep_challenges =
            synth.gen_porep_challenges(num_porep_challenges, &porep_challenge_randomness);
        assert_eq!(porep_challenges, expected_porep_challenges);
    }
}
