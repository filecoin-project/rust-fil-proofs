use std::fmt;

use blstrs::Scalar as Fr;
use log::trace;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use filecoin_hashers::Domain;
use sha2::{Digest, Sha256};

#[inline]
fn bigint_to_challenge(bigint: BigUint, sector_nodes: usize) -> usize {
    // Ensure that we don't challenge the first node.
    let non_zero_node = (bigint % (sector_nodes - 1)) + 1usize;
    // Assumes `sector_nodes` is less than 2^32.
    non_zero_node.to_u32_digits()[0] as usize
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LayerChallenges {
    /// How many layers we are generating challenges for.
    layers: usize,
    /// The maximum count of challenges
    max_count: usize,
    pub use_synthetic: bool,
}

/// Note that since this is used in the PublicParams 'identifier'
/// method (which affects the cacheable parameters), adding a single
/// field would normally change the default 'format!' of it, so we now
/// have to override it for backwards compatibility.
impl fmt::Debug for LayerChallenges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LayerChallenges")
            .field("layers", &self.layers)
            .field("max_count", &self.max_count)
            .finish()
    }
}

impl LayerChallenges {
    pub const fn new(layers: usize, max_count: usize) -> Self {
        LayerChallenges {
            layers,
            max_count,
            use_synthetic: false,
        }
    }

    pub const fn new_synthetic(layers: usize, max_count: usize) -> Self {
        LayerChallenges {
            layers,
            max_count,
            use_synthetic: true,
        }
    }

    pub fn layers(&self) -> usize {
        self.layers
    }

    /// Porep challenge count per partition.
    pub fn challenges_count_all(&self) -> usize {
        self.max_count
    }

    /// Returns the porep challenges for partition `k`.
    pub fn derive<D: Domain>(
        &self,
        sector_nodes: usize,
        replica_id: &D,
        seed: &[u8; 32],
        k: u8,
    ) -> Vec<usize> {
        assert!(sector_nodes > 2, "Too few sector_nodes: {}", sector_nodes);
        if self.use_synthetic {
            trace!(
                "deriving porep challenges from synthetic challenges (k = {})",
                k,
            );
            self.derive_porep_from_synth(sector_nodes, replica_id, seed, k)
        } else {
            trace!("deriving porep challenges (k = {})", k);
            self.derive_porep(sector_nodes, replica_id, seed, k)
        }
    }

    /// Returns the porep challenges for partition `k`.
    fn derive_porep<D: Domain>(
        &self,
        sector_nodes: usize,
        replica_id: &D,
        seed: &[u8; 32],
        k: u8,
    ) -> Vec<usize> {
        let partition_challenge_count = self.challenges_count_all();
        (0..partition_challenge_count)
            .map(|i| {
                let j: u32 = ((partition_challenge_count * k as usize) + i) as u32;

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

    /// Returns the porep challenges for partition `k` taken from the synthetic challenges.
    fn derive_porep_from_synth<D: Domain>(
        &self,
        sector_nodes: usize,
        replica_id: &D,
        seed: &[u8; 32],
        k: u8,
    ) -> Vec<usize> {
        assert!(self.use_synthetic);
        let partition_challenge_count = self.challenges_count_all();
        let replica_id: Fr = (*replica_id).into();
        SynthChallenges::default_chacha20(sector_nodes, &replica_id).gen_porep_partition_challenges(
            partition_challenge_count,
            seed,
            k as usize,
        )
    }

    /// Returns the synthetic challenge indexes of the porep challenges for partition `k`.
    pub fn derive_porep_synth_indexes<D: Domain>(
        &self,
        sector_nodes: usize,
        replica_id: &D,
        seed: &[u8; 32],
        k: u8,
    ) -> Vec<usize> {
        assert!(self.use_synthetic, "synth-porep is disabled");
        trace!(
            "generating porep partition synthetic challenge indexes (k = {})",
            k,
        );
        let partition_challenge_count = self.challenges_count_all();
        let replica_id: Fr = (*replica_id).into();
        SynthChallenges::default_chacha20(sector_nodes, &replica_id).gen_partition_synth_indexes(
            partition_challenge_count,
            seed,
            k as usize,
        )
    }

    /// Returns the entire synthetic challenge set.
    pub fn derive_synthetic<D: Domain>(&self, sector_nodes: usize, replica_id: &D) -> Vec<usize> {
        assert!(self.use_synthetic);
        let replica_id: Fr = (*replica_id).into();
        let synth = SynthChallenges::default_chacha20(sector_nodes, &replica_id);
        trace!(
            "generating entire synthetic challenge set (num_synth_challenges = {})",
            synth.num_synth_challenges,
        );
        synth.collect()
    }
}

#[derive(Debug, Default)]
pub struct ChallengeRequirements {
    pub minimum_challenges: usize,
}

pub mod synthetic {
    use super::*;

    use std::cmp::min;
    use std::convert::TryInto;

    use chacha20::{
        cipher::{KeyIvInit, StreamCipher, StreamCipherSeek},
        ChaCha20,
    };
    use ff::PrimeField;

    pub const SYNTHETIC_POREP_VANILLA_PROOFS_KEY: &str = "SynPoRepVanillaProofs";

    // Default synthetic challenge count for production sector sizes.
    const DEFAULT_SYNTH_CHALLENGE_COUNT: usize = 1 << 14;
    const CHACHA20_NONCE: [u8; 12] = [0; 12];
    const CHACHA20_BLOCK_SIZE: u32 = 64;

    // If the number of sector nodes is less than the default synthetic challenge count, set the
    // synthetic challenge count to the number of sector nodes.
    #[inline]
    fn synth_challenge_count_for_sector_size(sector_nodes: usize) -> usize {
        min(sector_nodes, DEFAULT_SYNTH_CHALLENGE_COUNT)
    }

    // The psuedo-random function used to generate synthetic challenges.
    pub enum Prf {
        Sha256,
        ChaCha20 {
            chacha20: ChaCha20,
            // Each call to the chacha20 PRF generates two synthetic challenges (whereas the sha256
            // PRF generates one challenge per call).
            next_challenge: Option<usize>,
        },
    }

    pub struct SynthChallenges {
        sector_nodes: usize,
        replica_id: [u8; 32],
        prf: Prf,
        // The number of synthetic challenges to generate; the porep challenge set will be a subset of
        // these generated synthetic challenges.
        pub(crate) num_synth_challenges: usize,
        // The index of the next synthetic challenge to generate.
        i: usize,
    }

    impl Clone for SynthChallenges {
        fn clone(&self) -> Self {
            let SynthChallenges {
                sector_nodes,
                replica_id,
                num_synth_challenges,
                i,
                ..
            } = *self;
            let replica_id =
                Fr::from_repr_vartime(replica_id).expect("replica-id from repr should not fail");
            let mut synth = match self.prf {
                Prf::Sha256 => Self::new_sha256(sector_nodes, &replica_id, num_synth_challenges),
                Prf::ChaCha20 { .. } => {
                    Self::new_chacha20(sector_nodes, &replica_id, num_synth_challenges)
                }
            };
            synth.seek(i);
            synth
        }
    }

    impl Iterator for SynthChallenges {
        type Item = usize;

        // Generates and returns the next synthetic challenge.
        #[allow(clippy::unwrap_used)]
        fn next(&mut self) -> Option<Self::Item> {
            if self.i >= self.num_synth_challenges {
                return None;
            }

            let challenge = match self.prf {
                Prf::Sha256 => {
                    let rand_bytes = Sha256::new()
                        .chain_update(self.replica_id)
                        .chain_update(&self.i.to_le_bytes()[..4])
                        .finalize();
                    let bigint = BigUint::from_bytes_le(rand_bytes.as_ref());
                    bigint_to_challenge(bigint, self.sector_nodes)
                }
                Prf::ChaCha20 {
                    ref mut chacha20,
                    ref mut next_challenge,
                } => {
                    // Two synthetic challenges are generated per chacha20 call.
                    if next_challenge.is_some() {
                        next_challenge.take().unwrap()
                    } else {
                        let mut rand_bytes = [0u8; 64];
                        chacha20.apply_keystream(&mut rand_bytes);
                        let bigint_1 = BigUint::from_bytes_le(&rand_bytes[..32]);
                        let bigint_2 = BigUint::from_bytes_le(&rand_bytes[32..]);
                        *next_challenge = Some(bigint_to_challenge(bigint_2, self.sector_nodes));
                        bigint_to_challenge(bigint_1, self.sector_nodes)
                    }
                }
            };

            self.i += 1;
            Some(challenge)
        }
    }

    impl SynthChallenges {
        pub fn new_sha256(
            sector_nodes: usize,
            replica_id: &Fr,
            num_synth_challenges: usize,
        ) -> Self {
            assert!(
                num_synth_challenges < 1 << 32,
                "num_synth_challenges must not exceed u32"
            );
            SynthChallenges {
                sector_nodes,
                replica_id: replica_id.to_repr(),
                prf: Prf::Sha256,
                num_synth_challenges,
                i: 0,
            }
        }

        pub fn new_chacha20(
            sector_nodes: usize,
            replica_id: &Fr,
            num_synth_challenges: usize,
        ) -> Self {
            assert!(
                num_synth_challenges < 1 << 32,
                "num_synth_challenges must not exceed u32"
            );
            let replica_id = replica_id.to_repr();
            let chacha20 = {
                let key = replica_id;
                ChaCha20::new(&key.into(), &CHACHA20_NONCE.into())
            };
            SynthChallenges {
                sector_nodes,
                replica_id,
                prf: Prf::ChaCha20 {
                    chacha20,
                    next_challenge: None,
                },
                num_synth_challenges,
                i: 0,
            }
        }

        #[inline]
        pub fn default_sha256(sector_nodes: usize, replica_id: &Fr) -> Self {
            let num_synth_challenges = synth_challenge_count_for_sector_size(sector_nodes);
            Self::new_sha256(sector_nodes, replica_id, num_synth_challenges)
        }

        #[inline]
        pub fn default_chacha20(sector_nodes: usize, replica_id: &Fr) -> Self {
            let num_synth_challenges = synth_challenge_count_for_sector_size(sector_nodes);
            Self::new_chacha20(sector_nodes, replica_id, num_synth_challenges)
        }

        /// Returns the `i`-th synthetic challenge.
        pub fn gen_synth_challenge(&mut self, i: usize) -> usize {
            assert!(i < self.num_synth_challenges);
            self.seek(i);
            self.next()
                .expect("generating `i`-th challenge should not fail")
        }

        /// Seeks to the `i`-th synthetic challenge; seeking to `i` results in the next call to
        /// `SynthChallenges::next` returning the `i`-th synthetic challenge.
        pub(super) fn seek(&mut self, i: usize) {
            match self.prf {
                Prf::Sha256 => self.i = i,
                Prf::ChaCha20 {
                    ref mut chacha20,
                    ref mut next_challenge,
                } => {
                    // Seek the chacha20 keystream to the challenge pair containing the `i`-th
                    // challenge; note that two 32-byte synthetic challenges are generated per
                    // 64-byte chacha20 block.
                    let challenge_pair_index = i >> 1;
                    let keystream_pos = challenge_pair_index as u32 * CHACHA20_BLOCK_SIZE;
                    chacha20
                        .try_seek(keystream_pos)
                        .expect("seek exceeds keystream length");

                    // Round the synthetic challenge index down to the nearest even number, i.e. the
                    // index of the synthetic challenge that generates the challenge pair containing
                    // the `i`-th synthetic challenge.
                    self.i = challenge_pair_index << 1;
                    *next_challenge = None;

                    // If we are seeking to the second challenge in a pair of challenges, we need to
                    // generate the challenge pair and discard the first challenge generated; doing
                    // so will store the second challenge (i.e. challenge `i`) in `next_challenge`.
                    if i & 1 == 1 {
                        self.next()
                            .expect("generating previous challenge should not fail");
                    }
                }
            };
        }

        /// Returns the synthetic challenge indexes that select the porep partition's challenges.
        pub fn gen_partition_synth_indexes(
            &self,
            num_partition_challenges: usize,
            rand: &[u8; 32],
            k: usize,
        ) -> Vec<usize> {
            let first_porep_challenge_index = k * num_partition_challenges;

            // The number of porep challenges generated per prf call.
            let prf_challenges: usize = match self.prf {
                Prf::Sha256 => 8,
                Prf::ChaCha20 { .. } => 16,
            };

            let mut prf_index =
                (first_porep_challenge_index as f32 / prf_challenges as f32).floor() as usize;

            // The first and last prf calls may generate porep challenges not included in this
            // partition; add capacity for their output.
            let mut synth_indexes =
                Vec::<usize>::with_capacity(num_partition_challenges + 2 * prf_challenges);

            match self.prf {
                Prf::Sha256 => {
                    while synth_indexes.len() < num_partition_challenges {
                        let rand_bytes = Sha256::new()
                            .chain_update(self.replica_id)
                            .chain_update(rand)
                            .chain_update(&prf_index.to_le_bytes()[..4])
                            .finalize();

                        for bytes in rand_bytes.as_slice().chunks(4) {
                            let bytes: [u8; 4] = bytes
                                .try_into()
                                .expect("bytes slice to array conversion should not fail");
                            let rand_u32 = u32::from_le_bytes(bytes) as usize;
                            synth_indexes.push(rand_u32 % self.num_synth_challenges);
                        }

                        prf_index += 1;
                    }
                }
                Prf::ChaCha20 { .. } => {
                    let key = Sha256::new()
                        .chain_update(self.replica_id)
                        .chain_update(rand)
                        .finalize();
                    let mut chacha20 = ChaCha20::new(&key, &CHACHA20_NONCE.into());
                    let seek_pos = prf_index as u32 * CHACHA20_BLOCK_SIZE;
                    chacha20
                        .try_seek(seek_pos)
                        .expect("seek should not exceed keystream length");

                    while synth_indexes.len() < num_partition_challenges {
                        let mut rand_bytes = [0u8; 64];
                        chacha20.apply_keystream(&mut rand_bytes);
                        for bytes in rand_bytes.chunks(4) {
                            let bytes: [u8; 4] = bytes
                                .try_into()
                                .expect("bytes slice to array conversion should not fail");
                            let rand_u32 = u32::from_le_bytes(bytes) as usize;
                            synth_indexes.push(rand_u32 % self.num_synth_challenges);
                        }
                    }
                }
            };

            synth_indexes
                .into_iter()
                // Ignore leading challenges not included in partition.
                .skip(first_porep_challenge_index % prf_challenges)
                // Ignore trailing challenges not included in partition.
                .take(num_partition_challenges)
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
            synth
                .gen_partition_synth_indexes(num_partition_challenges, rand, k)
                .into_iter()
                .map(|i| synth.gen_synth_challenge(i))
                .collect()
        }

        /// Returns all porep challenges selected from the synthetic challenges.
        pub fn gen_porep_challenges(
            &self,
            num_porep_challenges: usize,
            rand: &[u8; 32],
        ) -> Vec<usize> {
            let mut synth = self.clone();
            synth
                .gen_partition_synth_indexes(num_porep_challenges, rand, 0)
                .into_iter()
                .map(|i| synth.gen_synth_challenge(i))
                .collect()
        }
    }
}

pub use synthetic::SynthChallenges;

#[cfg(test)]
mod test {
    use super::*;

    use std::collections::HashMap;

    use filecoin_hashers::sha256::Sha256Domain;
    use rand::{thread_rng, Rng, RngCore};

    #[test]
    fn test_calculate_fixed_challenges() {
        let layer_challenges = LayerChallenges::new(10, 333);
        let expected = 333;

        let calculated_count = layer_challenges.challenges_count_all();
        assert_eq!(expected as usize, calculated_count);
    }

    #[test]
    fn challenge_derivation() {
        let n = 200;
        let layers = 100;

        let challenges = LayerChallenges::new(layers, n);
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
            let one_partition_challenges = LayerChallenges::new(layers, total_challenges).derive(
                leaves,
                &replica_id,
                &seed,
                0,
            );
            let many_partition_challenges = (0..partitions)
                .flat_map(|k| {
                    LayerChallenges::new(layers, n).derive(leaves, &replica_id, &seed, k as u8)
                })
                .collect::<Vec<_>>();

            assert_eq!(one_partition_challenges, many_partition_challenges);
        }
    }

    #[test]
    fn test_synth_challenges_chacha() {
        let sector_nodes = 1 << 30;
        let replica_id = Fr::from(thread_rng().next_u64());

        let mut synth = SynthChallenges::default_chacha20(sector_nodes, &replica_id);

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
    fn test_synth_challenges_sha() {
        let sector_nodes = 1 << 30;
        let replica_id = Fr::from(thread_rng().next_u64());

        let mut synth = SynthChallenges::default_sha256(sector_nodes, &replica_id);

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
    fn test_synth_challenges_chacha_against_hardcoded() {
        let sector_nodes = 1 << 10;
        let replica_id = Fr::from(55);
        let num_synth_challenges = 21;
        let num_porep_challenges = 10;
        let porep_challenge_randomness = [1u8; 32];

        // Expected challenges for `sector_nodes = 2^10`, `replica_id = 55`, and `rand = [1; 32]`.
        let expected_synth_challenges: [usize; 21] = [
            590, 410, 223, 559, 110, 1005, 69, 888, 296, 421, 328, 246, 350, 526, 394, 685, 979,
            212, 370, 354, 146,
        ];
        let expected_porep_challenges: [usize; 10] =
            [328, 559, 246, 888, 559, 146, 590, 354, 1005, 370];

        let mut synth =
            SynthChallenges::new_chacha20(sector_nodes, &replica_id, num_synth_challenges);

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

    #[test]
    fn test_synth_challenges_sha_against_hardcoded_small_sector() {
        const SECTOR_NODES_1_KIB: usize = 1 << 5;

        let replica_id = Fr::from(55);

        // The default number of synthetic challenges generated for "small" sector sizes is equal to
        // the number of sector nodes.
        let expected_synth_challenges: [usize; SECTOR_NODES_1_KIB] = [
            19, 27, 21, 23, 17, 12, 6, 9, 2, 22, 14, 20, 31, 11, 7, 23, 30, 9, 11, 22, 22, 1, 30,
            4, 29, 15, 23, 17, 7, 24, 1, 23,
        ];

        let mut synth = SynthChallenges::default_sha256(SECTOR_NODES_1_KIB, &replica_id);

        // Test synthetic challenges against hardcoded challenges.
        let synth_challenges: Vec<usize> = synth.clone().collect();
        assert_eq!(synth_challenges, expected_synth_challenges);

        // Test individual synthetic challenge generation against hardcoded challenges.
        for (i, challenge) in synth_challenges.into_iter().enumerate() {
            assert!(challenge < SECTOR_NODES_1_KIB);
            assert_eq!(synth.gen_synth_challenge(i), challenge);
        }
    }
}
