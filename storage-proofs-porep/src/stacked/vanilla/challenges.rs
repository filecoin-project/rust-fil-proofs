use filecoin_hashers::Domain;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[inline]
fn bigint_to_challenge(bigint: BigUint, sector_nodes: usize) -> usize {
    // Ensure that we don't challenge the first node.
    let non_zero_node = (bigint % (sector_nodes - 1)) + 1usize;
    // Assumes `sector_nodes` is less than 2^32.
    non_zero_node.to_u32_digits()[0] as usize
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerChallenges {
    /// How many layers we are generating challenges for.
    layers: usize,
    /// The maximum count of challenges
    max_count: usize,
    use_synthetic: bool,
}

impl LayerChallenges {
    pub const fn new(layers: usize, max_count: usize, use_synthetic: bool) -> Self {
        LayerChallenges {
            layers,
            max_count,
            use_synthetic,
        }
    }

    pub fn layers(&self) -> usize {
        self.layers
    }

    pub fn challenges_count_all(&self) -> usize {
        self.max_count
    }

    pub fn use_synthetic(&self) -> bool {
        self.use_synthetic
    }

    /// Derive all challenges.
    pub fn derive<D: Domain>(
        &self,
        leaves: usize,
        replica_id: &D,
        seed: &[u8; 32],
        k: u8,
    ) -> Vec<usize> {
        if self.use_synthetic {
            self.derive_synthetic_internal(self.challenges_count_all(), leaves, replica_id, seed, k)
        } else {
            self.derive_internal(self.challenges_count_all(), leaves, replica_id, seed, k)
        }
    }

    pub fn derive_internal<D: Domain>(
        &self,
        challenges_count: usize,
        leaves: usize,
        replica_id: &D,
        seed: &[u8; 32],
        k: u8,
    ) -> Vec<usize> {
        assert!(leaves > 2, "Too few leaves: {}", leaves);

        (0..challenges_count)
            .map(|i| {
                let j: u32 = ((challenges_count * k as usize) + i) as u32;

                let hash = Sha256::new()
                    .chain_update(replica_id.into_bytes())
                    .chain_update(seed)
                    .chain_update(j.to_le_bytes())
                    .finalize();

                let bigint = BigUint::from_bytes_le(hash.as_ref());
                bigint_to_challenge(bigint, leaves)
            })
            .collect()
    }

    pub fn derive_synthetic_internal<D: Domain>(
        &self,
        _challenges_count: usize,
        leaves: usize,
        replica_id: &D,
        _seed: &[u8; 32],
        _k: u8,
    ) -> Vec<usize> {
        use blstrs::Scalar as Fr;
        assert!(leaves > 2, "Too few leaves: {}", leaves);

        // FIXME: better way to convert Domain to Scalar?
        let mut id = [0u8; 32];
        id[..].copy_from_slice(&replica_id.into_bytes());
        let generator = SynthChallenges::default_chacha20(leaves, &Fr::from_bytes_le(&id).unwrap());

        generator.collect()
    }
}

#[derive(Debug, Default)]
pub struct ChallengeRequirements {
    pub minimum_challenges: usize,
}

pub mod synthetic {
    use super::*;

    use std::convert::TryInto;

    use blstrs::Scalar as Fr;
    use chacha20::{
        cipher::{KeyIvInit, StreamCipher, StreamCipherSeek},
        ChaCha20,
    };
    use ff::PrimeField;

    // Default synthetic challenge count for production sector sizes.
    const DEFAULT_SYNTH_CHALLENGE_COUNT: usize = 1 << 14;
    const CHACHA20_NONCE: [u8; 12] = [0; 12];
    const CHACHA20_BLOCK_SIZE: u32 = 64;

    // The psuedo-random function used to generate synthetic challenges.
    pub enum Prf {
        Sha256,
        ChaCha20 {
            chacha20: ChaCha20,
            // Each call to the chacha20 prf generates two synthetic challenges.
            next_challenge: Option<usize>,
        },
    }

    pub struct SynthChallenges {
        sector_nodes: usize,
        replica_id: [u8; 32],
        prf: Prf,
        num_synth_challenges: usize,
        i: usize,
    }

    impl Iterator for SynthChallenges {
        type Item = usize;

        // Returns the next synthetic challenge.
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
            // If the default synthethic challenge count exceeds the number of sector nodes, then
            // challenge all sector nodes.
            let num_synth_challenges = if sector_nodes < DEFAULT_SYNTH_CHALLENGE_COUNT {
                sector_nodes
            } else {
                DEFAULT_SYNTH_CHALLENGE_COUNT
            };
            Self::new_sha256(sector_nodes, replica_id, num_synth_challenges)
        }

        #[inline]
        pub fn default_chacha20(sector_nodes: usize, replica_id: &Fr) -> Self {
            // If the default synthethic challenge count exceeds the number of sector nodes, then
            // challenge all sector nodes.
            let num_synth_challenges = if sector_nodes < DEFAULT_SYNTH_CHALLENGE_COUNT {
                sector_nodes
            } else {
                DEFAULT_SYNTH_CHALLENGE_COUNT
            };
            Self::new_chacha20(sector_nodes, replica_id, num_synth_challenges)
        }

        // Returns the `i`-th synthetic challenge.
        pub fn gen_synth_challenge(&mut self, i: usize) -> usize {
            assert!(i < self.num_synth_challenges);
            self.seek(i);
            self.next()
                .expect("generating `i`-th challenge should not fail")
        }

        // Seek to the `i`-th synthetic challenge; seeking to `i` results in the next call to
        // `SynthChallenges::next` returning the `i`-th synthetic challenge.
        pub(super) fn seek(&mut self, i: usize) {
            match self.prf {
                Prf::Sha256 => self.i = i,
                Prf::ChaCha20 {
                    ref mut chacha20,
                    ref mut next_challenge,
                } => {
                    // Two 32-byte synthetic challenges are generated per 64-byte chacha20 block.
                    let challenge_pair_index = i >> 1;
                    let keystream_pos = challenge_pair_index as u32 * CHACHA20_BLOCK_SIZE;
                    chacha20
                        .try_seek(keystream_pos)
                        .expect("seek exceeds keystream length");

                    // Round the synthetic challenge index down to the nearest even number, i.e. the
                    // synthetic challenge index that generates the pair containing challenge `i`.
                    self.i = challenge_pair_index << 1;
                    *next_challenge = None;

                    // If we are seeking to the second challenge in a pair of challenges, we need to
                    // generate the pair (storing challenge `i` in `self`'s `next_challenge`.)
                    if i & 1 == 1 {
                        self.next()
                            .expect("generating previous challenge should not fail");
                    }
                }
            };
        }

        #[allow(clippy::unwrap_used)]
        pub fn gen_porep_challenges(
            mut self,
            num_porep_challenges: usize,
            rand: &[u8; 32],
        ) -> Vec<usize> {
            let rand_u32s: Vec<u32> = match self.prf {
                Prf::Sha256 => {
                    // For each digest `i` we generate a chunk of 8 porep challenges.
                    let num_chunks = (num_porep_challenges as f32 / 8.0).ceil() as usize;
                    let mut rand_u32s = Vec::<u32>::with_capacity(num_chunks << 3);
                    for i in 0..num_chunks {
                        let rand_bytes = Sha256::new()
                            .chain_update(self.replica_id)
                            .chain_update(rand)
                            .chain_update(&i.to_le_bytes()[..4])
                            .finalize();
                        let rand_bytes: &[u8] = rand_bytes.as_ref();
                        for bytes in rand_bytes.chunks(4) {
                            rand_u32s.push(u32::from_le_bytes(bytes.try_into().unwrap()));
                        }
                    }
                    rand_u32s
                }
                Prf::ChaCha20 { .. } => {
                    let key = Sha256::new()
                        .chain_update(self.replica_id)
                        .chain_update(rand)
                        .finalize();
                    let mut chacha20 = ChaCha20::new(&key, &CHACHA20_NONCE.into());
                    // For each encryption `i` we generate a chunk of 16 porep challenges.
                    let num_chunks = (num_porep_challenges as f32 / 16.0).ceil() as usize;
                    let mut rand_u32s = Vec::<u32>::with_capacity(num_chunks << 4);
                    for _ in 0..num_chunks {
                        let mut rand_bytes = [0u8; 64];
                        chacha20.apply_keystream(&mut rand_bytes);
                        for bytes in rand_bytes.chunks(4) {
                            rand_u32s.push(u32::from_le_bytes(bytes.try_into().unwrap()));
                        }
                    }
                    rand_u32s
                }
            };

            rand_u32s
                .iter()
                .take(num_porep_challenges)
                .map(|&rand_u32| {
                    let synth_challenge_index = rand_u32 as usize % self.num_synth_challenges;
                    self.gen_synth_challenge(synth_challenge_index)
                })
                .collect()
        }
    }
}

pub use synthetic::SynthChallenges;

#[cfg(test)]
mod test {
    use super::*;

    use std::collections::HashMap;

    use blstrs::Scalar as Fr;
    use filecoin_hashers::sha256::Sha256Domain;
    use rand::{thread_rng, Rng, RngCore};

    #[test]
    fn test_calculate_fixed_challenges() {
        let layer_challenges = LayerChallenges::new(10, 333, false);
        let expected = 333;

        let calculated_count = layer_challenges.challenges_count_all();
        assert_eq!(expected as usize, calculated_count);
    }

    #[test]
    fn challenge_derivation() {
        let n = 200;
        let layers = 100;

        let challenges = LayerChallenges::new(layers, n, false);
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
    fn synthetic_challenge_derivation_chacha() {
        let sector_nodes = 1 << 30;
        let replica_id = Fr::from(thread_rng().next_u64());

        let generator = SynthChallenges::default_chacha20(sector_nodes, &replica_id);
        let challenges: Vec<usize> = generator.collect();
        assert!(challenges
            .iter()
            .all(|cur_challenge| cur_challenge < &sector_nodes));

        let mut generator = SynthChallenges::default_chacha20(sector_nodes, &replica_id);
        for (i, expected) in challenges.into_iter().enumerate() {
            let challenge = generator.gen_synth_challenge(i);
            assert_eq!(challenge, expected);
        }
    }

    #[test]
    fn synthetic_challenge_derivation_sha() {
        let sector_nodes = 1 << 30;
        let replica_id = Fr::from(thread_rng().next_u64());

        let generator = SynthChallenges::default_sha256(sector_nodes, &replica_id);
        let challenges: Vec<usize> = generator.collect();
        assert!(challenges
            .iter()
            .all(|cur_challenge| cur_challenge < &sector_nodes));

        let mut generator = SynthChallenges::default_sha256(sector_nodes, &replica_id);
        for (i, expected) in challenges.into_iter().enumerate() {
            let challenge = generator.gen_synth_challenge(i);
            assert_eq!(challenge, expected);
        }
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
            let one_partition_challenges = LayerChallenges::new(layers, total_challenges, false)
                .derive(leaves, &replica_id, &seed, 0);
            let many_partition_challenges = (0..partitions)
                .flat_map(|k| {
                    LayerChallenges::new(layers, n, false).derive(
                        leaves,
                        &replica_id,
                        &seed,
                        k as u8,
                    )
                })
                .collect::<Vec<_>>();

            assert_eq!(one_partition_challenges, many_partition_challenges);
        }
    }

    #[test]
    fn test_synthetic_challenges() {
        use blstrs::Scalar as Fr;

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

        let synth_challenges: Vec<usize> =
            SynthChallenges::new_chacha20(sector_nodes, &replica_id, num_synth_challenges)
                .collect();
        assert!(synth_challenges.iter().all(|c| c < &sector_nodes));
        assert_eq!(
            synth_challenges[..expected_synth_challenges.len()],
            expected_synth_challenges
        );

        let mut synth =
            SynthChallenges::new_chacha20(sector_nodes, &replica_id, num_synth_challenges);
        for i in (0..num_synth_challenges).rev() {
            assert_eq!(synth.gen_synth_challenge(i), synth_challenges[i]);
        }
        synth.seek(num_synth_challenges);
        assert!(synth.next().is_none());

        let porep_challenges =
            synth.gen_porep_challenges(num_porep_challenges, &porep_challenge_randomness);
        assert_eq!(
            porep_challenges[..expected_porep_challenges.len()],
            expected_porep_challenges
        );
    }

    #[test]
    fn test_synthetic_challenges_sha_small() {
        let sector_nodes_1kib = 1 << 5;
        let replica_id = Fr::from(55);

        let generator = SynthChallenges::default_sha256(sector_nodes_1kib, &replica_id);
        let synth_challenges: Vec<usize> = generator.collect();
        assert!(synth_challenges
            .iter()
            .all(|challenge| challenge < &sector_nodes_1kib));
        assert_eq!(
            synth_challenges,
            [
                19, 27, 21, 23, 17, 12, 6, 9, 2, 22, 14, 20, 31, 11, 7, 23, 30, 9, 11, 22, 22, 1,
                30, 4, 29, 15, 23, 17, 7, 24, 1, 23
            ]
        );

        let mut generator = SynthChallenges::default_sha256(sector_nodes_1kib, &replica_id);
        for (i, expected) in synth_challenges.into_iter().enumerate() {
            let challenge = generator.gen_synth_challenge(i);
            assert_eq!(challenge, expected);
        }
    }
}
