use std::fmt;

use blstrs::Scalar as Fr;
use log::trace;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use filecoin_hashers::Domain;
use sha2::{Digest, Sha256};

#[inline]
fn bigint_to_challenge(bigint: BigUint, sector_nodes: usize) -> usize {
    debug_assert!(sector_nodes < 1 << 32);
    // Ensure that we don't challenge the first node.
    let non_zero_node = (bigint % (sector_nodes - 1)) + 1usize;
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
        comm_r: &D,
        seed: &[u8; 32],
        k: u8,
    ) -> Vec<usize> {
        assert!(sector_nodes > 2, "Too few sector_nodes: {}", sector_nodes);
        if self.use_synthetic {
            trace!(
                "deriving porep challenges from synthetic challenges (k = {})",
                k,
            );
            self.derive_porep_synth(sector_nodes, replica_id, comm_r, seed, k)
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
    fn derive_porep_synth<D: Domain>(
        &self,
        sector_nodes: usize,
        replica_id: &D,
        comm_r: &D,
        seed: &[u8; 32],
        k: u8,
    ) -> Vec<usize> {
        assert!(self.use_synthetic);
        let partition_challenge_count = self.challenges_count_all();
        let replica_id: Fr = (*replica_id).into();
        let comm_r: Fr = (*comm_r).into();
        SynthChallenges::default_chacha20(sector_nodes, &replica_id, &comm_r)
            .gen_porep_partition_challenges(partition_challenge_count, seed, k as usize)
    }

    /// Returns the synthetic challenge indexes of the porep challenges for partition `k`.
    pub fn derive_synth_indexes<D: Domain>(
        &self,
        sector_nodes: usize,
        replica_id: &D,
        comm_r: &D,
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
        let comm_r: Fr = (*comm_r).into();
        SynthChallenges::default_chacha20(sector_nodes, &replica_id, &comm_r)
            .gen_partition_synth_indexes(partition_challenge_count, seed, k as usize)
    }

    /// Returns the entire synthetic challenge set.
    pub fn derive_synthetic<D: Domain>(
        &self,
        sector_nodes: usize,
        replica_id: &D,
        comm_r: &D,
    ) -> Vec<usize> {
        assert!(self.use_synthetic);
        let replica_id: Fr = (*replica_id).into();
        let comm_r: Fr = (*comm_r).into();
        let synth = SynthChallenges::default_chacha20(sector_nodes, &replica_id, &comm_r);
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

    use blake2b_simd::Params as Blake2b;
    use chacha20::{
        cipher::{KeyIvInit, StreamCipher, StreamCipherSeek},
        ChaCha20,
    };
    use ff::PrimeField;
    use hmac::{Hmac, Mac};

    pub const SYNTHETIC_POREP_VANILLA_PROOFS_KEY: &str = "SynPoRepVanillaProofs";

    // Default synthetic challenge count for production sector sizes.
    const DEFAULT_SYNTH_CHALLENGE_COUNT: usize = 1 << 18;
    const CHACHA20_KEY_SIZE: usize = 32;
    const CHACHA20_BLOCK_SIZE: u32 = 64;
    const CHACHA20_NONCE: &[u8; 12] = b"synth-porep\x00";

    // If the number of sector nodes is less than the default synthetic challenge count, set the
    // synthetic challenge count to the number of sector nodes.
    #[inline]
    fn synth_challenge_count(sector_nodes: usize) -> usize {
        min(sector_nodes, DEFAULT_SYNTH_CHALLENGE_COUNT)
    }

    // The psuedo-random function used to generate synthetic challenges.
    pub enum Prf {
        Sha256 {
            sha256: Hmac<Sha256>,
        },
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
        comm_r: [u8; 32],
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
                comm_r,
                num_synth_challenges,
                i,
                ..
            } = *self;
            let replica_id =
                Fr::from_repr_vartime(replica_id).expect("replica-id from repr should not fail");
            let comm_r = Fr::from_repr_vartime(comm_r).expect("comm-r from repr should not fail");
            let mut synth = if self.is_sha256() {
                Self::new_sha256(sector_nodes, &replica_id, &comm_r, num_synth_challenges)
            } else {
                Self::new_chacha20(sector_nodes, &replica_id, &comm_r, num_synth_challenges)
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

            let challenge = match &mut self.prf {
                Prf::Sha256 { sha256 } => {
                    let rand_bytes = sha256
                        .clone()
                        .chain_update(&self.i.to_le_bytes()[..4])
                        .finalize();
                    let bigint = BigUint::from_bytes_le(&rand_bytes.into_bytes());
                    bigint_to_challenge(bigint, self.sector_nodes)
                }
                Prf::ChaCha20 {
                    chacha20,
                    next_challenge,
                } => {
                    // Two synthetic challenges are generated per chacha20 call.
                    match next_challenge.take() {
                        Some(next_challenge) => next_challenge,
                        None => {
                            let mut rand_bytes = [0u8; 64];
                            chacha20.apply_keystream(&mut rand_bytes);
                            let bigint_1 = BigUint::from_bytes_le(&rand_bytes[..32]);
                            let bigint_2 = BigUint::from_bytes_le(&rand_bytes[32..]);
                            *next_challenge =
                                Some(bigint_to_challenge(bigint_2, self.sector_nodes));
                            bigint_to_challenge(bigint_1, self.sector_nodes)
                        }
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
            comm_r: &Fr,
            num_synth_challenges: usize,
        ) -> Self {
            assert!(
                num_synth_challenges < 1 << 32,
                "num_synth_challenges must not exceed u32"
            );
            let replica_id = replica_id.to_repr();
            let comm_r = comm_r.to_repr();
            let sha256 =
                Hmac::<Sha256>::new_from_slice(b"filecoin.io|PoRep|1|Synthetic|1|Generation")
                    .expect("should not fail")
                    .chain_update(replica_id)
                    .chain_update(comm_r);
            SynthChallenges {
                sector_nodes,
                replica_id,
                comm_r,
                prf: Prf::Sha256 { sha256 },
                num_synth_challenges,
                i: 0,
            }
        }

        pub fn new_chacha20(
            sector_nodes: usize,
            replica_id: &Fr,
            comm_r: &Fr,
            num_synth_challenges: usize,
        ) -> Self {
            assert!(
                num_synth_challenges < 1 << 32,
                "num_synth_challenges must not exceed u32"
            );
            let replica_id = replica_id.to_repr();
            let comm_r = comm_r.to_repr();
            let key = Blake2b::new()
                .hash_length(CHACHA20_KEY_SIZE)
                .key(b"filecoin.io|PoRep|1|Synthetic|1|Generation")
                .to_state()
                .update(&replica_id)
                .update(&comm_r)
                .finalize();
            let chacha20 = ChaCha20::new(key.as_bytes().into(), CHACHA20_NONCE.into());
            SynthChallenges {
                sector_nodes,
                replica_id,
                comm_r,
                prf: Prf::ChaCha20 {
                    chacha20,
                    next_challenge: None,
                },
                num_synth_challenges,
                i: 0,
            }
        }

        #[inline]
        pub fn default_sha256(sector_nodes: usize, replica_id: &Fr, comm_r: &Fr) -> Self {
            let num_synth_challenges = synth_challenge_count(sector_nodes);
            Self::new_sha256(sector_nodes, replica_id, comm_r, num_synth_challenges)
        }

        #[inline]
        pub fn default_chacha20(sector_nodes: usize, replica_id: &Fr, comm_r: &Fr) -> Self {
            let num_synth_challenges = synth_challenge_count(sector_nodes);
            Self::new_chacha20(sector_nodes, replica_id, comm_r, num_synth_challenges)
        }

        #[inline]
        pub fn is_sha256(&self) -> bool {
            match self.prf {
                Prf::Sha256 { .. } => true,
                Prf::ChaCha20 { .. } => false,
            }
        }

        #[inline]
        pub fn is_chacha20(&self) -> bool {
            !self.is_sha256()
        }

        /// Seeks to the `i`-th synthetic challenge; seeking to `i` results in the next call to
        /// `SynthChallenges::next` returning the `i`-th synthetic challenge.
        pub(super) fn seek(&mut self, i: usize) {
            match self.prf {
                Prf::Sha256 { .. } => self.i = i,
                Prf::ChaCha20 {
                    ref mut chacha20,
                    ref mut next_challenge,
                } => {
                    // Seek the chacha20 keystream to the challenge pair containing the `i`-th
                    // challenge; note that two 32-byte synthetic challenges are generated per
                    // 64-byte chacha20 block.
                    let challenge_pair_index = i >> 1;
                    let seek_pos = challenge_pair_index as u32 * CHACHA20_BLOCK_SIZE;
                    chacha20
                        .try_seek(seek_pos)
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

        /// Returns the `i`-th synthetic challenge.
        pub fn gen_synth_challenge(&mut self, i: usize) -> usize {
            assert!(i < self.num_synth_challenges);
            self.seek(i);
            self.next()
                .expect("generating `i`-th challenge should not fail")
        }

        /// Returns the synthetic challenge indexes that select the porep partition's challenges.
        pub fn gen_partition_synth_indexes(
            &self,
            num_partition_challenges: usize,
            rand: &[u8; 32],
            k: usize,
        ) -> Vec<usize> {
            // The number of porep challenges generated per prf call.
            let prf_challenges: usize = if self.is_sha256() { 8 } else { 16 };

            let first_porep_challenge = k * num_partition_challenges;
            let last_porep_challenge = first_porep_challenge + num_partition_challenges - 1;
            let first_prf_index = first_porep_challenge / prf_challenges;
            let last_prf_index = last_porep_challenge / prf_challenges;

            // If the first porep challenge's synthetic index bytes are not aligned to the first
            // bytes generated by the prf, skip the leading bytes output by the first prf
            // corresponding with challenges in the previous partition.
            let skip_first_challenges = first_porep_challenge % prf_challenges;

            let rand_bytes: Vec<u8> = if self.is_sha256() {
                let sha256 =
                    Hmac::<Sha256>::new_from_slice(b"filecoin.io|PoRep|1|Synthetic|1|Selection")
                        .expect("should not fail")
                        .chain_update(self.replica_id)
                        .chain_update(rand);
                (first_prf_index..=last_prf_index)
                    .flat_map(|prf_index| {
                        sha256
                            .clone()
                            .chain_update(&prf_index.to_le_bytes()[..4])
                            .finalize()
                            .into_bytes()
                    })
                    .collect()
            } else {
                let key = Blake2b::new()
                    .hash_length(CHACHA20_KEY_SIZE)
                    .key(b"filecoin.io|PoRep|1|Synthetic|1|Selection")
                    .to_state()
                    .update(&self.replica_id)
                    .update(rand)
                    .finalize();
                let mut chacha20 = ChaCha20::new(key.as_bytes().into(), CHACHA20_NONCE.into());
                let seek_pos = first_prf_index as u32 * CHACHA20_BLOCK_SIZE;
                chacha20
                    .try_seek(seek_pos)
                    .expect("seek should not exceed keystream length");

                (first_prf_index..=last_prf_index)
                    .flat_map(|_| {
                        let mut rand_bytes = [0u8; 64];
                        chacha20.apply_keystream(&mut rand_bytes);
                        rand_bytes.to_vec()
                    })
                    .collect()
            };

            rand_bytes
                .chunks(4)
                .skip(skip_first_challenges)
                .take(num_partition_challenges)
                .map(|rand_bytes| {
                    let rand_bytes: [u8; 4] =
                        rand_bytes.try_into().expect("conversion should not fail");
                    let rand_u32 = u32::from_le_bytes(rand_bytes) as usize;
                    rand_u32 % self.num_synth_challenges
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
            let synth_indexes = self.gen_partition_synth_indexes(num_partition_challenges, rand, k);
            let mut synth = self.clone();
            synth_indexes
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
            self.clone()
                .gen_porep_partition_challenges(num_porep_challenges, rand, 0)
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
                let challenges = challenges.derive_porep(leaves, &replica_id, &seed, k as u8);

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
            let one_partition_challenges = LayerChallenges::new(layers, total_challenges)
                .derive_porep(leaves, &replica_id, &seed, 0);
            let many_partition_challenges = (0..partitions)
                .flat_map(|k| {
                    LayerChallenges::new(layers, n).derive_porep(
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
    fn test_synth_challenges_chacha() {
        let sector_nodes = 1 << 30;
        let replica_id = Fr::from(thread_rng().next_u64());
        let comm_r = Fr::from(thread_rng().next_u64());

        let mut synth = SynthChallenges::default_chacha20(sector_nodes, &replica_id, &comm_r);

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
        let comm_r = Fr::from(thread_rng().next_u64());

        let mut synth = SynthChallenges::default_sha256(sector_nodes, &replica_id, &comm_r);

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
            SynthChallenges::new_chacha20(sector_nodes, &replica_id, &comm_r, num_synth_challenges);

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
        let comm_r = Fr::from(101);

        // The default number of synthetic challenges generated for "small" sector sizes is equal to
        // the number of sector nodes.
        let expected_synth_challenges: [usize; SECTOR_NODES_1_KIB] = [
            30, 30, 7, 3, 15, 14, 11, 29, 16, 18, 22, 2, 26, 30, 8, 19, 4, 12, 26, 14, 8, 2, 3, 17,
            20, 1, 24, 4, 7, 12, 27, 8,
        ];

        let mut synth = SynthChallenges::default_sha256(SECTOR_NODES_1_KIB, &replica_id, &comm_r);

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
