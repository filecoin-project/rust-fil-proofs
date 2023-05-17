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
        SynthChallenges::default(sector_nodes, &replica_id, &comm_r).gen_porep_partition_challenges(
            partition_challenge_count,
            seed,
            k as usize,
        )
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
        SynthChallenges::default(sector_nodes, &replica_id, &comm_r).gen_partition_synth_indexes(
            partition_challenge_count,
            seed,
            k as usize,
        )
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
        let synth = SynthChallenges::default(sector_nodes, &replica_id, &comm_r);
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

    pub const SYNTHETIC_POREP_VANILLA_PROOFS_KEY: &str = "SynPoRepVanillaProofs";

    // Default synthetic challenge count for production sector sizes.
    const DEFAULT_SYNTH_CHALLENGE_COUNT: usize = 1 << 18;
    const CHACHA20_KEY_SIZE: usize = 32;
    const CHACHA20_BLOCK_SIZE: u32 = 64;
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

    pub struct SynthChallenges {
        sector_nodes: usize,
        replica_id: [u8; 32],
        comm_r: [u8; 32],
        // The number of synthetic challenges to generate; the porep challenge set will be a subset of
        // these generated synthetic challenges.
        pub(crate) num_synth_challenges: usize,
        // The prf used to generate synthetic challenges (not the synthetic challenge indices
        // selected for porep challenges).
        chacha20: ChaCha20,
        // Each call to chacha20 generates two synthetic challenges; this option stores the second
        // synthetic challenge generated per chacha20 call.
        next_challenge: Option<usize>,
        // The index `0 <= i < num_synth_challenges` of the next synthetic challenge to generate.
        i: usize,
    }

    impl Clone for SynthChallenges {
        fn clone(&self) -> Self {
            let mut synth = SynthChallenges {
                sector_nodes: self.sector_nodes,
                replica_id: self.replica_id,
                comm_r: self.comm_r,
                num_synth_challenges: self.num_synth_challenges,
                chacha20: chacha20_gen(&self.replica_id, &self.comm_r),
                next_challenge: None,
                i: 0,
            };
            synth.seek(self.i);
            synth
        }
    }

    impl Iterator for SynthChallenges {
        type Item = usize;

        // Generates and returns the next synthetic challenge.
        fn next(&mut self) -> Option<Self::Item> {
            if self.i >= self.num_synth_challenges {
                return None;
            }

            // Two synthetic challenges are generated per chacha20 call.
            let challenge = match self.next_challenge.take() {
                Some(next_challenge) => next_challenge,
                None => {
                    let mut rand_bytes = [0u8; 64];
                    self.chacha20.apply_keystream(&mut rand_bytes);
                    let bigint_1 = BigUint::from_bytes_le(&rand_bytes[..32]);
                    let bigint_2 = BigUint::from_bytes_le(&rand_bytes[32..]);
                    self.next_challenge = Some(bigint_to_challenge(bigint_2, self.sector_nodes));
                    bigint_to_challenge(bigint_1, self.sector_nodes)
                }
            };

            self.i += 1;
            Some(challenge)
        }
    }

    impl SynthChallenges {
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
            SynthChallenges {
                sector_nodes,
                replica_id,
                comm_r,
                num_synth_challenges,
                chacha20,
                next_challenge: None,
                i: 0,
            }
        }

        pub fn default(sector_nodes: usize, replica_id: &Fr, comm_r: &Fr) -> Self {
            let num_synth_challenges = min(sector_nodes, DEFAULT_SYNTH_CHALLENGE_COUNT);
            Self::new(sector_nodes, replica_id, comm_r, num_synth_challenges)
        }

        /// Seeks to the `i`-th synthetic challenge; seeking to `i` results in the next call to
        /// `SynthChallenges::next` returning the `i`-th synthetic challenge.
        pub(super) fn seek(&mut self, i: usize) {
            if i >= self.num_synth_challenges {
                self.i = i;
                self.next_challenge = None;
                return;
            }

            // Seek the chacha20 keystream to the 64-byte block used to generate challenge `i`'s 32
            // bytes (each 64-byte keystream block generates two 32-byte synthetic challenges).
            let block_index = i >> 1;
            let seek_pos = block_index as u32 * CHACHA20_BLOCK_SIZE;
            self.chacha20
                .try_seek(seek_pos)
                .expect("seek should not exceed keystream length");

            // Round the challenge index down to the nearest even number, i.e. set the challenge
            // index to the first challenge in the 2-challenge chacha20 block.
            self.i = block_index << 1;
            self.next_challenge = None;

            // If we are seeking to the second challenge generated by a chacha20 block (i.e. if `i`
            // is odd), we must generate the challenge pair then discard the first challenge
            // generated; doing so will store challenge `i` in `self.next_challenge`.
            if i & 1 == 1 {
                self.next()
                    .expect("challenge iterator should not be finished");
            }
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
            let last_porep_challenge = first_porep_challenge + num_partition_challenges - 1;

            // The number of porep challenges generated per prf call.
            let porep_challenges_per_block = 16;
            // Indexes of chacha20 blocks used to generate partition `k`'s challenges.
            let first_block = first_porep_challenge / porep_challenges_per_block;
            let last_block = last_porep_challenge / porep_challenges_per_block;

            // If the first porep challenge of the partition is not aligned to the first porep
            // challenge generated by a chacha20 block, skip the leading challenges generated by the
            // the first chacha20 block, i.e. skip the previous partition's last challenges.
            let skip_first_challenges = first_porep_challenge % porep_challenges_per_block;

            let mut chacha20 = chacha20_select(&self.replica_id, rand);
            let seek_pos = first_block as u32 * CHACHA20_BLOCK_SIZE;
            chacha20
                .try_seek(seek_pos)
                .expect("seek should not exceed keystream length");

            (first_block..=last_block)
                .flat_map(|_| {
                    let mut rand_bytes = [0u8; 64];
                    chacha20.apply_keystream(&mut rand_bytes);
                    rand_bytes
                })
                .collect::<Vec<u8>>()
                .chunks(4)
                .map(|index_bytes| {
                    let index_bytes: [u8; 4] =
                        index_bytes.try_into().expect("conversion should not fail");
                    let synth_index = u32::from_le_bytes(index_bytes) as usize;
                    synth_index % self.num_synth_challenges
                })
                .skip(skip_first_challenges)
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
            self.gen_partition_synth_indexes(num_partition_challenges, rand, k)
                .into_iter()
                .map(|i| synth.gen_synth_challenge(i))
                .collect()
        }

        /// Returns all porep challenges selected from the synthetic challenges.
        #[inline]
        pub fn gen_porep_challenges(
            &self,
            num_porep_challenges: usize,
            rand: &[u8; 32],
        ) -> Vec<usize> {
            self.gen_porep_partition_challenges(num_porep_challenges, rand, 0)
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
    fn test_synth_challenges_32gib() {
        let sector_nodes = 1 << 30;
        let replica_id = Fr::from(thread_rng().next_u64());
        let comm_r = Fr::from(thread_rng().next_u64());

        let mut synth = SynthChallenges::default(sector_nodes, &replica_id, &comm_r);

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
            SynthChallenges::new(sector_nodes, &replica_id, &comm_r, num_synth_challenges);

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
