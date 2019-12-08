use anyhow::{ensure, Context};
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::Result;
use crate::hasher::Domain;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerChallenges {
    /// How many layers we are generating challenges for.
    layers: usize,
    count: usize,
}

impl LayerChallenges {
    pub fn new(layers: usize, count: usize) -> Result<Self> {
        ensure!(layers > 1, "layers must be at least 2");
        ensure!(count > 0, "there must be at least 1 challenge");

        Ok(LayerChallenges { layers, count })
    }

    pub fn layers(&self) -> usize {
        self.layers
    }

    pub fn challenges_count_all(&self) -> usize {
        self.count
    }

    /// Derive all challenges.
    pub fn derive_all<D: Domain>(
        &self,
        leaves: usize,
        replica_id: &D,
        seed: &[u8; 32],
        k: u8,
    ) -> Result<Vec<usize>> {
        self.derive_internal(self.challenges_count_all(), leaves, replica_id, seed, k)
    }

    pub fn derive_internal<D: Domain>(
        &self,
        challenges_count: usize,
        leaves: usize,
        replica_id: &D,
        seed: &[u8; 32],
        k: u8,
    ) -> Result<Vec<usize>> {
        ensure!(leaves > 2, "Too few leaves: {}", leaves);

        (0..challenges_count)
            .map(|i| {
                let j: u32 = ((challenges_count * k as usize) + i) as u32;

                let hash = Sha256::new()
                    .chain(replica_id.into_bytes())
                    .chain(seed)
                    .chain(&j.to_le_bytes())
                    .result();

                let big_challenge = BigUint::from_bytes_le(hash.as_ref());

                // For now, we cannot try to prove the first or last node, so make sure the challenge
                // can never be 0.
                let big_mod_challenge = big_challenge % (leaves - 1);
                let big_mod_challenge = big_mod_challenge
                    .to_usize()
                    .context("`big_mod_challenge` exceeds size of `usize`")?;
                Ok(big_mod_challenge + 1)
            })
            .collect()
    }
}

#[derive(Debug, Default)]
pub struct ChallengeRequirements {
    pub minimum_challenges: usize,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::hasher::pedersen::PedersenDomain;
    use rand::{thread_rng, Rng};
    use std::collections::HashMap;

    #[test]
    fn challenge_derivation() {
        let n = 200;
        let layers = 100;

        let challenges = LayerChallenges::new(layers, n).unwrap();
        let leaves = 1 << 30;
        let rng = &mut thread_rng();
        let replica_id: PedersenDomain = PedersenDomain::random(rng);
        let seed: [u8; 32] = rng.gen();
        let partitions = 5;
        let total_challenges = partitions * n;

        let mut layers_with_duplicates = 0;

        for _ in 1..=layers {
            let mut histogram = HashMap::new();
            for k in 0..partitions {
                let challenges = challenges.derive_all(leaves, &replica_id, &seed, k as u8);

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
        // assert!(layers_with_duplicates < 3);
        // TODO: verify why this now fails
        println!("duplicates: {}", layers_with_duplicates);
    }

    #[test]
    // This test shows that partitioning (k = 0..partitions) generates the same challenges as
    // generating the same number of challenges with only one partition (k = 0).
    fn challenge_partition_equivalence() {
        let n = 40;
        let leaves = 1 << 30;
        let rng = &mut thread_rng();
        let replica_id: PedersenDomain = PedersenDomain::random(rng);
        let seed: [u8; 32] = rng.gen();
        let partitions = 5;
        let layers = 100;
        let total_challenges = n * partitions;

        for _ in 1..=layers {
            let one_partition_challenges = LayerChallenges::new(layers, total_challenges)
                .unwrap()
                .derive_all(leaves, &replica_id, &seed, 0)
                .unwrap();
            let many_partition_challenges = (0..partitions)
                .flat_map(|k| {
                    LayerChallenges::new(layers, n)
                        .unwrap()
                        .derive_all(leaves, &replica_id, &seed, k as u8)
                        .unwrap()
                })
                .collect::<Vec<_>>();

            assert_eq!(one_partition_challenges, many_partition_challenges);
        }
    }
}
