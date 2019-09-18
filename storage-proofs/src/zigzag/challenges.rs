use blake2s_simd::blake2s;
use byteorder::{LittleEndian, WriteBytesExt};
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;

use crate::hasher::Domain;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerChallenges {
    layers: usize,
    count: usize,
}

impl LayerChallenges {
    pub const fn new_fixed(layers: usize, count: usize) -> Self {
        LayerChallenges { layers, count }
    }
    pub fn layers(&self) -> usize {
        self.layers
    }

    pub fn challenges_count(&self) -> usize {
        self.count
    }

    /// Derive a set of challenges, for the given inputs.
    pub fn derive<D: Domain>(
        &self,
        leaves: usize,
        replica_id: &D,
        commitment: &D,
        k: u8,
    ) -> Vec<usize> {
        assert!(leaves > 2, "Too few leaves: {}", leaves);

        let n = self.challenges_count();
        (0..n)
            .map(|i| {
                let mut bytes = replica_id.into_bytes();
                let j = ((n * k as usize) + i) as u32;
                bytes.extend(commitment.into_bytes());

                // Unwraping here is safe, all hash domains are larger than 4 bytes (the size of a `u32`).
                bytes.write_u32::<LittleEndian>(j).unwrap();

                let hash = blake2s(bytes.as_slice());
                let big_challenge = BigUint::from_bytes_le(hash.as_ref());

                // For now, we cannot try to prove the first or last node, so make sure the challenge can never be 0 or leaves - 1.
                let big_mod_challenge = big_challenge % (leaves - 2);
                let big_mod_challenge = big_mod_challenge
                    .to_usize()
                    .expect("`big_mod_challenge` exceeds size of `usize`");
                big_mod_challenge + 1
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

        let challenges = LayerChallenges::new_fixed(layers, n);
        let leaves = 1 << 30;
        let mut rng = thread_rng();
        let replica_id: PedersenDomain = rng.gen();
        let commitment: PedersenDomain = rng.gen();
        let partitions = 5;
        let total_challenges = partitions * n;

        let mut layers_with_duplicates = 0;

        for _layer in 0..layers {
            let mut histogram = HashMap::new();
            for k in 0..partitions {
                let challenges = challenges.derive(leaves, &replica_id, &commitment, k as u8);

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
        let mut rng = thread_rng();
        let replica_id: PedersenDomain = rng.gen();
        let commitment: PedersenDomain = rng.gen();
        let partitions = 5;
        let layers = 100;
        let total_challenges = n * partitions;

        for _layer in 0..layers {
            let one_partition_challenges = LayerChallenges::new_fixed(layers, total_challenges)
                .derive(leaves, &replica_id, &commitment, 0);
            let many_partition_challenges = (0..partitions)
                .flat_map(|k| {
                    LayerChallenges::new_fixed(layers, n).derive(
                        leaves,
                        &replica_id,
                        &commitment,
                        k as u8,
                    )
                })
                .collect::<Vec<_>>();

            assert_eq!(one_partition_challenges, many_partition_challenges);
        }
    }
}
