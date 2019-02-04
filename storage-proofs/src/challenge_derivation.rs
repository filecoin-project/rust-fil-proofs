use byteorder::{LittleEndian, WriteBytesExt};
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;

use crate::crypto::blake2s::blake2s;
use crate::hasher::Domain;
use crate::layered_drgporep::LayerChallenges;

pub fn derive_challenges<D: Domain>(
    challenges: &LayerChallenges,
    layer: u8,
    leaves: usize,
    replica_id: &D,
    commitment: &D,
    k: u8,
) -> Vec<usize> {
    let n = challenges.challenges_for_layer(layer as usize);
    (0..n)
        .map(|i| {
            let mut bytes = replica_id.into_bytes();
            let j = ((n * k as usize) + i) as u32;
            bytes.extend(commitment.into_bytes());
            bytes.push(layer);
            bytes.write_u32::<LittleEndian>(j).unwrap();

            let hash = blake2s(bytes.as_slice());
            let big_challenge = BigUint::from_bytes_le(hash.as_slice());

            // For now, we cannot try to prove the first or last node, so make sure the challenge can never be 0 or leaves - 1.
            let big_mod_challenge = big_challenge % (leaves - 2);
            big_mod_challenge.to_usize().unwrap() + 1
        })
        .collect()
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

        for layer in 0..layers {
            let mut histogram = HashMap::new();
            for k in 0..partitions {
                let challenges = derive_challenges(
                    &challenges,
                    layer as u8,
                    leaves,
                    &replica_id,
                    &commitment,
                    k as u8,
                );

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
        assert!(layers_with_duplicates < 3);
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

        for layer in 0..layers {
            let one_partition_challenges = derive_challenges(
                &LayerChallenges::new_fixed(layers, total_challenges),
                layer as u8,
                leaves,
                &replica_id,
                &commitment,
                0,
            );
            let many_partition_challenges = (0..partitions)
                .flat_map(|k| {
                    derive_challenges(
                        &LayerChallenges::new_fixed(layers, n),
                        layer as u8,
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
