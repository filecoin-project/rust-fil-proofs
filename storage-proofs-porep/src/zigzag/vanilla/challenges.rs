use std::cmp::{max, min};

use blake2s_simd::blake2s;
use byteorder::{LittleEndian, WriteBytesExt};
use filecoin_hashers::Domain;
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use serde::{Deserialize, Serialize};

/// Per-layer challenge configuration for the ZigZag layered PoRep.
///
/// `Fixed` uses the same challenge count on every layer. `Tapered` reduces the challenge count on
/// earlier layers (the taper is applied to the last `taper_layers` layers), trading proof size for
/// prover work. Both variants are ported verbatim from the 2019 `layered_drgporep::LayerChallenges`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LayerChallenges {
    Fixed {
        layers: usize,
        count: usize,
    },
    Tapered {
        layers: usize,
        count: usize,
        taper: f64,
        taper_layers: usize,
    },
}

impl LayerChallenges {
    pub const fn new_fixed(layers: usize, count: usize) -> Self {
        LayerChallenges::Fixed { layers, count }
    }

    pub fn new_tapered(layers: usize, challenges: usize, taper_layers: usize, taper: f64) -> Self {
        LayerChallenges::Tapered {
            layers,
            count: challenges,
            taper,
            taper_layers,
        }
    }

    pub fn layers(&self) -> usize {
        match self {
            LayerChallenges::Fixed { layers, .. } => *layers,
            LayerChallenges::Tapered { layers, .. } => *layers,
        }
    }

    pub fn challenges_for_layer(&self, layer: usize) -> usize {
        match self {
            LayerChallenges::Fixed { count, .. } => *count,
            LayerChallenges::Tapered {
                taper,
                taper_layers,
                count,
                layers,
            } => {
                assert!(layer < *layers);
                let l = (layers - 1) - layer;

                let r: f64 = 1.0 - *taper;
                let t = min(l, *taper_layers);
                let total_taper = r.powi(t as i32);

                let calculated = (total_taper * *count as f64).ceil() as usize;

                // Although implied by the call to `ceil()` above, be explicit that a layer cannot
                // contain 0 challenges.
                max(1, calculated)
            }
        }
    }

    pub fn total_challenges(&self) -> usize {
        (0..self.layers())
            .map(|x| self.challenges_for_layer(x))
            .sum()
    }

    pub fn all_challenges(&self) -> Vec<usize> {
        (0..self.layers())
            .map(|x| self.challenges_for_layer(x))
            .collect()
    }
}

/// Derives the challenged node indices for a single layer.
///
/// Faithful to the 2019 implementation: `blake2s(replica_id | commitment | layer | j)` reduced into
/// `[1, leaves - 1)` so the first and last nodes are never challenged.
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
            // Unwrapping here is safe, all hash domains are larger than 4 bytes (the size of a `u32`).
            bytes
                .write_u32::<LittleEndian>(j)
                .expect("writing to a Vec cannot fail");

            let hash = blake2s(bytes.as_slice());
            let big_challenge = BigUint::from_bytes_le(hash.as_ref());

            // For now, we cannot try to prove the first or last node, so make sure the challenge
            // can never be 0 or `leaves - 1`.
            let big_mod_challenge = big_challenge % (leaves - 2);
            let big_mod_challenge = big_mod_challenge
                .to_usize()
                .expect("`big_mod_challenge` exceeds size of `usize`");
            big_mod_challenge + 1
        })
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;

    use std::collections::HashMap;

    use filecoin_hashers::sha256::Sha256Domain;
    use rand::thread_rng;

    #[test]
    fn challenge_derivation() {
        let n = 200;
        let layers = 100;

        let challenges = LayerChallenges::new_fixed(layers, n);
        let leaves = 1 << 30;
        let mut rng = thread_rng();
        let replica_id: Sha256Domain = Sha256Domain::random(&mut rng);
        let commitment: Sha256Domain = Sha256Domain::random(&mut rng);
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
        let replica_id: Sha256Domain = Sha256Domain::random(&mut rng);
        let commitment: Sha256Domain = Sha256Domain::random(&mut rng);
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
