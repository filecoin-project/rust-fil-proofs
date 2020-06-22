use std::convert::TryFrom;

use sha2::{Digest, Sha256};
use storage_proofs_core::hasher::Domain;

use super::Config;

#[derive(Debug, Default)]
pub struct ChallengeRequirements {
    pub minimum_challenges: usize,
}

/// An iterator which yields a fixed number of challenges over all windows.
///
/// Each challenge, challenges across all layers in the selected window.
#[derive(Debug, Clone)]
pub struct Challenges<D: Domain> {
    /// The number expander of layers.
    num_expander_layers: usize,
    /// The number butterfl of layers.
    num_butterfly_layers: usize,
    /// The number of windows.
    num_windows: usize,
    /// The number of layer challenges.
    num_layer_challenges: usize,
    /// Number of nodes per sector
    num_nodes_sector: usize,
    /// Number of nodes per window
    num_nodes_window: usize,
    /// Replica ID, to make the challenges unique to the replica.
    replica_id: D,
    /// Randomness seed
    seed: [u8; 32],
    /// Currently challenged node index. Goes from 0 to `num_layer_challenges` * `num_layers`.
    current_challenge: usize,
}

impl<D: Domain> Challenges<D> {
    pub fn new(
        config: &Config,
        num_layer_challenges: usize,
        replica_id: &D,
        seed: [u8; 32],
    ) -> Self {
        Self {
            num_expander_layers: config.num_expander_layers,
            num_butterfly_layers: config.num_butterfly_layers,
            num_windows: config.num_windows(),
            num_layer_challenges,
            num_nodes_sector: config.num_nodes_sector(),
            num_nodes_window: config.num_nodes_window,
            replica_id: *replica_id,
            seed,
            current_challenge: 0,
        }
    }

    /// Returns the number of layer challenges.
    pub fn len(&self) -> usize {
        self.num_layer_challenges
    }

    fn num_layers(&self) -> usize {
        self.num_expander_layers + self.num_butterfly_layers
    }
}

#[derive(Debug, Clone)]
pub struct LayerChallenge {
    /// Challenges the first layer, which has no parents.
    pub first_layer_challenge: Challenge,
    pub expander_challenges: Vec<Challenge>,
    pub butterfly_challenges: Vec<Challenge>,
    /// Challenges the last layer which is butterfly + encoding.
    pub last_layer_challenge: Challenge,
}

#[derive(Debug, Clone)]
pub struct Challenge {
    /// Index for the challenged window.
    pub window: u64,
    /// Index for the challenge node (absolute in the sector).
    pub absolute_index: u64,
    /// Index for the challenge node (relative in the window).
    pub relative_index: u32,
}

impl<D: Domain> Challenges<D> {
    fn next_node_challenge(&mut self) -> Challenge {
        let randomness = self.randomness(self.current_challenge as u64);
        let absolute_index = randomness % self.num_nodes_sector as u64;
        let window = absolute_index / self.num_nodes_window as u64;
        let relative_index = u32::try_from(absolute_index % self.num_nodes_window as u64)
            .expect("invalid sector/window size");

        // increase challenge index
        self.current_challenge += 1;

        Challenge {
            window,
            absolute_index,
            relative_index,
        }
    }

    fn randomness(&self, index: u64) -> u64 {
        let bytes = Sha256::new()
            .chain(self.replica_id.into_bytes())
            .chain(self.seed)
            .chain(&(index as u64).to_le_bytes())
            .result();

        let mut partial_bytes = [0u8; 8];
        partial_bytes.copy_from_slice(&bytes[..8]);

        u64::from_le_bytes(partial_bytes)
    }
}

impl<D: Domain> Iterator for Challenges<D> {
    type Item = LayerChallenge;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_challenge >= self.num_layer_challenges * self.num_layers() {
            return None;
        }

        let first_layer_challenge = self.next_node_challenge();
        let expander_challenges = (0..self.num_expander_layers - 1)
            .map(|_| self.next_node_challenge())
            .collect();
        let butterfly_challenges = (0..self.num_butterfly_layers - 1)
            .map(|_| self.next_node_challenge())
            .collect();
        let last_layer_challenge = self.next_node_challenge();

        Some(LayerChallenge {
            first_layer_challenge,
            expander_challenges,
            butterfly_challenges,
            last_layer_challenge,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.len();
        (size, Some(size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::hasher::{Hasher, PoseidonHasher};

    #[test]
    fn test_challenges_smoke() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let config = Config {
            k: 8,
            num_nodes_window: 2048 / 32,
            degree_expander: 12,
            degree_butterfly: 4,
            num_expander_layers: 6,
            num_butterfly_layers: 4,
            sector_size: 2048 * 8,
        };

        let replica_id = <PoseidonHasher as Hasher>::Domain::random(rng);
        let seed = rng.gen();
        let num_layer_challenges = 2;
        let challenges = Challenges::new(&config, num_layer_challenges, &replica_id, seed);

        let list: Vec<_> = challenges.collect();
        assert_eq!(list.len(), num_layer_challenges);

        for layer_challenge in list.iter() {
            assert_eq!(
                layer_challenge.butterfly_challenges.len(),
                config.num_butterfly_layers - 1
            );
            assert_eq!(
                layer_challenge.expander_challenges.len(),
                config.num_expander_layers - 1
            );

            assert!(layer_challenge.first_layer_challenge.window < config.num_windows() as u64);
            assert!(
                layer_challenge.first_layer_challenge.absolute_index
                    < config.num_nodes_sector() as u64
            );
            assert!(
                layer_challenge.first_layer_challenge.relative_index
                    < config.num_nodes_window as u32
            );

            for challenge in &layer_challenge.expander_challenges {
                assert!(challenge.window < config.num_windows() as u64);
                assert!(challenge.absolute_index < config.num_nodes_sector() as u64);
                assert!(challenge.relative_index < config.num_nodes_window as u32);
            }

            for challenge in &layer_challenge.butterfly_challenges {
                assert!(challenge.window < config.num_windows() as u64);
                assert!(challenge.absolute_index < config.num_nodes_sector() as u64);
                assert!(challenge.relative_index < config.num_nodes_window as u32);
            }
            assert!(layer_challenge.last_layer_challenge.window < config.num_windows() as u64);
            assert!(
                layer_challenge.last_layer_challenge.absolute_index
                    < config.num_nodes_sector() as u64
            );
            assert!(
                layer_challenge.last_layer_challenge.relative_index
                    < config.num_nodes_window as u32
            );
        }
    }
}
