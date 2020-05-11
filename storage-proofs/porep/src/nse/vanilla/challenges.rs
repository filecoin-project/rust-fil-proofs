use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
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
#[derive(Debug)]
pub struct Challenges<D: Domain> {
    /// The number of layers.
    num_layers: usize,
    /// The number of windows.
    num_windows: usize,
    /// The number of challenges per window.
    num_challenges_per_window: usize,
    /// Number of nodes in a single window.
    num_nodes_window: usize,
    /// Replica ID, to make the challenges unique to the replica.
    replica_id: D,
    /// Randomness seed
    seed: [u8; 32],
    /// Currently challenged window index.
    current_window: usize,
    /// Currently challenged node index for the window.
    current_challenge: usize,
}

impl<D: Domain> Challenges<D> {
    pub fn new(
        config: &Config,
        num_challenges_per_window: usize,
        replica_id: &D,
        seed: [u8; 32],
    ) -> Self {
        Self {
            num_layers: config.num_layers(),
            num_windows: config.num_windows(),
            num_challenges_per_window,
            num_nodes_window: config.num_nodes_window,
            replica_id: *replica_id,
            seed,
            current_window: 0,
            current_challenge: 0,
        }
    }
}

#[derive(Debug)]
pub struct Challenge {
    /// Index for the challenged window.
    pub window: usize,
    /// Index for the challenge node.
    pub node: usize,
    /// Index for the challenged layer.
    pub layer: usize,
}

impl<D: Domain> Iterator for Challenges<D> {
    type Item = Challenge;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_challenge == self.num_challenges_per_window
            && self.current_window == self.num_windows - 1
        {
            return None;
        }

        if self.current_challenge == self.num_challenges_per_window
            && self.current_window <= self.num_windows
        {
            self.current_challenge = 0;
            self.current_window += 1;
        }

        // Generate a challenge into any layer of the current window.
        let range = self.num_nodes_window * self.num_layers;
        let challenge_index = self.current_window * self.num_nodes_window + self.current_challenge;
        let hash = Sha256::new()
            .chain(self.replica_id.into_bytes())
            .chain(self.seed)
            .chain(&(challenge_index as u64).to_le_bytes())
            .result();

        let big_challenge = BigUint::from_bytes_le(hash.as_ref());

        // For now, we cannot try to prove the first or last node, so make sure the challenge can never be 0.
        let big_mod_challenge = big_challenge % (range - 1);
        let big_mod_challenge = big_mod_challenge
            .to_usize()
            .expect("`big_mod_challenge` exceeds size of `usize`");
        let challenged_node = big_mod_challenge + 1;
        let layer = challenged_node / self.num_nodes_window;
        let node = challenged_node % self.num_nodes_window;

        self.current_challenge += 1;

        Some(Challenge {
            window: self.current_window,
            node,
            layer: layer + 1, // layers are 1-indexed
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.num_windows * self.num_challenges_per_window;
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
        let num_challenges_per_window = 2;
        let challenges = Challenges::new(&config, num_challenges_per_window, &replica_id, seed);

        let list: Vec<_> = challenges.collect();
        assert_eq!(list.len(), num_challenges_per_window * config.num_windows());

        for (window, chunk) in list.chunks(num_challenges_per_window).enumerate() {
            for challenge in chunk {
                assert_eq!(challenge.window, window, "incorrect window");
                assert!(challenge.layer > 0, "layers are 1-indexed");
                assert!(
                    challenge.layer <= config.num_layers(),
                    "layer too large: {}, {}",
                    challenge.layer,
                    config.num_layers()
                );
                assert!(challenge.node > 1, "cannot challenge node 0");
                assert!(
                    challenge.node < config.num_nodes_window,
                    "challenge too large"
                );
            }
        }
    }
}
