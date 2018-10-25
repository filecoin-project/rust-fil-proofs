use byteorder::{LittleEndian, WriteBytesExt};
use crypto::blake2s::blake2s;
use hasher::Domain;
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;

pub fn derive_challenges<D: Domain>(
    n: usize,
    layer: u8,
    leaves: usize,
    replica_id: &D,
    commitment: &D,
    k: u8,
) -> Vec<usize> {
    (0..n)
        .map(|i| {
            let mut bytes = replica_id.into_bytes();
            bytes.extend(commitment.into_bytes());
            bytes.push(k);
            bytes.push(layer);
            bytes.write_u32::<LittleEndian>(i as u32).unwrap();

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
    use hasher::pedersen::PedersenDomain;
    use rand::{thread_rng, Rng};
    use std::collections::HashMap;

    #[test]
    fn challenge_derivation() {
        let n = 200;
        let leaves = 1 << 30;
        let mut rng = thread_rng();
        let replica_id: PedersenDomain = rng.gen();
        let commitment: PedersenDomain = rng.gen();
        let partitions = 5;
        let total_challenges = partitions * n;
        let layers = 100;

        let mut layers_with_duplicates = 0;

        for layer in 0..layers {
            let mut histogram = HashMap::new();
            for k in 0..partitions {
                let challenges =
                    derive_challenges(n, layer, leaves, &replica_id, &commitment, k as u8);

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
}
