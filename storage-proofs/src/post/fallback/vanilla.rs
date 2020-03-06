use std::marker::PhantomData;

use anyhow::{ensure, Context};
use byteorder::{ByteOrder, LittleEndian};
use generic_array::typenum;
use log::trace;
use merkletree::store::StoreConfig;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::drgraph::graph_height;
use crate::error::Result;
use crate::hasher::{Domain, HashFunction, Hasher};
use crate::merkle::{MerkleProof, OctLCMerkleTree};
use crate::parameter_cache::ParameterSetMetadata;
use crate::porep::stacked::OCT_ARITY;
use crate::proof::{NoRequirements, ProofScheme};
use crate::sector::*;
use crate::util::NODE_SIZE;

#[derive(Debug, Clone)]
pub struct SetupParams {
    /// Size of the sector in bytes.
    pub sector_size: u64,
    /// Number of challenges per sector.
    pub challenge_count: usize,
    /// Number of challenged sectors.
    pub sector_count: usize,
}

#[derive(Debug, Clone)]
pub struct PublicParams {
    /// Size of the sector in bytes.
    pub sector_size: u64,
    /// Number of challenges per sector.
    pub challenge_count: usize,
    /// Number of challenged sectors.
    pub sector_count: usize,
}

impl ParameterSetMetadata for PublicParams {
    fn identifier(&self) -> String {
        format!(
            "FallbackPoSt::PublicParams{{sector_size: {}, challenge_count: {}, sector_count: {}}}",
            self.sector_size(),
            self.challenge_count,
            self.sector_count,
        )
    }

    fn sector_size(&self) -> u64 {
        self.sector_size
    }
}

#[derive(Debug, Clone)]
pub struct PublicInputs<'a, T: Domain> {
    pub randomness: T,
    pub sector_ids: &'a [SectorId],
    pub prover_id: T,
    pub comm_rs: &'a [T],
}

#[derive(Debug)]
pub struct PrivateInputs<'a, H: Hasher> {
    pub trees: &'a [OctLCMerkleTree<H::Domain, H::Function>],
    pub comm_cs: &'a [H::Domain],
    pub comm_r_lasts: &'a [H::Domain],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<H: Hasher> {
    #[serde(bound(
        serialize = "MerkleProof<H, typenum::U8>: Serialize",
        deserialize = "MerkleProof<H, typenum::U8>: Deserialize<'de>"
    ))]
    inclusion_proofs: Vec<Vec<MerkleProof<H, typenum::U8>>>,
    pub comm_cs: Vec<H::Domain>,
    pub comm_r_lasts: Vec<H::Domain>,
}

impl<H: Hasher> Proof<H> {
    pub fn leafs(&self, sector: usize) -> Vec<H::Domain> {
        self.inclusion_proofs[sector]
            .iter()
            .map(MerkleProof::leaf)
            .collect()
    }

    pub fn comm_r_last(&self, sector: usize) -> H::Domain {
        *self.inclusion_proofs[sector][0].root()
    }

    pub fn commitments(&self, sector: usize) -> Vec<&H::Domain> {
        self.inclusion_proofs[sector]
            .iter()
            .map(MerkleProof::root)
            .collect()
    }

    #[allow(clippy::type_complexity)]
    pub fn paths(&self, sector: usize) -> Vec<&Vec<(Vec<H::Domain>, usize)>> {
        self.inclusion_proofs[sector]
            .iter()
            .map(MerkleProof::path)
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct FallbackPoSt<'a, H>
where
    H: 'a + Hasher,
{
    _h: PhantomData<&'a H>,
}

pub fn generate_sector_challenges<T: Domain>(
    randomness: T,
    challenge_count: u64,
    sectors: &OrderedSectorSet,
) -> Result<Vec<SectorId>> {
    (0..challenge_count)
        .into_par_iter()
        .map(|n| generate_sector_challenge(randomness, n as usize, sectors))
        .collect()
}

pub fn generate_sector_challenge<T: Domain>(
    randomness: T,
    n: usize,
    sectors: &OrderedSectorSet,
) -> Result<SectorId> {
    let mut hasher = Sha256::new();
    hasher.input(AsRef::<[u8]>::as_ref(&randomness));
    hasher.input(&n.to_le_bytes()[..]);
    let hash = hasher.result();

    let sector_challenge = LittleEndian::read_u64(&hash.as_ref()[..8]);
    let sector_index = (sector_challenge % sectors.len() as u64) as usize;
    let sector = *sectors
        .iter()
        .nth(sector_index)
        .context("invalid challenge generated")?;

    Ok(sector)
}

/// Generate all challenged leaf ranges for a single sector, such that the range fits into the sector.
pub fn generate_leaf_challenges<T: Domain>(
    pub_params: &PublicParams,
    randomness: T,
    sector_id: u64,
    challenge_count: usize,
) -> Result<Vec<u64>> {
    let mut challenges = Vec::with_capacity(challenge_count);

    for leaf_challenge_index in 0..challenge_count {
        let challenge = generate_leaf_challenge(
            pub_params,
            randomness,
            sector_id,
            leaf_challenge_index as u64,
        )?;
        challenges.push(challenge)
    }

    Ok(challenges)
}

/// Generates challenge, such that the range fits into the sector.
pub fn generate_leaf_challenge<T: Domain>(
    pub_params: &PublicParams,
    randomness: T,
    sector_id: u64,
    leaf_challenge_index: u64,
) -> Result<u64> {
    let mut hasher = Sha256::new();
    hasher.input(AsRef::<[u8]>::as_ref(&randomness));
    hasher.input(&sector_id.to_le_bytes()[..]);
    hasher.input(&leaf_challenge_index.to_le_bytes()[..]);
    let hash = hasher.result();

    let leaf_challenge = LittleEndian::read_u64(&hash.as_ref()[..8]);

    let challenged_range_index = leaf_challenge % (pub_params.sector_size / NODE_SIZE as u64);

    Ok(challenged_range_index * NODE_SIZE as u64)
}

impl<'a, H: 'a + Hasher> ProofScheme<'a> for FallbackPoSt<'a, H> {
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<'a, H::Domain>;
    type PrivateInputs = PrivateInputs<'a, H>;
    type Proof = Proof<H>;
    type Requirements = NoRequirements;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        Ok(PublicParams {
            sector_size: sp.sector_size,
            challenge_count: sp.challenge_count,
            sector_count: sp.sector_count,
        })
    }

    fn prove<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        let num_sectors = pub_params.sector_count;

        ensure!(
            num_sectors == pub_inputs.sector_ids.len(),
            "inconsistent (pub) comm_rs"
        );

        ensure!(
            num_sectors == pub_inputs.comm_rs.len(),
            "inconsistent (pub) comm_rs"
        );
        ensure!(
            num_sectors == priv_inputs.trees.len(),
            "inconsistent (priv) trees"
        );
        ensure!(
            num_sectors == priv_inputs.comm_r_lasts.len(),
            "inconsistent (priv) comm_r_lasts"
        );

        let mut inclusion_proofs = Vec::with_capacity(num_sectors);
        for (sector_id, tree) in pub_inputs.sector_ids.iter().zip(priv_inputs.trees.iter()) {
            let tree_leafs = tree.leafs();

            trace!(
                "Generating proof for tree of len {} with leafs {}, and cached_layers {}",
                tree.len(),
                tree_leafs,
                StoreConfig::default_cached_above_base_layer(tree_leafs, OCT_ARITY)
            );
            let proofs = (0..pub_params.challenge_count)
                .into_par_iter()
                .map(|n| {
                    // TODO: replace unwrap with proper error handling
                    let challenged_leaf_start = generate_leaf_challenge(
                        pub_params,
                        pub_inputs.randomness,
                        (*sector_id).into(),
                        n as u64,
                    )
                    .unwrap();
                    let (proof, _) = tree.gen_proof_and_partial_tree(
                        challenged_leaf_start as usize / NODE_SIZE,
                        StoreConfig::default_cached_above_base_layer(tree_leafs, OCT_ARITY),
                    )?;

                    Ok(MerkleProof::new_from_proof(&proof))
                })
                .collect::<Result<Vec<_>>>()?;
            inclusion_proofs.push(proofs);
        }

        Ok(Proof {
            inclusion_proofs,
            comm_cs: priv_inputs.comm_cs.to_vec(),
            comm_r_lasts: priv_inputs.comm_r_lasts.to_vec(),
        })
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        for (((sector_id, comm_r), proof), comm_c) in pub_inputs
            .sector_ids
            .iter()
            .zip(pub_inputs.comm_rs.iter())
            .zip(proof.inclusion_proofs.iter())
            .zip(proof.comm_cs.iter())
        {
            // verify that H(Comm_c || Comm_r_last) == Comm_R
            // comm_r_last is the root of the proof
            let comm_r_last = proof[0].root();

            if AsRef::<[u8]>::as_ref(&H::Function::hash2(&comm_c, comm_r_last))
                != AsRef::<[u8]>::as_ref(comm_r)
            {
                return Ok(false);
            }

            for n in 0..pub_params.challenge_count {
                let challenged_leaf_start = generate_leaf_challenge(
                    pub_params,
                    pub_inputs.randomness,
                    (*sector_id).into(),
                    n as u64,
                )?;
                let merkle_proof = &proof[n];

                // validate all comm_r_lasts match
                if merkle_proof.root() != comm_r_last {
                    return Ok(false);
                }

                // validate the path length
                let expected_path_length =
                    graph_height::<typenum::U8>(pub_params.sector_size as usize / NODE_SIZE) - 1;
                if expected_path_length != merkle_proof.path().len() {
                    return Ok(false);
                }

                if !merkle_proof.validate(challenged_leaf_start as usize / NODE_SIZE) {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use std::io::prelude::*;

    use ff::Field;
    use paired::bls12_381::{Bls12, Fr};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use crate::drgraph::{new_seed, BucketGraph, Graph, BASE_DEGREE};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::{PedersenHasher, PoseidonHasher};
    use crate::merkle::OctMerkleTree;

    fn test_fallback_post<H: Hasher>() {
        use merkletree::store::StoreConfigDataVersion;

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 64;
        let sector_size = leaves * NODE_SIZE;

        let pub_params = PublicParams {
            sector_size: sector_size as u64,
            challenge_count: 40,
            sector_count: 5,
        };

        let randomness = H::Domain::random(rng);
        let prover_id = H::Domain::random(rng);

        let mut sectors: Vec<SectorId> = Vec::new();
        let mut trees = Vec::new();

        // Construct and store an MT using a named DiskStore.
        let temp_dir = tempdir::TempDir::new("level_cache_tree").unwrap();
        let temp_path = temp_dir.path();
        let config = StoreConfig::new(
            &temp_path,
            String::from("test-lc-tree"),
            StoreConfig::default_cached_above_base_layer(leaves as usize, OCT_ARITY),
        );

        for i in 0..5 {
            sectors.push(i.into());
            let data: Vec<u8> = (0..leaves)
                .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
                .collect();

            let graph = BucketGraph::<H>::new(leaves, BASE_DEGREE, 0, new_seed()).unwrap();

            let replica_path = temp_path.join(format!("replica-path-{}", i));
            let mut f = File::create(&replica_path).unwrap();
            f.write_all(&data).unwrap();

            let cur_config = StoreConfig::from_config(&config, format!("test-lc-tree-{}", i), None);
            let mut tree: OctMerkleTree<_, _> = graph
                .merkle_tree(Some(cur_config.clone()), data.as_slice())
                .unwrap();
            let c = tree
                .compact(cur_config.clone(), StoreConfigDataVersion::Two as u32)
                .unwrap();
            assert_eq!(c, true);

            let lctree: OctLCMerkleTree<_, _> = graph
                .lcmerkle_tree(cur_config.clone(), &replica_path)
                .unwrap();
            trees.push(lctree);
        }

        let comm_r_lasts = trees.iter().map(|tree| tree.root()).collect::<Vec<_>>();
        let comm_cs = (0..5).map(|_| H::Domain::random(rng)).collect::<Vec<_>>();
        let comm_rs = comm_r_lasts
            .iter()
            .zip(comm_cs.iter())
            .map(|(comm_r_last, comm_c)| H::Function::hash2(&comm_c, &comm_r_last))
            .collect::<Vec<_>>();
        let pub_inputs = PublicInputs {
            randomness,
            sector_ids: &sectors,
            prover_id,
            comm_rs: &comm_rs,
        };

        let priv_inputs = PrivateInputs::<H> {
            trees: &trees,
            comm_cs: &comm_cs,
            comm_r_lasts: &comm_r_lasts,
        };

        let proof = FallbackPoSt::<H>::prove(&pub_params, &pub_inputs, &priv_inputs)
            .expect("proving failed");

        let is_valid = FallbackPoSt::<H>::verify(&pub_params, &pub_inputs, &proof)
            .expect("verification failed");

        assert!(is_valid);
    }

    #[test]
    fn fallback_post_pedersen() {
        test_fallback_post::<PedersenHasher>();
    }

    #[test]
    fn fallback_post_poseidon() {
        test_fallback_post::<PoseidonHasher>();
    }
}
