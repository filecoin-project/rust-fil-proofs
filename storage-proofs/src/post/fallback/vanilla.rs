use std::marker::PhantomData;

use anyhow::{ensure, Context};
use byteorder::{ByteOrder, LittleEndian};
use generic_array::typenum::{self, U8};
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
use crate::proof::ProofScheme;
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

#[derive(Debug, Default)]
pub struct ChallengeRequirements {
    /// The sum of challenges across all challenged sectors. (even across partitions)
    pub minimum_challenge_count: usize,
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
    pub prover_id: T,
    pub sectors: &'a [PublicSector<T>],
    /// Partition index
    pub k: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct PublicSector<T: Domain> {
    pub id: SectorId,
    pub comm_r: T,
}

#[derive(Debug)]
pub struct PrivateSector<'a, H: Hasher> {
    pub tree: &'a OctLCMerkleTree<H::Domain, H::Function>,
    pub comm_c: H::Domain,
    pub comm_r_last: H::Domain,
}

#[derive(Debug)]
pub struct PrivateInputs<'a, H: Hasher> {
    pub sectors: &'a [PrivateSector<'a, H>],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<H: Hasher> {
    #[serde(bound(
        serialize = "SectorProof<H>: Serialize",
        deserialize = "SectorProof<H>: Deserialize<'de>"
    ))]
    pub sectors: Vec<SectorProof<H>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectorProof<H: Hasher> {
    #[serde(bound(
        serialize = "MerkleProof<H, U8>: Serialize",
        deserialize = "MerkleProof<H, U8>: Deserialize<'de>"
    ))]
    inclusion_proofs: Vec<MerkleProof<H, U8>>,
    pub comm_c: H::Domain,
    pub comm_r_last: H::Domain,
}

impl<H: Hasher> SectorProof<H> {
    pub fn leafs(&self) -> Vec<H::Domain> {
        self.inclusion_proofs
            .iter()
            .map(MerkleProof::leaf)
            .collect()
    }

    pub fn comm_r_last(&self) -> H::Domain {
        *self.inclusion_proofs[0].root()
    }

    pub fn commitments(&self) -> Vec<&H::Domain> {
        self.inclusion_proofs
            .iter()
            .map(MerkleProof::root)
            .collect()
    }

    #[allow(clippy::type_complexity)]
    pub fn paths(&self) -> Vec<&Vec<(Vec<H::Domain>, usize)>> {
        self.inclusion_proofs
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
    challenge_count: usize,
    sectors: &OrderedSectorSet,
) -> Result<Vec<SectorId>> {
    (0..challenge_count)
        .map(|n| generate_sector_challenge(randomness, n, sectors))
        .collect()
}

/// Generate a single sector challenge.
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

    Ok(challenged_range_index)
}

impl<'a, H: 'a + Hasher> ProofScheme<'a> for FallbackPoSt<'a, H> {
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<'a, H::Domain>;
    type PrivateInputs = PrivateInputs<'a, H>;
    type Proof = Proof<H>;
    type Requirements = ChallengeRequirements;

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
        let proofs = Self::prove_all_partitions(pub_params, pub_inputs, priv_inputs, 1)?;
        let k = match pub_inputs.k {
            None => 0,
            Some(k) => k,
        };
        // Because partition proofs require a common setup, the general ProofScheme implementation,
        // which makes use of `ProofScheme::prove` cannot be used here. Instead, we need to prove all
        // partitions in one pass, as implemented by `prove_all_partitions` below.
        assert!(
            k < 1,
            "It is a programmer error to call StackedDrg::prove with more than one partition."
        );

        Ok(proofs[k].to_owned())
    }

    fn prove_all_partitions<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
        partition_count: usize,
    ) -> Result<Vec<Self::Proof>> {
        ensure!(
            priv_inputs.sectors.len() == pub_inputs.sectors.len(),
            "inconsistent number of private and public sectors {} != {}",
            priv_inputs.sectors.len(),
            pub_inputs.sectors.len(),
        );

        let num_sectors_per_chunk = pub_params.sector_count;
        let num_sectors = pub_inputs.sectors.len();

        ensure!(
            num_sectors <= partition_count * num_sectors_per_chunk,
            "cannot prove the provided number of sectors: {} > {} * {}",
            num_sectors,
            partition_count,
            num_sectors_per_chunk,
        );

        let mut partition_proofs = Vec::new();

        for (j, (pub_sectors_chunk, priv_sectors_chunk)) in pub_inputs
            .sectors
            .chunks(num_sectors_per_chunk)
            .zip(priv_inputs.sectors.chunks(num_sectors_per_chunk))
            .enumerate()
        {
            trace!("proving partition {}", j);

            let mut proofs = Vec::with_capacity(num_sectors_per_chunk);

            for (i, (pub_sector, priv_sector)) in pub_sectors_chunk
                .iter()
                .zip(priv_sectors_chunk.iter())
                .enumerate()
            {
                let tree = &priv_sector.tree;
                let sector_id = pub_sector.id;
                let tree_leafs = tree.leafs();
                let levels = StoreConfig::default_cached_above_base_layer(tree_leafs, OCT_ARITY);

                trace!(
                    "Generating proof for tree of len {} with leafs {}, and cached_layers {}",
                    tree.len(),
                    tree_leafs,
                    levels,
                );

                let inclusion_proofs = (0..pub_params.challenge_count)
                    .into_par_iter()
                    .map(|n| {
                        let challenge_index = ((j * num_sectors_per_chunk + i)
                            * pub_params.challenge_count
                            + n) as u64;
                        let challenged_leaf_start = generate_leaf_challenge(
                            pub_params,
                            pub_inputs.randomness,
                            sector_id.into(),
                            challenge_index,
                        )?;

                        let proof =
                            tree.gen_cached_proof(challenged_leaf_start as usize, levels)?;
                        Ok(MerkleProof::new_from_proof(&proof))
                    })
                    .collect::<Result<Vec<_>>>()?;

                proofs.push(SectorProof {
                    inclusion_proofs,
                    comm_c: priv_sector.comm_c,
                    comm_r_last: priv_sector.comm_r_last,
                });
            }

            // If there were less than the required number of sectors provided, we duplicate the last one
            // to pad the proof out, such that it works in the circuit part.
            while proofs.len() < num_sectors_per_chunk {
                proofs.push(proofs[proofs.len() - 1].clone());
            }

            partition_proofs.push(Proof { sectors: proofs });
        }

        Ok(partition_proofs)
    }

    fn verify_all_partitions(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        partition_proofs: &[Self::Proof],
    ) -> Result<bool> {
        let challenge_count = pub_params.challenge_count;
        let num_sectors_per_chunk = pub_params.sector_count;
        let num_sectors = pub_inputs.sectors.len();

        ensure!(
            num_sectors <= num_sectors_per_chunk * partition_proofs.len(),
            "inconsistent number of sectors: {} > {} * {}",
            num_sectors,
            num_sectors_per_chunk,
            partition_proofs.len(),
        );

        for (j, (proof, pub_sectors_chunk)) in partition_proofs
            .iter()
            .zip(pub_inputs.sectors.chunks(num_sectors_per_chunk))
            .enumerate()
        {
            ensure!(
                pub_sectors_chunk.len() <= num_sectors_per_chunk,
                "inconsistent number of public sectors: {} > {}",
                pub_sectors_chunk.len(),
                num_sectors_per_chunk,
            );
            ensure!(
                proof.sectors.len() == num_sectors_per_chunk,
                "invalid number of sectors in the partition proof {}: {} != {}",
                j,
                proof.sectors.len(),
                num_sectors_per_chunk,
            );
            for (i, (pub_sector, sector_proof)) in pub_sectors_chunk
                .iter()
                .zip(proof.sectors.iter())
                .enumerate()
            {
                let sector_id = pub_sector.id;
                let comm_r = &pub_sector.comm_r;
                let comm_c = sector_proof.comm_c;
                let inclusion_proofs = &sector_proof.inclusion_proofs;

                // Verify that H(Comm_c || Comm_r_last) == Comm_R

                // comm_r_last is the root of the proof
                let comm_r_last = inclusion_proofs[0].root();

                if AsRef::<[u8]>::as_ref(&H::Function::hash2(&comm_c, comm_r_last))
                    != AsRef::<[u8]>::as_ref(comm_r)
                {
                    return Ok(false);
                }

                ensure!(
                    challenge_count == inclusion_proofs.len(),
                    "unexpected umber of inclusion proofs: {} != {}",
                    challenge_count,
                    inclusion_proofs.len()
                );

                for (n, inclusion_proof) in inclusion_proofs.iter().enumerate() {
                    let challenge_index =
                        ((j * num_sectors_per_chunk + i) * pub_params.challenge_count + n) as u64;
                    let challenged_leaf_start = generate_leaf_challenge(
                        pub_params,
                        pub_inputs.randomness,
                        sector_id.into(),
                        challenge_index,
                    )?;

                    // validate all comm_r_lasts match
                    if inclusion_proof.root() != comm_r_last {
                        return Ok(false);
                    }

                    // validate the path length
                    let expected_path_length =
                        graph_height::<typenum::U8>(pub_params.sector_size as usize / NODE_SIZE)
                            - 1;
                    if expected_path_length != inclusion_proof.path().len() {
                        return Ok(false);
                    }

                    if !inclusion_proof.validate(challenged_leaf_start as usize) {
                        return Ok(false);
                    }
                }
            }
        }

        Ok(true)
    }

    fn satisfies_requirements(
        public_params: &Self::PublicParams,
        requirements: &Self::Requirements,
        partitions: usize,
    ) -> bool {
        partitions * public_params.sector_count * public_params.challenge_count
            >= requirements.minimum_challenge_count
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

    fn test_fallback_post<H: Hasher>(
        total_sector_count: usize,
        sector_count: usize,
        partitions: usize,
    ) {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 64;
        let sector_size = leaves * NODE_SIZE;

        let pub_params = PublicParams {
            sector_size: sector_size as u64,
            challenge_count: 10,
            sector_count,
        };

        let randomness = H::Domain::random(rng);
        let prover_id = H::Domain::random(rng);

        // Construct and store an MT using a named DiskStore.
        let temp_dir = tempdir::TempDir::new("level_cache_tree").unwrap();
        let temp_path = temp_dir.path();
        let config = StoreConfig::new(
            &temp_path,
            String::from("test-lc-tree"),
            StoreConfig::default_cached_above_base_layer(leaves as usize, OCT_ARITY),
        );

        let mut pub_sectors = Vec::new();
        let mut priv_sectors = Vec::new();
        let mut trees = Vec::new();

        for i in 0..total_sector_count {
            let data: Vec<u8> = (0..leaves)
                .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
                .collect();

            let graph = BucketGraph::<H>::new(leaves, BASE_DEGREE, 0, new_seed()).unwrap();

            let replica_path = temp_path.join(format!("replica-path-{}", i));
            let mut f = File::create(&replica_path).unwrap();
            f.write_all(&data).unwrap();

            let cur_config = StoreConfig::from_config(&config, format!("test-lc-tree-{}", i), None);

            trees.push(
                graph
                    .lcmerkle_tree(cur_config.clone(), &data, &replica_path)
                    .unwrap(),
            );
        }
        for (i, tree) in trees.iter().enumerate() {
            let comm_c = H::Domain::random(rng);
            let comm_r_last = tree.root();

            priv_sectors.push(PrivateSector {
                tree,
                comm_c,
                comm_r_last,
            });

            let comm_r = H::Function::hash2(&comm_c, &comm_r_last);
            pub_sectors.push(PublicSector {
                id: (i as u64).into(),
                comm_r,
            });
        }

        let pub_inputs = PublicInputs {
            randomness,
            prover_id,
            sectors: &pub_sectors,
            k: None,
        };

        let priv_inputs = PrivateInputs::<H> {
            sectors: &priv_sectors,
        };

        let proof = FallbackPoSt::<H>::prove_all_partitions(
            &pub_params,
            &pub_inputs,
            &priv_inputs,
            partitions,
        )
        .expect("proving failed");

        let is_valid = FallbackPoSt::<H>::verify_all_partitions(&pub_params, &pub_inputs, &proof)
            .expect("verification failed");

        assert!(is_valid);
    }

    #[test]
    fn fallback_post_pedersen_single_partition_matching() {
        test_fallback_post::<PedersenHasher>(5, 5, 1);
    }

    #[test]
    fn fallback_post_poseidon_single_partition_matching() {
        test_fallback_post::<PoseidonHasher>(5, 5, 1);
    }

    #[test]
    fn fallback_post_poseidon_single_partition_smaller() {
        test_fallback_post::<PoseidonHasher>(3, 5, 1);
    }

    #[test]
    fn fallback_post_poseidon_two_partitions_matching() {
        test_fallback_post::<PoseidonHasher>(4, 2, 2);
    }

    #[test]
    fn fallback_post_poseidon_two_partitions_smaller() {
        test_fallback_post::<PoseidonHasher>(5, 3, 2);
    }
}
