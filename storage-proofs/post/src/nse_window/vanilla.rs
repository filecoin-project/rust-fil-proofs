use std::marker::PhantomData;

use anyhow::ensure;
use byteorder::{ByteOrder, LittleEndian};
use generic_array::typenum::{Unsigned, U0};
use log::trace;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use storage_proofs_core::{
    error::Result,
    hasher::{Domain, Hasher},
    merkle::{MerkleProof, MerkleProofTrait, MerkleTreeTrait, MerkleTreeWrapper},
    parameter_cache::ParameterSetMetadata,
    proof::ProofScheme,
    sector::*,
    util::{default_rows_to_discard, NODE_SIZE},
};
use storage_proofs_porep::nse::vanilla::hash_comm_r;

#[derive(Debug, Clone)]
pub struct SetupParams {
    /// Size of the sector in bytes.
    pub sector_size: u64,
    /// Size of the window in bytes.
    pub window_size: u64,
    /// Number of challenges per window.
    pub window_challenge_count: usize,
    /// Number of challenged sectors.
    pub sector_count: usize,
    /// The total number of layers.
    pub num_layers: usize,
}

#[derive(Debug, Clone)]
pub struct PublicParams {
    /// Size of the sector in bytes.
    pub sector_size: u64,
    /// Size of the window in bytes.
    pub window_size: u64,
    /// Number of challenges per window.
    pub window_challenge_count: usize,
    /// Number of challenged sectors.
    pub sector_count: usize,
    /// The total number of layers.
    pub num_layers: usize,
}

impl PublicParams {
    pub fn num_windows(&self) -> usize {
        (self.sector_size / self.window_size) as usize
    }
}

#[derive(Debug, Default)]
pub struct ChallengeRequirements {
    /// The sum of challenges across all challenged sectors. (even across partitions)
    pub minimum_window_challenge_count: usize,
}

impl ParameterSetMetadata for PublicParams {
    fn identifier(&self) -> String {
        format!("NseWindowPoSt::PublicParams{{{:?}}}", self)
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
    /// The root of the individual layers.
    pub comm_layers: Vec<T>,
    /// The root of the replica layer.
    pub comm_replica: T,
}

#[derive(Debug)]
pub struct PrivateSector<'a, Tree: MerkleTreeTrait> {
    pub tree: &'a MerkleTreeWrapper<
        Tree::Hasher,
        Tree::Store,
        Tree::Arity,
        Tree::SubTreeArity,
        Tree::TopTreeArity,
    >,
}

#[derive(Debug)]
pub struct PrivateInputs<'a, Tree: MerkleTreeTrait> {
    pub sectors: &'a [PrivateSector<'a, Tree>],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<P: MerkleProofTrait> {
    #[serde(bound(
        serialize = "SectorProof<P>: Serialize",
        deserialize = "SectorProof<P>: Deserialize<'de>"
    ))]
    pub sectors: Vec<SectorProof<P>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectorProof<Proof: MerkleProofTrait> {
    /// Inclusion proofs outer vector has number of windows, inner vector has number of challenges length.
    #[serde(bound(
        serialize = "MerkleProof<Proof::Hasher, Proof::Arity, U0, U0>: Serialize",
        deserialize = "MerkleProof<Proof::Hasher, Proof::Arity, U0, U0>: serde::de::DeserializeOwned"
    ))]
    pub inclusion_proofs: Vec<Vec<MerkleProof<Proof::Hasher, Proof::Arity, U0, U0>>>,
    pub comm_layers: Vec<<Proof::Hasher as Hasher>::Domain>,
    pub comm_replica: <Proof::Hasher as Hasher>::Domain,
}

#[derive(Debug, Clone)]
pub struct NseWindowPoSt<'a, Tree>
where
    Tree: 'a + MerkleTreeTrait,
{
    _t: PhantomData<&'a Tree>,
}

/// Generates a list of challenged sectors.
pub fn generate_sector_challenges<T: Domain>(
    randomness: T,
    num_challenged_sectors: usize,
    sector_set_len: u64,
    prover_id: T,
) -> Result<Vec<u64>> {
    (0..num_challenged_sectors)
        .map(|challenge_index| {
            generate_sector_challenge(
                randomness,
                challenge_index as u64,
                sector_set_len,
                prover_id,
            )
        })
        .collect()
}

/// Generate a single sector challenge.
pub fn generate_sector_challenge<T: Domain>(
    randomness: T,
    challenge_index: u64,
    sector_set_len: u64,
    prover_id: T,
) -> Result<u64> {
    let mut hasher = Sha256::new();
    hasher.update(AsRef::<[u8]>::as_ref(&prover_id));
    hasher.update(AsRef::<[u8]>::as_ref(&randomness));
    hasher.update(&challenge_index.to_le_bytes()[..]);

    let hash = hasher.finalize();

    let sector_challenge = LittleEndian::read_u64(&hash[..8]);
    let sector_index = sector_challenge % sector_set_len;

    Ok(sector_index)
}

/// Generate all challenged nodes for a single sector, such that the range fits into the sector.
/// Returns a list of challenges for each window.
pub fn generate_leaf_challenges<T: Domain>(
    pub_params: &PublicParams,
    randomness: T,
    sector_id: u64,
    num_windows: usize,
    window_challenge_count: usize,
) -> Result<Vec<Vec<u64>>> {
    let mut challenges = Vec::with_capacity(num_windows);

    for window_index in 0..num_windows {
        let mut window_challenges = Vec::with_capacity(window_challenge_count);

        for leaf_challenge_index in 0..window_challenge_count {
            let challenge = generate_leaf_challenge(
                pub_params,
                randomness,
                sector_id,
                window_index as u64,
                leaf_challenge_index as u64,
            )?;
            window_challenges.push(challenge)
        }

        challenges.push(window_challenges);
    }

    Ok(challenges)
}

/// Generates challenge, such that the range fits into the window.
pub fn generate_leaf_challenge<T: Domain>(
    pub_params: &PublicParams,
    randomness: T,
    sector_id: u64,
    window_index: u64,
    leaf_challenge_index: u64,
) -> Result<u64> {
    let mut hasher = Sha256::new();
    hasher.update(AsRef::<[u8]>::as_ref(&randomness));
    hasher.update(&sector_id.to_le_bytes()[..]);
    hasher.update(&window_index.to_le_bytes()[..]);
    hasher.update(&leaf_challenge_index.to_le_bytes()[..]);
    let hash = hasher.finalize();

    let leaf_challenge = LittleEndian::read_u64(&hash[..8]);

    let challenged_range_index = leaf_challenge % (pub_params.window_size / NODE_SIZE as u64);

    Ok(challenged_range_index)
}

impl<'a, Tree: 'a + MerkleTreeTrait> ProofScheme<'a> for NseWindowPoSt<'a, Tree> {
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<'a, <Tree::Hasher as Hasher>::Domain>;
    type PrivateInputs = PrivateInputs<'a, Tree>;
    type Proof = Proof<Tree::Proof>;
    type Requirements = ChallengeRequirements;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        Ok(PublicParams {
            sector_size: sp.sector_size,
            window_size: sp.window_size,
            window_challenge_count: sp.window_challenge_count,
            sector_count: sp.sector_count,
            num_layers: sp.num_layers,
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
                let tree = priv_sector.tree;
                let sector_id = pub_sector.id;
                let tree_leafs = tree.leafs();
                let rows_to_discard = default_rows_to_discard(tree_leafs, Tree::Arity::to_usize());

                trace!(
                    "Generating proof for tree leafs {} and arity {}",
                    tree_leafs,
                    Tree::Arity::to_usize(),
                );

                let inclusion_proofs = (0..pub_params.num_windows())
                    .into_par_iter()
                    .map(|window_index| {
                        let offset =
                            (pub_params.window_size / NODE_SIZE as u64) * window_index as u64;

                        (0..pub_params.window_challenge_count)
                            .into_par_iter()
                            .map(|n| {
                                let challenge_index = ((j * num_sectors_per_chunk + i)
                                    * pub_params.window_challenge_count
                                    + n)
                                    as u64;
                                let challenged_leaf_relative = generate_leaf_challenge(
                                    pub_params,
                                    pub_inputs.randomness,
                                    sector_id.into(),
                                    window_index as u64,
                                    challenge_index,
                                )?;
                                let challenged_leaf_absolute = offset + challenged_leaf_relative;

                                tree.gen_cached_base_proof(
                                    challenged_leaf_absolute as usize,
                                    Some(rows_to_discard),
                                )
                            })
                            .collect::<Result<Vec<_>>>()
                    })
                    .collect::<Result<Vec<_>>>()?;

                let comm_layers = pub_sector.comm_layers.clone();
                ensure!(
                    comm_layers.len() == pub_params.num_layers - 1,
                    "invalid number of layer commitments {} != {}",
                    comm_layers.len(),
                    pub_params.num_layers - 1
                );
                proofs.push(SectorProof {
                    inclusion_proofs,
                    comm_layers,
                    comm_replica: pub_sector.comm_replica,
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
        let window_challenge_count = pub_params.window_challenge_count;
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
                trace!("partition {}", i);
                let sector_id = pub_sector.id;
                let comm_r = &pub_sector.comm_r;
                let comm_layers = &sector_proof.comm_layers;
                let inclusion_proofs = &sector_proof.inclusion_proofs;
                let comm_replica = sector_proof.comm_replica;

                // -- Verify that H(Comm_layers..| comm_replica) == Comm_R
                let comm_r_expected: <Tree::Hasher as Hasher>::Domain =
                    hash_comm_r(&comm_layers, comm_replica).into();
                if AsRef::<[u8]>::as_ref(&comm_r_expected) != AsRef::<[u8]>::as_ref(comm_r) {
                    trace!("invalid comm_r");
                    return Ok(false);
                }

                // -- Verify top part of the tree
                let tree = MerkleTreeWrapper::<
                    Tree::Hasher,
                    merkletree::store::VecStore<<Tree::Hasher as Hasher>::Domain>,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                    U0,
                >::try_from_iter(
                    inclusion_proofs.iter().map(|p| Ok(p[0].root()))
                )?;
                let comm_replica_expected = tree.root();

                if AsRef::<[u8]>::as_ref(&comm_replica_expected)
                    != AsRef::<[u8]>::as_ref(&comm_replica)
                {
                    trace!("invalid comm_replica");
                    return Ok(false);
                }

                // -- Verify inclusion proofs

                ensure!(
                    pub_params.num_windows() == inclusion_proofs.len(),
                    "unexpected number of inclusion proofs: {} != {}",
                    pub_params.num_windows(),
                    inclusion_proofs.len()
                );

                for (window_index, inclusion_proofs) in inclusion_proofs.iter().enumerate() {
                    trace!("window {}", window_index);
                    ensure!(
                        window_challenge_count == inclusion_proofs.len(),
                        "unexpected number of inclusion proofs: {} != {}",
                        window_challenge_count,
                        inclusion_proofs.len()
                    );

                    let comm_window = inclusion_proofs[0].root();

                    for (n, inclusion_proof) in inclusion_proofs.iter().enumerate() {
                        trace!("inclusion_proof {}", n);
                        let challenge_index = ((j * num_sectors_per_chunk + i)
                            * pub_params.window_challenge_count
                            + n) as u64;
                        let challenged_leaf_relative = generate_leaf_challenge(
                            pub_params,
                            pub_inputs.randomness,
                            sector_id.into(),
                            window_index as u64,
                            challenge_index,
                        )?;

                        // validate all comm_windows match
                        if inclusion_proof.root() != comm_window {
                            trace!("invalid root");
                            return Ok(false);
                        }

                        // validate the path length
                        let expected_path_length = inclusion_proof
                            .expected_len(pub_params.window_size as usize / NODE_SIZE);

                        if expected_path_length != inclusion_proof.path().len() {
                            trace!(
                                "invalid path length {} != {}",
                                expected_path_length,
                                inclusion_proof.path().len()
                            );
                            return Ok(false);
                        }

                        if !inclusion_proof.validate(challenged_leaf_relative as usize) {
                            trace!("invalid inclusion proof");
                            return Ok(false);
                        }
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
        let checked = partitions * public_params.sector_count;

        assert_eq!(
            partitions.checked_mul(public_params.sector_count),
            Some(checked)
        );
        assert_eq!(
            checked.checked_mul(public_params.window_challenge_count),
            Some(checked * public_params.window_challenge_count)
        );

        checked * public_params.window_challenge_count
            >= requirements.minimum_window_challenge_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use generic_array::typenum::{U0, U4, U8};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use storage_proofs_core::{
        hasher::{PedersenHasher, PoseidonHasher},
        merkle::{generate_tree, get_base_tree_count, LCTree, MerkleTreeTrait},
    };

    fn test_nse_window_post<Tree: MerkleTreeTrait>(
        total_sector_count: usize,
        sector_count: usize,
        partitions: usize,
    ) where
        Tree::Store: 'static,
    {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);
        // femme::with_level(log::LevelFilter::Trace);

        let window_leaves = 64;
        let num_windows = get_base_tree_count::<Tree>();
        let leaves = num_windows * window_leaves;
        let sector_size = leaves * NODE_SIZE;
        let num_layers = 4;

        let pub_params = PublicParams {
            sector_size: sector_size as u64,
            window_size: window_leaves as u64 * NODE_SIZE as u64,
            window_challenge_count: 2,
            sector_count,
            num_layers: 4,
        };

        let randomness = <Tree::Hasher as Hasher>::Domain::random(rng);
        let prover_id = <Tree::Hasher as Hasher>::Domain::random(rng);

        // Construct and store an MT using a named DiskStore.
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path();

        let mut pub_sectors = Vec::new();
        let mut priv_sectors = Vec::new();
        let mut trees = Vec::new();

        for _i in 0..total_sector_count {
            let (_data, tree) =
                generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));
            trees.push(tree);
        }
        for (i, tree) in trees.iter().enumerate() {
            let comm_layers: Vec<_> = (0..num_layers - 1)
                .map(|_| <Tree::Hasher as Hasher>::Domain::random(rng))
                .collect();
            let comm_replica = tree.root();
            let comm_r: <Tree::Hasher as Hasher>::Domain =
                hash_comm_r(&comm_layers, comm_replica).into();

            priv_sectors.push(PrivateSector { tree });

            pub_sectors.push(PublicSector {
                id: (i as u64).into(),
                comm_r,
                comm_layers,
                comm_replica,
            });
        }

        let pub_inputs = PublicInputs {
            randomness,
            prover_id,
            sectors: &pub_sectors,
            k: None,
        };

        let priv_inputs = PrivateInputs::<Tree> {
            sectors: &priv_sectors[..],
        };

        let proof = NseWindowPoSt::<Tree>::prove_all_partitions(
            &pub_params,
            &pub_inputs,
            &priv_inputs,
            partitions,
        )
        .expect("proving failed");

        let is_valid =
            NseWindowPoSt::<Tree>::verify_all_partitions(&pub_params, &pub_inputs, &proof)
                .expect("verification failed");

        assert!(is_valid);
    }

    #[test]
    fn nse_window_post_pedersen_single_partition_matching_sub_8_4() {
        test_nse_window_post::<LCTree<PedersenHasher, U8, U4, U0>>(5, 5, 1);
    }

    #[test]
    fn nse_window_post_poseidon_single_partition_matching_sub_8_4() {
        test_nse_window_post::<LCTree<PoseidonHasher, U8, U4, U0>>(5, 5, 1);
    }

    #[test]
    fn nse_window_post_poseidon_single_partition_smaller_sub_8_4() {
        test_nse_window_post::<LCTree<PoseidonHasher, U8, U4, U0>>(3, 5, 1);
    }

    #[test]
    fn nse_window_post_poseidon_two_partitions_matching_sub_8_4() {
        test_nse_window_post::<LCTree<PoseidonHasher, U8, U4, U0>>(4, 2, 2);
    }

    #[test]
    fn nse_window_post_poseidon_two_partitions_smaller_sub_8_4() {
        test_nse_window_post::<LCTree<PoseidonHasher, U8, U4, U0>>(5, 3, 2);
    }
}
