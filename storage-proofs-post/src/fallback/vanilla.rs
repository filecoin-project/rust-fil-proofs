use std::collections::BTreeSet;
use std::marker::PhantomData;

use anyhow::ensure;
use bellperson::bls::Fr;
use byteorder::{ByteOrder, LittleEndian};
use filecoin_hashers::{Domain, HashFunction, Hasher};
use generic_array::typenum::Unsigned;
use log::{error, trace};
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use storage_proofs_core::{
    api_version::ApiVersion,
    error::{Error, Result},
    merkle::{MerkleProof, MerkleProofTrait, MerkleTreeTrait, MerkleTreeWrapper},
    parameter_cache::ParameterSetMetadata,
    proof::ProofScheme,
    sector::SectorId,
    util::{default_rows_to_discard, NODE_SIZE},
};

#[derive(Debug, Clone)]
pub struct SetupParams {
    /// Size of the sector in bytes.
    pub sector_size: u64,
    /// Number of challenges per sector.
    pub challenge_count: usize,
    /// Number of challenged sectors.
    pub sector_count: usize,
    pub api_version: ApiVersion,
}

#[derive(Debug, Clone)]
pub struct PublicParams {
    /// Size of the sector in bytes.
    pub sector_size: u64,
    /// Number of challenges per sector.
    pub challenge_count: usize,
    /// Number of challenged sectors.
    pub sector_count: usize,
    pub api_version: ApiVersion,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicInputs<T: Domain> {
    #[serde(bound = "")]
    pub randomness: T,
    #[serde(bound = "")]
    pub prover_id: T,
    #[serde(bound = "")]
    pub sectors: Vec<PublicSector<T>>,
    /// Partition index
    pub k: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicSector<T: Domain> {
    pub id: SectorId,
    #[serde(bound = "")]
    pub comm_r: T,
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
    pub comm_c: <Tree::Hasher as Hasher>::Domain,
    pub comm_r_last: <Tree::Hasher as Hasher>::Domain,
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
    #[serde(bound(
        serialize = "MerkleProof<Proof::Hasher, Proof::Arity, Proof::SubTreeArity, Proof::TopTreeArity>: Serialize",
        deserialize = "MerkleProof<Proof::Hasher, Proof::Arity, Proof::SubTreeArity, Proof::TopTreeArity>: DeserializeOwned"
    ))]
    pub inclusion_proofs:
        Vec<MerkleProof<Proof::Hasher, Proof::Arity, Proof::SubTreeArity, Proof::TopTreeArity>>,
    pub comm_c: <Proof::Hasher as Hasher>::Domain,
    pub comm_r_last: <Proof::Hasher as Hasher>::Domain,
}

impl<P: MerkleProofTrait> SectorProof<P> {
    pub fn leafs(&self) -> Vec<<P::Hasher as Hasher>::Domain> {
        self.inclusion_proofs
            .iter()
            .map(MerkleProofTrait::leaf)
            .collect()
    }

    pub fn comm_r_last(&self) -> <P::Hasher as Hasher>::Domain {
        self.inclusion_proofs[0].root()
    }

    pub fn commitments(&self) -> Vec<<P::Hasher as Hasher>::Domain> {
        self.inclusion_proofs
            .iter()
            .map(MerkleProofTrait::root)
            .collect()
    }

    #[allow(clippy::type_complexity)]
    pub fn paths(&self) -> Vec<Vec<(Vec<<P::Hasher as Hasher>::Domain>, usize)>> {
        self.inclusion_proofs
            .iter()
            .map(MerkleProofTrait::path)
            .collect()
    }

    pub fn as_options(&self) -> Vec<Vec<(Vec<Option<Fr>>, Option<usize>)>> {
        self.inclusion_proofs
            .iter()
            .map(MerkleProofTrait::as_options)
            .collect()
    }

    // Returns a read-only reference.
    pub fn inclusion_proofs(
        &self,
    ) -> &Vec<MerkleProof<P::Hasher, P::Arity, P::SubTreeArity, P::TopTreeArity>> {
        &self.inclusion_proofs
    }
}

#[derive(Debug, Clone)]
pub struct FallbackPoSt<'a, Tree>
where
    Tree: MerkleTreeTrait,
{
    _t: PhantomData<&'a Tree>,
}

pub fn generate_sector_challenges<T: Domain>(
    randomness: T,
    challenge_count: usize,
    sector_set_len: u64,
    prover_id: T,
) -> Result<Vec<u64>> {
    (0..challenge_count)
        .map(|n| generate_sector_challenge(randomness, n, sector_set_len, prover_id))
        .collect()
}

/// Generate a single sector challenge.
pub fn generate_sector_challenge<T: Domain>(
    randomness: T,
    n: usize,
    sector_set_len: u64,
    prover_id: T,
) -> Result<u64> {
    let mut hasher = Sha256::new();
    hasher.update(AsRef::<[u8]>::as_ref(&prover_id));
    hasher.update(AsRef::<[u8]>::as_ref(&randomness));
    hasher.update(&n.to_le_bytes()[..]);

    let hash = hasher.finalize();

    let sector_challenge = LittleEndian::read_u64(&hash[..8]);
    let sector_index = sector_challenge % sector_set_len;

    Ok(sector_index)
}

/// Generate all challenged leaf ranges for a single sector, such that the range fits into the sector.
pub fn generate_leaf_challenges<T: Domain>(
    pub_params: &PublicParams,
    randomness: T,
    sector_id: u64,
    challenge_count: usize,
) -> Vec<u64> {
    let mut challenges = Vec::with_capacity(challenge_count);

    let mut hasher = Sha256::new();
    hasher.update(AsRef::<[u8]>::as_ref(&randomness));
    hasher.update(&sector_id.to_le_bytes()[..]);

    for challenge_index in 0..challenge_count {
        let challenge =
            generate_leaf_challenge_inner::<T>(hasher.clone(), pub_params, challenge_index as u64);
        challenges.push(challenge)
    }

    challenges
}

/// Generates challenge, such that the range fits into the sector.
pub fn generate_leaf_challenge<T: Domain>(
    pub_params: &PublicParams,
    randomness: T,
    sector_id: u64,
    leaf_challenge_index: u64,
) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(AsRef::<[u8]>::as_ref(&randomness));
    hasher.update(&sector_id.to_le_bytes()[..]);

    generate_leaf_challenge_inner::<T>(hasher, pub_params, leaf_challenge_index)
}

pub fn generate_leaf_challenge_inner<T: Domain>(
    mut hasher: Sha256,
    pub_params: &PublicParams,
    leaf_challenge_index: u64,
) -> u64 {
    hasher.update(&leaf_challenge_index.to_le_bytes()[..]);
    let hash = hasher.finalize();

    let leaf_challenge = LittleEndian::read_u64(&hash[..8]);

    leaf_challenge % (pub_params.sector_size / NODE_SIZE as u64)
}

// Generates a single vanilla proof, given the private inputs and sector challenges.
pub fn vanilla_proof<Tree: MerkleTreeTrait>(
    sector_id: SectorId,
    priv_inputs: &PrivateInputs<'_, Tree>,
    challenges: &[u64],
) -> Result<Proof<Tree::Proof>> {
    ensure!(
        priv_inputs.sectors.len() == 1,
        "vanilla_proof called with multiple sector proofs"
    );

    let priv_sector = &priv_inputs.sectors[0];
    let comm_c = priv_sector.comm_c;
    let comm_r_last = priv_sector.comm_r_last;
    let tree = priv_sector.tree;

    let tree_leafs = tree.leafs();
    let rows_to_discard = default_rows_to_discard(tree_leafs, Tree::Arity::to_usize());

    trace!(
        "Generating proof for tree leafs {} and arity {}",
        tree_leafs,
        Tree::Arity::to_usize(),
    );

    let inclusion_proofs = (0..challenges.len())
        .into_par_iter()
        .map(|challenged_leaf_index| {
            let challenged_leaf = challenges[challenged_leaf_index];
            let proof = tree.gen_cached_proof(challenged_leaf as usize, Some(rows_to_discard))?;

            ensure!(
                proof.validate(challenged_leaf as usize) && proof.root() == priv_sector.comm_r_last,
                "Generated vanilla proof for sector {} is invalid",
                sector_id
            );

            Ok(proof)
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(Proof {
        sectors: vec![SectorProof {
            inclusion_proofs,
            comm_c,
            comm_r_last,
        }],
    })
}

impl<'a, Tree: 'a + MerkleTreeTrait> ProofScheme<'a> for FallbackPoSt<'a, Tree> {
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<<Tree::Hasher as Hasher>::Domain>;
    type PrivateInputs = PrivateInputs<'a, Tree>;
    type Proof = Proof<Tree::Proof>;
    type Requirements = ChallengeRequirements;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        Ok(PublicParams {
            sector_size: sp.sector_size,
            challenge_count: sp.challenge_count,
            sector_count: sp.sector_count,
            api_version: sp.api_version,
        })
    }

    fn prove<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        let proofs = Self::prove_all_partitions(pub_params, pub_inputs, priv_inputs, 1)?;
        let k = pub_inputs.k.unwrap_or(0);
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

        // Use `BTreeSet` so failure result will be canonically ordered (sorted).
        let mut faulty_sectors = BTreeSet::new();

        for (j, (pub_sectors_chunk, priv_sectors_chunk)) in pub_inputs
            .sectors
            .chunks(num_sectors_per_chunk)
            .zip(priv_inputs.sectors.chunks(num_sectors_per_chunk))
            .enumerate()
        {
            let (mut proofs, mut faults) = pub_sectors_chunk
                .par_iter()
                .zip(priv_sectors_chunk.par_iter())
                .enumerate()
                .map(|(i, (pub_sector, priv_sector))| {
                    let sector_id = pub_sector.id;
                    let tree = priv_sector.tree;
                    let tree_leafs = tree.leafs();
                    let rows_to_discard =
                        default_rows_to_discard(tree_leafs, Tree::Arity::to_usize());

                    trace!(
                        "Generating proof for tree leafs {} and arity {}",
                        tree_leafs,
                        Tree::Arity::to_usize(),
                    );

                    // avoid rehashing fixed inputs
                    let mut challenge_hasher = Sha256::new();
                    challenge_hasher.update(AsRef::<[u8]>::as_ref(&pub_inputs.randomness));
                    challenge_hasher.update(&u64::from(sector_id).to_le_bytes()[..]);

                    let (inclusion_proofs, faults) = (0..pub_params.challenge_count)
                        .into_par_iter()
                        .fold(
                            || (Vec::new(), BTreeSet::new()),
                            |(mut inclusion_proofs, mut faults), n| {
                                let challenge_index =
                                    ((j * num_sectors_per_chunk + i) * pub_params.challenge_count
                                        + n) as u64;
                                let challenged_leaf = generate_leaf_challenge_inner::<
                                    <Tree::Hasher as Hasher>::Domain,
                                >(
                                    challenge_hasher.clone(),
                                    pub_params,
                                    challenge_index,
                                );
                                let proof = tree.gen_cached_proof(
                                    challenged_leaf as usize,
                                    Some(rows_to_discard),
                                );

                                match proof {
                                    Ok(proof) => {
                                        if proof.validate(challenged_leaf as usize)
                                            && proof.root() == priv_sector.comm_r_last
                                            && pub_sector.comm_r
                                                == <Tree::Hasher as Hasher>::Function::hash2(
                                                    &priv_sector.comm_c,
                                                    &priv_sector.comm_r_last,
                                                )
                                        {
                                            inclusion_proofs.push(proof);
                                        } else {
                                            error!("faulty sector: {:?}", sector_id);
                                            faults.insert(sector_id);
                                        }
                                    }
                                    Err(err) => {
                                        error!("faulty sector: {:?} ({:?})", sector_id, err);
                                        faults.insert(sector_id);
                                    }
                                }
                                (inclusion_proofs, faults)
                            },
                        )
                        .reduce(
                            || (Vec::new(), BTreeSet::new()),
                            |(mut inclusion_proofs, mut faults), (p, f)| {
                                inclusion_proofs.extend(p);
                                faults.extend(f);
                                (inclusion_proofs, faults)
                            },
                        );

                    (
                        SectorProof {
                            inclusion_proofs,
                            comm_c: priv_sector.comm_c,
                            comm_r_last: priv_sector.comm_r_last,
                        },
                        faults,
                    )
                })
                .fold(
                    || (Vec::new(), BTreeSet::new()),
                    |(mut sector_proofs, mut sector_faults), (sector_proof, mut faults)| {
                        sector_faults.append(&mut faults);
                        sector_proofs.push(sector_proof);
                        (sector_proofs, sector_faults)
                    },
                )
                .reduce(
                    || (Vec::new(), BTreeSet::new()),
                    |(mut sector_proofs, mut sector_faults), (proofs, mut faults)| {
                        sector_proofs.extend(proofs);
                        sector_faults.append(&mut faults);
                        (sector_proofs, sector_faults)
                    },
                );

            // If there were less than the required number of sectors provided, we duplicate the last one
            // to pad the proof out, such that it works in the circuit part.
            while proofs.len() < num_sectors_per_chunk {
                proofs.push(proofs[proofs.len() - 1].clone());
            }

            partition_proofs.push(Proof { sectors: proofs });
            faulty_sectors.append(&mut faults);
        }

        if faulty_sectors.is_empty() {
            Ok(partition_proofs)
        } else {
            Err(Error::FaultySectors(faulty_sectors.into_iter().collect()).into())
        }
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

            let is_valid = pub_sectors_chunk
                .par_iter()
                .zip(proof.sectors.par_iter())
                .enumerate()
                .map(|(i, (pub_sector, sector_proof))| {
                    let sector_id = pub_sector.id;
                    let comm_r = &pub_sector.comm_r;
                    let comm_c = sector_proof.comm_c;
                    let inclusion_proofs = &sector_proof.inclusion_proofs;

                    // Verify that H(Comm_c || Comm_r_last) == Comm_R

                    // comm_r_last is the root of the proof
                    let comm_r_last = inclusion_proofs[0].root();

                    if AsRef::<[u8]>::as_ref(&<Tree::Hasher as Hasher>::Function::hash2(
                        &comm_c,
                        &comm_r_last,
                    )) != AsRef::<[u8]>::as_ref(comm_r)
                    {
                        error!("hash(comm_c || comm_r_last) != comm_r: {:?}", sector_id);
                        return Ok(false);
                    }

                    ensure!(
                        challenge_count == inclusion_proofs.len(),
                        "unexpected number of inclusion proofs: {} != {}",
                        challenge_count,
                        inclusion_proofs.len()
                    );

                    // avoid rehashing fixed inputs
                    let mut challenge_hasher = Sha256::new();
                    challenge_hasher.update(AsRef::<[u8]>::as_ref(&pub_inputs.randomness));
                    challenge_hasher.update(&u64::from(sector_id).to_le_bytes()[..]);

                    let is_valid_list = inclusion_proofs
                        .par_iter()
                        .enumerate()
                        .map(|(n, inclusion_proof)| -> Result<bool> {
                            let challenge_index =
                                (j * num_sectors_per_chunk + i) * pub_params.challenge_count + n;
                            let challenged_leaf =
                                generate_leaf_challenge_inner::<<Tree::Hasher as Hasher>::Domain>(
                                    challenge_hasher.clone(),
                                    pub_params,
                                    challenge_index as u64,
                                );

                            // validate all comm_r_lasts match
                            if inclusion_proof.root() != comm_r_last {
                                error!("inclusion proof root != comm_r_last: {:?}", sector_id);
                                return Ok(false);
                            }

                            // validate the path length
                            let expected_path_length = inclusion_proof
                                .expected_len(pub_params.sector_size as usize / NODE_SIZE);

                            if expected_path_length != inclusion_proof.path().len() {
                                error!("wrong path length: {:?}", sector_id);
                                return Ok(false);
                            }

                            if !inclusion_proof.validate(challenged_leaf as usize) {
                                error!("invalid inclusion proof: {:?}", sector_id);
                                return Ok(false);
                            }
                            Ok(true)
                        })
                        .collect::<Result<Vec<bool>>>()?;

                    Ok(is_valid_list.into_iter().all(|v| v))
                })
                .reduce(
                    || Ok(true),
                    |all_valid, is_valid| Ok(all_valid? && is_valid?),
                )?;
            if !is_valid {
                return Ok(false);
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
            checked.checked_mul(public_params.challenge_count),
            Some(checked * public_params.challenge_count)
        );

        checked * public_params.challenge_count >= requirements.minimum_challenge_count
    }
}
