use std::collections::{BTreeMap, HashSet};
use std::marker::PhantomData;

use anyhow::{bail, ensure, Context};
use byteorder::{ByteOrder, LittleEndian};
use serde::{Deserialize, Serialize};

use storage_proofs_core::{
    error::{Error, Result},
    hasher::{Domain, HashFunction, Hasher},
    merkle::{MerkleProof, MerkleProofTrait, MerkleTreeTrait, MerkleTreeWrapper},
    parameter_cache::ParameterSetMetadata,
    proof::{NoRequirements, ProofScheme},
    sector::*,
    util::NODE_SIZE,
};

#[derive(Debug, Clone)]
pub struct SetupParams {
    /// The size of a sector.
    pub sector_size: u64,
    // TODO: can we drop this?
    /// How many challenges there are in total.
    pub challenges_count: usize,
}

#[derive(Debug, Clone)]
pub struct PublicParams {
    /// The size of a sector.
    pub sector_size: u64,
    /// How many challenges there are in total.
    pub challenges_count: usize,
}

impl ParameterSetMetadata for PublicParams {
    fn identifier(&self) -> String {
        format!(
            "RationalPoSt::PublicParams{{sector_size: {} challenges_count: {}}}",
            self.sector_size(),
            self.challenges_count,
        )
    }

    fn sector_size(&self) -> u64 {
        self.sector_size
    }
}

#[derive(Debug, Clone)]
pub struct PublicInputs<'a, T: 'a + Domain> {
    /// The challenges, which leafs to prove.
    pub challenges: &'a [Challenge],
    pub faults: &'a OrderedSectorSet,
    pub comm_rs: &'a [T],
}

#[derive(Debug, Clone)]
#[allow(clippy::type_complexity)]
pub struct PrivateInputs<'a, Tree: 'a + MerkleTreeTrait> {
    pub trees: &'a BTreeMap<
        SectorId,
        &'a MerkleTreeWrapper<
            Tree::Hasher,
            Tree::Store,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >,
    >,
    pub comm_cs: &'a Vec<<Tree::Hasher as Hasher>::Domain>,
    pub comm_r_lasts: &'a Vec<<Tree::Hasher as Hasher>::Domain>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<P: MerkleProofTrait> {
    #[serde(bound(
        serialize = "MerkleProof<P::Hasher, P::Arity, P::SubTreeArity, P::TopTreeArity>: Serialize",
        deserialize = "MerkleProof<P::Hasher, P::Arity, P::SubTreeArity, P::TopTreeArity>: serde::de::DeserializeOwned"
    ))]
    inclusion_proofs: Vec<MerkleProof<P::Hasher, P::Arity, P::SubTreeArity, P::TopTreeArity>>,
    pub comm_cs: Vec<<P::Hasher as Hasher>::Domain>,
}

impl<P: MerkleProofTrait> Proof<P> {
    pub fn leafs(&self) -> Vec<<P::Hasher as Hasher>::Domain> {
        self.inclusion_proofs
            .iter()
            .map(MerkleProof::leaf)
            .collect()
    }

    pub fn commitments(&self) -> Vec<<P::Hasher as Hasher>::Domain> {
        self.inclusion_proofs
            .iter()
            .map(MerkleProof::root)
            .collect()
    }

    #[allow(clippy::type_complexity)]
    pub fn paths(&self) -> Vec<Vec<(Vec<<P::Hasher as Hasher>::Domain>, usize)>> {
        self.inclusion_proofs
            .iter()
            .map(MerkleProof::path)
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct RationalPoSt<'a, Tree>
where
    Tree: 'a + MerkleTreeTrait,
{
    _t: PhantomData<&'a Tree>,
}

impl<'a, Tree: 'a + MerkleTreeTrait> ProofScheme<'a> for RationalPoSt<'a, Tree> {
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<'a, <Tree::Hasher as Hasher>::Domain>;
    type PrivateInputs = PrivateInputs<'a, Tree>;
    type Proof = Proof<Tree::Proof>;
    type Requirements = NoRequirements;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        Ok(PublicParams {
            sector_size: sp.sector_size,
            challenges_count: sp.challenges_count,
        })
    }

    fn prove<'b>(
        _pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        ensure!(
            pub_inputs.challenges.len() == pub_inputs.comm_rs.len(),
            "mismatched challenges and comm_rs"
        );
        ensure!(
            pub_inputs.challenges.len() == priv_inputs.comm_cs.len(),
            "mismatched challenges and comm_cs"
        );
        ensure!(
            pub_inputs.challenges.len() == priv_inputs.comm_r_lasts.len(),
            "mismatched challenges and comm_r_lasts"
        );
        let challenges = pub_inputs.challenges;

        let proofs = challenges
            .iter()
            .zip(priv_inputs.comm_r_lasts.iter())
            .map(|(challenge, comm_r_last)| {
                let challenged_leaf = challenge.leaf;

                if let Some(tree) = priv_inputs.trees.get(&challenge.sector) {
                    ensure!(comm_r_last == &tree.root(), Error::InvalidCommitment);

                    tree.gen_cached_proof(challenged_leaf as usize, None)
                } else {
                    bail!(Error::MalformedInput);
                }
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Proof {
            inclusion_proofs: proofs,
            comm_cs: priv_inputs.comm_cs.to_vec(),
        })
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        let challenges = pub_inputs.challenges;

        ensure!(
            challenges.len() == pub_inputs.comm_rs.len() as usize,
            Error::MalformedInput
        );

        ensure!(
            challenges.len() == proof.inclusion_proofs.len(),
            Error::MalformedInput
        );

        // validate each proof
        for (((merkle_proof, challenge), comm_r), comm_c) in proof
            .inclusion_proofs
            .iter()
            .zip(challenges.iter())
            .zip(pub_inputs.comm_rs.iter())
            .zip(proof.comm_cs.iter())
        {
            let challenged_leaf = challenge.leaf;

            // verify that H(Comm_c || Comm_r_last) == Comm_R
            // comm_r_last is the root of the proof
            let comm_r_last = merkle_proof.root();

            if AsRef::<[u8]>::as_ref(&<Tree::Hasher as Hasher>::Function::hash2(
                comm_c,
                &comm_r_last,
            )) != AsRef::<[u8]>::as_ref(&comm_r)
            {
                return Ok(false);
            }

            // validate the path length
            let expected_path_length =
                merkle_proof.expected_len(pub_params.sector_size as usize / NODE_SIZE);

            if expected_path_length != merkle_proof.path().len() {
                return Ok(false);
            }

            if !merkle_proof.validate(challenged_leaf as usize) {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

/// A challenge specifying a sector and leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    // The identifier of the challenged sector.
    pub sector: SectorId,
    // The leaf index this challenge points at.
    pub leaf: u64,
}

/// Rational PoSt specific challenge derivation.
pub fn derive_challenges(
    challenge_count: usize,
    sector_size: u64,
    sectors: &OrderedSectorSet,
    seed: &[u8],
    faults: &OrderedSectorSet,
) -> Result<Vec<Challenge>> {
    (0..challenge_count)
        .map(|n| {
            let mut attempt = 0;
            let mut attempted_sectors = HashSet::new();
            loop {
                let c = derive_challenge(seed, n as u64, attempt, sector_size, sectors)?;

                // check for faulty sector
                if !faults.contains(&c.sector) {
                    // valid challenge, not found
                    return Ok(c);
                } else {
                    attempt += 1;
                    attempted_sectors.insert(c.sector);

                    ensure!(
                        attempted_sectors.len() < sectors.len(),
                        "all sectors are faulty"
                    );
                }
            }
        })
        .collect()
}

fn derive_challenge(
    seed: &[u8],
    n: u64,
    attempt: u64,
    sector_size: u64,
    sectors: &OrderedSectorSet,
) -> Result<Challenge> {
    let mut data = seed.to_vec();
    data.extend_from_slice(&n.to_le_bytes()[..]);
    data.extend_from_slice(&attempt.to_le_bytes()[..]);

    let hash = blake2b_simd::blake2b(&data);
    let challenge_bytes = hash.as_bytes();
    let sector_challenge = LittleEndian::read_u64(&challenge_bytes[..8]);
    let leaf_challenge = LittleEndian::read_u64(&challenge_bytes[8..16]);

    let sector_index = (sector_challenge % sectors.len() as u64) as usize;
    let sector = *sectors
        .iter()
        .nth(sector_index)
        .context("invalid challenge generated")?;

    Ok(Challenge {
        sector,
        leaf: leaf_challenge % (sector_size / NODE_SIZE as u64),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use generic_array::typenum;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use typenum::{U0, U2, U8};

    use storage_proofs_core::{
        hasher::{Blake2sHasher, Domain, Hasher, PedersenHasher, PoseidonHasher, Sha256Hasher},
        merkle::{generate_tree, get_base_tree_count, LCTree, MerkleTreeTrait},
    };

    fn test_rational_post<Tree: MerkleTreeTrait>()
    where
        Tree::Store: 'static,
    {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 64 * get_base_tree_count::<Tree>();
        let sector_size = leaves as u64 * 32;
        let challenges_count = 8;

        let pub_params = PublicParams {
            sector_size,
            challenges_count,
        };

        // Construct and store an MT using a named store.
        let temp_dir = tempdir::TempDir::new("tree").unwrap();
        let temp_path = temp_dir.path();

        let (_data1, tree1) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));
        let (_data2, tree2) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));

        let seed = (0..leaves).map(|_| rng.gen()).collect::<Vec<u8>>();
        let mut faults = OrderedSectorSet::new();
        faults.insert(139.into());
        faults.insert(1.into());
        faults.insert(32.into());

        let mut sectors = OrderedSectorSet::new();
        sectors.insert(891.into());
        sectors.insert(139.into());
        sectors.insert(32.into());
        sectors.insert(1.into());

        let mut trees = BTreeMap::new();
        trees.insert(139.into(), &tree1); // faulty with tree
        trees.insert(891.into(), &tree2);
        // other two faults don't have a tree available

        let challenges =
            derive_challenges(challenges_count, sector_size, &sectors, &seed, &faults).unwrap();

        // the only valid sector to challenge is 891
        assert!(
            challenges.iter().all(|c| c.sector == 891.into()),
            "invalid challenge generated"
        );

        let comm_r_lasts = challenges
            .iter()
            .map(|c| trees.get(&c.sector).unwrap().root())
            .collect::<Vec<_>>();

        let comm_cs: Vec<<Tree::Hasher as Hasher>::Domain> = challenges
            .iter()
            .map(|_c| <Tree::Hasher as Hasher>::Domain::random(rng))
            .collect();

        let comm_rs: Vec<<Tree::Hasher as Hasher>::Domain> = comm_cs
            .iter()
            .zip(comm_r_lasts.iter())
            .map(|(comm_c, comm_r_last)| {
                <Tree::Hasher as Hasher>::Function::hash2(comm_c, comm_r_last)
            })
            .collect();

        let pub_inputs = PublicInputs {
            challenges: &challenges,
            comm_rs: &comm_rs,
            faults: &faults,
        };

        let priv_inputs = PrivateInputs::<Tree> {
            trees: &trees,
            comm_cs: &comm_cs,
            comm_r_lasts: &comm_r_lasts,
        };

        let proof = RationalPoSt::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs)
            .expect("proving failed");

        let is_valid = RationalPoSt::<Tree>::verify(&pub_params, &pub_inputs, &proof)
            .expect("verification failed");

        assert!(is_valid);
    }

    #[test]
    fn rational_post_pedersen() {
        test_rational_post::<LCTree<PedersenHasher, U8, U0, U0>>();
    }

    #[test]
    fn rational_post_sha256() {
        test_rational_post::<LCTree<Sha256Hasher, U8, U0, U0>>();
    }

    #[test]
    fn rational_post_blake2s() {
        test_rational_post::<LCTree<Blake2sHasher, U8, U0, U0>>();
    }

    #[test]
    fn rational_post_poseidon() {
        test_rational_post::<LCTree<PoseidonHasher, U8, U0, U0>>();
    }

    #[test]
    fn rational_post_poseidon_8_8() {
        test_rational_post::<LCTree<PoseidonHasher, U8, U8, U0>>();
    }

    #[test]
    fn rational_post_poseidon_8_8_2() {
        test_rational_post::<LCTree<PoseidonHasher, U8, U8, U2>>();
    }

    fn test_rational_post_validates_challenge_identity<Tree: 'static + MerkleTreeTrait>() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 64 * get_base_tree_count::<Tree>();
        let sector_size = leaves as u64 * 32;
        let challenges_count = 2;

        let pub_params = PublicParams {
            sector_size,
            challenges_count,
        };

        // Construct and store an MT using a named store.
        let temp_dir = tempdir::TempDir::new("tree").unwrap();
        let temp_path = temp_dir.path();

        let (_data, tree) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));
        let seed = (0..leaves).map(|_| rng.gen()).collect::<Vec<u8>>();
        let mut faults = OrderedSectorSet::new();
        faults.insert(1.into());
        let mut sectors = OrderedSectorSet::new();
        sectors.insert(0.into());
        sectors.insert(1.into());

        let mut trees = BTreeMap::new();
        trees.insert(0.into(), &tree);

        let challenges =
            derive_challenges(challenges_count, sector_size, &sectors, &seed, &faults).unwrap();
        let comm_r_lasts = challenges
            .iter()
            .map(|c| trees.get(&c.sector).unwrap().root())
            .collect::<Vec<_>>();

        let comm_cs: Vec<<Tree::Hasher as Hasher>::Domain> = challenges
            .iter()
            .map(|_c| <Tree::Hasher as Hasher>::Domain::random(rng))
            .collect();

        let comm_rs: Vec<<Tree::Hasher as Hasher>::Domain> = comm_cs
            .iter()
            .zip(comm_r_lasts.iter())
            .map(|(comm_c, comm_r_last)| {
                <Tree::Hasher as Hasher>::Function::hash2(comm_c, comm_r_last)
            })
            .collect();

        let pub_inputs = PublicInputs {
            challenges: &challenges,
            faults: &faults,
            comm_rs: &comm_rs,
        };

        let priv_inputs = PrivateInputs::<Tree> {
            trees: &trees,
            comm_cs: &comm_cs,
            comm_r_lasts: &comm_r_lasts,
        };

        let proof = RationalPoSt::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs)
            .expect("proving failed");

        let seed = (0..leaves).map(|_| rng.gen()).collect::<Vec<u8>>();
        let challenges =
            derive_challenges(challenges_count, sector_size, &sectors, &seed, &faults).unwrap();
        let comm_r_lasts = challenges.iter().map(|_c| tree.root()).collect::<Vec<_>>();

        let comm_cs: Vec<<Tree::Hasher as Hasher>::Domain> = challenges
            .iter()
            .map(|_c| <Tree::Hasher as Hasher>::Domain::random(rng))
            .collect();

        let comm_rs: Vec<<Tree::Hasher as Hasher>::Domain> = comm_cs
            .iter()
            .zip(comm_r_lasts.iter())
            .map(|(comm_c, comm_r_last)| {
                <Tree::Hasher as Hasher>::Function::hash2(comm_c, comm_r_last)
            })
            .collect();

        let different_pub_inputs = PublicInputs {
            challenges: &challenges,
            faults: &faults,
            comm_rs: &comm_rs,
        };

        let verified = RationalPoSt::<Tree>::verify(&pub_params, &different_pub_inputs, &proof)
            .expect("verification failed");

        // A proof created with a the wrong challenge not be verified!
        assert!(!verified);
    }

    #[test]
    fn rational_post_actually_validates_challenge_identity_sha256() {
        test_rational_post_validates_challenge_identity::<LCTree<Sha256Hasher, U8, U0, U0>>();
    }

    #[test]
    fn rational_post_actually_validates_challenge_identity_blake2s() {
        test_rational_post_validates_challenge_identity::<LCTree<Blake2sHasher, U8, U0, U0>>();
    }

    #[test]
    fn rational_post_actually_validates_challenge_identity_pedersen() {
        test_rational_post_validates_challenge_identity::<LCTree<PedersenHasher, U8, U0, U0>>();
    }

    #[test]
    fn rational_post_actually_validates_challenge_identity_poseidon() {
        test_rational_post_validates_challenge_identity::<LCTree<PoseidonHasher, U8, U0, U0>>();
    }

    #[test]
    fn rational_post_actually_validates_challenge_identity_poseidon_8_8() {
        test_rational_post_validates_challenge_identity::<LCTree<PoseidonHasher, U8, U8, U0>>();
    }

    #[test]
    fn rational_post_actually_validates_challenge_identity_poseidon_8_8_2() {
        test_rational_post_validates_challenge_identity::<LCTree<PoseidonHasher, U8, U8, U2>>();
    }

    #[test]
    fn test_derive_challenges_fails_on_all_faulty() {
        use std::collections::BTreeSet;

        let mut sectors = BTreeSet::new();
        sectors.insert(SectorId::from(1));
        sectors.insert(SectorId::from(2));

        let mut faults = BTreeSet::new();
        faults.insert(SectorId::from(1));
        faults.insert(SectorId::from(2));

        let seed = vec![0u8];

        assert!(derive_challenges(10, 1024, &sectors, &seed, &faults).is_err());
    }
}
