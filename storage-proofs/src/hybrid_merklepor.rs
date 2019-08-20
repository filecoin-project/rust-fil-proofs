use std::marker::PhantomData;

use crate::drgporep::DataProof;
use crate::drgraph::graph_height;
use crate::error::{Error, Result};
use crate::hasher::hybrid::HybridDomain;
use crate::hasher::{Domain, Hasher};
use crate::hybrid_merkle::{HybridMerkleProof, HybridMerkleTree};
use crate::parameter_cache::ParameterSetMetadata;
use crate::proof::{NoRequirements, ProofScheme};

/// The parameters shared between the prover and verifier.
#[derive(Clone, Debug)]
pub struct PublicParams {
    /// How many leaves the underlying merkle tree has.
    pub leaves: usize,
    pub beta_height: usize,
    pub private: bool,
}

impl ParameterSetMetadata for PublicParams {
    fn identifier(&self) -> String {
        format!(
            "merklepor::PublicParams{{leaves: {}; beta_height: {}, private: {}}}",
            self.leaves, self.beta_height, self.private
        )
    }

    fn sector_size(&self) -> u64 {
        unimplemented!("required for parameter metadata file generation")
    }
}

/// The inputs that are necessary for the verifier to verify the proof.
#[derive(Debug, Clone)]
pub struct PublicInputs<AD, BD>
where
    AD: Domain,
    BD: Domain,
{
    /// The root hash of the underlying merkle tree.
    pub commitment: Option<HybridDomain<AD, BD>>,
    /// The challenge, which leaf to prove.
    pub challenge: usize,
}

/// The inputs that are only available to the prover.
#[derive(Debug)]
pub struct PrivateInputs<'a, AH, BH>
where
    AH: Hasher + 'a,
    BH: Hasher + 'a,
{
    /// The data of the leaf.
    pub leaf: HybridDomain<AH::Domain, BH::Domain>,
    /// The underlying merkle tree.
    pub tree: &'a HybridMerkleTree<AH, BH>,
    _ah: PhantomData<AH>,
    _bh: PhantomData<BH>,
}

impl<'a, AH, BH> PrivateInputs<'a, AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    pub fn new(
        leaf: HybridDomain<AH::Domain, BH::Domain>,
        tree: &'a HybridMerkleTree<AH, BH>,
    ) -> Self {
        PrivateInputs {
            leaf,
            tree,
            _ah: PhantomData,
            _bh: PhantomData,
        }
    }
}

/// The proof that is returned from `prove`.
pub type Proof<AH, BH> = DataProof<AH, BH>;

#[derive(Debug)]
pub struct SetupParams {
    pub leaves: usize,
    pub beta_height: usize,
    pub private: bool,
}

/// Merkle tree based proof of retrievability.
#[derive(Debug, Default)]
pub struct HybridMerklePoR<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    _ah: PhantomData<AH>,
    _bh: PhantomData<BH>,
}

impl<'a, AH, BH> ProofScheme<'a> for HybridMerklePoR<AH, BH>
where
    AH: 'static + Hasher,
    BH: 'static + Hasher,
{
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<AH::Domain, BH::Domain>;
    type PrivateInputs = PrivateInputs<'a, AH, BH>;
    type Proof = Proof<AH, BH>;
    type Requirements = NoRequirements;

    fn setup(sp: &SetupParams) -> Result<PublicParams> {
        Ok(PublicParams {
            leaves: sp.leaves,
            beta_height: sp.beta_height,
            private: sp.private,
        })
    }

    fn prove<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        let challenge = pub_inputs.challenge % pub_params.leaves;
        let tree = priv_inputs.tree;

        if let Some(ref commitment) = pub_inputs.commitment {
            if commitment != &tree.root() {
                return Err(Error::InvalidCommitment);
            }
        }

        Ok(Proof {
            proof: HybridMerkleProof::new_from_proof(&tree.gen_proof(challenge)),
            data: priv_inputs.leaf,
        })
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        let commitments_match = match pub_inputs.commitment {
            Some(ref commitment) => commitment == proof.proof.root(),
            None => true,
        };

        if !commitments_match {
            return Ok(false);
        }

        let path_lengths_match = graph_height(pub_params.leaves) == proof.proof.path().len();

        if !path_lengths_match {
            return Ok(false);
        }

        let data_valid = proof.proof.validate_data(&proof.data.into_bytes());
        let path_valid = proof.proof.validate(pub_inputs.challenge);

        Ok(data_valid && path_valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use paired::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};

    use crate::drgraph::{new_seed, BucketGraph, Graph};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::{Blake2sHasher, HybridHasher, PedersenHasher, Sha256Hasher};
    use crate::hybrid_merkle::HybridMerkleProof;
    use crate::merkle::make_proof_for_test;
    use crate::util::data_at_node;

    const N_LEAVES: usize = 32;
    const BETA_HEIGHT: usize = 1;

    fn test_merklepor<AH, BH>()
    where
        AH: 'static + Hasher,
        BH: 'static + Hasher,
    {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let pub_params = PublicParams {
            leaves: N_LEAVES,
            beta_height: BETA_HEIGHT,
            private: false,
        };

        let data: Vec<u8> = (0..N_LEAVES)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let graph = BucketGraph::<AH, BH>::new(N_LEAVES, 5, 0, new_seed());
        let tree = graph.hybrid_merkle_tree(&data, BETA_HEIGHT).unwrap();

        let pub_inputs = PublicInputs {
            challenge: 3,
            commitment: Some(tree.root()),
        };

        // `BETA_HEIGHT` is set to 1, therefore each leaf will be a `HybridDomain::Beta`.
        let leaf = {
            let leaf_data = data_at_node(&data, pub_inputs.challenge).unwrap();
            let leaf_beta = BH::Domain::try_from_bytes(leaf_data).unwrap();
            HybridDomain::Beta(leaf_beta)
        };

        let priv_inputs = PrivateInputs::<AH, BH>::new(leaf, &tree);

        let proof = HybridMerklePoR::<AH, BH>::prove(&pub_params, &pub_inputs, &priv_inputs)
            .expect("proving failed");

        let is_valid = HybridMerklePoR::<AH, BH>::verify(&pub_params, &pub_inputs, &proof)
            .expect("verification failed");

        assert!(is_valid);
    }

    #[test]
    fn merklepor_pedersen() {
        test_merklepor::<PedersenHasher, PedersenHasher>();
    }

    #[test]
    fn merklepor_sha256() {
        test_merklepor::<Sha256Hasher, Sha256Hasher>();
    }

    #[test]
    fn merklepor_blake2s() {
        test_merklepor::<Blake2sHasher, Blake2sHasher>();
    }

    #[test]
    fn merklepor_pedersen_blake2s() {
        test_merklepor::<PedersenHasher, Blake2sHasher>();
    }

    // Construct a proof that satisfies a cursory validation:
    // Data and proof are minimally consistent.
    // Proof root matches that requested in public inputs.
    // However, note that data has no relationship to anything,
    // and proof path does not actually prove that data was in the tree corresponding to expected root.
    fn make_bogus_proof<AH, BH>(
        pub_inputs: &PublicInputs<AH::Domain, BH::Domain>,
        rng: &mut XorShiftRng,
    ) -> Proof<AH, BH>
    where
        AH: Hasher,
        BH: Hasher,
    {
        // Beta height is 1, so leaves are `Hybrid::Beta`s.
        let leaf: HybridDomain<AH::Domain, BH::Domain> = HybridDomain::Beta(rng.gen());
        let merkle_path = vec![(leaf, true)];
        let root = pub_inputs.commitment.unwrap();
        let merkle_proof = make_proof_for_test::<HybridHasher<AH, BH>>(root, leaf, merkle_path);

        Proof {
            data: leaf,
            proof: merkle_proof,
        }
    }

    fn test_merklepor_validates<AH, BH>()
    where
        AH: 'static + Hasher,
        BH: 'static + Hasher,
    {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let pub_params = PublicParams {
            leaves: N_LEAVES,
            beta_height: BETA_HEIGHT,
            private: false,
        };

        let data: Vec<u8> = (0..N_LEAVES)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let graph = BucketGraph::<AH, BH>::new(N_LEAVES, 5, 0, new_seed());
        let tree = graph.hybrid_merkle_tree(&data, BETA_HEIGHT).unwrap();

        let pub_inputs = PublicInputs {
            challenge: 3,
            commitment: Some(tree.root()),
        };

        let bad_proof = make_bogus_proof::<AH, BH>(&pub_inputs, rng);

        let verified = HybridMerklePoR::verify(&pub_params, &pub_inputs, &bad_proof)
            .expect("verification failed");

        // A bad proof should not be verified!
        assert!(!verified);
    }

    #[test]
    fn merklepor_actually_validates_sha256() {
        test_merklepor_validates::<Sha256Hasher, Sha256Hasher>();
    }

    #[test]
    fn merklepor_actually_validates_blake2s() {
        test_merklepor_validates::<Blake2sHasher, Blake2sHasher>();
    }

    #[test]
    fn merklepor_actually_validates_pedersen() {
        test_merklepor_validates::<PedersenHasher, PedersenHasher>();
    }

    #[test]
    fn merklepor_actually_validates_pedersen_blake2s() {
        test_merklepor_validates::<PedersenHasher, Blake2sHasher>();
    }

    fn test_merklepor_validates_challenge_identity<AH, BH>()
    where
        AH: 'static + Hasher,
        BH: 'static + Hasher,
    {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let pub_params = PublicParams {
            leaves: N_LEAVES,
            beta_height: BETA_HEIGHT,
            private: false,
        };

        let data: Vec<u8> = (0..N_LEAVES)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let graph = BucketGraph::<AH, BH>::new(N_LEAVES, 5, 0, new_seed());
        let tree = graph.hybrid_merkle_tree(&data, BETA_HEIGHT).unwrap();

        let pub_inputs = PublicInputs {
            challenge: 3,
            commitment: Some(tree.root()),
        };

        // Beta height is set to 1, therefore each leaf will be a `HybridDomain::Beta`.
        let leaf = {
            let leaf_data = data_at_node(&data, pub_inputs.challenge).unwrap();
            let leaf_beta = BH::Domain::try_from_bytes(leaf_data).unwrap();
            HybridDomain::Beta(leaf_beta)
        };

        let priv_inputs = PrivateInputs::<AH, BH>::new(leaf, &tree);

        let proof = HybridMerklePoR::<AH, BH>::prove(&pub_params, &pub_inputs, &priv_inputs)
            .expect("proving failed");

        let different_pub_inputs = PublicInputs {
            challenge: 999,
            commitment: Some(tree.root()),
        };

        let verified =
            HybridMerklePoR::<AH, BH>::verify(&pub_params, &different_pub_inputs, &proof)
                .expect("verification failed");

        // A proof created with the wrong challenge not be verified!
        assert!(!verified);
    }

    #[test]
    fn merklepor_actually_validates_challenge_identity_sha256() {
        test_merklepor_validates_challenge_identity::<Sha256Hasher, Sha256Hasher>();
    }

    #[test]
    fn merklepor_actually_validates_challenge_identity_blake2s() {
        test_merklepor_validates_challenge_identity::<Blake2sHasher, Blake2sHasher>();
    }

    #[test]
    fn merklepor_actually_validates_challenge_identity_pedersen() {
        test_merklepor_validates_challenge_identity::<PedersenHasher, PedersenHasher>();
    }

    #[test]
    fn merklepor_actually_validates_challenge_identity_pedersen_blake2s() {
        test_merklepor_validates_challenge_identity::<PedersenHasher, Blake2sHasher>();
    }
}
