use std::marker::PhantomData;

use serde::{Deserialize, Serialize};
use storage_proofs_core::{
    error::Result,
    merkle::{MerkleProof, MerkleTreeTrait},
    proof::ProofScheme,
};

use crate::{
    constants::{TreeRDomain, TreeRHasher},
    PrivateInputs, PublicParams, SetupParams,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct PublicInputs {
    pub comm_r_old: TreeRDomain,
    pub comm_d_new: TreeRDomain,
    pub comm_r_new: TreeRDomain,
    // The number of high bits to take from each challenge's bits. Used to verify replica encoding
    // in the vanilla proof. `h` is only a public-input for the vanilla proof; the circuit takes
    // `h_select` as a public-input rather than `h`.
    pub h: usize,
}

#[derive(Serialize, Deserialize)]
pub struct ChallengeProof<TreeR>
where
    TreeR: MerkleTreeTrait<Hasher = TreeRHasher>,
{
    #[serde(bound(
        serialize = "MerkleProof<TreeRHasher, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity>: Serialize",
        deserialize = "MerkleProof<TreeRHasher, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity>: Deserialize<'de>"
    ))]
    pub proof_r_old:
        MerkleProof<TreeRHasher, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity>,
    #[serde(bound(
        serialize = "MerkleProof<TreeRHasher, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity>: Serialize",
        deserialize = "MerkleProof<TreeRHasher, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity>: Deserialize<'de>"
    ))]
    pub proof_d_new:
        MerkleProof<TreeRHasher, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity>,
    #[serde(bound(
        serialize = "MerkleProof<TreeRHasher, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity>: Serialize",
        deserialize = "MerkleProof<TreeRHasher, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity>: Deserialize<'de>"
    ))]
    pub proof_r_new:
        MerkleProof<TreeRHasher, TreeR::Arity, TreeR::SubTreeArity, TreeR::TopTreeArity>,
}

// Implement `Clone` by hand because `MerkleTreeTrait` does not implement `Clone`.
impl<TreeR> Clone for ChallengeProof<TreeR>
where
    TreeR: MerkleTreeTrait<Hasher = TreeRHasher>,
{
    fn clone(&self) -> Self {
        ChallengeProof {
            proof_r_old: self.proof_r_old.clone(),
            proof_d_new: self.proof_d_new.clone(),
            proof_r_new: self.proof_r_new.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct PartitionProof<TreeR>
where
    TreeR: MerkleTreeTrait<Hasher = TreeRHasher>,
{
    pub comm_c: TreeRDomain,
    #[serde(bound(
        serialize = "ChallengeProof<TreeR>: Serialize",
        deserialize = "ChallengeProof<TreeR>: Deserialize<'de>"
    ))]
    pub challenge_proofs: Vec<ChallengeProof<TreeR>>,
}

// Implement `Clone` by hand because `MerkleTreeTrait` does not implement `Clone`.
impl<TreeR> Clone for PartitionProof<TreeR>
where
    TreeR: MerkleTreeTrait<Hasher = TreeRHasher>,
{
    fn clone(&self) -> Self {
        PartitionProof {
            comm_c: self.comm_c,
            challenge_proofs: self.challenge_proofs.clone(),
        }
    }
}

#[derive(Debug)]
#[allow(clippy::upper_case_acronyms)]
pub struct EmptySectorUpdate<TreeR>
where
    TreeR: MerkleTreeTrait<Hasher = TreeRHasher>,
{
    _tree_r: PhantomData<TreeR>,
}

impl<'a, TreeR> ProofScheme<'a> for EmptySectorUpdate<TreeR>
where
    TreeR: 'static + MerkleTreeTrait<Hasher = TreeRHasher>,
{
    type SetupParams = SetupParams;
    type PublicParams = PublicParams;
    type PublicInputs = PublicInputs;
    type PrivateInputs = PrivateInputs;
    type Proof = PartitionProof<TreeR>;
    type Requirements = ();

    fn setup(setup_params: &Self::SetupParams) -> Result<Self::PublicParams> {
        Ok(PublicParams::from_sector_size_poseidon(
            setup_params.sector_bytes,
        ))
    }

    fn prove(
        _pub_params: &Self::PublicParams,
        _pub_inputs: &Self::PublicInputs,
        _priv_inputs: &Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        unimplemented!("EmptySectorUpdate-Poseidon vanilla is not yet implemented");
    }

    fn prove_all_partitions(
        _pub_params: &Self::PublicParams,
        _pub_inputs: &Self::PublicInputs,
        _priv_inputs: &Self::PrivateInputs,
        _partition_count: usize,
    ) -> Result<Vec<Self::Proof>> {
        unimplemented!("EmptySectorUpdate-Poseidon vanilla is not yet implemented");
    }

    fn verify(
        _pub_params: &Self::PublicParams,
        _pub_inputs: &Self::PublicInputs,
        _proof: &Self::Proof,
    ) -> Result<bool> {
        unimplemented!("EmptySectorUpdate-Poseidon vanilla is not yet implemented");
    }

    fn verify_all_partitions(
        _pub_params: &Self::PublicParams,
        _pub_inputs: &Self::PublicInputs,
        _partition_proofs: &[Self::Proof],
    ) -> Result<bool> {
        unimplemented!("EmptySectorUpdate-Poseidon vanilla is not yet implemented");
    }

    fn with_partition(pub_inputs: Self::PublicInputs, k: Option<usize>) -> Self::PublicInputs {
        if let Some(k) = k {
            assert_eq!(k, 0, "nonzero EmptySectorUpdate-Poseidon `k` argument");
        }
        pub_inputs
    }
}
