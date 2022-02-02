use std::marker::PhantomData;

use ff::PrimeFieldBits;
use filecoin_hashers::{Hasher, PoseidonArity};
use serde::{Deserialize, Serialize};
use storage_proofs_core::{error::Result, merkle::MerkleProof, proof::ProofScheme};

use crate::{
    constants::{TreeRDomain, TreeRHasher},
    PrivateInputs, PublicParams, SetupParams,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct PublicInputs<F> {
    #[serde(bound(serialize = "TreeRDomain<F>: Serialize"))]
    #[serde(bound(deserialize = "TreeRDomain<F>: Deserialize<'de>"))]
    pub comm_r_old: TreeRDomain<F>,
    #[serde(bound(serialize = "TreeRDomain<F>: Serialize"))]
    #[serde(bound(deserialize = "TreeRDomain<F>: Deserialize<'de>"))]
    pub comm_d_new: TreeRDomain<F>,
    #[serde(bound(serialize = "TreeRDomain<F>: Serialize"))]
    #[serde(bound(deserialize = "TreeRDomain<F>: Deserialize<'de>"))]
    pub comm_r_new: TreeRDomain<F>,
    // The number of high bits to take from each challenge's bits. Used to verify replica encoding
    // in the vanilla proof. `h` is only a public-input for the vanilla proof; the circuit takes
    // `h_select` as a public-input rather than `h`.
    pub h: usize,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChallengeProof<F, U, V, W>
where
    TreeRHasher<F>: Hasher,
    U: PoseidonArity,
    V: PoseidonArity,
    W: PoseidonArity,
{
    #[serde(bound(serialize = "MerkleProof<TreeRHasher<F>, U, V, W>: Serialize"))]
    #[serde(bound(deserialize = "MerkleProof<TreeRHasher<F>, U, V, W>: Deserialize<'de>"))]
    pub proof_r_old: MerkleProof<TreeRHasher<F>, U, V, W>,
    #[serde(bound(serialize = "MerkleProof<TreeRHasher<F>, U, V, W>: Serialize"))]
    #[serde(bound(deserialize = "MerkleProof<TreeRHasher<F>, U, V, W>: Deserialize<'de>"))]
    pub proof_d_new: MerkleProof<TreeRHasher<F>, U, V, W>,
    #[serde(bound(serialize = "MerkleProof<TreeRHasher<F>, U, V, W>: Serialize"))]
    #[serde(bound(deserialize = "MerkleProof<TreeRHasher<F>, U, V, W>: Deserialize<'de>"))]
    pub proof_r_new: MerkleProof<TreeRHasher<F>, U, V, W>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PartitionProof<F, U, V, W>
where
    TreeRHasher<F>: Hasher,
    U: PoseidonArity,
    V: PoseidonArity,
    W: PoseidonArity,
{
    #[serde(bound(serialize = "TreeRDomain<F>: Serialize"))]
    #[serde(bound(deserialize = "TreeRDomain<F>: Deserialize<'de>"))]
    pub comm_c: TreeRDomain<F>,
    #[serde(bound(serialize = "ChallengeProof<F, U, V, W>: Serialize"))]
    #[serde(bound(deserialize = "ChallengeProof<F, U, V, W>: Deserialize<'de>"))]
    pub challenge_proofs: Vec<ChallengeProof<F, U, V, W>>,
}

#[derive(Debug)]
pub struct EmptySectorUpdate<F, U, V, W> {
    _f: PhantomData<F>,
    _tree_r: PhantomData<(U, V, W)>,
}

impl<'a, F, U, V, W> ProofScheme<'a> for EmptySectorUpdate<F, U, V, W>
where
    F: PrimeFieldBits,
    TreeRHasher<F>: Hasher<Domain = TreeRDomain<F>>,
    U: PoseidonArity,
    V: PoseidonArity,
    W: PoseidonArity,
{
    type SetupParams = SetupParams;
    type PublicParams = PublicParams;
    type PublicInputs = PublicInputs<F>;
    type PrivateInputs = PrivateInputs<F>;
    type Proof = PartitionProof<F, U, V, W>;
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
