use storage_proofs_core::{
    error::Result, hasher::Hasher, merkle::MerkleTreeTrait, proof::ProofScheme,
};

use super::{
    NarrowStackedExpander,
    {ChallengeRequirements, PrivateInputs, Proof, PublicInputs, PublicParams, SetupParams},
};

impl<'a, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher> ProofScheme<'a>
    for NarrowStackedExpander<'a, Tree, G>
{
    type PublicParams = PublicParams<Tree>;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<<Tree::Hasher as Hasher>::Domain, <G as Hasher>::Domain>;
    type PrivateInputs = PrivateInputs<Tree, G>;
    type Proof = Vec<Proof<Tree, G>>;
    type Requirements = ChallengeRequirements;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        Ok(sp.clone().into())
    }

    fn prove<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        todo!()
    }

    fn prove_all_partitions<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
        partition_count: usize,
    ) -> Result<Vec<Self::Proof>> {
        todo!()
    }

    fn verify_all_partitions(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        partition_proofs: &[Self::Proof],
    ) -> Result<bool> {
        todo!()
    }

    fn with_partition(pub_in: Self::PublicInputs, k: Option<usize>) -> Self::PublicInputs {
        todo!()
    }

    fn satisfies_requirements(
        public_params: &PublicParams<Tree>,
        requirements: &ChallengeRequirements,
        partitions: usize,
    ) -> bool {
        todo!()
    }
}
