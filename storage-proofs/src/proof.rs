use std::time::Instant;

use crate::error::Result;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;

use crate::SP_LOG;

/// The ProofScheme trait provides the methods that any proof scheme needs to implement.
pub trait ProofScheme<'a> {
    type PublicParams: Clone;
    type SetupParams;
    type PublicInputs: Clone;
    type PrivateInputs;
    type Proof: Clone + Serialize + DeserializeOwned;

    /// setup is used to generate public parameters from setup parameters in order to specialize
    /// a ProofScheme to the specific parameters required by a consumer.
    fn setup(_: &Self::SetupParams) -> Result<Self::PublicParams>;

    /// prove generates and returns a proof from public parameters, public inputs, and private inputs.
    fn prove<'b>(
        _: &'b Self::PublicParams,
        _: &'b Self::PublicInputs,
        _: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof>;

    fn prove_all_partitions<'b>(
        pub_params: &'b Self::PublicParams,
        pub_in: &'b Self::PublicInputs,
        priv_in: &'b Self::PrivateInputs,
        partition_count: usize,
    ) -> Result<Vec<Self::Proof>> {
        info!(SP_LOG, "groth_proof_count: {}", partition_count; "target" => "stats");
        info!(SP_LOG, "generating {} groth proofs.", partition_count; "target" => "groth_proving");
        let start = Instant::now();

        let result = (0..partition_count)
            .map(|k| {
                info!(SP_LOG, "generating groth proof {}.", k; "target" => "groth_proving");
                let start = Instant::now();

                let partition_pub_in = Self::with_partition((*pub_in).clone(), Some(k));
                let proof = Self::prove(pub_params, &partition_pub_in, priv_in);

                let proof_time = start.elapsed();
                info!(SP_LOG, "groth_proof_time: {:?}", proof_time; "target" => "stats");

                proof
            })
            .collect::<Result<Vec<Self::Proof>>>();

        let total_proof_time = start.elapsed();
        info!(SP_LOG, "total_groth_proof_time: {:?}", total_proof_time; "target" => "stats");

        result
    }

    /// verify returns true if the supplied proof is valid for the given public parameter and public inputs.
    /// Note that verify does not have access to private inputs.
    /// Remember that proof is untrusted, and any data it provides MUST be validated as corresponding
    /// to the supplied public parameters and inputs.
    fn verify(
        _pub_params: &Self::PublicParams,
        _pub_inputs: &Self::PublicInputs,
        _proof: &Self::Proof,
    ) -> Result<bool> {
        unimplemented!();
    }

    fn verify_all_partitions(
        pub_params: &Self::PublicParams,
        pub_in: &Self::PublicInputs,
        proofs: &[Self::Proof],
    ) -> Result<bool> {
        for (k, proof) in proofs.iter().enumerate() {
            let partition_pub_in = Self::with_partition((*pub_in).clone(), Some(k)); //

            if !Self::verify(pub_params, &partition_pub_in, proof)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    // This method must be specialized by concrete ProofScheme implementations which use partitions.
    fn with_partition(pub_in: Self::PublicInputs, _k: Option<usize>) -> Self::PublicInputs {
        pub_in
    }
}
