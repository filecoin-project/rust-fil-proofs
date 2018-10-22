use error::Result;

/// The ProofScheme trait provides the methods that any proof scheme needs to implement.
pub trait ProofScheme<'a> {
    type PublicParams: Clone;
    type SetupParams;
    type PublicInputs;
    type PrivateInputs;
    type Proof: Clone;

    /// setup is used to generate public parameters from setup parameters in order to specialize
    /// a ProofScheme to the specific parameters required by a consumer.
    fn setup(&Self::SetupParams) -> Result<Self::PublicParams>;

    /// prove generates and returns a proof from public parameters, public inputs, and private inputs.
    fn prove<'b>(
        &'b Self::PublicParams,
        &'b Self::PublicInputs,
        &'b Self::PrivateInputs,
    ) -> Result<Self::Proof>;

    /// verify returns true if the supplied proof is valid for the given public parameter and public inputs.
    /// Note that verify does not have access to private inputs.
    /// Remember that proof is untrusted, and any data it provides MUST be validated as corresponding
    /// to the supplied public parameters and inputs.
    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool>;

    // This method must be implemented/specialized for concrete ProofScheme using partitions.
    fn with_partition(pub_in: Self::PublicInputs, _k: Option<usize>) -> Self::PublicInputs {
        pub_in
    }
}
