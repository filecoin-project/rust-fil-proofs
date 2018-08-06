use bellman::{Circuit, ConstraintSystem, SynthesisError};
use circuit::drgporep::DrgPoRepCircuit;
use compound_proof::CompoundProof;
use drgraph::BucketGraph;
use pairing::bls12_381::{Bls12, Fr};
use proof::ProofScheme;
use sapling_crypto::jubjub::JubjubEngine;
use zigzag_drgporep::ZigZagDrgPoRep;
use zigzag_graph::ZigZagGraph;

pub struct ZigZagCircuit<'a, E: JubjubEngine> {
    params: &'a E::Params,
    drgporep: DrgPoRepCircuit<'a, E>,
}

impl<'a, E: JubjubEngine> Circuit<E> for ZigZagCircuit<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError>
    where
        E: JubjubEngine,
    {
        unimplemented!();
    }
}

struct ZigZagCompound {}

impl<'a>
    CompoundProof<'a, Bls12, ZigZagDrgPoRep<'a, ZigZagGraph<BucketGraph>>, ZigZagCircuit<'a, Bls12>>
    for ZigZagCompound
{
    fn generate_public_inputs(
        pub_in: &<ZigZagDrgPoRep<ZigZagGraph<BucketGraph>> as ProofScheme>::PublicInputs,
        pub_params: &<ZigZagDrgPoRep<ZigZagGraph<BucketGraph>> as ProofScheme>::PublicParams,
    ) -> Vec<Fr> {
        unimplemented!()
    }

    fn circuit(
        public_inputs: &<ZigZagDrgPoRep<ZigZagGraph<BucketGraph>> as ProofScheme>::PublicInputs,
        vanilla_proof: &<ZigZagDrgPoRep<ZigZagGraph<BucketGraph>> as ProofScheme>::Proof,
        public_params: &<ZigZagDrgPoRep<ZigZagGraph<BucketGraph>> as ProofScheme>::PublicParams,
        params: &<Bls12 as JubjubEngine>::Params,
    ) -> ZigZagCircuit<'a, Bls12> {
        unimplemented!()
    }
}
