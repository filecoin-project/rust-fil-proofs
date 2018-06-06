use drgporep::{self, DrgPoRep};
use drgraph;
use error::Result;
use porep::PoRep;
use proof::ProofScheme;

#[derive(Debug)]
pub struct SetupParams {
    drgPorepSetupParams: drgporep::SetupParams,
    layers: usize,
}

#[derive(Debug)]
pub struct PublicParams {
    drgPorepPublicParams: drgporep::PublicParams,
    layers: usize,
}

type EncodingProof<'a> = drgporep::Proof<'a>;
type PublicInputs<'a> = drgporep::PublicInputs<'a>;
type PrivateInputs<'a> = drgporep::PrivateInputs<'a>;

#[derive(Debug)]
pub struct PermutationProof {}

pub struct Proof<'a> {
    pub encoding_proof: EncodingProof<'a>,
    pub permutation_proof: PermutationProof,
}

impl<'a> Proof<'a> {
    pub fn new(encoding_proof: EncodingProof, permutation_proof: PermutationProof) -> Proof {
        Proof {
            encoding_proof: encoding_proof,
            permutation_proof: permutation_proof,
        }
    }
}

pub struct LayeredDrgPorep {}

impl LayeredDrgPorep {
    pub fn new() -> LayeredDrgPorep {
        LayeredDrgPorep {}
    }
}

fn permute(pp: drgporep::PublicParams, layer: usize) -> drgporep::PublicParams {
    if layer == 0 {
        return pp;
    }

    return drgporep::PublicParams {
        graph: drgraph::permute(pp.graph, &[1, 2, 3, 4]),
        lambda: pp.lambda,
    };
}

//static DP: DrgPoRep = DrgPoRep {};

impl<'a> ProofScheme<'a> for LayeredDrgPorep {
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<'a>;
    type PrivateInputs = PrivateInputs<'a>;
    type Proof = &'a [Proof<'a>];

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        let dpSp = DrgPoRep::setup(&sp.drgPorepSetupParams)?;

        let pp = PublicParams {
            drgPorepPublicParams: dpSp,
            layers: sp.layers,
        };

        Ok(pp)
    }

    fn prove(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        priv_inputs: &Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        let mut proofs = Vec::new();
        let pp = pub_params.drgPorepPublicParams;

        for layer in 0..pub_params.layers {
            let pp = permute(pp, layer);

            let r = priv_inputs.replica.iter().map(|x| *x).collect::<Vec<u8>>();
            let rr = &mut r[..];

            <DrgPoRep as PoRep>::replicate(&pp, pub_inputs.prover_id, rr);

            let new_priv_inputs = PrivateInputs {
                replica: rr,
                aux: priv_inputs.aux,
            };

            let encoding_proof = DrgPoRep::prove(&pp, pub_inputs, &new_priv_inputs)?;
            let permutation_proof = PermutationProof {};

            proofs.push(Proof {
                encoding_proof: encoding_proof,
                permutation_proof: permutation_proof,
            });
        }
        Ok(proofs.as_slice())
    }

    fn verify(
        _pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        unimplemented!()
    }
}
