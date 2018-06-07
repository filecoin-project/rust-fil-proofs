use drgporep::{self, DrgPoRep};
use drgraph;
use error::Result;
use porep::{self, PoRep};
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

pub type ReplicaParents = Vec<(usize, DataProof)>;

#[derive(Debug, Clone)]
pub struct EncodingProof {
    replica_node: DataProof,
    replica_parents: ReplicaParents,
    node: drgraph::MerkleProof,
}

impl<'a> Into<EncodingProof> for drgporep::Proof {
    fn into(self) -> EncodingProof {
        let p = self
            .replica_parents
            .into_iter()
            .map(|input| (input.0, input.1.into()))
            .collect::<Vec<_>>();

        EncodingProof {
            replica_node: self.replica_node.into(),
            replica_parents: p,
            node: self.node,
        }
    }
}

impl<'a> Into<drgporep::Proof> for EncodingProof {
    fn into(self) -> drgporep::Proof {
        let p = self
            .replica_parents
            .into_iter()
            .map(|input| (input.0, input.1.into()))
            .collect::<Vec<_>>();

        drgporep::Proof {
            replica_node: self.replica_node.into(),
            replica_parents: p,
            node: self.node,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DataProof {
    proof: drgraph::MerkleProof,
    data: Vec<u8>,
    //data: &'a Vec,
}

impl<'a> Into<DataProof> for drgporep::DataProof {
    fn into(self) -> DataProof {
        DataProof {
            proof: self.proof,
            data: self.data.to_vec().clone(),
        }
    }
}

impl Into<drgporep::DataProof> for DataProof {
    fn into(self) -> drgporep::DataProof {
        drgporep::DataProof {
            proof: self.proof,
            data: self.data.clone(),
        }
    }
}

type PublicInputs<'a> = drgporep::PublicInputs<'a>;
type PrivateInputs<'a> = drgporep::PrivateInputs<'a>;

#[derive(Debug, Clone)]
pub struct PermutationProof {}

#[derive(Debug, Clone)]
pub struct Proof {
    pub encoding_proof: EncodingProof,
    pub permutation_proof: PermutationProof,
}

impl Proof {
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

fn permute(pp: &drgporep::PublicParams, layer: usize) -> drgporep::PublicParams {
    if layer == 0 {
        return (*pp).clone();
    }

    return drgporep::PublicParams {
        graph: drgraph::permute(&pp.graph, &[1, 2, 3, 4]),
        lambda: pp.lambda,
    };
}

//static DP: DrgPoRep = DrgPoRep {};

type Tau<'a> = &'a [porep::Tau];

type ProverAux<'a> = &'a [porep::ProverAux];

impl<'a> ProofScheme<'a> for LayeredDrgPorep {
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<'a>;
    type PrivateInputs = PrivateInputs<'a>;
    type Proof = Vec<Proof>;

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
        let pp = &pub_params.drgPorepPublicParams;

        let mut scratch = priv_inputs.replica.to_vec().clone();

        for layer in 0..pub_params.layers {
            let pp = permute(&pp, layer);

            <DrgPoRep as PoRep<porep::Tau, porep::ProverAux>>::replicate(
                &pp,
                pub_inputs.prover_id,
                scratch.as_mut_slice(),
            );

            let new_priv_inputs = PrivateInputs {
                replica: scratch.as_slice(),
                aux: priv_inputs.aux,
            };

            let drg_proof = DrgPoRep::prove(&pp, pub_inputs, &new_priv_inputs)?;
            let permutation_proof = PermutationProof {};

            proofs.push(Proof {
                encoding_proof: drg_proof.into(),
                permutation_proof: permutation_proof,
            });
        }
        Ok(proofs)
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        for layer in 0..pub_params.layers {
            let res = DrgPoRep::verify(
                &pub_params.drgPorepPublicParams,
                &pub_inputs,
                &proof[layer].encoding_proof.clone().into(),
            )?;

            if !res {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl<'a> PoRep<'a, Vec<porep::Tau>, Vec<porep::ProverAux>> for LayeredDrgPorep {
    fn replicate(
        pp: &PublicParams,
        prover_id: &[u8],
        data: &mut [u8],
    ) -> Result<(Vec<porep::Tau>, Vec<porep::ProverAux>)> {
        let mut taus = Vec::new();
        let mut auxs = Vec::new();
        let dpp = &pp.drgPorepPublicParams;

        for layer in 0..pp.layers {
            let dpp = &permute(dpp, layer);
            let (tau, aux) = DrgPoRep::replicate(dpp, prover_id, data)?;
            taus.push(tau);
            auxs.push(aux);
        }

        Ok((taus, auxs))
    }

    fn extract_all<'b>(
        pp: &'b PublicParams,
        prover_id: &'b [u8],
        data: &'b [u8],
    ) -> Result<Vec<u8>> {
        let mut res = DrgPoRep::extract_all(&pp.drgPorepPublicParams, prover_id, data)?;

        for layer in 0..pp.layers {
            res = DrgPoRep::extract_all(&pp.drgPorepPublicParams, prover_id, data)?;
        }
        Ok(res)
    }

    fn extract(pp: &PublicParams, prover_id: &[u8], data: &[u8], node: usize) -> Result<Vec<u8>> {
        DrgPoRep::extract(&pp.drgPorepPublicParams, prover_id, data, node)
    }
}
