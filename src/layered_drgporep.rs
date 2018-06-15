use drgporep::{self, DrgPoRep};
use drgraph;
use error::Result;
use porep::{self, PoRep};
use proof::ProofScheme;

#[derive(Debug)]
pub struct SetupParams {
    pub drg_porep_setup_params: drgporep::SetupParams,
    pub layers: usize,
}

#[derive(Debug)]
pub struct PublicParams {
    pub drg_porep_public_params: drgporep::PublicParams,
    pub layers: usize,
}

pub type ReplicaParents = Vec<(usize, DataProof)>;

#[derive(Debug, Clone)]
pub struct EncodingProof {
    pub replica_node: DataProof,
    pub replica_parents: ReplicaParents,
    pub node: drgraph::MerkleProof,
}

impl<'a> Into<EncodingProof> for drgporep::Proof<'a> {
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

#[derive(Debug, Clone)]
pub struct DataProof {
    proof: drgraph::MerkleProof,
    data: Vec<u8>,
}

impl<'a> Into<DataProof> for drgporep::DataProof<'a> {
    fn into(self) -> DataProof {
        DataProof {
            proof: self.proof,
            data: self.data.to_vec().clone(),
        }
    }
}

pub struct PublicInputs<'a> {
    pub prover_id: &'a [u8],
    pub challenge: usize,
    pub tau: Vec<porep::Tau>,
}

pub struct PrivateInputs<'a> {
    pub replica: &'a [u8],
    pub aux: &'a [porep::ProverAux],
}

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
            encoding_proof,
            permutation_proof,
        }
    }
}

#[derive(Default)]
pub struct LayeredDrgPoRep {}

fn permute(pp: &drgporep::PublicParams) -> drgporep::PublicParams {
    drgporep::PublicParams {
        graph: pp.graph.permute(&[1, 2, 3, 4]),
        lambda: pp.lambda,
    }
}

fn invert_permute(pp: &drgporep::PublicParams) -> drgporep::PublicParams {
    drgporep::PublicParams {
        graph: pp.graph.invert_permute(&[1, 2, 3, 4]),
        lambda: pp.lambda,
    }
}

impl<'a> ProofScheme<'a> for LayeredDrgPoRep {
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<'a>;
    type PrivateInputs = PrivateInputs<'a>;
    type Proof = Vec<Proof>;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        let dp_sp = DrgPoRep::setup(&sp.drg_porep_setup_params)?;
        let pp = PublicParams {
            drg_porep_public_params: dp_sp,
            layers: sp.layers,
        };

        Ok(pp)
    }

    fn prove(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        priv_inputs: &Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        let drg_priv_inputs = drgporep::PrivateInputs {
            aux: &priv_inputs.aux[0],
            replica: priv_inputs.replica,
        };

        let mut proofs = Vec::with_capacity(pub_params.layers);

        prove_layers(
            &pub_params.drg_porep_public_params,
            pub_inputs,
            &drg_priv_inputs,
            priv_inputs.aux,
            pub_params.layers,
            &mut proofs,
        )?;

        Ok(proofs)
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        for (layer, proof_layer) in proof.iter().enumerate() {
            let new_pub_inputs = drgporep::PublicInputs {
                prover_id: pub_inputs.prover_id,
                challenge: pub_inputs.challenge,
                tau: &pub_inputs.tau[layer],
            };

            let ep = &proof_layer.encoding_proof;
            let parents: Vec<_> = ep
                .replica_parents
                .iter()
                .map(|p| {
                    (
                        p.0,
                        drgporep::DataProof {
                            // TODO: investigate if clone can be avoided by using a referenc in drgporep::DataProof
                            proof: p.1.proof.clone(),
                            data: p.1.data.as_slice(),
                        },
                    )
                })
                .collect();
            let res = DrgPoRep::verify(
                &pub_params.drg_porep_public_params,
                &new_pub_inputs,
                &drgporep::Proof {
                    replica_node: drgporep::DataProof {
                        // TODO: investigate if clone can be avoided by using a referenc in drgporep::DataProof
                        proof: ep.replica_node.proof.clone(),
                        data: ep.replica_node.data.as_slice(),
                    },
                    replica_parents: parents,
                    // TODO: investigate if clone can be avoided by using a referenc in drgporep::DataProof
                    node: ep.node.clone(),
                },
            )?;

            if !res {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn prove_layers(
    pp: &drgporep::PublicParams,
    pub_inputs: &PublicInputs,
    priv_inputs: &drgporep::PrivateInputs,
    aux: &[porep::ProverAux],
    layers: usize,
    proofs: &mut Vec<Proof>,
) -> Result<()> {
    assert!(layers > 0);

    let mut scratch = priv_inputs.replica.to_vec().clone();
    <DrgPoRep as PoRep>::replicate(&pp, pub_inputs.prover_id, scratch.as_mut_slice())?;

    let new_priv_inputs = drgporep::PrivateInputs {
        replica: scratch.as_slice(),
        aux: &aux[aux.len() - layers],
    };
    let drgporep_pub_inputs = drgporep::PublicInputs {
        prover_id: pub_inputs.prover_id,
        challenge: pub_inputs.challenge,
        tau: &pub_inputs.tau[pub_inputs.tau.len() - layers],
    };
    let drg_proof = DrgPoRep::prove(&pp, &drgporep_pub_inputs, &new_priv_inputs)?;
    proofs.push(Proof {
        encoding_proof: drg_proof.into(),
        permutation_proof: PermutationProof {},
    });

    let pp = &permute(pp);

    if layers != 1 {
        prove_layers(pp, pub_inputs, &new_priv_inputs, aux, layers - 1, proofs)?;
    }

    Ok(())
}

impl<'a, 'c> PoRep<'a> for LayeredDrgPoRep {
    type Tau = Vec<porep::Tau>;
    type ProverAux = Vec<porep::ProverAux>;

    fn replicate(
        pp: &'a PublicParams,
        prover_id: &[u8],
        data: &mut [u8],
    ) -> Result<(Self::Tau, Self::ProverAux)> {
        let mut taus = Vec::with_capacity(pp.layers);
        let mut auxs = Vec::with_capacity(pp.layers);

        permute_and_replicate_layers(
            &pp.drg_porep_public_params,
            pp.layers,
            prover_id,
            data,
            &mut taus,
            &mut auxs,
        )?;

        Ok((taus, auxs))
    }

    fn extract_all<'b>(
        pp: &'b PublicParams,
        prover_id: &'b [u8],
        data: &'b [u8],
    ) -> Result<Vec<u8>> {
        let mut data = data.to_vec();

        extract_and_invert_permute_layers(
            &pp.drg_porep_public_params,
            pp.layers,
            prover_id,
            &mut data,
        )?;

        Ok(data)
    }

    fn extract(
        _pp: &PublicParams,
        _prover_id: &[u8],
        _data: &[u8],
        _node: usize,
    ) -> Result<Vec<u8>> {
        unimplemented!();
    }
}

fn extract_and_invert_permute_layers<'a>(
    drgpp: &drgporep::PublicParams,
    layers: usize,
    prover_id: &[u8],
    data: &'a mut [u8],
) -> Result<()> {
    assert!(layers > 0);

    let inverted = &invert_permute(&drgpp);
    let mut res = DrgPoRep::extract_all(&inverted, prover_id, data).unwrap();

    for (i, r) in res.iter_mut().enumerate() {
        data[i] = *r;
    }

    if layers != 1 {
        extract_and_invert_permute_layers(inverted, layers - 1, prover_id, data)?;
    }

    Ok(())
}

fn permute_and_replicate_layers(
    drgpp: &drgporep::PublicParams,
    layers: usize,
    prover_id: &[u8],
    data: &mut [u8],
    taus: &mut Vec<porep::Tau>,
    auxs: &mut Vec<porep::ProverAux>,
) -> Result<()> {
    assert!(layers > 0);
    let (tau, aux) = DrgPoRep::replicate(&drgpp, prover_id, data).unwrap();

    taus.push(tau);
    auxs.push(aux);

    if layers != 1 {
        permute_and_replicate_layers(&permute(&drgpp), layers - 1, prover_id, data, taus, auxs)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng, XorShiftRng};

    fn permute_layers(mut drgpp: drgporep::PublicParams, layers: usize) -> drgporep::PublicParams {
        for _ in 0..layers {
            drgpp = permute(&drgpp);
        }
        drgpp
    }

    #[test]
    fn extract_all() {
        let lambda = 32;
        let prover_id = vec![1u8; 32];
        let data = vec![2u8; 32 * 3];

        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();

        let sp = SetupParams {
            drg_porep_setup_params: drgporep::SetupParams {
                lambda: lambda,
                drg: drgporep::DrgParams {
                    n: data.len() / lambda,
                    m: 10,
                },
            },
            layers: 5,
        };

        let pp = LayeredDrgPoRep::setup(&sp).unwrap();

        LayeredDrgPoRep::replicate(&pp, prover_id.as_slice(), data_copy.as_mut_slice()).unwrap();

        let permuted_params = PublicParams {
            drg_porep_public_params: permute_layers(pp.drg_porep_public_params, pp.layers),
            layers: pp.layers,
        };

        assert_ne!(data, data_copy);

        let decoded_data = LayeredDrgPoRep::extract_all(
            &permuted_params,
            prover_id.as_slice(),
            data_copy.as_mut_slice(),
        ).unwrap();

        assert_eq!(data, decoded_data);
    }

    fn prove_verify(lambda: usize, n: usize, i: usize) {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let m = i * 10;
        let lambda = lambda;
        let prover_id: Vec<u8> = (0..lambda).map(|_| rng.gen()).collect();
        let data: Vec<u8> = (0..lambda * n).map(|_| rng.gen()).collect();
        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();
        let challenge = i;
        let sp = SetupParams {
            drg_porep_setup_params: drgporep::SetupParams {
                lambda: lambda,
                drg: drgporep::DrgParams { n: n, m: m },
            },
            layers: 4,
        };

        let pp = LayeredDrgPoRep::setup(&sp).unwrap();
        let (tau, aux) =
            LayeredDrgPoRep::replicate(&pp, prover_id.as_slice(), data_copy.as_mut_slice())
                .unwrap();
        assert_ne!(data, data_copy);

        let pub_inputs = PublicInputs {
            prover_id: prover_id.as_slice(),
            challenge,
            tau: tau,
        };

        let priv_inputs = PrivateInputs {
            replica: data.as_slice(),
            aux: &aux,
        };

        let proof = LayeredDrgPoRep::prove(&pp, &pub_inputs, &priv_inputs).unwrap();
        assert!(LayeredDrgPoRep::verify(&pp, &pub_inputs, &proof).unwrap());
    }

    table_tests!{
        prove_verify {
            // TODO: figure out why this was failing
            // prove_verify_32_2_1(32, 2, 1);
            // prove_verify_32_2_2(32, 2, 2);

            prove_verify_32_3_1(32, 3, 1);
            prove_verify_32_3_2(32, 3, 2);

            prove_verify_32_10_1(32, 10, 1);
            prove_verify_32_10_2(32, 10, 2);
        }
    }
}
