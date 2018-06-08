use drgporep::{self, DrgPoRep};
use drgraph;
use error::Result;
use porep::{self, PoRep};
use proof::ProofScheme;

#[derive(Debug)]
pub struct SetupParams {
    pub drgPorepSetupParams: drgporep::SetupParams,
    pub layers: usize,
}

#[derive(Debug)]
pub struct PublicParams {
    pub drgPorepPublicParams: drgporep::PublicParams,
    pub layers: usize,
}

pub type ReplicaParents = Vec<(usize, DataProof)>;

#[derive(Debug, Clone)]
pub struct EncodingProof {
    pub replica_node: DataProof,
    pub replica_parents: ReplicaParents,
    pub node: drgraph::MerkleProof,
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

pub struct LayeredDrgPoRep {}

impl LayeredDrgPoRep {
    pub fn new() -> LayeredDrgPoRep {
        LayeredDrgPoRep {}
    }
}

fn permute(pp: &drgporep::PublicParams, layer: usize) -> drgporep::PublicParams {
    if layer == 0 {
        return (*pp).clone();
    }

    return drgporep::PublicParams {
        graph: pp.graph.permute(&[1, 2, 3, 4]),
        lambda: pp.lambda,
    };
}

fn invert_permute(pp: &drgporep::PublicParams, layer: usize) -> drgporep::PublicParams {
    if layer == 0 {
        return (*pp).clone();
    }

    return drgporep::PublicParams {
        graph: pp.graph.invert_permute(&[1, 2, 3, 4]),
        lambda: pp.lambda,
    };
}


//static DP: DrgPoRep = DrgPoRep {};

type Tau<'a> = &'a [porep::Tau];

type ProverAux<'a> = &'a [porep::ProverAux];

impl<'a> ProofScheme<'a> for LayeredDrgPoRep {
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

            <DrgPoRep as PoRep>::replicate(
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

fn permute_layers(drgpp: drgporep::PublicParams, layer:usize) -> drgporep::PublicParams {
    if layer == 0 {
        return drgpp;
    }
    let permuted = permute(&drgpp, layer);
    permute_layers(permuted, layer-1)
}

fn permute_and_replicate_layer(
    drgpp: &drgporep::PublicParams,
    layer: usize,
    prover_id: &[u8],
    data: &mut [u8],
    mut taus: Vec<porep::Tau>,
    mut auxs: Vec<porep::ProverAux>,
) -> Result<(Vec<porep::Tau>, Vec<porep::ProverAux>)> {
    if layer == 0 {
        return Ok((taus, auxs));
    }
    let permuted = permute(&drgpp, layer);
    let (tau, aux) = DrgPoRep::replicate(&permuted, prover_id, data).unwrap();

    taus.push(tau); auxs.push(aux);
    permute_and_replicate_layer(&permuted, layer - 1, prover_id, data, taus, auxs)
}

fn extract_and_invert_permute_layer<'a, 'b>(
    drgpp: &drgporep::PublicParams,
    layer: usize,
    prover_id: &[u8],
    mut data: &'a mut [u8],
) -> Result< &'a[u8]> {
    if layer == 0 {
        return Ok(data);
    }
    let mut res = DrgPoRep::extract_all(&drgpp, prover_id, data).unwrap();
    let inverted = &invert_permute(&drgpp, layer);

    for (i, r) in res.iter_mut().enumerate() {
        data[i] = *r;
    }
    extract_and_invert_permute_layer(inverted, layer - 1, prover_id, data)
}

//<'a, Vec<porep::Tau>, Vec<porep::ProverAux>
impl<'a, 'c> PoRep<'a> for LayeredDrgPoRep {
    type Tau = Vec<porep::Tau>;
    type ProverAux = Vec<porep::ProverAux>;

    fn replicate(
        pp: &'a PublicParams,
        prover_id: &[u8],
        data: &mut [u8],
    ) -> Result<(Self::Tau, Self::ProverAux)> {
        let mut taus = Vec::new();
        let mut auxs = Vec::new();
        permute_and_replicate_layer(&pp.drgPorepPublicParams, pp.layers, prover_id, data, taus, auxs)
    }

    fn extract_all<'b>(
        pp: &'b PublicParams,
        prover_id: &'b [u8],
        data: &'b [u8],
    ) -> Result<Vec<u8>> {
        let mut d: Vec<u8> = data.to_vec();
        let dd = d.as_mut_slice();

        Ok(extract_and_invert_permute_layer(&pp.drgPorepPublicParams, pp.layers, prover_id, dd)?.to_vec())
    }

    fn extract(pp: &PublicParams, prover_id: &[u8], data: &[u8], node: usize) -> Result<Vec<u8>> {
        unimplemented!();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn test_layered_extract_all() {
        let lambda = 16;
        let prover_id = vec![1u8; 16];
        let data = vec![2u8; 16 * 3];
        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();

        let sp = SetupParams {
            drgPorepSetupParams: drgporep::SetupParams {
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
            drgPorepPublicParams: permute_layers(pp.drgPorepPublicParams, pp.layers),
            layers: pp.layers,
        };

        assert_ne!(data, data_copy);

        let decoded_data =
            LayeredDrgPoRep::extract_all(&permuted_params, prover_id.as_slice(), data_copy.as_mut_slice())
                .unwrap();

        assert_eq!(data, decoded_data);
    }

    /*fn prove_verify(lambda: usize, n: usize) {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let prover_id = vec![1u8; 16];
        let data = vec![2u8; 16 * 3];
        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();


        for i in 1..10 {
            let m = i * 10;
            let lambda = lambda;
            let prover_id = vec![rng.gen(); lambda];
            let data = vec![rng.gen(); lambda * n];
            // create a copy, so we can comare roundtrips
            let mut data_copy = data.clone();
            let challenge = 1;

            let sp = SetupParams {
                drgPorepSetupParams: drgporep::SetupParams {
                    lambda: lambda,
                    drg: drgporep::DrgParams {
                        n: n,
                        m: m,
                    },
                },
                layers: 5,
            };

            let pp = LayeredDrgPoRep::setup(&sp).unwrap();

            let (taus, auxs) =
                LayeredDrgPoRep::replicate(&pp, prover_id.as_slice(), data_copy.as_mut_slice()).unwrap();

            assert_ne!(data, data_copy);

            let pub_inputs = PublicInputs {
                prover_id: prover_id.as_slice(),
                challenge: challenge,
                tau: &tau,
            };

            let priv_inputs = PrivateInputs {
                replica: data_copy.as_slice(),
                aux: &aux,
            };

            let proof = LayeredDrgPoRep::prove(&pp, &pub_inputs, &priv_inputs).unwrap();
            assert!(LayeredDrgPoRep::verify(&pp, &pub_inputs, &proof).unwrap());
        }
    }

    #[test]
    fn test_prove_verify_16_2() {
        prove_verify(16, 2);
    }
*/
}
