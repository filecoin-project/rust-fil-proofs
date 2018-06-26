use drgporep::{self, DrgPoRep};
use drgraph::{BucketGraph, Graph};
use error::Result;
use fr32::fr_into_bytes;
use pairing::bls12_381::{Bls12, Fr};
use porep::{self, PoRep};
use proof::ProofScheme;
use std::marker::PhantomData;

const DEFAULT_ZIGZAG_LAYERS: usize = 6;

#[derive(Debug)]
pub struct SetupParams {
    pub drg_porep_setup_params: drgporep::SetupParams,
    pub layers: usize,
}

#[derive(Debug)]
pub struct PublicParams<G: Graph> {
    pub drg_porep_public_params: drgporep::PublicParams<G>,
    pub layers: usize,
}

pub type ReplicaParents = Vec<(usize, DataProof)>;
pub type EncodingProof = drgporep::Proof;
pub type DataProof = drgporep::DataProof;

pub struct PublicInputs<'a> {
    pub prover_id: &'a Fr,
    pub challenge: usize,
    pub tau: Vec<porep::Tau>,
}

pub struct PrivateInputs<'a> {
    pub replica: &'a [u8],
    pub aux: &'a [porep::ProverAux],
}

#[derive(Debug, Clone)]
pub struct Proof {
    pub encoding_proofs: Vec<EncodingProof>,
}

impl Proof {
    pub fn new(encoding_proofs: Vec<EncodingProof>) -> Proof {
        Proof { encoding_proofs }
    }
}
pub trait Layers {
    fn transform(
        pp: &drgporep::PublicParams<BucketGraph>,
        layer: usize,
        layers: usize,
    ) -> drgporep::PublicParams<BucketGraph>;
    fn invert_transform(
        pp: &drgporep::PublicParams<BucketGraph>,
        layer: usize,
        layers: usize,
    ) -> drgporep::PublicParams<BucketGraph>;
    fn prove_layers<'a>(
        pp: &drgporep::PublicParams<BucketGraph>,
        pub_inputs: &PublicInputs,
        priv_inputs: &drgporep::PrivateInputs,
        aux: &[porep::ProverAux],
        layers: usize,
        total_layers: usize,
        proofs: &'a mut Vec<EncodingProof>,
    ) -> Result<&'a Vec<EncodingProof>> {
        assert!(layers > 0);

        let mut scratch = priv_inputs.replica.to_vec().clone();
        let prover_id = fr_into_bytes::<Bls12>(pub_inputs.prover_id);
        <DrgPoRep as PoRep>::replicate(pp, &prover_id, scratch.as_mut_slice())?;

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
        proofs.push(drg_proof);

        let pp = &Self::transform(pp, total_layers - layers, total_layers);

        if layers != 1 {
            Self::prove_layers(
                pp,
                pub_inputs,
                &new_priv_inputs,
                aux,
                layers - 1,
                layers,
                proofs,
            )?;
        }

        Ok(proofs)
    }

    fn extract_and_invert_transform_layers<'a>(
        drgpp: &drgporep::PublicParams<BucketGraph>,
        layer: usize,
        layers: usize,
        prover_id: &[u8],
        data: &'a mut [u8],
    ) -> Result<()> {
        assert!(layers > 0);

        let inverted = &Self::invert_transform(&drgpp, layer, layers);
        let mut res = DrgPoRep::extract_all(inverted, prover_id, data).unwrap();

        for (i, r) in res.iter_mut().enumerate() {
            data[i] = *r;
        }

        if layers != 1 {
            Self::extract_and_invert_transform_layers(
                inverted,
                layer + 1,
                layers - 1,
                prover_id,
                data,
            )?;
        }

        Ok(())
    }

    fn transform_and_replicate_layers(
        drgpp: &drgporep::PublicParams<BucketGraph>,
        layer: usize,
        layers: usize,
        prover_id: &[u8],
        data: &mut [u8],
        taus: &mut Vec<porep::Tau>,
        auxs: &mut Vec<porep::ProverAux>,
    ) -> Result<()> {
        assert!(layers > 0);
        let (tau, aux) = DrgPoRep::replicate(drgpp, prover_id, data).unwrap();

        taus.push(tau);
        auxs.push(aux);

        if layers != 1 {
            Self::transform_and_replicate_layers(
                &Self::transform(&drgpp, layer, layers),
                layer + 1,
                layers - 1,
                prover_id,
                data,
                taus,
                auxs,
            )?;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct ZigZagDrgPoRep<G: Graph> {
    phantom: PhantomData<G>,
}

impl<G: Graph> Layers for ZigZagDrgPoRep<G> {
    fn transform(
        pp: &drgporep::PublicParams<BucketGraph>,
        _layer: usize,
        _layers: usize,
    ) -> drgporep::PublicParams<BucketGraph> {
        zigzag(pp)
    }

    fn invert_transform(
        pp: &drgporep::PublicParams<BucketGraph>,
        _layer: usize,
        _layers: usize,
    ) -> drgporep::PublicParams<BucketGraph> {
        zigzag(pp)
    }
}

fn zigzag<G: Graph>(pp: &drgporep::PublicParams<G>) -> drgporep::PublicParams<G> {
    drgporep::PublicParams {
        graph: pp.graph.zigzag(),
        lambda: pp.lambda,
    }
}

impl<'a, L: Layers> ProofScheme<'a> for L {
    type PublicParams = PublicParams<BucketGraph>;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<'a>;
    type PrivateInputs = PrivateInputs<'a>;
    type Proof = Proof;

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

        Self::prove_layers(
            &pub_params.drg_porep_public_params,
            pub_inputs,
            &drg_priv_inputs,
            priv_inputs.aux,
            pub_params.layers,
            pub_params.layers,
            &mut proofs,
        )?;

        Ok(Proof::new(proofs))
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        if !(proof.encoding_proofs.len() == pub_params.layers) {
            return Ok(false);
        }

        let total_layers = pub_params.layers;
        let mut pp = pub_params.drg_porep_public_params.clone();
        // TODO: verification is broken for the first node, figure out how to unbreak
        // with permuations
        for (layer, proof_layer) in proof.encoding_proofs.iter().enumerate() {
            let new_pub_inputs = drgporep::PublicInputs {
                prover_id: pub_inputs.prover_id,
                challenge: pub_inputs.challenge,
                tau: &pub_inputs.tau[layer],
            };

            let ep = &proof_layer; //.encoding_proofs;
            let parents: Vec<_> = ep
                .replica_parents
                .iter()
                .map(|p| {
                    (
                        p.0,
                        drgporep::DataProof {
                            // TODO: investigate if clone can be avoided by using a reference in drgporep::DataProof
                            proof: p.1.proof.clone(),
                            data: p.1.data,
                        },
                    )
                })
                .collect();

            let res = DrgPoRep::verify(
                &pp,
                //&pub_params.drg_porep_public_params,
                &new_pub_inputs,
                &drgporep::Proof {
                    replica_node: drgporep::DataProof {
                        // TODO: investigate if clone can be avoided by using a reference in drgporep::DataProof
                        proof: ep.replica_node.proof.clone(),
                        data: ep.replica_node.data,
                    },
                    replica_parents: parents,
                    // TODO: investigate if clone can be avoided by using a reference in drgporep::DataProof
                    node: ep.node.clone(),
                },
            )?;

            pp = Self::transform(&pp, layer, total_layers);

            if !res {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl<'a, 'c, L: Layers> PoRep<'a> for L {
    type Tau = Vec<porep::Tau>;
    type ProverAux = Vec<porep::ProverAux>;

    fn replicate(
        pp: &'a PublicParams<BucketGraph>,
        prover_id: &[u8],
        data: &mut [u8],
    ) -> Result<(Self::Tau, Self::ProverAux)> {
        let mut taus = Vec::with_capacity(pp.layers);
        let mut auxs = Vec::with_capacity(pp.layers);

        Self::transform_and_replicate_layers(
            &pp.drg_porep_public_params,
            0,
            pp.layers,
            prover_id,
            data,
            &mut taus,
            &mut auxs,
        )?;

        Ok((taus, auxs))
    }

    fn extract_all<'b>(
        pp: &'b PublicParams<BucketGraph>,
        prover_id: &'b [u8],
        data: &'b [u8],
    ) -> Result<Vec<u8>> {
        let mut data = data.to_vec();

        Self::extract_and_invert_transform_layers(
            &pp.drg_porep_public_params,
            0,
            pp.layers,
            prover_id,
            &mut data,
        )?;

        Ok(data)
    }

    fn extract(
        _pp: &PublicParams<BucketGraph>,
        _prover_id: &[u8],
        _data: &[u8],
        _node: usize,
    ) -> Result<Vec<u8>> {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use drgraph::DEFAULT_EXPANSION_DEGREE;
    use fr32::bytes_into_fr;
    use pairing::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};

    fn transform_layers(
        mut drgpp: drgporep::PublicParams<BucketGraph>,
        layers: usize,
    ) -> drgporep::PublicParams<BucketGraph> {
        for _ in 0..layers {
            drgpp = zigzag(&drgpp);
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
                    exp: 8,
                },
            },
            layers: DEFAULT_ZIGZAG_LAYERS,
        };

        let pp = ZigZagDrgPoRep::<BucketGraph>::setup(&sp).unwrap();

        ZigZagDrgPoRep::<BucketGraph>::replicate(
            &pp,
            prover_id.as_slice(),
            data_copy.as_mut_slice(),
        ).unwrap();

        let transformed_params = PublicParams {
            drg_porep_public_params: transform_layers(pp.drg_porep_public_params, pp.layers),
            layers: pp.layers,
        };

        assert_ne!(data, data_copy);

        let decoded_data = ZigZagDrgPoRep::<BucketGraph>::extract_all(
            &transformed_params,
            prover_id.as_slice(),
            data_copy.as_mut_slice(),
        ).unwrap();

        assert_eq!(data, decoded_data);
    }

    fn prove_verify(lambda: usize, n: usize, i: usize) {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let m = i * 10;
        let lambda = lambda;
        let prover_id: Vec<u8> = fr_into_bytes::<Bls12>(&rng.gen());
        let data: Vec<u8> = (0..n)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();
        let challenge = i;
        let sp = SetupParams {
            drg_porep_setup_params: drgporep::SetupParams {
                lambda,
                drg: drgporep::DrgParams {
                    n,
                    m,
                    exp: DEFAULT_EXPANSION_DEGREE,
                },
            },
            layers: DEFAULT_ZIGZAG_LAYERS,
        };

        let pp = ZigZagDrgPoRep::<BucketGraph>::setup(&sp).unwrap();
        let (tau, aux) = ZigZagDrgPoRep::<BucketGraph>::replicate(
            &pp,
            prover_id.as_slice(),
            data_copy.as_mut_slice(),
        ).unwrap();
        assert_ne!(data, data_copy);

        let pub_inputs = PublicInputs {
            prover_id: &bytes_into_fr::<Bls12>(prover_id.as_slice()).unwrap(),
            challenge,
            tau: tau,
        };

        let priv_inputs = PrivateInputs {
            replica: data.as_slice(),
            aux: &aux,
        };

        let proof = ZigZagDrgPoRep::<BucketGraph>::prove(&pp, &pub_inputs, &priv_inputs).unwrap();
        assert!(ZigZagDrgPoRep::<BucketGraph>::verify(&pp, &pub_inputs, &proof).unwrap());
    }

    table_tests!{
        prove_verify {
            // TODO: figure out why this was failing
             //prove_verify_32_2_1(32, 2, 1);
             //prove_verify_32_2_2(32, 2, 2);

            // TODO: why u fail???
            //prove_verify_32_3_1(32, 3, 1);
            //prove_verify_32_3_2(32, 3, 2);

             prove_verify_32_5_1(32, 5, 1);
             prove_verify_32_5_2(32, 5, 2);
             prove_verify_32_5_3(32, 5, 3);
        }
    }
}
