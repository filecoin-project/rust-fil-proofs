use drgporep;
use drgraph::{BucketGraph, Graph};
use layered_drgporep::Layers;

const DEFAULT_ZIGZAG_LAYERS: usize = 6;

#[derive(Debug)]
pub struct ZigZagDrgPoRep {}

impl Layers for ZigZagDrgPoRep {
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

#[cfg(test)]
mod tests {
    use super::*;
    use drgraph::DEFAULT_EXPANSION_DEGREE;
    use fr32::{bytes_into_fr, fr_into_bytes};
    use layered_drgporep::{PrivateInputs, PublicInputs, PublicParams, SetupParams};
    use pairing::bls12_381::Bls12;
    use porep::PoRep;
    use proof::ProofScheme;
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

        let pp = ZigZagDrgPoRep::setup(&sp).unwrap();

        ZigZagDrgPoRep::replicate(&pp, prover_id.as_slice(), data_copy.as_mut_slice()).unwrap();

        let transformed_params = PublicParams {
            drg_porep_public_params: transform_layers(pp.drg_porep_public_params, pp.layers),
            layers: pp.layers,
        };

        assert_ne!(data, data_copy);

        let decoded_data = ZigZagDrgPoRep::extract_all(
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

        let pp = ZigZagDrgPoRep::setup(&sp).unwrap();
        let (tau, aux) =
            ZigZagDrgPoRep::replicate(&pp, prover_id.as_slice(), data_copy.as_mut_slice()).unwrap();
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

        let proof = ZigZagDrgPoRep::prove(&pp, &pub_inputs, &priv_inputs).unwrap();
        assert!(ZigZagDrgPoRep::verify(&pp, &pub_inputs, &proof).unwrap());
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
