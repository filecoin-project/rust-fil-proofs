use drgporep;
use drgraph::Graph;
use layered_drgporep::Layers;
use parameter_cache::ParameterSetIdentifier;
use std::marker::PhantomData;
use zigzag_graph::{ZigZag, ZigZagGraph};

/// ZigZagDrgPorep is a layered PoRep which replicates layer by layer.
/// Between layers, the graph is 'reversed' in such a way that the dependencies expand with each iteration.
/// This reversal is not a straightforward inversion -- so we coin the term 'zigzag' to describe the transformation.
/// Each graph can be divided into base and expansion components.
/// The 'base' component is an ordinary DRG. The expansion component attempts to add a target (expansion_degree) number of connections
/// between nodes in a reversible way. Expansion connections are therefore simply inverted at each layer.
/// Because of how DRG-sampled parents are calculated on demand, the base components are not. Instead, a same-degree
/// DRG with connections in the opposite direction (and using the same random seed) is used when calculating parents on demand.
/// For the algorithm to have the desired properties, it is important that the expansion components are directly inverted at each layer.
/// However, it is fortunately not necessary that the base DRG components also have this property.

#[derive(Debug)]
pub struct ZigZagDrgPoRep<'a, G: 'a>
where
    G: ZigZag,
{
    phantom: PhantomData<&'a G>,
}

impl<'a, G: 'a> Layers for ZigZagDrgPoRep<'a, G>
where
    G: ZigZag + 'static + ParameterSetIdentifier,
{
    type Graph = ZigZagGraph<G>;

    fn transform(
        pp: &drgporep::PublicParams<Self::Graph>,
        _layer: usize,
        _layers: usize,
    ) -> drgporep::PublicParams<Self::Graph> {
        zigzag::<Self::Graph>(pp)
    }

    fn invert_transform(
        pp: &drgporep::PublicParams<Self::Graph>,
        _layer: usize,
        _layers: usize,
    ) -> drgporep::PublicParams<Self::Graph> {
        zigzag::<Self::Graph>(pp)
    }
}

fn zigzag<Z>(pp: &drgporep::PublicParams<Z>) -> drgporep::PublicParams<Z>
where
    Z: ZigZag + Graph + ParameterSetIdentifier,
{
    drgporep::PublicParams {
        graph: pp.graph.zigzag(),
        lambda: pp.lambda,
        sloth_iter: pp.sloth_iter,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use drgraph::new_seed;
    use fr32::{bytes_into_fr, fr_into_bytes};
    use layered_drgporep::{simplify_tau, PrivateInputs, PublicInputs, PublicParams, SetupParams};
    use pairing::bls12_381::Bls12;
    use porep::PoRep;
    use proof::ProofScheme;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use zigzag_graph::ZigZagBucketGraph;

    const DEFAULT_ZIGZAG_LAYERS: usize = 6;

    #[test]
    fn extract_all() {
        let lambda = 32;
        let sloth_iter = 1;
        let prover_id = vec![1u8; 32];
        let data = vec![2u8; 32 * 3];

        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();

        let sp = SetupParams {
            drg_porep_setup_params: drgporep::SetupParams {
                lambda,
                drg: drgporep::DrgParams {
                    nodes: data.len() / lambda,
                    degree: 5,
                    expansion_degree: 5,
                    seed: new_seed(),
                },
                sloth_iter,
            },
            layers: DEFAULT_ZIGZAG_LAYERS,
        };

        let mut pp = ZigZagDrgPoRep::<ZigZagBucketGraph>::setup(&sp).unwrap();
        // Get the public params for the last layer.
        // In reality, this is a no-op with an even number of layers.
        for _ in 0..pp.layers {
            pp.drg_porep_public_params = zigzag(&pp.drg_porep_public_params);
        }

        ZigZagDrgPoRep::replicate(&pp, prover_id.as_slice(), data_copy.as_mut_slice()).unwrap();

        let transformed_params = PublicParams {
            drg_porep_public_params: pp.drg_porep_public_params,
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

        let degree = 1 + i;
        let expansion_degree = i;
        let lambda = lambda;
        let sloth_iter = 1;
        let prover_id: Vec<u8> = fr_into_bytes::<Bls12>(&rng.gen());
        let data: Vec<u8> = (0..n)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();
        let challenges = vec![i];
        let sp = SetupParams {
            drg_porep_setup_params: drgporep::SetupParams {
                lambda,
                drg: drgporep::DrgParams {
                    nodes: n,
                    degree,
                    expansion_degree,
                    seed: new_seed(),
                },
                sloth_iter,
            },
            layers: DEFAULT_ZIGZAG_LAYERS,
        };

        let pp = ZigZagDrgPoRep::<ZigZagBucketGraph>::setup(&sp).unwrap();
        let (tau, aux) =
            ZigZagDrgPoRep::replicate(&pp, prover_id.as_slice(), data_copy.as_mut_slice()).unwrap();
        assert_ne!(data, data_copy);

        let pub_inputs = PublicInputs {
            prover_id: bytes_into_fr::<Bls12>(prover_id.as_slice()).unwrap(),
            challenges,
            tau: Some(simplify_tau(&tau)),
        };

        let priv_inputs = PrivateInputs {
            replica: data.as_slice(),
            aux,
            tau,
        };

        let proof = ZigZagDrgPoRep::prove(&pp, &pub_inputs, &priv_inputs).unwrap();
        assert!(ZigZagDrgPoRep::verify(&pp, &pub_inputs, &proof).unwrap());
    }

    table_tests!{
        prove_verify{
            // TODO: figure out why this was failing
            // prove_verify_32_2_1(32, 2, 1);
            // prove_verify_32_2_2(32, 2, 2);

            // TODO: why u fail???
            // prove_verify_32_3_1(32, 3, 1);
            // prove_verify_32_3_2(32, 3, 2);

           prove_verify_32_5_1(32, 5, 1);
           prove_verify_32_5_2(32, 5, 2);
           prove_verify_32_5_3(32, 5, 3);
    }}
}
