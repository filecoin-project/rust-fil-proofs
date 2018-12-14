use std::marker::PhantomData;

use crate::drgporep;
use crate::drgraph::Graph;
use crate::hasher::Hasher;
use crate::layered_drgporep::Layers;
use crate::parameter_cache::ParameterSetIdentifier;
use crate::zigzag_graph::{ZigZag, ZigZagBucketGraph};

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
pub struct ZigZagDrgPoRep<'a, H: 'a + Hasher> {
    _a: PhantomData<&'a H>,
}

impl<'a, H: 'static + Hasher> Layers for ZigZagDrgPoRep<'a, H> where {
    type Hasher = <ZigZagBucketGraph<H> as ZigZag>::BaseHasher;
    type Graph = ZigZagBucketGraph<Self::Hasher>;

    fn transform(
        pp: &drgporep::PublicParams<Self::Hasher, Self::Graph>,
        _layer: usize,
        _layers: usize,
    ) -> drgporep::PublicParams<Self::Hasher, Self::Graph> {
        zigzag::<Self::Hasher, Self::Graph>(pp)
    }

    fn invert_transform(
        pp: &drgporep::PublicParams<Self::Hasher, Self::Graph>,
        _layer: usize,
        _layers: usize,
    ) -> drgporep::PublicParams<Self::Hasher, Self::Graph> {
        zigzag::<Self::Hasher, Self::Graph>(pp)
    }
}

fn zigzag<H, Z>(pp: &drgporep::PublicParams<H, Z>) -> drgporep::PublicParams<H, Z>
where
    H: Hasher,
    Z: ZigZag + Graph<H> + ParameterSetIdentifier,
{
    drgporep::PublicParams::new(pp.graph.zigzag(), pp.sloth_iter)
}

#[cfg(test)]
mod tests {
    use super::*;

    use pairing::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};

    use crate::drgraph::new_seed;
    use crate::fr32::fr_into_bytes;
    use crate::hasher::{Blake2sHasher, PedersenHasher, Sha256Hasher};
    use crate::layered_drgporep::{PrivateInputs, PublicInputs, PublicParams, SetupParams};
    use crate::porep::PoRep;
    use crate::proof::ProofScheme;

    const DEFAULT_ZIGZAG_LAYERS: usize = 10;

    #[test]
    fn extract_all_pedersen() {
        test_extract_all::<PedersenHasher>();
    }

    #[test]
    fn extract_all_sha256() {
        test_extract_all::<Sha256Hasher>();
    }

    #[test]
    fn extract_all_blake2s() {
        test_extract_all::<Blake2sHasher>();
    }

    fn test_extract_all<H: 'static + Hasher>() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let sloth_iter = 1;
        let replica_id: H::Domain = rng.gen();
        let data = vec![2u8; 32 * 3];
        let challenge_count = 5;

        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();

        let sp = SetupParams {
            drg_porep_setup_params: drgporep::SetupParams {
                drg: drgporep::DrgParams {
                    nodes: data.len() / 32,
                    degree: 5,
                    expansion_degree: 5,
                    seed: new_seed(),
                },
                sloth_iter,
            },
            layers: DEFAULT_ZIGZAG_LAYERS,
            challenge_count,
        };

        let mut pp = ZigZagDrgPoRep::<H>::setup(&sp).unwrap();
        // Get the public params for the last layer.
        // In reality, this is a no-op with an even number of layers.
        for _ in 0..pp.layers {
            pp.drg_porep_public_params = zigzag(&pp.drg_porep_public_params);
        }

        ZigZagDrgPoRep::<H>::replicate(&pp, &replica_id, data_copy.as_mut_slice(), None).unwrap();

        let transformed_params = PublicParams {
            drg_porep_public_params: pp.drg_porep_public_params,
            layers: pp.layers,
            challenge_count,
        };

        assert_ne!(data, data_copy);

        let decoded_data = ZigZagDrgPoRep::<H>::extract_all(
            &transformed_params,
            &replica_id,
            data_copy.as_mut_slice(),
        )
        .unwrap();

        assert_eq!(data, decoded_data);
    }

    fn prove_verify(n: usize, i: usize) {
        test_prove_verify::<PedersenHasher>(n, i);
        test_prove_verify::<Sha256Hasher>(n, i);
        test_prove_verify::<Blake2sHasher>(n, i);
    }

    fn test_prove_verify<H: 'static + Hasher>(n: usize, i: usize) {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let degree = 1 + i;
        let expansion_degree = i;
        let sloth_iter = 1;
        let replica_id: H::Domain = rng.gen();
        let data: Vec<u8> = (0..n)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();
        let challenge_count = 5;
        let partitions = 2;

        let sp = SetupParams {
            drg_porep_setup_params: drgporep::SetupParams {
                drg: drgporep::DrgParams {
                    nodes: n,
                    degree,
                    expansion_degree,
                    seed: new_seed(),
                },
                sloth_iter,
            },
            layers: DEFAULT_ZIGZAG_LAYERS,
            challenge_count,
        };

        let pp = ZigZagDrgPoRep::<H>::setup(&sp).unwrap();
        let (tau, aux) =
            ZigZagDrgPoRep::<H>::replicate(&pp, &replica_id, data_copy.as_mut_slice(), None)
                .unwrap();
        assert_ne!(data, data_copy);

        let pub_inputs = PublicInputs::<H::Domain> {
            replica_id,
            challenge_count,
            tau: Some(tau.simplify().into()),
            comm_r_star: tau.comm_r_star,
            k: None,
        };

        let priv_inputs = PrivateInputs {
            replica: data.as_slice(),
            aux,
            tau: tau.layer_taus,
        };

        let all_partition_proofs =
            &ZigZagDrgPoRep::<H>::prove_all_partitions(&pp, &pub_inputs, &priv_inputs, partitions)
                .unwrap();

        assert!(
            ZigZagDrgPoRep::<H>::verify_all_partitions(&pp, &pub_inputs, all_partition_proofs)
                .unwrap()
        );
    }

    table_tests! {
        prove_verify{
            // TODO: figure out why this was failing
            // prove_verify_32_2_1(32, 2, 1);
            // prove_verify_32_2_2(32, 2, 2);

            // TODO: why u fail???
            // prove_verify_32_3_1(32, 3, 1);
            // prove_verify_32_3_2(32, 3, 2);

           prove_verify_32_5_1(5, 1);
           prove_verify_32_5_2( 5, 2);
           prove_verify_32_5_3( 5, 3);
    }}
}
