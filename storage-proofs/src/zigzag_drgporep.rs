use std::marker::PhantomData;

use crate::drgraph::Graph;
use crate::hasher::Hasher;
use crate::layered_drgporep::Layers;
use crate::parameter_cache::ParameterSetMetadata;
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

impl<'a, H: 'static + Hasher> Layers for ZigZagDrgPoRep<'a, H> {
    type Hasher = <ZigZagBucketGraph<H> as ZigZag>::BaseHasher;
    type BaseGraph = <ZigZagBucketGraph<H> as ZigZag>::BaseGraph;
    type Graph = ZigZagBucketGraph<Self::Hasher>;

    fn transform(graph: &Self::Graph) -> Self::Graph {
        zigzag::<Self::Hasher, Self::Graph>(graph)
    }

    fn invert_transform(graph: &Self::Graph) -> Self::Graph {
        zigzag::<Self::Hasher, Self::Graph>(graph)
    }
}

fn zigzag<H, Z>(graph: &Z) -> Z
where
    H: Hasher,
    Z: ZigZag + Graph<H> + ParameterSetMetadata,
{
    graph.zigzag()
}

#[cfg(test)]
mod tests {
    use super::*;

    use paired::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};

    use crate::drgporep;
    use crate::drgraph::{new_seed, BASE_DEGREE};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::{Blake2sHasher, PedersenHasher, Sha256Hasher};
    use crate::layered_drgporep::{
        LayerChallenges, PrivateInputs, PublicInputs, PublicParams, SetupParams,
    };
    use crate::porep::PoRep;
    use crate::proof::ProofScheme;
    use crate::zigzag_graph::EXP_DEGREE;

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
        let replica_id: H::Domain = rng.gen();
        let data = vec![2u8; 32 * 3];
        let challenges = LayerChallenges::new_fixed(DEFAULT_ZIGZAG_LAYERS, 5);

        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();

        let sp = SetupParams {
            drg: drgporep::DrgParams {
                nodes: data.len() / 32,
                degree: BASE_DEGREE,
                expansion_degree: EXP_DEGREE,
                seed: new_seed(),
            },
            layer_challenges: challenges.clone(),
        };

        let mut pp = ZigZagDrgPoRep::<H>::setup(&sp).expect("setup failed");
        // Get the graph for the last layer.
        // In reality, this is a no-op with an even number of layers.
        for _ in 0..pp.layer_challenges.layers() {
            pp.graph = zigzag(&pp.graph);
        }

        ZigZagDrgPoRep::<H>::replicate(&pp, &replica_id, data_copy.as_mut_slice(), None)
            .expect("replication failed");

        let transformed_params = PublicParams::new(pp.graph, challenges.clone());

        assert_ne!(data, data_copy);

        let decoded_data = ZigZagDrgPoRep::<H>::extract_all(
            &transformed_params,
            &replica_id,
            data_copy.as_mut_slice(),
        )
        .expect("failed to extract data");

        assert_eq!(data, decoded_data);
    }

    fn prove_verify_fixed(n: usize) {
        let challenges = LayerChallenges::new_fixed(DEFAULT_ZIGZAG_LAYERS, 5);

        test_prove_verify::<PedersenHasher>(n, challenges.clone());
        test_prove_verify::<Sha256Hasher>(n, challenges.clone());
        test_prove_verify::<Blake2sHasher>(n, challenges.clone());
    }

    fn test_prove_verify<H: 'static + Hasher>(n: usize, challenges: LayerChallenges) {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let degree = BASE_DEGREE;
        let expansion_degree = EXP_DEGREE;
        let replica_id: H::Domain = rng.gen();
        let data: Vec<u8> = (0..n)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();
        let partitions = 2;

        let sp = SetupParams {
            drg: drgporep::DrgParams {
                nodes: n,
                degree,
                expansion_degree,
                seed: new_seed(),
            },
            layer_challenges: challenges.clone(),
        };

        let pp = ZigZagDrgPoRep::<H>::setup(&sp).expect("setup failed");
        let (tau, aux) =
            ZigZagDrgPoRep::<H>::replicate(&pp, &replica_id, data_copy.as_mut_slice(), None)
                .expect("replication failed");
        assert_ne!(data, data_copy);

        let pub_inputs = PublicInputs::<H::Domain> {
            replica_id,
            seed: None,
            tau: Some(tau.simplify().into()),
            comm_r_star: tau.comm_r_star,
            k: None,
        };

        let priv_inputs = PrivateInputs {
            aux,
            tau: tau.layer_taus,
        };

        let all_partition_proofs =
            &ZigZagDrgPoRep::<H>::prove_all_partitions(&pp, &pub_inputs, &priv_inputs, partitions)
                .expect("failed to generate partition proofs");

        let proofs_are_valid =
            ZigZagDrgPoRep::<H>::verify_all_partitions(&pp, &pub_inputs, all_partition_proofs)
                .expect("failed to verify partition proofs");

        assert!(proofs_are_valid);
    }

    table_tests! {
        prove_verify_fixed{
            // TODO: figure out why this was failing
            // prove_verify_32_2_1(32, 2, 1);
            // prove_verify_32_2_2(32, 2, 2);

            // TODO: why u fail???
            // prove_verify_32_3_1(32, 3, 1);
            // prove_verify_32_3_2(32, 3, 2);

           prove_verify_fixed_32_5(5);
        }
    }

    #[test]
    // We are seeing a bug, in which setup never terminates for some sector sizes.
    // This test is to debug that and should remain as a regression teset.
    fn setup_terminates() {
        let degree = BASE_DEGREE;
        let expansion_degree = EXP_DEGREE;
        let nodes = 1024 * 1024 * 32 * 8; // This corresponds to 8GiB sectors (32-byte nodes)
        let layer_challenges = LayerChallenges::new_fixed(10, 333);
        let sp = SetupParams {
            drg: drgporep::DrgParams {
                nodes,
                degree,
                expansion_degree,
                seed: new_seed(),
            },
            layer_challenges: layer_challenges.clone(),
        };

        // When this fails, the call to setup should panic, but seems to actually hang (i.e. neither return nor panic) for some reason.
        // When working as designed, the call to setup returns without error.
        let _pp = ZigZagDrgPoRep::<PedersenHasher>::setup(&sp).expect("setup failed");
    }
}
