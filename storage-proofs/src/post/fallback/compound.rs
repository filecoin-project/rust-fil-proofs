use std::marker::PhantomData;

use anyhow::ensure;
use bellperson::Circuit;
use fil_sapling_crypto::jubjub::JubjubEngine;
use generic_array::typenum;
use paired::bls12_381::{Bls12, Fr};

use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::error::Result;
use crate::gadgets::por::PoRCompound;
use crate::hasher::Hasher;
use crate::parameter_cache::{CacheableParameters, ParameterSetMetadata};
use crate::por;
use crate::post::fallback::{self, FallbackPoSt, FallbackPoStCircuit};
use crate::proof::ProofScheme;
use crate::util::NODE_SIZE;

use super::circuit::Sector;

pub struct FallbackPoStCompound<H>
where
    H: Hasher,
{
    _h: PhantomData<H>,
}

impl<E: JubjubEngine, C: Circuit<E>, P: ParameterSetMetadata, H: Hasher>
    CacheableParameters<E, C, P> for FallbackPoStCompound<H>
{
    fn cache_prefix() -> String {
        format!("proof-of-spacetime-fallback-{}", H::name())
    }
}

impl<'a, H> CompoundProof<'a, Bls12, FallbackPoSt<'a, H>, FallbackPoStCircuit<'a, Bls12, H>>
    for FallbackPoStCompound<H>
where
    H: 'a + Hasher,
{
    fn generate_public_inputs(
        pub_inputs: &<FallbackPoSt<'a, H> as ProofScheme<'a>>::PublicInputs,
        pub_params: &<FallbackPoSt<'a, H> as ProofScheme<'a>>::PublicParams,
        _partition_k: Option<usize>,
    ) -> Result<Vec<Fr>> {
        let mut inputs = Vec::new();

        let por_pub_params = por::PublicParams {
            leaves: (pub_params.sector_size as usize / NODE_SIZE),
            private: true,
        };

        for sector in pub_inputs.sectors.iter() {
            // 1. Inputs for verifying comm_r = H(comm_c || comm_r_last)

            inputs.push(sector.comm_r.into());

            // 2. Inputs for verifying inclusion paths

            for n in 0..pub_params.challenge_count {
                let challenged_leaf_start = fallback::generate_leaf_challenge(
                    &pub_params,
                    pub_inputs.randomness,
                    sector.id.into(),
                    n as u64,
                )?;

                let por_pub_inputs = por::PublicInputs {
                    commitment: None,
                    challenge: challenged_leaf_start as usize / NODE_SIZE,
                };
                let por_inputs = PoRCompound::<H, typenum::U8>::generate_public_inputs(
                    &por_pub_inputs,
                    &por_pub_params,
                    None,
                )?;

                inputs.extend(por_inputs);
            }
        }

        Ok(inputs)
    }

    fn circuit(
        pub_in: &<FallbackPoSt<'a, H> as ProofScheme<'a>>::PublicInputs,
        _priv_in: <FallbackPoStCircuit<'a, Bls12, H> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &<FallbackPoSt<'a, H> as ProofScheme<'a>>::Proof,
        pub_params: &<FallbackPoSt<'a, H> as ProofScheme<'a>>::PublicParams,
    ) -> Result<FallbackPoStCircuit<'a, Bls12, H>> {
        ensure!(
            pub_params.sector_count == pub_in.sectors.len(),
            "invalid public inputs"
        );
        ensure!(
            pub_params.sector_count == vanilla_proof.sectors.len(),
            "invalid vanilla proofs"
        );

        let sectors = vanilla_proof
            .sectors
            .iter()
            .zip(pub_in.sectors.iter())
            .map(|(vanilla_proof, pub_sector)| Sector::circuit(pub_sector, vanilla_proof))
            .collect::<Result<_>>()?;

        Ok(FallbackPoStCircuit {
            prover_id: Some(pub_in.prover_id.into()),
            sectors,
        })
    }

    fn blank_circuit(
        pub_params: &<FallbackPoSt<'a, H> as ProofScheme<'a>>::PublicParams,
    ) -> FallbackPoStCircuit<'a, Bls12, H> {
        let sectors = (0..pub_params.sector_count)
            .map(|_| Sector::blank_circuit(pub_params))
            .collect();

        FallbackPoStCircuit {
            prover_id: None,
            sectors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ff::Field;
    use merkletree::store::StoreConfig;
    use pretty_assertions::assert_eq;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use crate::compound_proof;
    use crate::drgraph::{new_seed, BucketGraph, Graph, BASE_DEGREE};
    use crate::fr32::fr_into_bytes;
    use crate::gadgets::{MetricCS, TestConstraintSystem};
    use crate::hasher::{Domain, HashFunction, Hasher, PedersenHasher, PoseidonHasher};
    use crate::merkle::OctLCMerkleTree;
    use crate::porep::stacked::OCT_ARITY;
    use crate::post::fallback;
    use crate::proof::NoRequirements;

    use super::super::{PrivateInputs, PrivateSector, PublicInputs, PublicSector};

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn fallback_post_test_compound_pedersen() {
        fallback_post_test_compound::<PedersenHasher>();
    }

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn fallback_post_test_compound_poseidon() {
        fallback_post_test_compound::<PoseidonHasher>();
    }

    fn fallback_post_test_compound<H: Hasher>() {
        use std::fs::File;
        use std::io::prelude::*;

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 64;
        let sector_size = (leaves * NODE_SIZE) as u64;
        let randomness = H::Domain::random(rng);
        let prover_id = H::Domain::random(rng);
        let sector_count = 3;

        let setup_params = compound_proof::SetupParams {
            vanilla_params: fallback::SetupParams {
                sector_size: sector_size as u64,
                challenge_count: 5,
                sector_count,
            },
            partitions: None,
            priority: false,
        };

        // Construct and store an MT using a named DiskStore.
        let temp_dir = tempdir::TempDir::new("level_cache_tree_v1").unwrap();
        let temp_path = temp_dir.path();
        let config = StoreConfig::new(
            &temp_path,
            String::from("test-lc-tree"),
            StoreConfig::default_cached_above_base_layer(leaves as usize, OCT_ARITY),
        );

        let mut pub_sectors = Vec::new();
        let mut priv_sectors = Vec::new();

        for i in 0..sector_count {
            let data: Vec<u8> = (0..leaves)
                .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
                .collect();

            let graph = BucketGraph::<H>::new(leaves, BASE_DEGREE, 0, new_seed()).unwrap();

            let replica_path = temp_path.join(format!("replica-path-{}", i));
            let mut f = File::create(&replica_path).unwrap();
            f.write_all(&data).unwrap();

            let cur_config = StoreConfig::from_config(&config, format!("test-lc-tree-{}", i), None);
            let lctree: OctLCMerkleTree<_, _> = graph
                .lcmerkle_tree(cur_config.clone(), &data, &replica_path)
                .unwrap();

            let comm_c = H::Domain::random(rng);
            let comm_r_last = lctree.root();

            priv_sectors.push(PrivateSector {
                tree: lctree,
                comm_c,
                comm_r_last,
            });

            let comm_r = H::Function::hash2(&comm_c, &comm_r_last);
            pub_sectors.push(PublicSector {
                id: (i as u64).into(),
                comm_r,
            });
        }

        let pub_params = FallbackPoStCompound::<H>::setup(&setup_params).expect("setup failed");

        let pub_inputs = PublicInputs {
            randomness,
            prover_id,
            sectors: &pub_sectors,
        };

        let priv_inputs = PrivateInputs::<H> {
            sectors: &priv_sectors,
        };

        {
            let (circuit, inputs) =
                FallbackPoStCompound::circuit_for_test(&pub_params, &pub_inputs, &priv_inputs)
                    .unwrap();

            let mut cs = TestConstraintSystem::new();

            circuit.synthesize(&mut cs).expect("failed to synthesize");

            if !cs.is_satisfied() {
                panic!(
                    "failed to satisfy: {:?}",
                    cs.which_is_unsatisfied().unwrap()
                );
            }
            assert!(
                cs.verify(&inputs),
                "verification failed with TestContraintSystem and generated inputs"
            );
        }

        // Use this to debug differences between blank and regular circuit generation.
        {
            let (circuit1, _inputs) =
                FallbackPoStCompound::circuit_for_test(&pub_params, &pub_inputs, &priv_inputs)
                    .unwrap();
            let blank_circuit =
                FallbackPoStCompound::<H>::blank_circuit(&pub_params.vanilla_params);

            let mut cs_blank = MetricCS::new();
            blank_circuit
                .synthesize(&mut cs_blank)
                .expect("failed to synthesize");

            let a = cs_blank.pretty_print_list();

            let mut cs1 = TestConstraintSystem::new();
            circuit1.synthesize(&mut cs1).expect("failed to synthesize");
            let b = cs1.pretty_print_list();

            for (i, (a, b)) in a.chunks(100).zip(b.chunks(100)).enumerate() {
                assert_eq!(a, b, "failed at chunk {}", i);
            }
        }
        let blank_groth_params =
            FallbackPoStCompound::<H>::groth_params(Some(rng), &pub_params.vanilla_params)
                .expect("failed to generate groth params");

        let proof = FallbackPoStCompound::prove(
            &pub_params,
            &pub_inputs,
            &priv_inputs,
            &blank_groth_params,
        )
        .expect("failed while proving");

        let verified =
            FallbackPoStCompound::verify(&pub_params, &pub_inputs, &proof, &NoRequirements)
                .expect("failed while verifying");

        assert!(verified);
    }
}
