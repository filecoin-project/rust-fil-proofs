use std::marker::PhantomData;

use anyhow::{anyhow, ensure};
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
        partition_k: Option<usize>,
    ) -> Result<Vec<Fr>> {
        let mut inputs = Vec::new();

        let por_pub_params = por::PublicParams {
            leaves: (pub_params.sector_size as usize / NODE_SIZE),
            private: true,
        };

        let num_sectors_per_chunk = pub_params.sector_count;

        let partition_index = partition_k.unwrap_or(0);

        let sectors = pub_inputs
            .sectors
            .chunks(num_sectors_per_chunk)
            .nth(partition_index)
            .ok_or_else(|| anyhow!("invalid number of sectors/partition index"))?;

        for (i, sector) in sectors.iter().enumerate() {
            // 1. Inputs for verifying comm_r = H(comm_c || comm_r_last)
            inputs.push(sector.comm_r.into());

            // 2. Inputs for verifying inclusion paths
            for n in 0..pub_params.challenge_count {
                let challenge_index = (partition_index * pub_params.sector_count
                    + i * pub_params.challenge_count
                    + n) as u64;
                let challenged_leaf_start = fallback::generate_leaf_challenge(
                    &pub_params,
                    pub_inputs.randomness,
                    sector.id.into(),
                    challenge_index,
                )?;

                let por_pub_inputs = por::PublicInputs {
                    commitment: None,
                    challenge: challenged_leaf_start as usize,
                };
                let por_inputs = PoRCompound::<H, typenum::U8>::generate_public_inputs(
                    &por_pub_inputs,
                    &por_pub_params,
                    partition_k,
                )?;

                inputs.extend(por_inputs);
            }
        }
        let num_inputs_per_sector = inputs.len() / sectors.len();

        // dupliate last one if too little sectors available
        while inputs.len() / num_inputs_per_sector < num_sectors_per_chunk {
            let s = inputs[inputs.len() - num_inputs_per_sector..].to_vec();
            inputs.extend_from_slice(&s);
        }
        assert_eq!(inputs.len(), num_inputs_per_sector * num_sectors_per_chunk);

        Ok(inputs)
    }

    fn circuit(
        pub_in: &<FallbackPoSt<'a, H> as ProofScheme<'a>>::PublicInputs,
        _priv_in: <FallbackPoStCircuit<'a, Bls12, H> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &<FallbackPoSt<'a, H> as ProofScheme<'a>>::Proof,
        pub_params: &<FallbackPoSt<'a, H> as ProofScheme<'a>>::PublicParams,
        partition_k: Option<usize>,
    ) -> Result<FallbackPoStCircuit<'a, Bls12, H>> {
        let num_sectors_per_chunk = pub_params.sector_count;
        ensure!(
            pub_params.sector_count == vanilla_proof.sectors.len(),
            "vanilla proofs must equal sector_count: {} != {}",
            num_sectors_per_chunk,
            vanilla_proof.sectors.len(),
        );

        let partition_index = partition_k.unwrap_or(0);
        let sectors = pub_in
            .sectors
            .chunks(num_sectors_per_chunk)
            .nth(partition_index)
            .ok_or_else(|| anyhow!("invalid number of sectors/partition index"))?;

        let mut res_sectors = Vec::with_capacity(vanilla_proof.sectors.len());

        for (i, vanilla_proof) in vanilla_proof.sectors.iter().enumerate() {
            let pub_sector = if i < sectors.len() {
                &sectors[i]
            } else {
                // Repeat the last sector, iff there are too little inputs to fill the circuit.
                &sectors[sectors.len() - 1]
            };

            res_sectors.push(Sector::circuit(pub_sector, vanilla_proof)?);
        }

        assert_eq!(res_sectors.len(), num_sectors_per_chunk);

        Ok(FallbackPoStCircuit {
            prover_id: Some(pub_in.prover_id.into()),
            sectors: res_sectors,
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
    use crate::porep::stacked::OCT_ARITY;
    use crate::post::fallback;
    use crate::proof::NoRequirements;

    use super::super::{PrivateInputs, PrivateSector, PublicInputs, PublicSector};

    #[ignore]
    #[test]
    fn fallback_post_pedersen_single_partition_matching() {
        fallback_post::<PedersenHasher>(3, 3, 1);
    }

    #[ignore]
    #[test]
    fn fallback_post_poseidon_single_partition_matching() {
        fallback_post::<PoseidonHasher>(3, 3, 1);
    }

    #[ignore]
    #[test]
    fn fallback_post_poseidon_single_partition_smaller() {
        fallback_post::<PoseidonHasher>(2, 3, 1);
    }

    #[ignore]
    #[test]
    fn fallback_post_poseidon_two_partitions_matching() {
        fallback_post::<PoseidonHasher>(4, 2, 2);
    }

    #[ignore]
    #[test]
    fn fallback_post_poseidon_two_partitions_smaller() {
        fallback_post::<PoseidonHasher>(5, 3, 2);
    }

    fn fallback_post<H: Hasher>(total_sector_count: usize, sector_count: usize, partitions: usize) {
        use std::fs::File;
        use std::io::prelude::*;

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 64;
        let sector_size = (leaves * NODE_SIZE) as u64;
        let randomness = H::Domain::random(rng);
        let prover_id = H::Domain::random(rng);

        let setup_params = compound_proof::SetupParams {
            vanilla_params: fallback::SetupParams {
                sector_size: sector_size as u64,
                challenge_count: 2,
                sector_count,
            },
            partitions: Some(partitions),
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
        let mut trees = Vec::new();

        for i in 0..total_sector_count {
            let data: Vec<u8> = (0..leaves)
                .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
                .collect();

            let graph = BucketGraph::<H>::new(leaves, BASE_DEGREE, 0, new_seed()).unwrap();

            let replica_path = temp_path.join(format!("replica-path-{}", i));
            let mut f = File::create(&replica_path).unwrap();
            f.write_all(&data).unwrap();

            let cur_config = StoreConfig::from_config(&config, format!("test-lc-tree-{}", i), None);
            trees.push(
                graph
                    .lcmerkle_tree(cur_config.clone(), &data, &replica_path)
                    .unwrap(),
            );
        }
        for (i, tree) in trees.iter().enumerate() {
            let comm_c = H::Domain::random(rng);
            let comm_r_last = tree.root();

            priv_sectors.push(PrivateSector {
                tree,
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
            k: None,
        };

        let priv_inputs = PrivateInputs::<H> {
            sectors: &priv_sectors,
        };

        // Use this to debug differences between blank and regular circuit generation.
        {
            let circuits =
                FallbackPoStCompound::circuit_for_test_all(&pub_params, &pub_inputs, &priv_inputs)
                    .unwrap();
            let blank_circuit =
                FallbackPoStCompound::<H>::blank_circuit(&pub_params.vanilla_params);

            let mut cs_blank = MetricCS::new();
            blank_circuit
                .synthesize(&mut cs_blank)
                .expect("failed to synthesize");

            let a = cs_blank.pretty_print_list();

            for (circuit1, _inputs) in circuits.into_iter() {
                let mut cs1 = TestConstraintSystem::new();
                circuit1.synthesize(&mut cs1).expect("failed to synthesize");
                let b = cs1.pretty_print_list();

                for (i, (a, b)) in a.chunks(100).zip(b.chunks(100)).enumerate() {
                    assert_eq!(a, b, "failed at chunk {}", i);
                }
            }
        }

        {
            let circuits =
                FallbackPoStCompound::circuit_for_test_all(&pub_params, &pub_inputs, &priv_inputs)
                    .unwrap();

            for (circuit, inputs) in circuits.into_iter() {
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
