use std::marker::PhantomData;

use anyhow::{anyhow, ensure};
use bellperson::bls::{Bls12, Fr};
use bellperson::Circuit;

use storage_proofs_core::{
    compound_proof::{CircuitComponent, CompoundProof},
    error::Result,
    gadgets::por::PoRCompound,
    merkle::MerkleTreeTrait,
    parameter_cache::{CacheableParameters, ParameterSetMetadata},
    por,
    proof::ProofScheme,
    util::NODE_SIZE,
};

use super::circuit::Sector;
use crate::fallback::{self, FallbackPoSt, FallbackPoStCircuit};

pub struct FallbackPoStCompound<Tree>
where
    Tree: MerkleTreeTrait,
{
    _t: PhantomData<Tree>,
}

impl<C: Circuit<Bls12>, P: ParameterSetMetadata, Tree: MerkleTreeTrait> CacheableParameters<C, P>
    for FallbackPoStCompound<Tree>
{
    fn cache_prefix() -> String {
        format!("proof-of-spacetime-fallback-{}", Tree::display())
    }
}

impl<'a, Tree: 'static + MerkleTreeTrait>
    CompoundProof<'a, FallbackPoSt<'a, Tree>, FallbackPoStCircuit<Tree>>
    for FallbackPoStCompound<Tree>
{
    fn generate_public_inputs(
        pub_inputs: &<FallbackPoSt<'a, Tree> as ProofScheme<'a>>::PublicInputs,
        pub_params: &<FallbackPoSt<'a, Tree> as ProofScheme<'a>>::PublicParams,
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
                let challenge_index = ((partition_index * pub_params.sector_count + i)
                    * pub_params.challenge_count
                    + n) as u64;
                let challenged_leaf_start = fallback::generate_leaf_challenge(
                    &pub_params,
                    pub_inputs.randomness,
                    sector.id.into(),
                    challenge_index,
                );

                let por_pub_inputs = por::PublicInputs {
                    commitment: None,
                    challenge: challenged_leaf_start as usize,
                };
                let por_inputs = PoRCompound::<Tree>::generate_public_inputs(
                    &por_pub_inputs,
                    &por_pub_params,
                    partition_k,
                )?;

                inputs.extend(por_inputs);
            }
        }
        let num_inputs_per_sector = inputs.len() / sectors.len();

        // duplicate last one if too little sectors available
        while inputs.len() / num_inputs_per_sector < num_sectors_per_chunk {
            let s = inputs[inputs.len() - num_inputs_per_sector..].to_vec();
            inputs.extend_from_slice(&s);
        }
        assert_eq!(inputs.len(), num_inputs_per_sector * num_sectors_per_chunk);

        Ok(inputs)
    }

    fn circuit(
        pub_in: &<FallbackPoSt<'a, Tree> as ProofScheme<'a>>::PublicInputs,
        _priv_in: <FallbackPoStCircuit<Tree> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &<FallbackPoSt<'a, Tree> as ProofScheme<'a>>::Proof,
        pub_params: &<FallbackPoSt<'a, Tree> as ProofScheme<'a>>::PublicParams,
        partition_k: Option<usize>,
    ) -> Result<FallbackPoStCircuit<Tree>> {
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
        pub_params: &<FallbackPoSt<'a, Tree> as ProofScheme<'a>>::PublicParams,
    ) -> FallbackPoStCircuit<Tree> {
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

    use bellperson::util_cs::{metric_cs::MetricCS, test_cs::TestConstraintSystem};
    use generic_array::typenum::{U0, U2, U4, U8};
    use pretty_assertions::assert_eq;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::{
        compound_proof,
        hasher::{Domain, HashFunction, Hasher, PoseidonHasher},
        merkle::{generate_tree, get_base_tree_count, LCTree, MerkleTreeTrait},
    };

    use crate::fallback::{
        self, ChallengeRequirements, PrivateInputs, PrivateSector, PublicInputs, PublicSector,
    };

    #[ignore]
    #[test]
    fn fallback_post_poseidon_single_partition_matching_base_8() {
        fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(15, 15, 1);
    }

    #[ignore]
    #[test]
    fn fallback_post_poseidon_single_partition_matching_sub_8_4() {
        fallback_post::<LCTree<PoseidonHasher, U8, U4, U0>>(3, 3, 1);
    }

    #[ignore]
    #[test]
    fn fallback_post_poseidon_single_partition_matching_top_8_4_2() {
        fallback_post::<LCTree<PoseidonHasher, U8, U4, U2>>(3, 3, 1);
    }

    #[ignore]
    #[test]
    fn fallback_post_poseidon_single_partition_smaller_base_8() {
        fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(2, 3, 1);
    }

    #[ignore]
    #[test]
    fn fallback_post_poseidon_two_partitions_matching_base_8() {
        fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(4, 2, 2);
    }

    #[ignore]
    #[test]
    fn fallback_post_poseidon_two_partitions_smaller_base_8() {
        fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(5, 3, 2);
    }

    fn fallback_post<Tree: 'static + MerkleTreeTrait>(
        total_sector_count: usize,
        sector_count: usize,
        partitions: usize,
    ) where
        Tree::Store: 'static,
    {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 64 * get_base_tree_count::<Tree>();
        let sector_size = (leaves * NODE_SIZE) as u64;
        let randomness = <Tree::Hasher as Hasher>::Domain::random(rng);
        let prover_id = <Tree::Hasher as Hasher>::Domain::random(rng);
        let challenge_count = 2;

        let setup_params = compound_proof::SetupParams {
            vanilla_params: fallback::SetupParams {
                sector_size: sector_size as u64,
                challenge_count,
                sector_count,
            },
            partitions: Some(partitions),
            priority: false,
        };

        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path();

        let mut pub_sectors = Vec::new();
        let mut priv_sectors = Vec::new();
        let mut trees = Vec::new();

        for _i in 0..total_sector_count {
            let (_data, tree) =
                generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));
            trees.push(tree);
        }
        for (i, tree) in trees.iter().enumerate() {
            let comm_c = <Tree::Hasher as Hasher>::Domain::random(rng);
            let comm_r_last = tree.root();

            priv_sectors.push(PrivateSector {
                tree,
                comm_c,
                comm_r_last,
            });

            let comm_r = <Tree::Hasher as Hasher>::Function::hash2(&comm_c, &comm_r_last);
            pub_sectors.push(PublicSector {
                id: (i as u64).into(),
                comm_r,
            });
        }

        let pub_params = FallbackPoStCompound::<Tree>::setup(&setup_params).expect("setup failed");

        let pub_inputs = PublicInputs {
            randomness,
            prover_id,
            sectors: &pub_sectors,
            k: None,
        };

        let priv_inputs = PrivateInputs::<Tree> {
            sectors: &priv_sectors,
        };

        // Use this to debug differences between blank and regular circuit generation.
        {
            let circuits =
                FallbackPoStCompound::circuit_for_test_all(&pub_params, &pub_inputs, &priv_inputs)
                    .unwrap();
            let blank_circuit =
                FallbackPoStCompound::<Tree>::blank_circuit(&pub_params.vanilla_params);

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
            FallbackPoStCompound::<Tree>::groth_params(Some(rng), &pub_params.vanilla_params)
                .expect("failed to generate groth params");

        let proof = FallbackPoStCompound::prove(
            &pub_params,
            &pub_inputs,
            &priv_inputs,
            &blank_groth_params,
        )
        .expect("failed while proving");

        let verified = FallbackPoStCompound::verify(
            &pub_params,
            &pub_inputs,
            &proof,
            &ChallengeRequirements {
                minimum_challenge_count: total_sector_count * challenge_count,
            },
        )
        .expect("failed while verifying");

        assert!(verified);
    }
}
