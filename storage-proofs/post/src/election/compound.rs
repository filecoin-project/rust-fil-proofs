use std::marker::PhantomData;

use bellperson::Circuit;
use generic_array::typenum;
use paired::bls12_381::{Bls12, Fr};
use typenum::marker_traits::Unsigned;

use storage_proofs_core::{
    compound_proof::{CircuitComponent, CompoundProof},
    drgraph,
    error::Result,
    gadgets::por::PoRCompound,
    hasher::Hasher,
    merkle::{DiskStore, MerkleTreeWrapper},
    parameter_cache::{CacheableParameters, ParameterSetMetadata},
    por,
    proof::ProofScheme,
    util::NODE_SIZE,
};

use crate::election::{self, ElectionPoSt, ElectionPoStCircuit};

pub struct ElectionPoStCompound<H>
where
    H: Hasher,
{
    _h: PhantomData<H>,
}

impl<C: Circuit<Bls12>, P: ParameterSetMetadata, H: Hasher> CacheableParameters<C, P>
    for ElectionPoStCompound<H>
{
    fn cache_prefix() -> String {
        format!("proof-of-spacetime-election-{}", H::name())
    }
}

impl<'a, H> CompoundProof<'a, ElectionPoSt<'a, H>, ElectionPoStCircuit<H>>
    for ElectionPoStCompound<H>
where
    H: 'static + Hasher,
{
    fn generate_public_inputs(
        pub_inputs: &<ElectionPoSt<'a, H> as ProofScheme<'a>>::PublicInputs,
        pub_params: &<ElectionPoSt<'a, H> as ProofScheme<'a>>::PublicParams,
        _partition_k: Option<usize>,
    ) -> Result<Vec<Fr>> {
        let mut inputs = Vec::new();

        let por_pub_params = por::PublicParams {
            leaves: (pub_params.sector_size as usize / NODE_SIZE),
            private: true,
        };

        // 1. Inputs for verifying comm_r = H(comm_c || comm_r_last)

        inputs.push(pub_inputs.comm_r.into());

        // 2. Inputs for verifying inclusion paths

        for n in 0..pub_params.challenge_count {
            let challenged_leaf_start = election::generate_leaf_challenge(
                &pub_params,
                pub_inputs.randomness,
                pub_inputs.sector_challenge_index,
                n as u64,
            )?;
            for i in 0..pub_params.challenged_nodes {
                let por_pub_inputs = por::PublicInputs {
                    commitment: None,
                    challenge: challenged_leaf_start as usize + i,
                };
                let por_inputs = PoRCompound::<
                    MerkleTreeWrapper<
                        H,
                        DiskStore<H::Domain>,
                        typenum::U8,
                        typenum::U0,
                        typenum::U0,
                    >,
                >::generate_public_inputs(
                    &por_pub_inputs, &por_pub_params, None
                )?;

                inputs.extend(por_inputs);
            }
        }

        // 3. Inputs for verifying partial_ticket generation
        inputs.push(pub_inputs.partial_ticket);

        Ok(inputs)
    }

    fn circuit(
        pub_in: &<ElectionPoSt<'a, H> as ProofScheme<'a>>::PublicInputs,
        _priv_in: <ElectionPoStCircuit<H> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &<ElectionPoSt<'a, H> as ProofScheme<'a>>::Proof,
        _pub_params: &<ElectionPoSt<'a, H> as ProofScheme<'a>>::PublicParams,
        _partition_k: Option<usize>,
    ) -> Result<ElectionPoStCircuit<H>> {
        let comm_r = pub_in.comm_r.into();
        let comm_c = vanilla_proof.comm_c.into();
        let comm_r_last = vanilla_proof.comm_r_last().into();

        let leafs: Vec<_> = vanilla_proof
            .leafs()
            .iter()
            .map(|c| Some((*c).into()))
            .collect();

        let paths: Vec<Vec<_>> = vanilla_proof
            .paths()
            .iter()
            .map(|v| {
                v.iter()
                    .map(|p| {
                        (
                            (*p).0.iter().copied().map(Into::into).map(Some).collect(),
                            Some(p.1),
                        )
                    })
                    .collect()
            })
            .collect();

        Ok(ElectionPoStCircuit {
            leafs,
            comm_r: Some(comm_r),
            comm_c: Some(comm_c),
            comm_r_last: Some(comm_r_last),
            paths,
            partial_ticket: Some(pub_in.partial_ticket),
            randomness: Some(pub_in.randomness.into()),
            prover_id: Some(pub_in.prover_id.into()),
            sector_id: Some(pub_in.sector_id.into()),
            _h: PhantomData,
        })
    }

    fn blank_circuit(
        pub_params: &<ElectionPoSt<'a, H> as ProofScheme<'a>>::PublicParams,
    ) -> ElectionPoStCircuit<H> {
        let challenges_count = pub_params.challenged_nodes * pub_params.challenge_count;
        let height =
            drgraph::graph_height::<typenum::U8>(pub_params.sector_size as usize / NODE_SIZE);

        let leafs = vec![None; challenges_count];
        let paths = vec![
            vec![(vec![None; typenum::U8::to_usize() - 1], None); height - 1];
            challenges_count
        ];

        ElectionPoStCircuit {
            comm_r: None,
            comm_c: None,
            comm_r_last: None,
            partial_ticket: None,
            leafs,
            paths,
            randomness: None,
            prover_id: None,
            sector_id: None,
            _h: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use ff::Field;
    use merkletree::store::StoreConfig;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use storage_proofs_core::{
        compound_proof,
        fr32::fr_into_bytes,
        gadgets::{MetricCS, TestConstraintSystem},
        hasher::{Domain, HashFunction, Hasher, PedersenHasher, PoseidonHasher},
        merkle::{create_base_lcmerkle_tree, MerkleTreeTrait, OctLCMerkleTree},
        proof::NoRequirements,
        sector::SectorId,
    };

    use crate::election;

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn election_post_test_compound_pedersen() {
        election_post_test_compound::<PedersenHasher>();
    }

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn election_post_test_compound_poseidon() {
        election_post_test_compound::<PoseidonHasher>();
    }

    fn election_post_test_compound<H: 'static + Hasher>() {
        use std::fs::File;
        use std::io::prelude::*;

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 64;
        let sector_size = (leaves * NODE_SIZE) as u64;
        let randomness = H::Domain::random(rng);
        let prover_id = H::Domain::random(rng);

        let setup_params = compound_proof::SetupParams {
            vanilla_params: election::SetupParams {
                sector_size,
                challenge_count: 20,
                challenged_nodes: 1,
            },
            partitions: None,
            priority: true,
        };

        let mut sectors: Vec<SectorId> = Vec::new();
        let mut trees = BTreeMap::new();

        // Construct and store an MT using a named DiskStore.
        let temp_dir = tempdir::TempDir::new("level_cache_tree").unwrap();
        let temp_path = temp_dir.path();
        let config = StoreConfig::new(
            &temp_path,
            String::from("test-lc-tree"),
            StoreConfig::default_cached_above_base_layer(leaves as usize, 8),
        );

        for i in 0..5 {
            sectors.push(i.into());
            let data: Vec<u8> = (0..leaves)
                .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
                .collect();

            let replica_path = temp_path.join(format!("replica-path-{}", i));
            let mut f = File::create(&replica_path).unwrap();
            f.write_all(&data).unwrap();

            let cur_config = StoreConfig::from_config(&config, format!("test-lc-tree-{}", i), None);
            let lctree = create_base_lcmerkle_tree::<
                H,
                <OctLCMerkleTree<H> as MerkleTreeTrait>::Arity,
            >(cur_config.clone(), leaves, &data, &replica_path)
            .unwrap();
            trees.insert(i.into(), lctree);
        }

        let pub_params = ElectionPoStCompound::<H>::setup(&setup_params).expect("setup failed");

        let candidates = election::generate_candidates::<H>(
            &pub_params.vanilla_params,
            &sectors,
            &trees,
            prover_id,
            randomness,
        )
        .unwrap();

        let candidate = &candidates[0];
        let tree = trees.remove(&candidate.sector_id).unwrap();
        let comm_r_last = tree.root();
        let comm_c = H::Domain::random(rng);
        let comm_r = H::Function::hash2(&comm_c, &comm_r_last);

        let pub_inputs = election::PublicInputs {
            randomness,
            sector_id: candidate.sector_id,
            prover_id,
            comm_r,
            partial_ticket: candidate.partial_ticket,
            sector_challenge_index: 0,
        };

        let priv_inputs = election::PrivateInputs::<H> {
            tree,
            comm_c,
            comm_r_last,
        };

        {
            let (circuit, inputs) =
                ElectionPoStCompound::circuit_for_test(&pub_params, &pub_inputs, &priv_inputs)
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
                ElectionPoStCompound::circuit_for_test(&pub_params, &pub_inputs, &priv_inputs)
                    .unwrap();
            let blank_circuit =
                ElectionPoStCompound::<H>::blank_circuit(&pub_params.vanilla_params);

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
            ElectionPoStCompound::<H>::groth_params(Some(rng), &pub_params.vanilla_params)
                .expect("failed to generate groth params");

        let proof = ElectionPoStCompound::prove(
            &pub_params,
            &pub_inputs,
            &priv_inputs,
            &blank_groth_params,
        )
        .expect("failed while proving");

        let verified =
            ElectionPoStCompound::verify(&pub_params, &pub_inputs, &proof, &NoRequirements)
                .expect("failed while verifying");

        assert!(verified);
    }
}
