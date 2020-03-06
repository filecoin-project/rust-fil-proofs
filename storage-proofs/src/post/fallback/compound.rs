use std::marker::PhantomData;

use bellperson::Circuit;
use fil_sapling_crypto::jubjub::JubjubEngine;
use generic_array::typenum;
use paired::bls12_381::{Bls12, Fr};
use typenum::marker_traits::Unsigned;

use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::crypto::pedersen::JJ_PARAMS;
use crate::drgraph;
use crate::error::Result;
use crate::gadgets::por::PoRCompound;
use crate::hasher::Hasher;
use crate::parameter_cache::{CacheableParameters, ParameterSetMetadata};
use crate::por;
use crate::post::fallback::{self, FallbackPoSt, FallbackPoStCircuit};
use crate::proof::ProofScheme;
use crate::util::NODE_SIZE;

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

        for (comm_r, sector_id) in pub_inputs.comm_rs.iter().zip(pub_inputs.sector_ids.iter()) {
            // 1. Inputs for verifying comm_r = H(comm_c || comm_r_last)

            inputs.push((*comm_r).into());

            // 2. Inputs for verifying inclusion paths

            for n in 0..pub_params.challenge_count {
                let challenged_leaf_start = fallback::generate_leaf_challenge(
                    &pub_params,
                    pub_inputs.randomness,
                    (*sector_id).into(),
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
        let mut leafs = Vec::new();
        let mut paths = Vec::new();

        for i in 0..pub_params.sector_count {
            leafs.push(
                vanilla_proof
                    .leafs(i)
                    .iter()
                    .map(|c| Some((*c).into()))
                    .collect(),
            );

            paths.push(
                vanilla_proof
                    .paths(i)
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
                    .collect(),
            );
        }

        Ok(FallbackPoStCircuit {
            params: &*JJ_PARAMS,
            leafs,
            comm_rs: pub_in.comm_rs.iter().map(|r| Some((*r).into())).collect(),
            comm_cs: vanilla_proof
                .comm_cs
                .iter()
                .map(|r| Some((*r).into()))
                .collect(),
            comm_r_lasts: vanilla_proof
                .comm_r_lasts
                .iter()
                .map(|r| Some((*r).into()))
                .collect(),
            paths,
            prover_id: Some(pub_in.prover_id.into()),
            sector_ids: pub_in
                .sector_ids
                .iter()
                .map(|s| Some((*s).into()))
                .collect(),
            _h: PhantomData,
        })
    }

    fn blank_circuit(
        pub_params: &<FallbackPoSt<'a, H> as ProofScheme<'a>>::PublicParams,
    ) -> FallbackPoStCircuit<'a, Bls12, H> {
        let challenges_count = pub_params.challenge_count;
        let height =
            drgraph::graph_height::<typenum::U8>(pub_params.sector_size as usize / NODE_SIZE);

        let leafs = vec![vec![None; challenges_count]; pub_params.sector_count];
        let paths = vec![
            vec![
                vec![(vec![None; typenum::U8::to_usize() - 1], None); height - 1];
                challenges_count
            ];
            pub_params.sector_count
        ];

        let comm_rs = vec![None; pub_params.sector_count];
        let comm_cs = vec![None; pub_params.sector_count];
        let comm_r_lasts = vec![None; pub_params.sector_count];
        let sector_ids = vec![None; pub_params.sector_count];

        FallbackPoStCircuit {
            params: &*JJ_PARAMS,
            comm_rs,
            comm_cs,
            comm_r_lasts,
            leafs,
            paths,
            prover_id: None,
            sector_ids,
            _h: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use ff::Field;
    use merkletree::store::{StoreConfig, StoreConfigDataVersion};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use crate::compound_proof;
    use crate::drgraph::{new_seed, BucketGraph, Graph, BASE_DEGREE};
    use crate::fr32::fr_into_bytes;
    use crate::gadgets::{MetricCS, TestConstraintSystem};
    use crate::hasher::{Domain, HashFunction, Hasher, PedersenHasher, PoseidonHasher};
    use crate::merkle::{OctLCMerkleTree, OctMerkleTree};
    use crate::porep::stacked::OCT_ARITY;
    use crate::post::fallback;
    use crate::proof::NoRequirements;
    use crate::sector::SectorId;

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
        // use std::fs::File;
        // use std::io::prelude::*;

        // let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        // let leaves = 64;
        // let sector_size = (leaves * NODE_SIZE) as u64;
        // let randomness = H::Domain::random(rng);
        // let prover_id = H::Domain::random(rng);

        // let setup_params = compound_proof::SetupParams {
        //     vanilla_params: fallback::SetupParams {
        //         sector_size,
        //         challenge_count: 20,
        //         challenged_nodes: 1,
        //     },
        //     partitions: None,
        //     priority: true,
        // };

        // let mut sectors: Vec<SectorId> = Vec::new();
        // let mut trees = BTreeMap::new();

        // // Construct and store an MT using a named DiskStore.
        // let temp_dir = tempdir::TempDir::new("level_cache_tree").unwrap();
        // let temp_path = temp_dir.path();
        // let config = StoreConfig::new(
        //     &temp_path,
        //     String::from("test-lc-tree"),
        //     StoreConfig::default_cached_above_base_layer(leaves as usize, OCT_ARITY),
        // );

        // for i in 0..5 {
        //     sectors.push(i.into());
        //     let data: Vec<u8> = (0..leaves)
        //         .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
        //         .collect();

        //     let graph = BucketGraph::<H>::new(leaves, BASE_DEGREE, 0, new_seed()).unwrap();

        //     let replica_path = temp_path.join(format!("replica-path-{}", i));
        //     let mut f = File::create(&replica_path).unwrap();
        //     f.write_all(&data).unwrap();

        //     let cur_config = StoreConfig::from_config(&config, format!("test-lc-tree-{}", i), None);
        //     let mut tree: OctMerkleTree<_, _> = graph
        //         .merkle_tree(Some(cur_config.clone()), data.as_slice())
        //         .unwrap();
        //     let c = tree
        //         .compact(cur_config.clone(), StoreConfigDataVersion::Two as u32)
        //         .unwrap();
        //     assert_eq!(c, true);

        //     let lctree: OctLCMerkleTree<_, _> = graph
        //         .lcmerkle_tree(cur_config.clone(), &replica_path)
        //         .unwrap();
        //     trees.insert(i.into(), lctree);
        // }

        // let pub_params = FallbackPoStCompound::<H>::setup(&setup_params).expect("setup failed");

        // let candidates = fallback::generate_candidates::<H>(
        //     &pub_params.vanilla_params,
        //     &sectors,
        //     &trees,
        //     prover_id,
        //     randomness,
        // )
        // .unwrap();

        // let candidate = &candidates[0];
        // let tree = trees.remove(&candidate.sector_id).unwrap();
        // let comm_r_last = tree.root();
        // let comm_c = H::Domain::random(rng);
        // let comm_r = H::Function::hash2(&comm_c, &comm_r_last);

        // let pub_inputs = fallback::PublicInputs {
        //     randomness,
        //     sector_id: candidate.sector_id,
        //     prover_id,
        //     comm_r,
        //     partial_ticket: candidate.partial_ticket,
        //     sector_challenge_index: 0,
        // };

        // let priv_inputs = fallback::PrivateInputs::<H> {
        //     tree,
        //     comm_c,
        //     comm_r_last,
        // };

        // {
        //     let (circuit, inputs) =
        //         FallbackPoStCompound::circuit_for_test(&pub_params, &pub_inputs, &priv_inputs)
        //             .unwrap();

        //     let mut cs = TestConstraintSystem::new();

        //     circuit.synthesize(&mut cs).expect("failed to synthesize");

        //     if !cs.is_satisfied() {
        //         panic!(
        //             "failed to satisfy: {:?}",
        //             cs.which_is_unsatisfied().unwrap()
        //         );
        //     }
        //     assert!(
        //         cs.verify(&inputs),
        //         "verification failed with TestContraintSystem and generated inputs"
        //     );
        // }

        // // Use this to debug differences between blank and regular circuit generation.
        // {
        //     let (circuit1, _inputs) =
        //         FallbackPoStCompound::circuit_for_test(&pub_params, &pub_inputs, &priv_inputs)
        //             .unwrap();
        //     let blank_circuit =
        //         FallbackPoStCompound::<H>::blank_circuit(&pub_params.vanilla_params);

        //     let mut cs_blank = MetricCS::new();
        //     blank_circuit
        //         .synthesize(&mut cs_blank)
        //         .expect("failed to synthesize");

        //     let a = cs_blank.pretty_print_list();

        //     let mut cs1 = TestConstraintSystem::new();
        //     circuit1.synthesize(&mut cs1).expect("failed to synthesize");
        //     let b = cs1.pretty_print_list();

        //     for (i, (a, b)) in a.chunks(100).zip(b.chunks(100)).enumerate() {
        //         assert_eq!(a, b, "failed at chunk {}", i);
        //     }
        // }
        // let blank_groth_params =
        //     FallbackPoStCompound::<H>::groth_params(&pub_params.vanilla_params)
        //         .expect("failed to generate groth params");

        // let proof = FallbackPoStCompound::prove(
        //     &pub_params,
        //     &pub_inputs,
        //     &priv_inputs,
        //     &blank_groth_params,
        // )
        // .expect("failed while proving");

        // let verified =
        //     FallbackPoStCompound::verify(&pub_params, &pub_inputs, &proof, &NoRequirements)
        //         .expect("failed while verifying");

        // assert!(verified);
    }
}
