use std::marker::PhantomData;

use bellperson::gadgets::num;
use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use fil_sapling_crypto::jubjub::JubjubEngine;
use generic_array::typenum;

use crate::compound_proof::CircuitComponent;
use crate::error::Result;
use crate::gadgets::constraint;
use crate::gadgets::por::PoRCircuit;
use crate::gadgets::variables::Root;
use crate::hasher::{HashFunction, Hasher, PoseidonArity, PoseidonEngine, PoseidonMDArity};

/// This is the `FallbackPoSt` circuit.
pub struct FallbackPoStCircuit<'a, E: JubjubEngine, H: Hasher> {
    /// Paramters for the engine.
    pub params: &'a E::Params,
    pub comm_rs: Vec<Option<E::Fr>>,
    pub comm_cs: Vec<Option<E::Fr>>,
    pub comm_r_lasts: Vec<Option<E::Fr>>,
    pub leafs: Vec<Vec<Option<E::Fr>>>,
    #[allow(clippy::type_complexity)]
    pub paths: Vec<Vec<Vec<(Vec<Option<E::Fr>>, Option<usize>)>>>,
    pub prover_id: Option<E::Fr>,
    pub sector_ids: Vec<Option<E::Fr>>,
    pub _h: PhantomData<H>,
}

#[derive(Clone, Default)]
pub struct ComponentPrivateInputs {}

impl<'a, E: JubjubEngine, H: Hasher> CircuitComponent for FallbackPoStCircuit<'a, E, H> {
    type ComponentPrivateInputs = ComponentPrivateInputs;
}

impl<
        'a,
        E: JubjubEngine
            + PoseidonEngine<typenum::U8>
            + PoseidonEngine<typenum::U2>
            + PoseidonEngine<PoseidonMDArity>,
        H: Hasher,
    > Circuit<E> for FallbackPoStCircuit<'a, E, H>
where
    typenum::U8: PoseidonArity<E>,
{
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let params = self.params;

        for (i, ((((comm_r, comm_c), comm_r_last), leafs), paths)) in self
            .comm_rs
            .iter()
            .zip(self.comm_cs.iter())
            .zip(self.comm_r_lasts.iter())
            .zip(self.leafs.iter())
            .zip(self.paths.iter())
            .enumerate()
        {
            assert_eq!(paths.len(), leafs.len());
            let cs = &mut cs.namespace(|| format!("sector_{}", i));

            // 1. Verify comm_r

            let comm_r_last_num = num::AllocatedNum::alloc(cs.namespace(|| "comm_r_last"), || {
                comm_r_last
                    .map(Into::into)
                    .ok_or_else(|| SynthesisError::AssignmentMissing)
            })?;

            let comm_c_num = num::AllocatedNum::alloc(cs.namespace(|| "comm_c"), || {
                comm_c
                    .map(Into::into)
                    .ok_or_else(|| SynthesisError::AssignmentMissing)
            })?;

            let comm_r_num = num::AllocatedNum::alloc(cs.namespace(|| "comm_r"), || {
                comm_r
                    .map(Into::into)
                    .ok_or_else(|| SynthesisError::AssignmentMissing)
            })?;

            comm_r_num.inputize(cs.namespace(|| "comm_r_input"))?;

            // Verify H(Comm_C || comm_r_last) == comm_r
            {
                let hash_num = H::Function::hash2_circuit(
                    cs.namespace(|| "H_comm_c_comm_r_last"),
                    &comm_c_num,
                    &comm_r_last_num,
                    params,
                )?;

                // Check actual equality
                constraint::equal(
                    cs,
                    || "enforce_comm_c_comm_r_last_hash_comm_r",
                    &comm_r_num,
                    &hash_num,
                );
            }

            // 2. Verify Inclusion Paths
            for (i, (leaf, path)) in leafs.iter().zip(paths.iter()).enumerate() {
                PoRCircuit::<typenum::U8, E, H>::synthesize(
                    cs.namespace(|| format!("challenge_inclusion{}", i)),
                    &params,
                    Root::Val(*leaf),
                    path.clone(),
                    Root::from_allocated::<CS>(comm_r_last_num.clone()),
                    true,
                )?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ff::Field;
    use merkletree::store::{StoreConfig, StoreConfigDataVersion};
    use paired::bls12_381::{Bls12, Fr};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use crate::compound_proof::CompoundProof;
    use crate::crypto::pedersen::JJ_PARAMS;
    use crate::drgraph::{new_seed, BucketGraph, Graph, BASE_DEGREE};
    use crate::fr32::fr_into_bytes;
    use crate::gadgets::TestConstraintSystem;
    use crate::hasher::{Domain, HashFunction, Hasher, PedersenHasher, PoseidonHasher};
    use crate::merkle::{OctLCMerkleTree, OctMerkleTree};
    use crate::porep::stacked::EXP_DEGREE;
    use crate::porep::stacked::OCT_ARITY;
    use crate::post::fallback::{
        self, FallbackPoSt, FallbackPoStCompound, PrivateInputs, PublicInputs,
    };
    use crate::proof::ProofScheme;
    use crate::sector::SectorId;
    use crate::util::NODE_SIZE;

    #[test]
    fn test_fallback_post_circuit_pedersen() {
        test_fallback_post_circuit::<PedersenHasher>(294_459);
    }

    #[test]
    fn test_fallback_post_circuit_poseidon() {
        test_fallback_post_circuit::<PoseidonHasher>(17_988);
    }

    #[test]
    #[ignore]
    fn metric_fallback_post_circuit_poseidon() {
        use crate::gadgets::BenchCS;

        let params = fallback::SetupParams {
            sector_size: 1024 * 1024 * 1024 * 32 as u64,
            challenge_count: 10,
            sector_count: 5,
        };

        let pp = FallbackPoSt::<PoseidonHasher>::setup(&params).unwrap();

        let mut cs = BenchCS::<Bls12>::new();
        FallbackPoStCompound::<PoseidonHasher>::blank_circuit(&pp)
            .synthesize(&mut cs)
            .unwrap();

        assert_eq!(cs.num_constraints(), 285_180);
    }

    fn test_fallback_post_circuit<H: Hasher>(expected_constraints: usize) {
        use std::fs::File;
        use std::io::prelude::*;

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 64;
        let sector_size = leaves * NODE_SIZE;
        let randomness = H::Domain::random(rng);
        let prover_id = H::Domain::random(rng);
        let sector_count = 3;

        let pub_params = fallback::PublicParams {
            sector_size: sector_size as u64,
            challenge_count: 5,
            sector_count,
        };

        let mut sectors: Vec<SectorId> = Vec::new();
        let mut trees = Vec::new();

        // Construct and store an MT using a named DiskStore.
        let temp_dir = tempdir::TempDir::new("level_cache_tree_v1").unwrap();
        let temp_path = temp_dir.path();
        let config = StoreConfig::new(
            &temp_path,
            String::from("test-lc-tree"),
            StoreConfig::default_cached_above_base_layer(leaves as usize, OCT_ARITY),
        );

        for i in 0..sector_count {
            sectors.push((i as u64).into());
            let data: Vec<u8> = (0..leaves)
                .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
                .collect();

            let graph = BucketGraph::<H>::new(leaves, BASE_DEGREE, 0, new_seed()).unwrap();

            let replica_path = temp_path.join(format!("replica-path-{}", i));
            let mut f = File::create(&replica_path).unwrap();
            f.write_all(&data).unwrap();

            let cur_config = StoreConfig::from_config(&config, format!("test-lc-tree-{}", i), None);
            let mut tree: OctMerkleTree<_, _> = graph
                .merkle_tree(Some(cur_config.clone()), data.as_slice())
                .unwrap();
            let c = tree
                .compact(cur_config.clone(), StoreConfigDataVersion::Two as u32)
                .unwrap();
            assert_eq!(c, true);

            let lctree: OctLCMerkleTree<_, _> = graph
                .lcmerkle_tree(cur_config.clone(), &replica_path)
                .unwrap();
            trees.push(lctree);
        }

        let comm_r_lasts = trees.iter().map(|tree| tree.root()).collect::<Vec<_>>();
        let comm_cs = (0..sector_count)
            .map(|_| H::Domain::random(rng))
            .collect::<Vec<_>>();
        let comm_rs = comm_r_lasts
            .iter()
            .zip(comm_cs.iter())
            .map(|(comm_r_last, comm_c)| H::Function::hash2(&comm_c, &comm_r_last))
            .collect::<Vec<_>>();
        let pub_inputs = PublicInputs {
            randomness,
            sector_ids: &sectors,
            prover_id,
            comm_rs: &comm_rs,
        };

        let priv_inputs = PrivateInputs::<H> {
            trees: &trees,
            comm_cs: &comm_cs,
            comm_r_lasts: &comm_r_lasts,
        };

        let proof = FallbackPoSt::<H>::prove(&pub_params, &pub_inputs, &priv_inputs)
            .expect("proving failed");

        let is_valid = FallbackPoSt::<H>::verify(&pub_params, &pub_inputs, &proof)
            .expect("verification failed");
        assert!(is_valid);

        // actual circuit test
        let paths: Vec<_> = (0..sector_count)
            .map(|i| {
                proof
                    .paths(i)
                    .iter()
                    .map(|p| {
                        p.iter()
                            .map(|v| {
                                (
                                    v.0.iter().copied().map(Into::into).map(Some).collect(),
                                    Some(v.1),
                                )
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect()
            })
            .collect();
        let leafs: Vec<_> = (0..sector_count)
            .map(|i| proof.leafs(i).iter().map(|l| Some((*l).into())).collect())
            .collect();

        let mut cs = TestConstraintSystem::<Bls12>::new();

        let instance = FallbackPoStCircuit::<_, H> {
            params: &*JJ_PARAMS,
            leafs,
            paths,
            comm_rs: comm_rs.iter().map(|r| Some((*r).into())).collect(),
            comm_cs: comm_cs.iter().map(|r| Some((*r).into())).collect(),
            comm_r_lasts: comm_r_lasts.iter().map(|r| Some((*r).into())).collect(),
            prover_id: Some(prover_id.into()),
            sector_ids: sectors.iter().map(|s| Some((*s).into())).collect(),
            _h: PhantomData,
        };

        instance
            .synthesize(&mut cs)
            .expect("failed to synthesize circuit");

        assert!(cs.is_satisfied(), "constraints not satisfied");

        assert_eq!(cs.num_inputs(), 19, "wrong number of inputs");
        assert_eq!(
            cs.num_constraints(),
            expected_constraints,
            "wrong number of constraints"
        );
        assert_eq!(cs.get_input(0, "ONE"), Fr::one());

        let generated_inputs =
            FallbackPoStCompound::<H>::generate_public_inputs(&pub_inputs, &pub_params, None)
                .unwrap();
        let expected_inputs = cs.get_inputs();

        for ((input, label), generated_input) in
            expected_inputs.iter().skip(1).zip(generated_inputs.iter())
        {
            assert_eq!(input, generated_input, "{}", label);
        }

        assert_eq!(
            generated_inputs.len(),
            expected_inputs.len() - 1,
            "inputs are not the same length"
        );
    }
}
