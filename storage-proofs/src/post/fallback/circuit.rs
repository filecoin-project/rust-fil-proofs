use std::marker::PhantomData;

use bellperson::gadgets::num;
use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use fil_sapling_crypto::jubjub::JubjubEngine;
use generic_array::typenum::{self, marker_traits::Unsigned, U8};
use paired::bls12_381::Bls12;

use crate::compound_proof::CircuitComponent;
use crate::crypto::pedersen::JJ_PARAMS;
use crate::drgraph::graph_height;
use crate::error::Result;
use crate::gadgets::constraint;
use crate::gadgets::por::PoRCircuit;
use crate::gadgets::variables::Root;
use crate::hasher::{HashFunction, Hasher, PoseidonArity, PoseidonEngine, PoseidonMDArity};
use crate::util::NODE_SIZE;

use super::vanilla::{PublicParams, PublicSector, SectorProof};

/// This is the `FallbackPoSt` circuit.
pub struct FallbackPoStCircuit<'a, E: JubjubEngine, H: Hasher> {
    pub prover_id: Option<E::Fr>,
    pub sectors: Vec<Sector<'a, E, H>>,
}

#[derive(Clone)]
pub struct Sector<'a, E: JubjubEngine, H: Hasher> {
    /// Paramters for the engine.
    pub params: &'a E::Params,
    pub comm_r: Option<E::Fr>,
    pub comm_c: Option<E::Fr>,
    pub comm_r_last: Option<E::Fr>,
    pub leafs: Vec<Option<E::Fr>>,
    #[allow(clippy::type_complexity)]
    pub paths: Vec<Vec<(Vec<Option<E::Fr>>, Option<usize>)>>,
    pub id: Option<E::Fr>,
    pub _h: PhantomData<H>,
}

impl<'a, H: Hasher> Sector<'a, Bls12, H> {
    pub fn circuit(
        pub_in: &PublicSector<H::Domain>,
        vanilla_proof: &SectorProof<H>,
    ) -> Result<Self> {
        let leafs = vanilla_proof
            .leafs()
            .iter()
            .map(|c| Some((*c).into()))
            .collect();

        let paths = vanilla_proof
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

        Ok(Sector {
            params: &*JJ_PARAMS,
            leafs,
            comm_r: Some(pub_in.comm_r.into()),
            comm_c: Some(vanilla_proof.comm_c.into()),
            comm_r_last: Some(vanilla_proof.comm_r_last.into()),
            paths,
            id: Some(pub_in.id.into()),
            _h: PhantomData,
        })
    }

    pub fn blank_circuit(pub_params: &PublicParams) -> Self {
        let challenges_count = pub_params.challenge_count;
        let height = graph_height::<U8>(pub_params.sector_size as usize / NODE_SIZE);

        let leafs = vec![None; challenges_count];
        pub_params.sector_count;
        let paths =
            vec![vec![(vec![None; U8::to_usize() - 1], None); height - 1]; challenges_count];

        Sector {
            params: &*JJ_PARAMS,
            id: None,
            comm_r: None,
            comm_c: None,
            comm_r_last: None,
            leafs,
            paths,
            _h: PhantomData,
        }
    }
}

impl<
        'a,
        E: JubjubEngine
            + PoseidonEngine<typenum::U8>
            + PoseidonEngine<typenum::U2>
            + PoseidonEngine<PoseidonMDArity>,
        H: Hasher,
    > Circuit<E> for &Sector<'a, E, H>
where
    typenum::U8: PoseidonArity<E>,
{
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let params = self.params;

        let Sector {
            comm_r,
            comm_c,
            comm_r_last,
            leafs,
            paths,
            ..
        } = self;

        assert_eq!(paths.len(), leafs.len());

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

        // 1. Verify H(Comm_C || comm_r_last) == comm_r
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
                cs.namespace(|| format!("challenge_inclusion_{}", i)),
                &params,
                Root::Val(*leaf),
                path.clone(),
                Root::from_allocated::<CS>(comm_r_last_num.clone()),
                true,
            )?;
        }

        Ok(())
    }
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
        for (i, sector) in self.sectors.iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("sector_{}", i));

            sector.synthesize(cs)?;
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
        self, FallbackPoSt, FallbackPoStCompound, PrivateInputs, PrivateSector, PublicInputs,
        PublicSector,
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

        let pub_inputs = PublicInputs {
            randomness,
            prover_id,
            sectors: &pub_sectors,
        };

        let priv_inputs = PrivateInputs::<H> {
            sectors: &priv_sectors,
        };

        let proof = FallbackPoSt::<H>::prove(&pub_params, &pub_inputs, &priv_inputs)
            .expect("proving failed");

        let is_valid = FallbackPoSt::<H>::verify(&pub_params, &pub_inputs, &proof)
            .expect("verification failed");
        assert!(is_valid);

        // actual circuit test
        let circuit_sectors = proof
            .sectors
            .iter()
            .enumerate()
            .map(|(i, proof)| {
                let paths = proof
                    .paths()
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
                    .collect();
                let leafs = proof.leafs().iter().map(|l| Some((*l).into())).collect();

                Sector {
                    params: &*JJ_PARAMS,
                    id: Some(pub_sectors[i].id.into()),
                    leafs,
                    paths,
                    comm_r: Some(pub_sectors[i].comm_r.into()),
                    comm_c: Some(priv_sectors[i].comm_c.into()),
                    comm_r_last: Some(priv_sectors[i].comm_r_last.into()),
                    _h: PhantomData,
                }
            })
            .collect();

        let mut cs = TestConstraintSystem::<Bls12>::new();

        let instance = FallbackPoStCircuit::<_, H> {
            sectors: circuit_sectors,
            prover_id: Some(prover_id.into()),
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
