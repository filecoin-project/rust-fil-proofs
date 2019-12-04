use std::marker::PhantomData;

use anyhow::ensure;
use bellperson::gadgets::num;
use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use fil_sapling_crypto::jubjub::JubjubEngine;
use paired::bls12_381::{Bls12, Fr};

use crate::circuit::constraint;
use crate::circuit::por::{PoRCircuit, PoRCompound};
use crate::circuit::stacked::hash::hash2;
use crate::circuit::variables::Root;
use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::crypto::pedersen::JJ_PARAMS;
use crate::drgraph;
use crate::error::Result;
use crate::hasher::Hasher;
use crate::merklepor;
use crate::parameter_cache::{CacheableParameters, ParameterSetMetadata};
use crate::proof::ProofScheme;
use crate::rational_post::RationalPoSt;
use crate::util::NODE_SIZE;

/// This is the `RationalPoSt` circuit.
pub struct RationalPoStCircuit<'a, E: JubjubEngine, H: Hasher> {
    /// Paramters for the engine.
    pub params: &'a E::Params,
    pub comm_rs: Vec<Option<E::Fr>>,
    pub comm_cs: Vec<Option<E::Fr>>,
    pub comm_r_lasts: Vec<Option<E::Fr>>,
    pub leafs: Vec<Option<E::Fr>>,
    #[allow(clippy::type_complexity)]
    pub paths: Vec<Vec<Option<(E::Fr, bool)>>>,
    _h: PhantomData<H>,
}

pub struct RationalPoStCompound<H>
where
    H: Hasher,
{
    _h: PhantomData<H>,
}

impl<E: JubjubEngine, C: Circuit<E>, P: ParameterSetMetadata, H: Hasher>
    CacheableParameters<E, C, P> for RationalPoStCompound<H>
{
    fn cache_prefix() -> String {
        String::from("proof-of-spacetime-rational")
    }
}

#[derive(Clone, Default)]
pub struct ComponentPrivateInputs {}

impl<'a, E: JubjubEngine, H: Hasher> CircuitComponent for RationalPoStCircuit<'a, E, H> {
    type ComponentPrivateInputs = ComponentPrivateInputs;
}

impl<'a, H> CompoundProof<'a, Bls12, RationalPoSt<'a, H>, RationalPoStCircuit<'a, Bls12, H>>
    for RationalPoStCompound<H>
where
    H: 'a + Hasher,
{
    fn generate_public_inputs(
        pub_in: &<RationalPoSt<'a, H> as ProofScheme<'a>>::PublicInputs,
        pub_params: &<RationalPoSt<'a, H> as ProofScheme<'a>>::PublicParams,
        _partition_k: Option<usize>,
    ) -> Result<Vec<Fr>> {
        let mut inputs = Vec::new();

        let por_pub_params = merklepor::PublicParams {
            leaves: (pub_params.sector_size as usize / NODE_SIZE),
            private: true,
        };

        ensure!(
            pub_in.challenges.len() == pub_in.comm_rs.len(),
            "Missmatch in challenges and comm_rs"
        );

        for (challenge, comm_r) in pub_in.challenges.iter().zip(pub_in.comm_rs.iter()) {
            inputs.push((*comm_r).into());

            let por_pub_inputs = merklepor::PublicInputs {
                commitment: None,
                challenge: challenge.leaf as usize,
            };
            let por_inputs =
                PoRCompound::<H>::generate_public_inputs(&por_pub_inputs, &por_pub_params, None)?;

            inputs.extend(por_inputs);
        }

        Ok(inputs)
    }

    fn circuit(
        pub_in: &<RationalPoSt<'a, H> as ProofScheme<'a>>::PublicInputs,
        _priv_in: <RationalPoStCircuit<'a, Bls12, H> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &<RationalPoSt<'a, H> as ProofScheme<'a>>::Proof,
        _pub_params: &<RationalPoSt<'a, H> as ProofScheme<'a>>::PublicParams,
    ) -> Result<RationalPoStCircuit<'a, Bls12, H>> {
        let comm_rs: Vec<_> = pub_in.comm_rs.iter().map(|c| Some((*c).into())).collect();
        let comm_cs: Vec<_> = vanilla_proof
            .comm_cs
            .iter()
            .map(|c| Some((*c).into()))
            .collect();

        let comm_r_lasts: Vec<_> = vanilla_proof
            .commitments()
            .into_iter()
            .map(|c| Some((*c).into()))
            .collect();

        let leafs: Vec<_> = vanilla_proof
            .leafs()
            .iter()
            .map(|c| Some((**c).into()))
            .collect();

        let paths: Vec<Vec<_>> = vanilla_proof
            .paths()
            .iter()
            .map(|v| v.iter().map(|p| Some(((*p).0.into(), p.1))).collect())
            .collect();

        Ok(RationalPoStCircuit {
            params: &*JJ_PARAMS,
            leafs,
            comm_rs,
            comm_cs,
            comm_r_lasts,
            paths,
            _h: PhantomData,
        })
    }

    fn blank_circuit(
        pub_params: &<RationalPoSt<'a, H> as ProofScheme<'a>>::PublicParams,
    ) -> RationalPoStCircuit<'a, Bls12, H> {
        let challenges_count = pub_params.challenges_count;
        let height = drgraph::graph_height(pub_params.sector_size as usize / NODE_SIZE);

        let comm_rs = vec![None; challenges_count];
        let comm_cs = vec![None; challenges_count];
        let comm_r_lasts = vec![None; challenges_count];
        let leafs = vec![None; challenges_count];
        let paths = vec![vec![None; height]; challenges_count];

        RationalPoStCircuit {
            params: &*JJ_PARAMS,
            comm_rs,
            comm_cs,
            comm_r_lasts,
            leafs,
            paths,
            _h: PhantomData,
        }
    }
}

impl<'a, E: JubjubEngine, H: Hasher> Circuit<E> for RationalPoStCircuit<'a, E, H> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let params = self.params;
        let comm_rs = self.comm_rs;
        let comm_cs = self.comm_cs;
        let comm_r_lasts = self.comm_r_lasts;
        let leafs = self.leafs;
        let paths = self.paths;

        assert_eq!(paths.len(), leafs.len());
        assert_eq!(paths.len(), comm_rs.len());
        assert_eq!(paths.len(), comm_cs.len());
        assert_eq!(paths.len(), comm_r_lasts.len());

        for (((i, comm_r_last), comm_c), comm_r) in comm_r_lasts
            .iter()
            .enumerate()
            .zip(comm_cs.iter())
            .zip(comm_rs.iter())
        {
            let comm_r_last_num =
                num::AllocatedNum::alloc(cs.namespace(|| format!("comm_r_last_{}", i)), || {
                    comm_r_last
                        .map(Into::into)
                        .ok_or_else(|| SynthesisError::AssignmentMissing)
                })?;

            let comm_c_num =
                num::AllocatedNum::alloc(cs.namespace(|| format!("comm_c_{}", i)), || {
                    comm_c
                        .map(Into::into)
                        .ok_or_else(|| SynthesisError::AssignmentMissing)
                })?;

            let comm_r_num =
                num::AllocatedNum::alloc(cs.namespace(|| format!("comm_r_{}", i)), || {
                    comm_r
                        .map(Into::into)
                        .ok_or_else(|| SynthesisError::AssignmentMissing)
                })?;

            comm_r_num.inputize(cs.namespace(|| format!("comm_r_{}_input", i)))?;

            // Verify H(Comm_C || comm_r_last) == comm_r
            {
                // Allocate comm_c as booleansn
                let comm_c_bits =
                    comm_c_num.to_bits_le(cs.namespace(|| format!("comm_c_{}_bits", i)))?;

                // Allocate comm_r_last as booleans
                let comm_r_last_bits = comm_r_last_num
                    .to_bits_le(cs.namespace(|| format!("comm_r_last_{}_bits", i)))?;

                let hash_num = hash2(
                    cs.namespace(|| format!("H_comm_c_comm_r_last_{}", i)),
                    params,
                    &comm_c_bits,
                    &comm_r_last_bits,
                )?;

                // Check actual equality
                constraint::equal(
                    cs,
                    || format!("enforce_comm_c_comm_r_last_hash_comm_r_{}", i),
                    &comm_r_num,
                    &hash_num,
                );
            }

            PoRCircuit::<E, H>::synthesize(
                cs.namespace(|| format!("challenge_inclusion{}", i)),
                &params,
                Root::Val(leafs[i]),
                paths[i].clone(),
                Root::from_allocated::<CS>(comm_r_last_num),
                true,
            )?;
        }

        Ok(())
    }
}

impl<'a, E: JubjubEngine, H: Hasher> RationalPoStCircuit<'a, E, H> {
    #[allow(clippy::type_complexity)]
    pub fn synthesize<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        params: &'a E::Params,
        leafs: Vec<Option<E::Fr>>,
        comm_rs: Vec<Option<E::Fr>>,
        comm_cs: Vec<Option<E::Fr>>,
        comm_r_lasts: Vec<Option<E::Fr>>,
        paths: Vec<Vec<Option<(E::Fr, bool)>>>,
    ) -> Result<(), SynthesisError> {
        Self {
            params,
            leafs,
            comm_rs,
            comm_cs,
            comm_r_lasts,
            paths,
            _h: PhantomData,
        }
        .synthesize(cs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use ff::Field;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    use crate::circuit::test::*;
    use crate::compound_proof;
    use crate::crypto::pedersen::JJ_PARAMS;
    use crate::drgraph::{new_seed, BucketGraph, Graph, BASE_DEGREE};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::{pedersen::*, Domain};
    use crate::proof::{NoRequirements, ProofScheme};
    use crate::rational_post::{self, derive_challenges, RationalPoSt};
    use crate::sector::OrderedSectorSet;
    use crate::stacked::hash::hash2;

    #[test]
    fn test_rational_post_circuit_with_bls12_381() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 32;
        let sector_size = leaves * 32;
        let challenges_count = 2;

        let pub_params = rational_post::PublicParams {
            sector_size,
            challenges_count,
        };

        let data1: Vec<u8> = (0..32)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
            .collect();
        let data2: Vec<u8> = (0..32)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
            .collect();

        let graph1 = BucketGraph::<PedersenHasher>::new(32, BASE_DEGREE, 0, new_seed()).unwrap();
        let tree1 = graph1.merkle_tree(data1.as_slice()).unwrap();

        let graph2 = BucketGraph::<PedersenHasher>::new(32, BASE_DEGREE, 0, new_seed()).unwrap();
        let tree2 = graph2.merkle_tree(data2.as_slice()).unwrap();

        let faults = OrderedSectorSet::new();
        let mut sectors = OrderedSectorSet::new();
        sectors.insert(0.into());
        sectors.insert(1.into());

        let seed = (0..32).map(|_| rng.gen()).collect::<Vec<u8>>();
        let challenges =
            derive_challenges(challenges_count, sector_size, &sectors, &seed, &faults).unwrap();
        let comm_r_lasts_raw = vec![tree1.root(), tree2.root()];
        let comm_r_lasts: Vec<_> = challenges
            .iter()
            .map(|c| comm_r_lasts_raw[u64::from(c.sector) as usize])
            .collect();

        let comm_cs: Vec<PedersenDomain> = challenges
            .iter()
            .map(|_c| PedersenDomain::random(rng))
            .collect();

        let comm_rs: Vec<PedersenDomain> = comm_cs
            .iter()
            .zip(comm_r_lasts.iter())
            .map(|(comm_c, comm_r_last)| hash2(comm_c, comm_r_last).into())
            .collect();

        let pub_inputs = rational_post::PublicInputs {
            challenges: &challenges,
            faults: &faults,
            comm_rs: &comm_rs,
        };

        let mut trees = BTreeMap::new();
        trees.insert(0.into(), &tree1);
        trees.insert(1.into(), &tree2);

        let priv_inputs = rational_post::PrivateInputs::<PedersenHasher> {
            trees: &trees,
            comm_cs: &comm_cs,
            comm_r_lasts: &comm_r_lasts,
        };

        let proof = RationalPoSt::<PedersenHasher>::prove(&pub_params, &pub_inputs, &priv_inputs)
            .expect("proving failed");

        let is_valid = RationalPoSt::<PedersenHasher>::verify(&pub_params, &pub_inputs, &proof)
            .expect("verification failed");
        assert!(is_valid);

        // actual circuit test

        let paths: Vec<_> = proof
            .paths()
            .iter()
            .map(|p| {
                p.iter()
                    .map(|v| Some((v.0.into(), v.1)))
                    .collect::<Vec<_>>()
            })
            .collect();
        let leafs: Vec<_> = proof.leafs().iter().map(|l| Some((**l).into())).collect();

        let mut cs = TestConstraintSystem::<Bls12>::new();

        let instance = RationalPoStCircuit::<_, PedersenHasher> {
            params: &*JJ_PARAMS,
            leafs,
            paths,
            comm_rs: comm_rs.iter().copied().map(|c| Some(c.into())).collect(),
            comm_cs: comm_cs.into_iter().map(|c| Some(c.into())).collect(),
            comm_r_lasts: comm_r_lasts.into_iter().map(|c| Some(c.into())).collect(),
            _h: PhantomData,
        };

        instance
            .synthesize(&mut cs)
            .expect("failed to synthesize circuit");

        assert!(cs.is_satisfied(), "constraints not satisfied");

        assert_eq!(cs.num_inputs(), 5, "wrong number of inputs");
        assert_eq!(cs.num_constraints(), 16_496, "wrong number of constraints");
        assert_eq!(cs.get_input(0, "ONE"), Fr::one());

        let generated_inputs = RationalPoStCompound::<PedersenHasher>::generate_public_inputs(
            &pub_inputs,
            &pub_params,
            None,
        )
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

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn rational_post_test_compound() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 32;
        let sector_size = leaves * 32;
        let challenges_count = 2;

        let setup_params = compound_proof::SetupParams {
            vanilla_params: rational_post::SetupParams {
                sector_size,
                challenges_count,
            },
            partitions: None,
        };

        let pub_params =
            RationalPoStCompound::<PedersenHasher>::setup(&setup_params).expect("setup failed");

        let data1: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
            .collect();
        let data2: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
            .collect();

        let graph1 = BucketGraph::<PedersenHasher>::new(32, BASE_DEGREE, 0, new_seed()).unwrap();
        let tree1 = graph1.merkle_tree(data1.as_slice()).unwrap();

        let graph2 = BucketGraph::<PedersenHasher>::new(32, BASE_DEGREE, 0, new_seed()).unwrap();
        let tree2 = graph2.merkle_tree(data2.as_slice()).unwrap();

        let faults = OrderedSectorSet::new();
        let mut sectors = OrderedSectorSet::new();
        sectors.insert(0.into());
        sectors.insert(1.into());

        let seed = (0..32).map(|_| rng.gen()).collect::<Vec<u8>>();
        let challenges =
            derive_challenges(challenges_count, sector_size, &sectors, &seed, &faults).unwrap();

        let comm_r_lasts_raw = vec![tree1.root(), tree2.root()];
        let comm_r_lasts: Vec<_> = challenges
            .iter()
            .map(|c| comm_r_lasts_raw[u64::from(c.sector) as usize])
            .collect();

        let comm_cs: Vec<PedersenDomain> = challenges
            .iter()
            .map(|_c| PedersenDomain::random(rng))
            .collect();

        let comm_rs: Vec<PedersenDomain> = comm_cs
            .iter()
            .zip(comm_r_lasts.iter())
            .map(|(comm_c, comm_r_last)| hash2(comm_c, comm_r_last).into())
            .collect();

        let pub_inputs = rational_post::PublicInputs {
            challenges: &challenges,
            faults: &faults,
            comm_rs: &comm_rs,
        };

        let mut trees = BTreeMap::new();
        trees.insert(0.into(), &tree1);
        trees.insert(1.into(), &tree2);

        let priv_inputs = rational_post::PrivateInputs::<PedersenHasher> {
            trees: &trees,
            comm_r_lasts: &comm_r_lasts,
            comm_cs: &comm_cs,
        };

        let gparams = RationalPoStCompound::<PedersenHasher>::groth_params(
            Some(rng),
            &pub_params.vanilla_params,
        )
        .expect("failed to create groth params");

        let proof = RationalPoStCompound::<PedersenHasher>::prove(
            &pub_params,
            &pub_inputs,
            &priv_inputs,
            &gparams,
        )
        .expect("proving failed");

        let (circuit, inputs) = RationalPoStCompound::<PedersenHasher>::circuit_for_test(
            &pub_params,
            &pub_inputs,
            &priv_inputs,
        )
        .unwrap();

        {
            let mut cs = TestConstraintSystem::new();

            circuit.synthesize(&mut cs).expect("failed to synthesize");
            assert!(cs.is_satisfied());
            assert!(cs.verify(&inputs));
        }

        let verified = RationalPoStCompound::<PedersenHasher>::verify(
            &pub_params,
            &pub_inputs,
            &proof,
            &NoRequirements,
        )
        .expect("failed while verifying");

        assert!(verified);
    }
}
