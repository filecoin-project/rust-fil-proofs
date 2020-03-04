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
use crate::hasher::{HashFunction, Hasher, PoseidonArity, PoseidonEngine};

/// This is the `RationalPoSt` circuit.
pub struct RationalPoStCircuit<'a, E: JubjubEngine, H: Hasher> {
    /// Paramters for the engine.
    pub params: &'a E::Params,
    pub comm_rs: Vec<Option<E::Fr>>,
    pub comm_cs: Vec<Option<E::Fr>>,
    pub comm_r_lasts: Vec<Option<E::Fr>>,
    pub leafs: Vec<Option<E::Fr>>,
    #[allow(clippy::type_complexity)]
    pub paths: Vec<Vec<(Vec<Option<E::Fr>>, Option<usize>)>>,
    pub _h: PhantomData<H>,
}

#[derive(Clone, Default)]
pub struct ComponentPrivateInputs {}

impl<'a, E: JubjubEngine, H: Hasher> CircuitComponent for RationalPoStCircuit<'a, E, H> {
    type ComponentPrivateInputs = ComponentPrivateInputs;
}

impl<'a, E: JubjubEngine + PoseidonEngine<typenum::U2>, H: Hasher> Circuit<E>
    for RationalPoStCircuit<'a, E, H>
where
    typenum::U2: PoseidonArity<E>,
{
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
                let hash_num = H::Function::hash2_circuit(
                    cs.namespace(|| format!("H_comm_c_comm_r_last_{}", i)),
                    &comm_c_num,
                    &comm_r_last_num,
                    params,
                )?;

                // Check actual equality
                constraint::equal(
                    cs,
                    || format!("enforce_comm_c_comm_r_last_hash_comm_r_{}", i),
                    &comm_r_num,
                    &hash_num,
                );
            }

            PoRCircuit::<typenum::U2, E, H>::synthesize(
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use ff::Field;
    use paired::bls12_381::{Bls12, Fr};
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    use crate::compound_proof::CompoundProof;
    use crate::crypto::pedersen::JJ_PARAMS;
    use crate::drgraph::{new_seed, BucketGraph, Graph, BASE_DEGREE};
    use crate::fr32::fr_into_bytes;
    use crate::gadgets::TestConstraintSystem;
    use crate::hasher::{Domain, HashFunction, Hasher, PedersenHasher, PoseidonHasher};
    use crate::post::rational::{self, derive_challenges, RationalPoSt, RationalPoStCompound};
    use crate::proof::ProofScheme;
    use crate::sector::OrderedSectorSet;
    use crate::util::NODE_SIZE;

    #[test]
    fn test_rational_post_circuit_pedersen() {
        test_rational_post_circuit::<PedersenHasher>(16_490);
    }

    #[test]
    fn test_rational_post_circuit_poseidon() {
        test_rational_post_circuit::<PoseidonHasher>(3_806);
    }

    fn test_rational_post_circuit<H: Hasher>(expected_constraints: usize) {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 32;
        let sector_size = (leaves * NODE_SIZE) as u64;
        let challenges_count = 2;

        let pub_params = rational::PublicParams {
            sector_size,
            challenges_count,
        };

        let data1: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
            .collect();
        let data2: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
            .collect();

        let graph1 = BucketGraph::<H>::new(leaves, BASE_DEGREE, 0, new_seed()).unwrap();
        let tree1 = graph1
            .merkle_tree::<typenum::U2>(None, data1.as_slice())
            .unwrap();

        let graph2 = BucketGraph::<H>::new(leaves, BASE_DEGREE, 0, new_seed()).unwrap();
        let tree2 = graph2
            .merkle_tree::<typenum::U2>(None, data2.as_slice())
            .unwrap();

        let faults = OrderedSectorSet::new();
        let mut sectors = OrderedSectorSet::new();
        sectors.insert(0.into());
        sectors.insert(1.into());

        let seed = (0..leaves).map(|_| rng.gen()).collect::<Vec<u8>>();
        let challenges =
            derive_challenges(challenges_count, sector_size, &sectors, &seed, &faults).unwrap();
        let comm_r_lasts_raw = vec![tree1.root(), tree2.root()];
        let comm_r_lasts: Vec<_> = challenges
            .iter()
            .map(|c| comm_r_lasts_raw[u64::from(c.sector) as usize])
            .collect();

        let comm_cs: Vec<H::Domain> = challenges.iter().map(|_c| H::Domain::random(rng)).collect();

        let comm_rs: Vec<_> = comm_cs
            .iter()
            .zip(comm_r_lasts.iter())
            .map(|(comm_c, comm_r_last)| H::Function::hash2(comm_c, comm_r_last))
            .collect();

        let pub_inputs = rational::PublicInputs {
            challenges: &challenges,
            faults: &faults,
            comm_rs: &comm_rs,
        };

        let mut trees = BTreeMap::new();
        trees.insert(0.into(), &tree1);
        trees.insert(1.into(), &tree2);

        let priv_inputs = rational::PrivateInputs::<H> {
            trees: &trees,
            comm_cs: &comm_cs,
            comm_r_lasts: &comm_r_lasts,
        };

        let proof = RationalPoSt::<H>::prove(&pub_params, &pub_inputs, &priv_inputs)
            .expect("proving failed");

        let is_valid = RationalPoSt::<H>::verify(&pub_params, &pub_inputs, &proof)
            .expect("verification failed");
        assert!(is_valid);

        // actual circuit test

        let paths: Vec<_> = proof
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
        let leafs: Vec<_> = proof.leafs().iter().map(|l| Some((*l).into())).collect();

        let mut cs = TestConstraintSystem::<Bls12>::new();

        let instance = RationalPoStCircuit::<_, H> {
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
        assert_eq!(
            cs.num_constraints(),
            expected_constraints,
            "wrong number of constraints"
        );
        assert_eq!(cs.get_input(0, "ONE"), Fr::one());

        let generated_inputs =
            RationalPoStCompound::<H>::generate_public_inputs(&pub_inputs, &pub_params, None)
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
