use std::marker::PhantomData;

use bellperson::gadgets::num;
use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use ff::Field;
use fil_sapling_crypto::jubjub::JubjubEngine;
use generic_array::typenum;
use typenum::marker_traits::Unsigned;

use crate::compound_proof::CircuitComponent;
use crate::error::Result;
use crate::gadgets::constraint;
use crate::gadgets::por::PoRCircuit;
use crate::gadgets::variables::Root;
use crate::hasher::{
    HashFunction, Hasher, PoseidonArity, PoseidonEngine, PoseidonFunction, PoseidonMDArity,
};

/// This is the `ElectionPoSt` circuit.
pub struct ElectionPoStCircuit<'a, E: JubjubEngine, H: Hasher> {
    /// Paramters for the engine.
    pub params: &'a E::Params,
    pub comm_r: Option<E::Fr>,
    pub comm_c: Option<E::Fr>,
    pub comm_r_last: Option<E::Fr>,
    pub leafs: Vec<Option<E::Fr>>,
    #[allow(clippy::type_complexity)]
    pub paths: Vec<Vec<(Vec<Option<E::Fr>>, Option<usize>)>>,
    pub partial_ticket: Option<E::Fr>,
    pub randomness: Option<E::Fr>,
    pub prover_id: Option<E::Fr>,
    pub sector_id: Option<E::Fr>,
    pub _h: PhantomData<H>,
}

#[derive(Clone, Default)]
pub struct ComponentPrivateInputs {}

impl<'a, E: JubjubEngine, H: Hasher> CircuitComponent for ElectionPoStCircuit<'a, E, H> {
    type ComponentPrivateInputs = ComponentPrivateInputs;
}

impl<
        'a,
        E: JubjubEngine
            + PoseidonEngine<typenum::U8>
            + PoseidonEngine<typenum::U2>
            + PoseidonEngine<PoseidonMDArity>,
        H: Hasher,
    > Circuit<E> for ElectionPoStCircuit<'a, E, H>
where
    typenum::U8: PoseidonArity<E>,
{
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let params = self.params;
        let comm_r = self.comm_r;
        let comm_c = self.comm_c;
        let comm_r_last = self.comm_r_last;
        let leafs = self.leafs;
        let paths = self.paths;
        let partial_ticket = self.partial_ticket;
        let randomness = self.randomness;
        let prover_id = self.prover_id;
        let sector_id = self.sector_id;

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

        // 3. Verify partial ticket

        // randomness
        let randomness_num = num::AllocatedNum::alloc(cs.namespace(|| "randomness"), || {
            randomness
                .map(Into::into)
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        // prover_id
        let prover_id_num = num::AllocatedNum::alloc(cs.namespace(|| "prover_id"), || {
            prover_id
                .map(Into::into)
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        // sector_id
        let sector_id_num = num::AllocatedNum::alloc(cs.namespace(|| "sector_id"), || {
            sector_id
                .map(Into::into)
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        let mut partial_ticket_nums = vec![randomness_num, prover_id_num, sector_id_num];
        for (i, leaf) in leafs.iter().enumerate() {
            let leaf_num =
                num::AllocatedNum::alloc(cs.namespace(|| format!("leaf_{}", i)), || {
                    leaf.map(Into::into)
                        .ok_or_else(|| SynthesisError::AssignmentMissing)
                })?;
            partial_ticket_nums.push(leaf_num);
        }

        // pad to a multiple of md arity
        let arity = PoseidonMDArity::to_usize();
        while partial_ticket_nums.len() % arity != 0 {
            partial_ticket_nums.push(num::AllocatedNum::alloc(
                cs.namespace(|| format!("padding_{}", partial_ticket_nums.len())),
                || Ok(E::Fr::zero()),
            )?);
        }

        // hash it
        let partial_ticket_num = PoseidonFunction::hash_md_circuit::<E, _>(
            &mut cs.namespace(|| "partial_ticket_hash"),
            &partial_ticket_nums,
        )?;

        // allocate expected input
        let expected_partial_ticket_num =
            num::AllocatedNum::alloc(cs.namespace(|| "partial_ticket"), || {
                partial_ticket
                    .map(Into::into)
                    .ok_or_else(|| SynthesisError::AssignmentMissing)
            })?;

        expected_partial_ticket_num.inputize(cs.namespace(|| "partial_ticket_input"))?;

        // check equality
        constraint::equal(
            cs,
            || "enforce partial_ticket is correct",
            &partial_ticket_num,
            &expected_partial_ticket_num,
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use ff::Field;
    use merkletree::store::StoreConfig;
    use paired::bls12_381::{Bls12, Fr};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use crate::compound_proof::CompoundProof;
    use crate::crypto::pedersen::JJ_PARAMS;
    use crate::drgraph::{new_seed, BucketGraph, Graph, BASE_DEGREE};
    use crate::fr32::fr_into_bytes;
    use crate::gadgets::TestConstraintSystem;
    use crate::hasher::{Domain, HashFunction, Hasher, PedersenHasher, PoseidonHasher};
    use crate::merkle::OctLCMerkleTree;
    use crate::porep::stacked::OCT_ARITY;
    use crate::post::election::{self, ElectionPoSt, ElectionPoStCompound};
    use crate::proof::ProofScheme;
    use crate::sector::SectorId;
    use crate::util::NODE_SIZE;

    #[test]
    fn test_election_post_circuit_pedersen() {
        test_election_post_circuit::<PedersenHasher>(389_883);
    }

    #[test]
    fn test_election_post_circuit_poseidon() {
        test_election_post_circuit::<PoseidonHasher>(24_426);
    }

    fn test_election_post_circuit<H: Hasher>(expected_constraints: usize) {
        use std::fs::File;
        use std::io::prelude::*;

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 64;
        let sector_size = leaves * NODE_SIZE;

        let randomness = H::Domain::random(rng);
        let prover_id = H::Domain::random(rng);

        let pub_params = election::PublicParams {
            sector_size: sector_size as u64,
            challenge_count: 20,
            challenged_nodes: 1,
        };

        let mut sectors: Vec<SectorId> = Vec::new();
        let mut trees = BTreeMap::new();

        // Construct and store an MT using a named DiskStore.
        let temp_dir = tempdir::TempDir::new("level_cache_tree_v1").unwrap();
        let temp_path = temp_dir.path();
        let config = StoreConfig::new(
            &temp_path,
            String::from("test-lc-tree"),
            StoreConfig::default_cached_above_base_layer(leaves as usize, OCT_ARITY),
        );

        for i in 0..5 {
            sectors.push(i.into());
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
            trees.insert(i.into(), lctree);
        }

        let candidates = election::generate_candidates::<H>(
            &pub_params,
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

        let proof = ElectionPoSt::<H>::prove(&pub_params, &pub_inputs, &priv_inputs)
            .expect("proving failed");

        let is_valid = ElectionPoSt::<H>::verify(&pub_params, &pub_inputs, &proof)
            .expect("verification failed");
        assert!(is_valid);

        // actual circuit test

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
        let leafs: Vec<_> = proof.leafs().iter().map(|l| Some((*l).into())).collect();

        let mut cs = TestConstraintSystem::<Bls12>::new();

        let instance = ElectionPoStCircuit::<_, H> {
            params: &*JJ_PARAMS,
            leafs,
            paths,
            comm_r: Some(comm_r.into()),
            comm_c: Some(comm_c.into()),
            comm_r_last: Some(comm_r_last.into()),
            partial_ticket: Some(candidate.partial_ticket.into()),
            randomness: Some(randomness.into()),
            prover_id: Some(prover_id.into()),
            sector_id: Some(candidate.sector_id.into()),
            _h: PhantomData,
        };

        instance
            .synthesize(&mut cs)
            .expect("failed to synthesize circuit");

        assert!(cs.is_satisfied(), "constraints not satisfied");

        assert_eq!(cs.num_inputs(), 23, "wrong number of inputs");
        assert_eq!(
            cs.num_constraints(),
            expected_constraints,
            "wrong number of constraints"
        );
        assert_eq!(cs.get_input(0, "ONE"), Fr::one());

        let generated_inputs =
            ElectionPoStCompound::<H>::generate_public_inputs(&pub_inputs, &pub_params, None)
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
