use std::marker::PhantomData;

use bellperson::bls::{Bls12, Fr};
use bellperson::gadgets::num;
use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use ff::Field;
use generic_array::typenum;
use typenum::marker_traits::Unsigned;

use storage_proofs_core::{
    compound_proof::CircuitComponent,
    gadgets::constraint,
    gadgets::por::PoRCircuit,
    gadgets::variables::Root,
    hasher::{HashFunction, Hasher, PoseidonFunction, PoseidonMDArity},
    merkle::MerkleTreeTrait,
};

/// This is the `ElectionPoSt` circuit.
pub struct ElectionPoStCircuit<Tree: MerkleTreeTrait> {
    pub comm_r: Option<Fr>,
    pub comm_c: Option<Fr>,
    pub comm_r_last: Option<Fr>,
    pub leafs: Vec<Option<Fr>>,
    #[allow(clippy::type_complexity)]
    pub paths: Vec<Vec<(Vec<Option<Fr>>, Option<usize>)>>,
    pub partial_ticket: Option<Fr>,
    pub randomness: Option<Fr>,
    pub prover_id: Option<Fr>,
    pub sector_id: Option<Fr>,
    pub _t: PhantomData<Tree>,
}

#[derive(Clone, Default)]
pub struct ComponentPrivateInputs {}

impl<'a, Tree: MerkleTreeTrait> CircuitComponent for ElectionPoStCircuit<Tree> {
    type ComponentPrivateInputs = ComponentPrivateInputs;
}

impl<'a, Tree: 'static + MerkleTreeTrait> Circuit<Bls12> for ElectionPoStCircuit<Tree> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
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
            let hash_num = <Tree::Hasher as Hasher>::Function::hash2_circuit(
                cs.namespace(|| "H_comm_c_comm_r_last"),
                &comm_c_num,
                &comm_r_last_num,
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
            PoRCircuit::<Tree>::synthesize(
                cs.namespace(|| format!("challenge_inclusion{}", i)),
                Root::Val(*leaf),
                path.clone().into(),
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
                || Ok(Fr::zero()),
            )?);
        }

        // hash it
        let partial_ticket_num = PoseidonFunction::hash_md_circuit::<_>(
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

    use bellperson::bls::{Bls12, Fr};
    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use ff::Field;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::{
        compound_proof::CompoundProof,
        hasher::{Domain, HashFunction, Hasher, PoseidonHasher},
        merkle::{generate_tree, get_base_tree_count, LCTree, MerkleTreeTrait},
        proof::ProofScheme,
        sector::SectorId,
        util::NODE_SIZE,
    };
    use typenum::{U0, U8};

    use crate::election::{self, ElectionPoSt, ElectionPoStCompound};

    #[test]
    fn test_election_post_circuit_poseidon() {
        test_election_post_circuit::<LCTree<PoseidonHasher, U8, U0, U0>>(22_940);
    }

    fn test_election_post_circuit<Tree: 'static + MerkleTreeTrait>(expected_constraints: usize) {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 64 * get_base_tree_count::<Tree>();
        let sector_size = leaves * NODE_SIZE;

        let randomness = <Tree::Hasher as Hasher>::Domain::random(rng);
        let prover_id = <Tree::Hasher as Hasher>::Domain::random(rng);

        let pub_params = election::PublicParams {
            sector_size: sector_size as u64,
            challenge_count: 20,
            challenged_nodes: 1,
        };

        let mut sectors: Vec<SectorId> = Vec::new();
        let mut trees = BTreeMap::new();

        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path();

        for i in 0..5 {
            sectors.push(i.into());
            let (_data, tree) =
                generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));
            trees.insert(i.into(), tree);
        }

        let candidates = election::generate_candidates::<Tree>(
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
        let comm_c = <Tree::Hasher as Hasher>::Domain::random(rng);
        let comm_r = <Tree::Hasher as Hasher>::Function::hash2(&comm_c, &comm_r_last);

        let pub_inputs = election::PublicInputs {
            randomness,
            sector_id: candidate.sector_id,
            prover_id,
            comm_r,
            partial_ticket: candidate.partial_ticket,
            sector_challenge_index: 0,
        };

        let priv_inputs = election::PrivateInputs::<Tree> {
            tree,
            comm_c,
            comm_r_last,
        };

        let proof = ElectionPoSt::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs)
            .expect("proving failed");

        let is_valid = ElectionPoSt::<Tree>::verify(&pub_params, &pub_inputs, &proof)
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

        let instance = ElectionPoStCircuit::<Tree> {
            leafs,
            paths,
            comm_r: Some(comm_r.into()),
            comm_c: Some(comm_c.into()),
            comm_r_last: Some(comm_r_last.into()),
            partial_ticket: Some(candidate.partial_ticket),
            randomness: Some(randomness.into()),
            prover_id: Some(prover_id.into()),
            sector_id: Some(candidate.sector_id.into()),
            _t: PhantomData,
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
            ElectionPoStCompound::<Tree>::generate_public_inputs(&pub_inputs, &pub_params, None)
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
