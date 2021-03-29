use std::marker::PhantomData;

use bellperson::{
    bls::{Bls12, Fr},
    gadgets::num::AllocatedNum,
    Circuit, ConstraintSystem, SynthesisError,
};
use ff::Field;
use filecoin_hashers::{poseidon::PoseidonFunction, HashFunction, Hasher, PoseidonMDArity};
use generic_array::typenum::Unsigned;
use storage_proofs_core::{
    compound_proof::CircuitComponent,
    gadgets::{constraint, por::PoRCircuit, variables::Root},
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

        let comm_r_last_num = AllocatedNum::alloc(cs.namespace(|| "comm_r_last"), || {
            comm_r_last
                .map(Into::into)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let comm_c_num = AllocatedNum::alloc(cs.namespace(|| "comm_c"), || {
            comm_c
                .map(Into::into)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let comm_r_num = AllocatedNum::alloc(cs.namespace(|| "comm_r"), || {
            comm_r
                .map(Into::into)
                .ok_or(SynthesisError::AssignmentMissing)
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
        let randomness_num = AllocatedNum::alloc(cs.namespace(|| "randomness"), || {
            randomness
                .map(Into::into)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // prover_id
        let prover_id_num = AllocatedNum::alloc(cs.namespace(|| "prover_id"), || {
            prover_id
                .map(Into::into)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // sector_id
        let sector_id_num = AllocatedNum::alloc(cs.namespace(|| "sector_id"), || {
            sector_id
                .map(Into::into)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let mut partial_ticket_nums = vec![randomness_num, prover_id_num, sector_id_num];
        for (i, leaf) in leafs.iter().enumerate() {
            let leaf_num = AllocatedNum::alloc(cs.namespace(|| format!("leaf_{}", i)), || {
                leaf.map(Into::into)
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            partial_ticket_nums.push(leaf_num);
        }

        // pad to a multiple of md arity
        let arity = PoseidonMDArity::to_usize();
        while partial_ticket_nums.len() % arity != 0 {
            partial_ticket_nums.push(AllocatedNum::alloc(
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
            AllocatedNum::alloc(cs.namespace(|| "partial_ticket"), || {
                partial_ticket
                    .map(Into::into)
                    .ok_or(SynthesisError::AssignmentMissing)
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
