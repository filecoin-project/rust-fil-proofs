use std::marker::PhantomData;

use bellperson::{
    bls::{Bls12, Fr},
    gadgets::num::AllocatedNum,
    Circuit, ConstraintSystem, SynthesisError,
};
use filecoin_hashers::{HashFunction, Hasher};
use storage_proofs_core::{
    compound_proof::CircuitComponent, error::Result, gadgets::constraint, gadgets::por::PoRCircuit,
    gadgets::variables::Root, merkle::MerkleTreeTrait,
};

/// This is the `RationalPoSt` circuit.
pub struct RationalPoStCircuit<Tree: MerkleTreeTrait> {
    /// Paramters for the engine.
    pub comm_rs: Vec<Option<Fr>>,
    pub comm_cs: Vec<Option<Fr>>,
    pub comm_r_lasts: Vec<Option<Fr>>,
    pub leafs: Vec<Option<Fr>>,
    #[allow(clippy::type_complexity)]
    pub paths: Vec<Vec<(Vec<Option<Fr>>, Option<usize>)>>,
    pub _t: PhantomData<Tree>,
}

#[derive(Clone, Default)]
pub struct ComponentPrivateInputs {}

impl<'a, Tree: MerkleTreeTrait> CircuitComponent for RationalPoStCircuit<Tree> {
    type ComponentPrivateInputs = ComponentPrivateInputs;
}

impl<'a, Tree: 'static + MerkleTreeTrait> Circuit<Bls12> for RationalPoStCircuit<Tree> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
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
                AllocatedNum::alloc(cs.namespace(|| format!("comm_r_last_{}", i)), || {
                    comm_r_last
                        .map(Into::into)
                        .ok_or(SynthesisError::AssignmentMissing)
                })?;

            let comm_c_num = AllocatedNum::alloc(cs.namespace(|| format!("comm_c_{}", i)), || {
                comm_c
                    .map(Into::into)
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

            let comm_r_num = AllocatedNum::alloc(cs.namespace(|| format!("comm_r_{}", i)), || {
                comm_r
                    .map(Into::into)
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

            comm_r_num.inputize(cs.namespace(|| format!("comm_r_{}_input", i)))?;

            // Verify H(Comm_C || comm_r_last) == comm_r
            {
                let hash_num = <Tree::Hasher as Hasher>::Function::hash2_circuit(
                    cs.namespace(|| format!("H_comm_c_comm_r_last_{}", i)),
                    &comm_c_num,
                    &comm_r_last_num,
                )?;

                // Check actual equality
                constraint::equal(
                    cs,
                    || format!("enforce_comm_c_comm_r_last_hash_comm_r_{}", i),
                    &comm_r_num,
                    &hash_num,
                );
            }

            PoRCircuit::<Tree>::synthesize(
                cs.namespace(|| format!("challenge_inclusion{}", i)),
                Root::Val(leafs[i]),
                paths[i].clone().into(),
                Root::from_allocated::<CS>(comm_r_last_num),
                true,
            )?;
        }

        Ok(())
    }
}
