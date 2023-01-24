use std::marker::PhantomData;

use anyhow::ensure;
use bellperson::{gadgets::num::AllocatedNum, Circuit, ConstraintSystem, SynthesisError};
use filecoin_hashers::{Hasher, R1CSHasher};
use storage_proofs_core::{
    compound_proof::CircuitComponent, error::Result, gadgets::constraint, gadgets::por::PoRCircuit,
    gadgets::variables::Root, merkle::MerkleTreeTrait, por, util::NODE_SIZE,
};

use crate::rational as vanilla;

/// This is the `RationalPoSt` circuit.
pub struct RationalPoStCircuit<Tree>
where
    Tree: MerkleTreeTrait,
    Tree::Hasher: R1CSHasher,
{
    /// Paramters for the engine.
    pub comm_rs: Vec<Option<Tree::Field>>,
    pub comm_cs: Vec<Option<Tree::Field>>,
    pub comm_r_lasts: Vec<Option<Tree::Field>>,
    pub leafs: Vec<Option<Tree::Field>>,
    #[allow(clippy::type_complexity)]
    pub paths: Vec<Vec<(Vec<Option<Tree::Field>>, Option<usize>)>>,
    pub _t: PhantomData<Tree>,
}

#[derive(Clone, Default)]
pub struct ComponentPrivateInputs {}

impl<Tree> CircuitComponent for RationalPoStCircuit<Tree>
where
    Tree: MerkleTreeTrait,
    Tree::Hasher: R1CSHasher,
{
    type ComponentPrivateInputs = ComponentPrivateInputs;
}

impl<Tree> Circuit<Tree::Field> for RationalPoStCircuit<Tree>
where
    Tree: MerkleTreeTrait,
    Tree::Hasher: R1CSHasher,
{
    fn synthesize<CS: ConstraintSystem<Tree::Field>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
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
                let hash_num = Tree::Hasher::hash2_circuit(
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

impl<Tree> RationalPoStCircuit<Tree>
where
    Tree: MerkleTreeTrait,
    Tree::Hasher: R1CSHasher,
{
    pub fn generate_public_inputs(
        pub_params: &vanilla::PublicParams,
        pub_inputs: &vanilla::PublicInputs<<Tree::Hasher as Hasher>::Domain>,
    ) -> Result<Vec<Tree::Field>> {
        let mut inputs = Vec::new();

        let por_pub_params = por::PublicParams {
            leaves: (pub_params.sector_size as usize / NODE_SIZE),
            private: true,
        };

        ensure!(
            pub_inputs.challenges.len() == pub_inputs.comm_rs.len(),
            "Missmatch in challenges and comm_rs"
        );

        for (challenge, comm_r) in pub_inputs.challenges.iter().zip(pub_inputs.comm_rs.iter()) {
            inputs.push((*comm_r).into());

            let por_pub_inputs = por::PublicInputs {
                commitment: None,
                challenge: challenge.leaf as usize,
            };
            let por_inputs =
                PoRCircuit::<Tree>::generate_public_inputs(&por_pub_params, &por_pub_inputs)?;

            inputs.extend(por_inputs);
        }

        Ok(inputs)
    }
}
