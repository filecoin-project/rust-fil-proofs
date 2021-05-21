use std::marker::PhantomData;

use bellperson::bls::{Bls12, Fr};
use bellperson::gadgets::num;
use bellperson::{Circuit, ConstraintSystem, SynthesisError};

use storage_proofs_core::{
    compound_proof::CircuitComponent,
    error::Result,
    gadgets::constraint,
    gadgets::por::PoRCircuit,
    gadgets::variables::Root,
    hasher::{HashFunction, Hasher},
    merkle::MerkleTreeTrait,
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use bellperson::bls::{Bls12, Fr};
    use ff::Field;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use storage_proofs_core::{
        compound_proof::CompoundProof,
        hasher::{Domain, HashFunction, Hasher, PoseidonHasher},
        merkle::{generate_tree, get_base_tree_count, BinaryMerkleTree},
        proof::ProofScheme,
        sector::OrderedSectorSet,
        util::NODE_SIZE,
    };

    use crate::rational::{self, derive_challenges, RationalPoSt, RationalPoStCompound};

    #[test]
    fn test_rational_post_circuit_poseidon() {
        test_rational_post_circuit::<BinaryMerkleTree<PoseidonHasher>>(3_770);
    }

    fn test_rational_post_circuit<Tree: 'static + MerkleTreeTrait>(expected_constraints: usize) {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 32 * get_base_tree_count::<Tree>();
        let sector_size = (leaves * NODE_SIZE) as u64;
        let challenges_count = 2;

        let pub_params = rational::PublicParams {
            sector_size,
            challenges_count,
        };

        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path();

        let (_data1, tree1) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));
        let (_data2, tree2) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));

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

        let comm_cs: Vec<<Tree::Hasher as Hasher>::Domain> = challenges
            .iter()
            .map(|_c| <Tree::Hasher as Hasher>::Domain::random(rng))
            .collect();

        let comm_rs: Vec<_> = comm_cs
            .iter()
            .zip(comm_r_lasts.iter())
            .map(|(comm_c, comm_r_last)| {
                <Tree::Hasher as Hasher>::Function::hash2(comm_c, comm_r_last)
            })
            .collect();

        let pub_inputs = rational::PublicInputs {
            challenges: &challenges,
            faults: &faults,
            comm_rs: &comm_rs,
        };

        let mut trees = BTreeMap::new();
        trees.insert(0.into(), &tree1);
        trees.insert(1.into(), &tree2);

        let priv_inputs = rational::PrivateInputs::<Tree> {
            trees: &trees,
            comm_cs: &comm_cs,
            comm_r_lasts: &comm_r_lasts,
        };

        let proof = RationalPoSt::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs)
            .expect("proving failed");

        let is_valid = RationalPoSt::<Tree>::verify(&pub_params, &pub_inputs, &proof)
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

        let instance = RationalPoStCircuit::<Tree> {
            leafs,
            paths,
            comm_rs: comm_rs.iter().copied().map(|c| Some(c.into())).collect(),
            comm_cs: comm_cs.into_iter().map(|c| Some(c.into())).collect(),
            comm_r_lasts: comm_r_lasts.into_iter().map(|c| Some(c.into())).collect(),
            _t: PhantomData,
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
            RationalPoStCompound::<Tree>::generate_public_inputs(&pub_inputs, &pub_params, None)
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
