use bellperson::bls::{Bls12, Fr};
use bellperson::gadgets::num;
use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use ff::Field;
use rayon::prelude::*;

use storage_proofs_core::{
    compound_proof::CircuitComponent,
    error::Result,
    gadgets::constraint,
    gadgets::por::{AuthPath, PoRCircuit},
    gadgets::variables::Root,
    hasher::{HashFunction, Hasher},
    merkle::MerkleTreeTrait,
    por, settings,
    util::NODE_SIZE,
};

use super::vanilla::{PublicParams, PublicSector, SectorProof};

/// This is the `FallbackPoSt` circuit.
pub struct FallbackPoStCircuit<Tree: MerkleTreeTrait> {
    pub prover_id: Option<Fr>,
    pub sectors: Vec<Sector<Tree>>,
}

#[derive(Clone)]
pub struct Sector<Tree: MerkleTreeTrait> {
    pub comm_r: Option<Fr>,
    pub comm_c: Option<Fr>,
    pub comm_r_last: Option<Fr>,
    pub leafs: Vec<Option<Fr>>,
    pub paths: Vec<AuthPath<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>,
    pub id: Option<Fr>,
}

impl<Tree: 'static + MerkleTreeTrait> Sector<Tree> {
    pub fn circuit(
        sector: &PublicSector<<Tree::Hasher as Hasher>::Domain>,
        vanilla_proof: &SectorProof<Tree::Proof>,
    ) -> Result<Self> {
        let leafs = vanilla_proof
            .leafs()
            .iter()
            .map(|l| Some((*l).into()))
            .collect();

        let paths = vanilla_proof
            .as_options()
            .into_iter()
            .map(Into::into)
            .collect();

        Ok(Sector {
            leafs,
            id: Some(sector.id.into()),
            comm_r: Some(sector.comm_r.into()),
            comm_c: Some(vanilla_proof.comm_c.into()),
            comm_r_last: Some(vanilla_proof.comm_r_last.into()),
            paths,
        })
    }

    pub fn blank_circuit(pub_params: &PublicParams) -> Self {
        let challenges_count = pub_params.challenge_count;
        let leaves = pub_params.sector_size as usize / NODE_SIZE;

        let por_params = por::PublicParams {
            leaves,
            private: true,
        };
        let leafs = vec![None; challenges_count];
        let paths = vec![AuthPath::blank(por_params.leaves); challenges_count];

        Sector {
            id: None,
            comm_r: None,
            comm_c: None,
            comm_r_last: None,
            leafs,
            paths,
        }
    }
}

impl<Tree: 'static + MerkleTreeTrait> Circuit<Bls12> for &Sector<Tree> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
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
                cs.namespace(|| format!("challenge_inclusion_{}", i)),
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

impl<Tree: MerkleTreeTrait> CircuitComponent for FallbackPoStCircuit<Tree> {
    type ComponentPrivateInputs = ComponentPrivateInputs;
}

impl<Tree: 'static + MerkleTreeTrait> Circuit<Bls12> for FallbackPoStCircuit<Tree> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        if CS::is_extensible() {
            return self.synthesize_extendable(cs);
        }

        self.synthesize_default(cs)
    }
}

impl<Tree: 'static + MerkleTreeTrait> FallbackPoStCircuit<Tree> {
    fn synthesize_default<CS: ConstraintSystem<Bls12>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let cs = &mut cs.namespace(|| "outer namespace".to_string());

        for (i, sector) in self.sectors.iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("sector_{}", i));
            sector.synthesize(cs)?;
        }
        Ok(())
    }

    fn synthesize_extendable<CS: ConstraintSystem<Bls12>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let FallbackPoStCircuit { sectors, .. } = self;

        let num_chunks = settings::SETTINGS.window_post_synthesis_num_cpus as usize;

        let chunk_size = (sectors.len() / num_chunks).max(1);
        let css = sectors
            .par_chunks(chunk_size)
            .map(|sector_group| {
                let mut cs = CS::new();
                cs.alloc_input(|| "temp ONE", || Ok(Fr::one()))?;

                for (i, sector) in sector_group.iter().enumerate() {
                    let mut cs = cs.namespace(|| format!("sector_{}", i));

                    sector.synthesize(&mut cs)?;
                }
                Ok(cs)
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        for sector_cs in css.into_iter() {
            cs.extend(sector_cs);
        }

        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use ff::Field;
    use generic_array::typenum::{U0, U2, U4, U8};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::{
        compound_proof::CompoundProof,
        hasher::{Domain, HashFunction, Hasher, PoseidonHasher},
        merkle::{generate_tree, get_base_tree_count, LCTree, MerkleTreeTrait, OctMerkleTree},
        proof::ProofScheme,
        util::NODE_SIZE,
    };

    use crate::fallback::{
        self, FallbackPoSt, FallbackPoStCompound, PrivateInputs, PrivateSector, PublicInputs,
        PublicSector,
    };

    #[test]
    fn fallback_post_poseidon_single_partition_matching_base_8() {
        fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(3, 3, 1, 19, 16_869);
    }

    #[test]
    fn fallback_post_poseidon_single_partition_matching_sub_8_4() {
        fallback_post::<LCTree<PoseidonHasher, U8, U4, U0>>(3, 3, 1, 19, 22_674);
    }

    #[test]
    fn fallback_post_poseidon_single_partition_matching_top_8_4_2() {
        fallback_post::<LCTree<PoseidonHasher, U8, U4, U2>>(3, 3, 1, 19, 27_384);
    }

    #[test]
    fn fallback_post_poseidon_single_partition_smaller_base_8() {
        fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(2, 3, 1, 19, 16_869);
    }

    #[test]
    fn fallback_post_poseidon_two_partitions_matching_base_8() {
        fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(4, 2, 2, 13, 11_246);
    }

    #[test]
    fn fallback_post_poseidon_two_partitions_smaller_base_8() {
        fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(5, 3, 2, 19, 16_869);
    }

    #[test]
    #[ignore]
    fn metric_fallback_post_circuit_poseidon() {
        use bellperson::util_cs::bench_cs::BenchCS;
        let params = fallback::SetupParams {
            sector_size: 1024 * 1024 * 1024 * 32 as u64,
            challenge_count: 10,
            sector_count: 5,
        };

        let pp = FallbackPoSt::<OctMerkleTree<PoseidonHasher>>::setup(&params)
            .expect("fallback post setup failure");

        let mut cs = BenchCS::<Bls12>::new();
        FallbackPoStCompound::<OctMerkleTree<PoseidonHasher>>::blank_circuit(&pp)
            .synthesize(&mut cs)
            .expect("blank circuit failure");

        assert_eq!(cs.num_constraints(), 266_665);
    }

    fn fallback_post<Tree: 'static + MerkleTreeTrait>(
        total_sector_count: usize,
        sector_count: usize,
        partitions: usize,
        expected_num_inputs: usize,
        expected_constraints: usize,
    ) where
        Tree::Store: 'static,
    {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 64 * get_base_tree_count::<Tree>();
        let sector_size = leaves * NODE_SIZE;
        let randomness = <Tree::Hasher as Hasher>::Domain::random(rng);
        let prover_id = <Tree::Hasher as Hasher>::Domain::random(rng);

        let pub_params = fallback::PublicParams {
            sector_size: sector_size as u64,
            challenge_count: 5,
            sector_count,
        };

        let temp_dir = tempfile::tempdir().expect("tempdir failure");
        let temp_path = temp_dir.path();

        let mut pub_sectors = Vec::new();
        let mut priv_sectors = Vec::new();
        let mut trees = Vec::new();

        for _i in 0..total_sector_count {
            let (_data, tree) =
                generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));
            trees.push(tree);
        }

        for (i, tree) in trees.iter().enumerate() {
            let comm_c = <Tree::Hasher as Hasher>::Domain::random(rng);
            let comm_r_last = tree.root();

            priv_sectors.push(PrivateSector {
                tree,
                comm_c,
                comm_r_last,
            });

            let comm_r = <Tree::Hasher as Hasher>::Function::hash2(&comm_c, &comm_r_last);
            pub_sectors.push(PublicSector {
                id: (i as u64).into(),
                comm_r,
            });
        }

        let pub_inputs = PublicInputs {
            randomness,
            prover_id,
            sectors: &pub_sectors,
            k: None,
        };

        let priv_inputs = PrivateInputs::<Tree> {
            sectors: &priv_sectors,
        };

        let proofs = FallbackPoSt::<Tree>::prove_all_partitions(
            &pub_params,
            &pub_inputs,
            &priv_inputs,
            partitions,
        )
        .expect("proving failed");
        assert_eq!(proofs.len(), partitions);

        let is_valid =
            FallbackPoSt::<Tree>::verify_all_partitions(&pub_params, &pub_inputs, &proofs)
                .expect("verification failed");
        assert!(is_valid);

        // actual circuit test

        for (j, proof) in proofs.iter().enumerate() {
            // iterates over each partition
            let circuit_sectors = proof
                .sectors
                .iter()
                .enumerate()
                .map(|(i, proof)| {
                    // index into sectors by the correct offset
                    let i = j * sector_count + i;

                    if i < pub_sectors.len() {
                        Sector::circuit(&pub_sectors[i], proof)
                    } else {
                        // duplicated last one
                        let k = pub_sectors.len() - 1;
                        Sector::circuit(&pub_sectors[k], proof)
                    }
                })
                .collect::<Result<_>>()
                .expect("circuit sectors failure");

            let mut cs = TestConstraintSystem::<Bls12>::new();

            let instance = FallbackPoStCircuit::<Tree> {
                sectors: circuit_sectors,
                prover_id: Some(prover_id.into()),
            };

            instance
                .synthesize(&mut cs)
                .expect("failed to synthesize circuit");

            assert!(cs.is_satisfied(), "constraints not satisfied");

            assert_eq!(
                cs.num_inputs(),
                expected_num_inputs,
                "wrong number of inputs"
            );
            assert_eq!(
                cs.num_constraints(),
                expected_constraints,
                "wrong number of constraints"
            );
            assert_eq!(cs.get_input(0, "ONE"), Fr::one());

            let generated_inputs = FallbackPoStCompound::<Tree>::generate_public_inputs(
                &pub_inputs,
                &pub_params,
                Some(j),
            )
            .expect("generate_public_inputs failure");
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

            assert!(
                cs.verify(&generated_inputs),
                "verification failed with TestContraintSystem and generated inputs"
            );
        }
    }
}
