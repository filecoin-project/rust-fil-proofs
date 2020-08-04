use bellperson::gadgets::num;
use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use ff::Field;
use generic_array::typenum::{Unsigned, U0};
use neptune::circuit::poseidon_hash;
use paired::bls12_381::{Bls12, Fr};
use rayon::prelude::*;

use storage_proofs_core::{
    compound_proof::CircuitComponent,
    error::Result,
    gadgets::constraint,
    gadgets::por::{AuthPath, PoRCircuit},
    gadgets::variables::Root,
    hasher::types::POSEIDON_CONSTANTS_15_BASE,
    hasher::{HashFunction, Hasher},
    merkle::{MerkleProofTrait, MerkleTreeTrait, MerkleTreeWrapper},
    por, settings,
    util::NODE_SIZE,
};

use super::vanilla::{PublicParams, PublicSector, SectorProof};

/// This is the `NseWindowPoSt` circuit.
pub struct NseWindowPoStCircuit<Tree: MerkleTreeTrait> {
    pub prover_id: Option<Fr>,
    pub sectors: Vec<Sector<Tree>>,
}

#[derive(Clone)]
pub struct Sector<Tree: MerkleTreeTrait> {
    pub comm_r: Option<Fr>,
    pub comm_replica: Option<Fr>,
    pub comm_layers: Vec<Option<Fr>>,
    pub windows: Vec<Window<Tree>>,
    pub id: Option<Fr>,
}

pub struct Window<Tree: MerkleTreeTrait> {
    pub root: Option<Fr>,
    pub leafs: Vec<Option<Fr>>,
    pub paths: Vec<AuthPath<Tree::Hasher, Tree::Arity, U0, U0>>,
}

impl<Tree: MerkleTreeTrait> Clone for Window<Tree> {
    fn clone(&self) -> Self {
        Window {
            root: self.root.clone(),
            leafs: self.leafs.clone(),
            paths: self.paths.clone(),
        }
    }
}

impl<Tree: 'static + MerkleTreeTrait> Sector<Tree> {
    pub fn circuit(
        sector: &PublicSector<<Tree::Hasher as Hasher>::Domain>,
        vanilla_proof: &SectorProof<Tree::Proof>,
    ) -> Result<Self> {
        let windows = vanilla_proof
            .inclusion_proofs
            .iter()
            .map(|proofs| {
                let root = proofs[0].root();
                let leafs = proofs
                    .iter()
                    .map(MerkleProofTrait::leaf)
                    .map(Into::into)
                    .map(Some)
                    .collect();
                let paths = proofs
                    .iter()
                    .map(MerkleProofTrait::as_options)
                    .map(Into::into)
                    .collect();

                Window {
                    root: Some(root.into()),
                    leafs,
                    paths,
                }
            })
            .collect();

        Ok(Sector {
            id: Some(sector.id.into()),
            comm_r: Some(sector.comm_r.into()),
            comm_replica: Some(vanilla_proof.comm_replica.into()),
            comm_layers: vanilla_proof
                .comm_layers
                .iter()
                .map(|c| Some((*c).into()))
                .collect(),
            windows,
        })
    }

    pub fn blank_circuit(pub_params: &PublicParams) -> Self {
        let windows = vec![Window::blank_circuit(pub_params); pub_params.num_windows()];
        let comm_layers = vec![None; pub_params.num_layers - 1];

        Sector {
            id: None,
            windows,
            comm_r: None,
            comm_replica: None,
            comm_layers,
        }
    }
}

impl<Tree: MerkleTreeTrait> Window<Tree> {
    pub fn blank_circuit(pub_params: &PublicParams) -> Self {
        let challenges_count = pub_params.window_challenge_count;
        let leaves = pub_params.sector_size as usize / NODE_SIZE;

        let por_params = por::PublicParams {
            leaves,
            private: true,
        };
        let leafs = vec![None; challenges_count];
        let paths = vec![AuthPath::blank(por_params.leaves); challenges_count];

        Window {
            root: None,
            leafs,
            paths,
        }
    }
}

impl<Tree: 'static + MerkleTreeTrait> Window<Tree> {
    pub fn synthesize<CS: ConstraintSystem<Bls12>>(
        &self,
        mut cs: CS,
        root_num: &num::AllocatedNum<Bls12>,
    ) -> Result<(), SynthesisError> {
        let Window { leafs, paths, .. } = self;

        assert_eq!(
            paths.len(),
            leafs.len(),
            "inconsistent number of leafs and paths"
        );

        // Verify Inclusion Paths
        for (i, (leaf, path)) in leafs.iter().zip(paths.iter()).enumerate() {
            PoRCircuit::<MerkleTreeWrapper<Tree::Hasher, Tree::Store, Tree::Arity, U0, U0>>::synthesize(
                cs.namespace(|| format!("challenge_inclusion_{}", i)),
                Root::Val(*leaf),
                path.clone(),
                Root::from_allocated::<CS>(root_num.clone()),
                true,
            )?;
        }

        Ok(())
    }
}

impl<Tree: 'static + MerkleTreeTrait> Circuit<Bls12> for &Sector<Tree> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let Sector {
            comm_r,
            comm_layers,
            comm_replica,
            windows,
            ..
        } = self;

        // 1. Verify comm_r = H(comm_layer_0 | ..)

        // Allocate comm_r
        let comm_r_num = num::AllocatedNum::alloc(cs.namespace(|| "comm_r"), || {
            comm_r
                .map(Into::into)
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        comm_r_num.inputize(cs.namespace(|| "comm_r_input"))?;

        // Allocate comm_layers
        let mut comm_layers_nums = Vec::with_capacity(comm_layers.len());
        for (layer_index, comm_layer) in comm_layers.iter().enumerate() {
            let mut cs = cs.namespace(|| format!("layer_{}", layer_index));
            let comm_layer_num = num::AllocatedNum::alloc(cs.namespace(|| "comm_layer"), || {
                comm_layer
                    .map(Into::into)
                    .ok_or_else(|| SynthesisError::AssignmentMissing)
            })?;

            comm_layer_num.inputize(cs.namespace(|| "comm_layer_input"))?;
            comm_layers_nums.push(comm_layer_num);
        }

        // Allocate comm_replica
        let comm_replica_num = num::AllocatedNum::alloc(cs.namespace(|| "comm_replica"), || {
            comm_replica
                .map(Into::into)
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        comm_replica_num.inputize(cs.namespace(|| "comm_replica_input"))?;

        // comm_layers only includes the layers that are not the replica, so need to add it here.
        comm_layers_nums.push(comm_replica_num.clone());

        // Verify equality
        {
            let c = POSEIDON_CONSTANTS_15_BASE.with_length(comm_layers_nums.len());
            let hash_num = poseidon_hash(
                &mut cs.namespace(|| "comm_layers_hash"),
                comm_layers_nums.clone(),
                &c,
            )?;
            constraint::equal(
                cs,
                || "enforce comm_r = H(comm_layers)",
                &comm_r_num,
                &hash_num,
            );
        }

        // 2. Verify comm_replica = Root(MerkleTree(comm_window_0 | ..))

        // Allocate window roots
        let mut window_roots = Vec::with_capacity(windows.len());
        for (window_index, window) in windows.iter().enumerate() {
            let mut cs = cs.namespace(|| format!("win_{}", window_index));
            let window_root_num = num::AllocatedNum::alloc(cs.namespace(|| "window_root"), || {
                window
                    .root
                    .map(Into::into)
                    .ok_or_else(|| SynthesisError::AssignmentMissing)
            })?;

            window_roots.push(window_root_num);
        }

        // Construct Top MerkleTree

        let mut hashes = window_roots.clone();
        let mut height = 0;
        while hashes.len() != 1 {
            let mut new_hashes = Vec::new();
            for (j, chunk) in window_roots
                .chunks_exact(Tree::SubTreeArity::to_usize())
                .enumerate()
            {
                let hash = <Tree::Hasher as Hasher>::Function::hash_multi_leaf_circuit::<
                    Tree::SubTreeArity,
                    _,
                >(
                    cs.namespace(|| format!("hash_multi_leaf_{}_{}", height, j)),
                    chunk,
                    height,
                )?;
                new_hashes.push(hash);
            }
            hashes = new_hashes;
            height += 1;
        }

        // Compare comm_replica with constructed version.
        constraint::equal(
            cs,
            || "enforce top merkletree",
            &hashes[0],
            &comm_replica_num,
        );

        // 3. Verify windows
        for (window_index, window) in windows.iter().enumerate() {
            window.synthesize(
                cs.namespace(|| format!("window_proof_{}", window_index)),
                &window_roots[window_index],
            )?;
        }

        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct ComponentPrivateInputs {}

impl<Tree: MerkleTreeTrait> CircuitComponent for NseWindowPoStCircuit<Tree> {
    type ComponentPrivateInputs = ComponentPrivateInputs;
}

impl<Tree: 'static + MerkleTreeTrait> Circuit<Bls12> for NseWindowPoStCircuit<Tree> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        if CS::is_extensible() {
            return self.synthesize_extendable(cs);
        }

        self.synthesize_default(cs)
    }
}

impl<Tree: 'static + MerkleTreeTrait> NseWindowPoStCircuit<Tree> {
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
        let NseWindowPoStCircuit { sectors, .. } = self;

        let num_chunks = settings::SETTINGS
            .lock()
            .unwrap()
            .window_post_synthesis_num_cpus as usize;

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
    use generic_array::typenum::{U0, U4, U8};
    use paired::bls12_381::{Bls12, Fr};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::{
        compound_proof::CompoundProof,
        hasher::{Domain, Hasher, PoseidonHasher},
        merkle::{generate_tree, get_base_tree_count, LCTree, MerkleTreeTrait},
        proof::ProofScheme,
        util::NODE_SIZE,
    };

    use crate::nse_window::{
        self, NseWindowPoSt, NseWindowPoStCompound, PrivateInputs, PrivateSector, PublicInputs,
        PublicSector,
    };
    use storage_proofs_porep::nse::vanilla::hash_comm_r;

    #[test]
    fn nse_window_post_poseidon_single_partition_matching_sub_8_4() {
        nse_window_post::<LCTree<PoseidonHasher, U8, U4, U0>>(3, 3, 1, 40, 28_830);
    }

    #[test]
    fn nse_window_post_poseidon_single_partition_smaller_sub_8_4() {
        nse_window_post::<LCTree<PoseidonHasher, U8, U4, U0>>(2, 3, 1, 40, 28_830);
    }

    #[test]
    fn nse_window_post_poseidon_two_partitions_matching_sub_8_4() {
        nse_window_post::<LCTree<PoseidonHasher, U8, U4, U0>>(4, 2, 2, 27, 19_220);
    }

    #[test]
    fn nse_window_post_poseidon_two_partitions_smaller_sub_8_4() {
        nse_window_post::<LCTree<PoseidonHasher, U8, U4, U0>>(5, 3, 2, 40, 28_830);
    }

    #[test]
    #[ignore]
    fn metric_nse_window_post_circuit_poseidon() {
        use bellperson::util_cs::bench_cs::BenchCS;
        let params = nse_window::SetupParams {
            sector_size: 1024 * 1024 * 1024 * 1024,
            window_size: 1024 * 1024 * 1024 * 4,
            window_challenge_count: 2,
            sector_count: 1,
            num_layers: 15,
        };

        let pp = NseWindowPoSt::<LCTree<PoseidonHasher, U8, U4, U0>>::setup(&params).unwrap();

        let mut cs = BenchCS::<Bls12>::new();
        NseWindowPoStCompound::<LCTree<PoseidonHasher, U8, U4, U0>>::blank_circuit(&pp)
            .synthesize(&mut cs)
            .unwrap();

        assert_eq!(cs.num_constraints(), 266_665);
    }

    fn nse_window_post<Tree: 'static + MerkleTreeTrait>(
        total_sector_count: usize,
        sector_count: usize,
        partitions: usize,
        expected_num_inputs: usize,
        expected_constraints: usize,
    ) where
        Tree::Store: 'static,
    {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let window_leaves = 64;
        let num_windows = get_base_tree_count::<Tree>();
        let leaves = num_windows * window_leaves;
        let sector_size = leaves * NODE_SIZE;
        let num_layers = 4;

        let randomness = <Tree::Hasher as Hasher>::Domain::random(rng);
        let prover_id = <Tree::Hasher as Hasher>::Domain::random(rng);

        let pub_params = nse_window::PublicParams {
            sector_size: sector_size as u64,
            window_size: window_leaves as u64 * NODE_SIZE as u64,
            window_challenge_count: 2,
            sector_count,
            num_layers,
        };

        // Construct and store an MT using a named DiskStore.
        let temp_dir = tempfile::tempdir().unwrap();
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
            let comm_layers: Vec<_> = (0..pub_params.num_layers - 1)
                .map(|_| <Tree::Hasher as Hasher>::Domain::random(rng))
                .collect();
            let comm_replica = tree.root();
            let comm_r: <Tree::Hasher as Hasher>::Domain =
                hash_comm_r(&comm_layers[..], comm_replica).into();

            priv_sectors.push(PrivateSector { tree });
            pub_sectors.push(PublicSector {
                id: (i as u64).into(),
                comm_r,
                comm_layers,
                comm_replica,
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

        let proofs = NseWindowPoSt::<Tree>::prove_all_partitions(
            &pub_params,
            &pub_inputs,
            &priv_inputs,
            partitions,
        )
        .expect("proving failed");
        assert_eq!(proofs.len(), partitions, "wrong number of proofs");

        let is_valid =
            NseWindowPoSt::<Tree>::verify_all_partitions(&pub_params, &pub_inputs, &proofs)
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
                .unwrap();

            let mut cs = TestConstraintSystem::<Bls12>::new();

            let instance = NseWindowPoStCircuit::<Tree> {
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

            let generated_inputs = NseWindowPoStCompound::<Tree>::generate_public_inputs(
                &pub_inputs,
                &pub_params,
                Some(j),
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

            assert!(
                cs.verify(&generated_inputs),
                "verification failed with TestContraintSystem and generated inputs"
            );
        }
    }
}
