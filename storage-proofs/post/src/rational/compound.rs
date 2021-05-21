use std::marker::PhantomData;

use anyhow::ensure;
use bellperson::bls::{Bls12, Fr};
use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use generic_array::typenum;

use storage_proofs_core::{
    compound_proof::{CircuitComponent, CompoundProof},
    drgraph,
    error::Result,
    gadgets::por::PoRCompound,
    merkle::MerkleTreeTrait,
    parameter_cache::{CacheableParameters, ParameterSetMetadata},
    por,
    proof::ProofScheme,
    util::NODE_SIZE,
};

use super::{RationalPoSt, RationalPoStCircuit};

pub struct RationalPoStCompound<Tree>
where
    Tree: MerkleTreeTrait,
{
    _t: PhantomData<Tree>,
}

impl<C: Circuit<Bls12>, P: ParameterSetMetadata, Tree: MerkleTreeTrait> CacheableParameters<C, P>
    for RationalPoStCompound<Tree>
{
    fn cache_prefix() -> String {
        format!("proof-of-spacetime-rational-{}", Tree::display())
    }
}

impl<'a, Tree: 'static + MerkleTreeTrait>
    CompoundProof<'a, RationalPoSt<'a, Tree>, RationalPoStCircuit<Tree>>
    for RationalPoStCompound<Tree>
where
    Tree: 'static + MerkleTreeTrait,
{
    fn generate_public_inputs(
        pub_in: &<RationalPoSt<'a, Tree> as ProofScheme<'a>>::PublicInputs,
        pub_params: &<RationalPoSt<'a, Tree> as ProofScheme<'a>>::PublicParams,
        _partition_k: Option<usize>,
    ) -> Result<Vec<Fr>> {
        let mut inputs = Vec::new();

        let por_pub_params = por::PublicParams {
            leaves: (pub_params.sector_size as usize / NODE_SIZE),
            private: true,
        };

        ensure!(
            pub_in.challenges.len() == pub_in.comm_rs.len(),
            "Missmatch in challenges and comm_rs"
        );

        for (challenge, comm_r) in pub_in.challenges.iter().zip(pub_in.comm_rs.iter()) {
            inputs.push((*comm_r).into());

            let por_pub_inputs = por::PublicInputs {
                commitment: None,
                challenge: challenge.leaf as usize,
            };
            let por_inputs = PoRCompound::<Tree>::generate_public_inputs(
                &por_pub_inputs,
                &por_pub_params,
                None,
            )?;

            inputs.extend(por_inputs);
        }

        Ok(inputs)
    }

    fn circuit(
        pub_in: &<RationalPoSt<'a, Tree> as ProofScheme<'a>>::PublicInputs,
        _priv_in: <RationalPoStCircuit<Tree> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &<RationalPoSt<'a, Tree> as ProofScheme<'a>>::Proof,
        _pub_params: &<RationalPoSt<'a, Tree> as ProofScheme<'a>>::PublicParams,
        _partition_k: Option<usize>,
    ) -> Result<RationalPoStCircuit<Tree>> {
        let comm_rs: Vec<_> = pub_in.comm_rs.iter().map(|c| Some((*c).into())).collect();
        let comm_cs: Vec<_> = vanilla_proof
            .comm_cs
            .iter()
            .map(|c| Some((*c).into()))
            .collect();

        let comm_r_lasts: Vec<_> = vanilla_proof
            .commitments()
            .into_iter()
            .map(|c| Some(c.into()))
            .collect();

        let leafs: Vec<_> = vanilla_proof
            .leafs()
            .iter()
            .map(|c| Some((*c).into()))
            .collect();

        let paths: Vec<Vec<_>> = vanilla_proof
            .paths()
            .iter()
            .map(|v| {
                v.iter()
                    .map(|p| {
                        (
                            (*p).0.iter().copied().map(Into::into).map(Some).collect(),
                            Some(p.1),
                        )
                    })
                    .collect()
            })
            .collect();

        Ok(RationalPoStCircuit {
            leafs,
            comm_rs,
            comm_cs,
            comm_r_lasts,
            paths,
            _t: PhantomData,
        })
    }

    fn blank_circuit(
        pub_params: &<RationalPoSt<'a, Tree> as ProofScheme<'a>>::PublicParams,
    ) -> RationalPoStCircuit<Tree> {
        let challenges_count = pub_params.challenges_count;
        let height =
            drgraph::graph_height::<typenum::U2>(pub_params.sector_size as usize / NODE_SIZE);

        let comm_rs = vec![None; challenges_count];
        let comm_cs = vec![None; challenges_count];
        let comm_r_lasts = vec![None; challenges_count];
        let leafs = vec![None; challenges_count];
        let paths = vec![vec![(vec![None; 1], None); height - 1]; challenges_count];

        RationalPoStCircuit {
            comm_rs,
            comm_cs,
            comm_r_lasts,
            leafs,
            paths,
            _t: PhantomData,
        }
    }
}

impl<'a, Tree: 'static + MerkleTreeTrait> RationalPoStCircuit<Tree> {
    #[allow(clippy::type_complexity)]
    pub fn synthesize<CS: ConstraintSystem<Bls12>>(
        cs: &mut CS,
        leafs: Vec<Option<Fr>>,
        comm_rs: Vec<Option<Fr>>,
        comm_cs: Vec<Option<Fr>>,
        comm_r_lasts: Vec<Option<Fr>>,
        paths: Vec<Vec<(Vec<Option<Fr>>, Option<usize>)>>,
    ) -> Result<(), SynthesisError> {
        Self {
            leafs,
            comm_rs,
            comm_cs,
            comm_r_lasts,
            paths,
            _t: PhantomData,
        }
        .synthesize(cs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::{
        compound_proof,
        hasher::{Domain, HashFunction, Hasher, PoseidonHasher},
        merkle::{generate_tree, get_base_tree_count, BinaryMerkleTree},
        proof::NoRequirements,
        sector::OrderedSectorSet,
    };

    use crate::rational::{self, derive_challenges};

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn rational_post_test_compound_poseidon() {
        rational_post_test_compound::<BinaryMerkleTree<PoseidonHasher>>();
    }

    fn rational_post_test_compound<Tree: 'static + MerkleTreeTrait>() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 32 * get_base_tree_count::<Tree>();
        let sector_size = (leaves * NODE_SIZE) as u64;
        let challenges_count = 2;

        let setup_params = compound_proof::SetupParams {
            vanilla_params: rational::SetupParams {
                sector_size,
                challenges_count,
            },
            partitions: None,
            priority: true,
        };

        let pub_params = RationalPoStCompound::<Tree>::setup(&setup_params).expect("setup failed");

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
            comm_r_lasts: &comm_r_lasts,
            comm_cs: &comm_cs,
        };

        let gparams =
            RationalPoStCompound::<Tree>::groth_params(Some(rng), &pub_params.vanilla_params)
                .expect("failed to create groth params");

        let proof =
            RationalPoStCompound::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs, &gparams)
                .expect("proving failed");

        let (circuit, inputs) =
            RationalPoStCompound::<Tree>::circuit_for_test(&pub_params, &pub_inputs, &priv_inputs)
                .unwrap();

        {
            let mut cs = TestConstraintSystem::new();

            circuit.synthesize(&mut cs).expect("failed to synthesize");
            assert!(cs.is_satisfied());
            assert!(cs.verify(&inputs));
        }

        let verified =
            RationalPoStCompound::<Tree>::verify(&pub_params, &pub_inputs, &proof, &NoRequirements)
                .expect("failed while verifying");

        assert!(verified);
    }
}
