use std::marker::PhantomData;

use anyhow::ensure;
use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use fil_sapling_crypto::jubjub::JubjubEngine;
use generic_array::typenum;
use paired::bls12_381::{Bls12, Fr};

use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::crypto::pedersen::JJ_PARAMS;
use crate::drgraph;
use crate::error::Result;
use crate::gadgets::por::PoRCompound;
use crate::hasher::{Hasher, PoseidonArity, PoseidonEngine};
use crate::parameter_cache::{CacheableParameters, ParameterSetMetadata};
use crate::por;
use crate::post::rational::{RationalPoSt, RationalPoStCircuit};
use crate::proof::ProofScheme;
use crate::util::NODE_SIZE;

pub struct RationalPoStCompound<H>
where
    H: Hasher,
{
    _h: PhantomData<H>,
}

impl<E: JubjubEngine, C: Circuit<E>, P: ParameterSetMetadata, H: Hasher>
    CacheableParameters<E, C, P> for RationalPoStCompound<H>
{
    fn cache_prefix() -> String {
        format!("proof-of-spacetime-rational-{}", H::name())
    }
}

impl<'a, H> CompoundProof<'a, Bls12, RationalPoSt<'a, H>, RationalPoStCircuit<'a, Bls12, H>>
    for RationalPoStCompound<H>
where
    H: 'a + Hasher,
{
    fn generate_public_inputs(
        pub_in: &<RationalPoSt<'a, H> as ProofScheme<'a>>::PublicInputs,
        pub_params: &<RationalPoSt<'a, H> as ProofScheme<'a>>::PublicParams,
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
            let por_inputs = PoRCompound::<H, typenum::U2>::generate_public_inputs(
                &por_pub_inputs,
                &por_pub_params,
                None,
            )?;

            inputs.extend(por_inputs);
        }

        Ok(inputs)
    }

    fn circuit(
        pub_in: &<RationalPoSt<'a, H> as ProofScheme<'a>>::PublicInputs,
        _priv_in: <RationalPoStCircuit<'a, Bls12, H> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &<RationalPoSt<'a, H> as ProofScheme<'a>>::Proof,
        _pub_params: &<RationalPoSt<'a, H> as ProofScheme<'a>>::PublicParams,
    ) -> Result<RationalPoStCircuit<'a, Bls12, H>> {
        let comm_rs: Vec<_> = pub_in.comm_rs.iter().map(|c| Some((*c).into())).collect();
        let comm_cs: Vec<_> = vanilla_proof
            .comm_cs
            .iter()
            .map(|c| Some((*c).into()))
            .collect();

        let comm_r_lasts: Vec<_> = vanilla_proof
            .commitments()
            .into_iter()
            .map(|c| Some((*c).into()))
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
            params: &*JJ_PARAMS,
            leafs,
            comm_rs,
            comm_cs,
            comm_r_lasts,
            paths,
            _h: PhantomData,
        })
    }

    fn blank_circuit(
        pub_params: &<RationalPoSt<'a, H> as ProofScheme<'a>>::PublicParams,
    ) -> RationalPoStCircuit<'a, Bls12, H> {
        let challenges_count = pub_params.challenges_count;
        let height =
            drgraph::graph_height::<typenum::U2>(pub_params.sector_size as usize / NODE_SIZE);

        let comm_rs = vec![None; challenges_count];
        let comm_cs = vec![None; challenges_count];
        let comm_r_lasts = vec![None; challenges_count];
        let leafs = vec![None; challenges_count];
        let paths = vec![vec![(vec![None; 1], None); height - 1]; challenges_count];

        RationalPoStCircuit {
            params: &*JJ_PARAMS,
            comm_rs,
            comm_cs,
            comm_r_lasts,
            leafs,
            paths,
            _h: PhantomData,
        }
    }
}

impl<'a, E: JubjubEngine + PoseidonEngine<typenum::U2>, H: Hasher> RationalPoStCircuit<'a, E, H>
where
    typenum::U2: PoseidonArity<E>,
{
    #[allow(clippy::type_complexity)]
    pub fn synthesize<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        params: &'a E::Params,
        leafs: Vec<Option<E::Fr>>,
        comm_rs: Vec<Option<E::Fr>>,
        comm_cs: Vec<Option<E::Fr>>,
        comm_r_lasts: Vec<Option<E::Fr>>,
        paths: Vec<Vec<(Vec<Option<E::Fr>>, Option<usize>)>>,
    ) -> Result<(), SynthesisError> {
        Self {
            params,
            leafs,
            comm_rs,
            comm_cs,
            comm_r_lasts,
            paths,
            _h: PhantomData,
        }
        .synthesize(cs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use ff::Field;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    use crate::compound_proof;
    use crate::drgraph::{new_seed, BucketGraph, Graph, BASE_DEGREE};
    use crate::fr32::fr_into_bytes;
    use crate::gadgets::TestConstraintSystem;
    use crate::hasher::{Domain, HashFunction, Hasher, PedersenHasher, PoseidonHasher};
    use crate::post::rational::{self, derive_challenges};
    use crate::proof::NoRequirements;
    use crate::sector::OrderedSectorSet;

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn rational_post_test_compound_pedersen() {
        rational_post_test_compound::<PedersenHasher>();
    }

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn rational_post_test_compound_poseidon() {
        rational_post_test_compound::<PoseidonHasher>();
    }

    fn rational_post_test_compound<H: Hasher>() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 32;
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

        let pub_params = RationalPoStCompound::<H>::setup(&setup_params).expect("setup failed");

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
            comm_r_lasts: &comm_r_lasts,
            comm_cs: &comm_cs,
        };

        let gparams =
            RationalPoStCompound::<H>::groth_params(Some(rng), &pub_params.vanilla_params)
                .expect("failed to create groth params");

        let proof =
            RationalPoStCompound::<H>::prove(&pub_params, &pub_inputs, &priv_inputs, &gparams)
                .expect("proving failed");

        let (circuit, inputs) =
            RationalPoStCompound::<H>::circuit_for_test(&pub_params, &pub_inputs, &priv_inputs)
                .unwrap();

        {
            let mut cs = TestConstraintSystem::new();

            circuit.synthesize(&mut cs).expect("failed to synthesize");
            assert!(cs.is_satisfied());
            assert!(cs.verify(&inputs));
        }

        let verified =
            RationalPoStCompound::<H>::verify(&pub_params, &pub_inputs, &proof, &NoRequirements)
                .expect("failed while verifying");

        assert!(verified);
    }
}
