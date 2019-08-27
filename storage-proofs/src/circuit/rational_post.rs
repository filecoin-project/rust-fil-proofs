use std::marker::PhantomData;

use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use fil_sapling_crypto::jubjub::JubjubEngine;
use paired::bls12_381::{Bls12, Fr};

use crate::circuit::por::{PoRCircuit, PoRCompound};
use crate::circuit::variables::Root;
use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::drgraph;
use crate::hasher::Hasher;
use crate::merklepor;
use crate::parameter_cache::{CacheableParameters, ParameterSetMetadata};
use crate::proof::ProofScheme;
use crate::rational_post::RationalPoSt;
use crate::util::NODE_SIZE;

/// This is the `RationalPoSt` circuit.
pub struct RationalPoStCircuit<'a, E: JubjubEngine, H: Hasher> {
    /// Paramters for the engine.
    pub params: &'a E::Params,
    pub commitments: Vec<Option<E::Fr>>,
    pub leafs: Vec<Option<E::Fr>>,
    #[allow(clippy::type_complexity)]
    pub paths: Vec<Vec<Option<(E::Fr, bool)>>>,
    _h: PhantomData<H>,
}

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
        String::from("proof-of-spacetime-rational")
    }
}

#[derive(Clone, Default)]
pub struct ComponentPrivateInputs {}

impl<'a, E: JubjubEngine, H: Hasher> CircuitComponent for RationalPoStCircuit<'a, E, H> {
    type ComponentPrivateInputs = ComponentPrivateInputs;
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
    ) -> Vec<Fr> {
        let mut inputs = Vec::new();

        let por_pub_params = merklepor::PublicParams {
            leaves: (pub_params.sector_size as usize / NODE_SIZE),
            private: false,
        };

        assert_eq!(
            pub_in.challenges.len(),
            pub_in.commitments.len(),
            "Missmatch in challenges and commitments"
        );

        for (challenge, commitment) in pub_in.challenges.iter().zip(pub_in.commitments) {
            let por_pub_inputs = merklepor::PublicInputs {
                commitment: Some(*commitment),
                challenge: challenge.leaf as usize,
            };
            let por_inputs =
                PoRCompound::<H>::generate_public_inputs(&por_pub_inputs, &por_pub_params, None);

            inputs.extend(por_inputs);
        }

        inputs
    }

    fn circuit(
        pub_in: &<RationalPoSt<'a, H> as ProofScheme<'a>>::PublicInputs,
        _component_private_inputs: <RationalPoStCircuit<'a, Bls12, H> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &<RationalPoSt<'a, H> as ProofScheme<'a>>::Proof,
        _pub_params: &<RationalPoSt<'a, H> as ProofScheme<'a>>::PublicParams,
        engine_params: &'a <Bls12 as JubjubEngine>::Params,
    ) -> RationalPoStCircuit<'a, Bls12, H> {
        let commitments: Vec<_> = pub_in
            .commitments
            .iter()
            .map(|c| Some((*c).into()))
            .collect();

        let leafs: Vec<_> = vanilla_proof
            .leafs()
            .iter()
            .map(|c| Some((**c).into()))
            .collect();

        let paths: Vec<Vec<_>> = vanilla_proof
            .paths()
            .iter()
            .map(|v| v.iter().map(|p| Some(((*p).0.into(), p.1))).collect())
            .collect();

        RationalPoStCircuit {
            params: engine_params,
            leafs,
            commitments,
            paths,
            _h: PhantomData,
        }
    }

    fn blank_circuit(
        pub_params: &<RationalPoSt<'a, H> as ProofScheme<'a>>::PublicParams,
        params: &'a <Bls12 as JubjubEngine>::Params,
    ) -> RationalPoStCircuit<'a, Bls12, H> {
        let challenges_count = pub_params.challenges_count;
        let height = drgraph::graph_height(pub_params.sector_size as usize / NODE_SIZE);

        let commitments = vec![None; challenges_count];
        let leafs = vec![None; challenges_count];
        let paths = vec![vec![None; height]; challenges_count];

        RationalPoStCircuit {
            params,
            commitments,
            leafs,
            paths,
            _h: PhantomData,
        }
    }
}

impl<'a, E: JubjubEngine, H: Hasher> Circuit<E> for RationalPoStCircuit<'a, E, H> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let params = self.params;
        let commitments = self.commitments;
        let leafs = self.leafs;
        let paths = self.paths;

        assert_eq!(paths.len(), leafs.len());
        assert_eq!(paths.len(), commitments.len());

        for (i, commitment) in commitments.iter().enumerate() {
            PoRCircuit::<_, H>::synthesize(
                cs.namespace(|| format!("challenge_inclusion{}", i)),
                &params,
                leafs[i],
                paths[i].clone(),
                Root::Val(*commitment),
                false,
            )?;
        }

        Ok(())
    }
}

impl<'a, E: JubjubEngine, H: Hasher> RationalPoStCircuit<'a, E, H> {
    #[allow(clippy::type_complexity)]
    pub fn synthesize<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        params: &'a E::Params,
        leafs: Vec<Option<E::Fr>>,
        commitments: Vec<Option<E::Fr>>,
        paths: Vec<Vec<Option<(E::Fr, bool)>>>,
    ) -> Result<(), SynthesisError> {
        Self {
            params,
            leafs,
            commitments,
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
    use fil_sapling_crypto::jubjub::JubjubBls12;
    use rand::{Rng, SeedableRng, XorShiftRng};

    use crate::circuit::test::*;
    use crate::compound_proof;
    use crate::drgraph::{new_seed, BucketGraph, Graph};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::pedersen::*;
    use crate::proof::{NoRequirements, ProofScheme};
    use crate::rational_post::{self, derive_challenges, RationalPoSt};
    use crate::sector::OrderedSectorSet;

    #[test]
    fn test_rational_post_circuit_with_bls12_381() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let leaves = 32;
        let sector_size = leaves * 32;
        let challenges_count = 2;

        let pub_params = rational_post::PublicParams {
            sector_size,
            challenges_count,
        };

        let data1: Vec<u8> = (0..32)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        let data2: Vec<u8> = (0..32)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let graph1 = BucketGraph::<PedersenHasher>::new(32, 5, 0, new_seed());
        let tree1 = graph1.merkle_tree(data1.as_slice()).unwrap();

        let graph2 = BucketGraph::<PedersenHasher>::new(32, 5, 0, new_seed());
        let tree2 = graph2.merkle_tree(data2.as_slice()).unwrap();

        let faults = OrderedSectorSet::new();
        let mut sectors = OrderedSectorSet::new();
        sectors.insert(0.into());
        sectors.insert(1.into());

        let seed = (0..32).map(|_| rng.gen()).collect::<Vec<u8>>();
        let challenges =
            derive_challenges(challenges_count, sector_size, &sectors, &seed, &faults).unwrap();
        let commitments_raw = vec![tree1.root(), tree2.root()];
        let commitments: Vec<_> = challenges
            .iter()
            .map(|c| commitments_raw[u64::from(c.sector) as usize])
            .collect();

        let pub_inputs = rational_post::PublicInputs {
            challenges: &challenges,
            faults: &faults,
            commitments: &commitments,
        };

        let mut trees = BTreeMap::new();
        trees.insert(0.into(), &tree1);
        trees.insert(1.into(), &tree2);

        let priv_inputs = rational_post::PrivateInputs::<PedersenHasher> { trees: &trees };

        let proof = RationalPoSt::<PedersenHasher>::prove(&pub_params, &pub_inputs, &priv_inputs)
            .expect("proving failed");

        let is_valid = RationalPoSt::<PedersenHasher>::verify(&pub_params, &pub_inputs, &proof)
            .expect("verification failed");
        assert!(is_valid);

        // actual circuit test

        let paths: Vec<_> = proof
            .paths()
            .iter()
            .map(|p| {
                p.iter()
                    .map(|v| Some((v.0.into(), v.1)))
                    .collect::<Vec<_>>()
            })
            .collect();
        let leafs: Vec<_> = proof.leafs().iter().map(|l| Some((**l).into())).collect();

        let mut cs = TestConstraintSystem::<Bls12>::new();

        let instance = RationalPoStCircuit::<_, PedersenHasher> {
            params,
            leafs,
            paths,
            commitments: commitments.into_iter().map(|c| Some(c.into())).collect(),
            _h: PhantomData,
        };

        instance
            .synthesize(&mut cs)
            .expect("failed to synthesize circuit");

        assert!(cs.is_satisfied(), "constraints not satisfied");

        assert_eq!(cs.num_inputs(), 5, "wrong number of inputs");
        assert_eq!(cs.num_constraints(), 13746, "wrong number of constraints");
        assert_eq!(cs.get_input(0, "ONE"), Fr::one());
    }

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn rational_post_test_compound() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let leaves = 32;
        let sector_size = leaves * 32;
        let challenges_count = 2;

        let setup_params = compound_proof::SetupParams {
            vanilla_params: &rational_post::SetupParams {
                sector_size,
                challenges_count,
            },
            engine_params: params,
            partitions: None,
        };

        let pub_params =
            RationalPoStCompound::<PedersenHasher>::setup(&setup_params).expect("setup failed");

        let data1: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        let data2: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let graph1 = BucketGraph::<PedersenHasher>::new(32, 5, 0, new_seed());
        let tree1 = graph1.merkle_tree(data1.as_slice()).unwrap();

        let graph2 = BucketGraph::<PedersenHasher>::new(32, 5, 0, new_seed());
        let tree2 = graph2.merkle_tree(data2.as_slice()).unwrap();

        let faults = OrderedSectorSet::new();
        let mut sectors = OrderedSectorSet::new();
        sectors.insert(0.into());
        sectors.insert(1.into());

        let seed = (0..32).map(|_| rng.gen()).collect::<Vec<u8>>();
        let challenges =
            derive_challenges(challenges_count, sector_size, &sectors, &seed, &faults).unwrap();
        let commitments_raw = vec![tree1.root(), tree2.root()];
        let commitments: Vec<_> = challenges
            .iter()
            .map(|c| commitments_raw[u64::from(c.sector) as usize].into())
            .collect();

        let pub_inputs = rational_post::PublicInputs {
            challenges: &challenges,
            faults: &faults,
            commitments: &commitments,
        };

        let mut trees = BTreeMap::new();
        trees.insert(0.into(), &tree1);
        trees.insert(1.into(), &tree2);

        let priv_inputs = rational_post::PrivateInputs::<PedersenHasher> { trees: &trees };

        let gparams = RationalPoStCompound::<PedersenHasher>::groth_params(
            &pub_params.vanilla_params,
            &params,
        )
        .expect("failed to create groth params");

        let proof = RationalPoStCompound::<PedersenHasher>::prove(
            &pub_params,
            &pub_inputs,
            &priv_inputs,
            &gparams,
        )
        .expect("proving failed");

        let (circuit, inputs) = RationalPoStCompound::<PedersenHasher>::circuit_for_test(
            &pub_params,
            &pub_inputs,
            &priv_inputs,
        );

        {
            let mut cs = TestConstraintSystem::new();

            circuit.synthesize(&mut cs).expect("failed to synthesize");
            assert!(cs.is_satisfied());
            assert!(cs.verify(&inputs));
        }

        let verified = RationalPoStCompound::<PedersenHasher>::verify(
            &pub_params,
            &pub_inputs,
            &proof,
            &NoRequirements,
        )
        .expect("failed while verifying");

        assert!(verified);
    }
}
