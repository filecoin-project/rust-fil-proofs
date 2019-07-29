use std::marker::PhantomData;

use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use ff::Field;
use fil_sapling_crypto::circuit::boolean::Boolean;
use fil_sapling_crypto::circuit::num::{AllocatedNum, Num};
use fil_sapling_crypto::circuit::{boolean, num, pedersen_hash};
use fil_sapling_crypto::jubjub::JubjubEngine;
use paired::bls12_381::{Bls12, Fr};
use paired::Engine;

use crate::circuit::constraint;
use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::drgraph;
use crate::fr32::u32_into_fr;
use crate::hasher::Hasher;
use crate::parameter_cache::{CacheableParameters, ParameterSetMetadata};
use crate::rational_post::RationalPoSt;
use crate::proof::ProofScheme;
use crate::circuit::porc::pack_into_allocated_num;


/// This is the `RationalPoSt` circuit.
pub struct RationalPoStCircuit<'a, E: JubjubEngine> {
    /// Paramters for the engine.
    pub params: &'a E::Params,
    pub commitments: Vec<Option<E::Fr>>,
    pub leafs: Vec<Option<E::Fr>>,
    #[allow(clippy::type_complexity)]
    pub paths: Vec<Vec<Option<(E::Fr, bool)>>>,
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

impl<'a, E: JubjubEngine> CircuitComponent for RationalPoStCircuit<'a, E> {
    type ComponentPrivateInputs = ComponentPrivateInputs;
}

impl<'a, H> CompoundProof<'a, Bls12, RationalPoSt<'a, H>, RationalPoStCircuit<'a, Bls12>> for RationalPoStCompound<H>
where
    H: 'a + Hasher,
{
    fn generate_public_inputs(
        _pub_in: &<RationalPoSt<'a, H> as ProofScheme<'a>>::PublicInputs,
        _pub_params: &<RationalPoSt<'a, H> as ProofScheme<'a>>::PublicParams,
        _partition_k: Option<usize>,
    ) -> Vec<Fr> {
        Vec::new()
    }

    fn circuit(
        pub_in: &<RationalPoSt<'a, H> as ProofScheme<'a>>::PublicInputs,
        _component_private_inputs: <RationalPoStCircuit<'a, Bls12> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &<RationalPoSt<'a, H> as ProofScheme<'a>>::Proof,
        _pub_params: &<RationalPoSt<'a, H> as ProofScheme<'a>>::PublicParams,
        engine_params: &'a <Bls12 as JubjubEngine>::Params,
    ) -> RationalPoStCircuit<'a, Bls12> {
        let commitments: Vec<_> = pub_in
            .commitments
            .iter()
            .map(|c| Some((*c).into()))
            .collect();

        let leafs: Vec<_> = vanilla_proof.leafs()
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
        }
    }

    fn blank_circuit(
        pub_params: &<RationalPoSt<'a, H> as ProofScheme<'a>>::PublicParams,
        params: &'a <Bls12 as JubjubEngine>::Params,
    ) -> RationalPoStCircuit<'a, Bls12> {
        let challenges_count = pub_params.challenges_count;
        let height = drgraph::graph_height(pub_params.sector_size as usize / 32);

        let commitments = vec![None; challenges_count];
        let leafs = vec![None; challenges_count];
        let paths = vec![vec![None; height]; challenges_count];

        RationalPoStCircuit {
            params,
            commitments,
            leafs,
            paths,
        }
    }
}

impl<'a, E: JubjubEngine> Circuit<E> for RationalPoStCircuit<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let params = self.params;
        let commitments = self.commitments;
        let leafs = self.leafs;
        let paths = self.paths;

        assert_eq!(paths.len(), leafs.len());
        assert_eq!(paths.len(), commitments.len());

        for (i, ((commitment, path), leaf)) in commitments.iter().zip(paths).zip(leafs).enumerate() {
            let mut cs = cs.namespace(|| format!("challenge_{}", i));

            // Allocate the commitment
            let rt = num::AllocatedNum::alloc(cs.namespace(|| "commitment_num"), || {
                commitment.ok_or_else(|| SynthesisError::AssignmentMissing)
            })?;

            let leaf_num = num::AllocatedNum::alloc(cs.namespace(|| "leaf_num"), || {
                leaf.ok_or_else(|| SynthesisError::AssignmentMissing)
            })?;

            // This is an injective encoding, as cur is a point in the prime order subgroup.
            let mut cur = leaf_num;

            let mut path_bits = Vec::with_capacity(path.len());

            // Ascend the merkle tree authentication path
            for (i, e) in path.iter().enumerate() {
                let cs = &mut cs.namespace(|| format!("merkle tree hash {}", i));

                // Determines if the current subtree is the "right" leaf at this
                // depth of the tree.
                let cur_is_right = boolean::Boolean::from(boolean::AllocatedBit::alloc(
                    cs.namespace(|| "position bit"),
                    e.map(|e| e.1),
                )?);

                // Witness the authentication path element adjacent
                // at this depth.
                let path_element =
                    num::AllocatedNum::alloc(cs.namespace(|| "path element"), || {
                        Ok(e.ok_or_else(|| SynthesisError::AssignmentMissing)?.0)
                    })?;

                // Swap the two if the current subtree is on the right
                let (xl, xr) = num::AllocatedNum::conditionally_reverse(
                    cs.namespace(|| "conditional reversal of preimage"),
                    &cur,
                    &path_element,
                    &cur_is_right,
                )?;

                let mut preimage = vec![];
                preimage.extend(xl.into_bits_le(cs.namespace(|| "xl into bits"))?);
                preimage.extend(xr.into_bits_le(cs.namespace(|| "xr into bits"))?);

                // Compute the new subtree value
                cur = pedersen_hash::pedersen_hash(
                    cs.namespace(|| "computation of pedersen hash"),
                    pedersen_hash::Personalization::None,
                    &preimage,
                    params,
                )?
                .get_x()
                .clone(); // Injective encoding

                path_bits.push(cur_is_right);
            }

            {
                // Validate that the root of the merkle tree that we calculated is the same as the input.
                constraint::equal(&mut cs, || "enforce commitment correct", &cur, &rt);
            }
        }

        Ok(())
    }
}

impl<'a, E: JubjubEngine> RationalPoStCircuit<'a, E> {
    #[allow(clippy::type_complexity)]
    pub fn synthesize<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        params: &'a E::Params,
        leafs: Vec<Option<E::Fr>>,
        commitments: Vec<Option<E::Fr>>,
        paths: Vec<Vec<Option<(E::Fr, bool)>>>,
    ) -> Result<(), SynthesisError> {
        RationalPoStCircuit {
            params,
            leafs,
            commitments,
            paths,
        }
        .synthesize(cs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ff::Field;
    use fil_sapling_crypto::jubjub::JubjubBls12;
    use rand::{Rng, SeedableRng, XorShiftRng};

    use crate::circuit::test::*;
    use crate::compound_proof;
    use crate::drgraph::{new_seed, BucketGraph, Graph};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::pedersen::*;
    use crate::rational_post::{self, RationalPoSt};
    use crate::proof::{NoRequirements, ProofScheme};

    #[test]
    fn test_rational_post_circuit_with_bls12_381() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let leaves = 32;

        let pub_params = rational_post::PublicParams {
            sector_size: leaves * 32,
            challenges_count: 2,
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

        let faults = vec![];
        let seed = (0..32).map(|_| rng.gen()).collect::<Vec<u8>>();

        let pub_inputs = rational_post::PublicInputs {
            challenge_seed: &seed,
            faults: &faults,
            commitments: &[tree1.root(), tree2.root()],
        };

        let priv_inputs = rational_post::PrivateInputs::<PedersenHasher> {
            trees: &[&tree1, &tree2],
        };

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

        let commitments: Vec<_> = proof.challenges()
            .iter()
            .map(|c| {
                let sector = *c as usize % pub_inputs.commitments.len();
                Some(pub_inputs.commitments[sector].into())
            })
            .collect();

        let mut cs = TestConstraintSystem::<Bls12>::new();

        let instance = RationalPoStCircuit {
            params,
            leafs,
            paths,
            commitments,
        };

        instance
            .synthesize(&mut cs)
            .expect("failed to synthesize circuit");

        assert!(cs.is_satisfied(), "constraints not satisfied");

        assert_eq!(cs.num_inputs(), 1, "wrong number of inputs");
        assert_eq!(cs.num_constraints(), 13742, "wrong number of constraints");
        assert_eq!(cs.get_input(0, "ONE"), Fr::one());
    }

    // #[ignore] // Slow test – run only when compiled for release.
    // #[test]
    // fn rational_post_test_compound() {
    //     let params = &JubjubBls12::new();
    //     let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    //     let leaves = 32;

    //     let setup_params = compound_proof::SetupParams {
    //         vanilla_params: &rational_post::SetupParams {
    //             leaves,
    //             sectors_count: 2,
    //             challenges_count: 2,
    //         },
    //         engine_params: params,
    //         partitions: None,
    //     };

    //     let pub_params =
    //         RationalPoStCompound::<PedersenHasher>::setup(&setup_params).expect("setup failed");

    //     let data1: Vec<u8> = (0..32)
    //         .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
    //         .collect();
    //     let data2: Vec<u8> = (0..32)
    //         .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
    //         .collect();

    //     let graph1 = BucketGraph::<PedersenHasher>::new(32, 5, 0, new_seed());
    //     let tree1 = graph1.merkle_tree(data1.as_slice()).unwrap();

    //     let graph2 = BucketGraph::<PedersenHasher>::new(32, 5, 0, new_seed());
    //     let tree2 = graph2.merkle_tree(data2.as_slice()).unwrap();

    //     let pub_inputs = rational_post::PublicInputs {
    //         challenges: &vec![rng.gen_range(0, leaves), rng.gen_range(0, leaves)],
    //         challenged_sectors: &[0, 1],
    //         commitments: &[tree1.root(), tree2.root()],
    //     };

    //     let priv_inputs = rational_post::PrivateInputs::<PedersenHasher> {
    //         trees: &[&tree1, &tree2],
    //     };

    //     let gparams =
    //         RationalPoStCompound::<PedersenHasher>::groth_params(&pub_params.vanilla_params, &params)
    //             .expect("failed to create groth params");

    //     let proof =
    //         RationalPoStCompound::<PedersenHasher>::prove(&pub_params, &pub_inputs, &priv_inputs, &gparams)
    //             .expect("proving failed");

    //     let (circuit, inputs) = RationalPoStCompound::<PedersenHasher>::circuit_for_test(
    //         &pub_params,
    //         &pub_inputs,
    //         &priv_inputs,
    //     );

    //     let mut cs = TestConstraintSystem::new();

    //     circuit.synthesize(&mut cs).expect("failed to synthesize");
    //     assert!(cs.is_satisfied());
    //     assert!(cs.verify(&inputs));

    //     let verified = RationalPoStCompound::<PedersenHasher>::verify(
    //         &pub_params,
    //         &pub_inputs,
    //         &proof,
    //         &NoRequirements,
    //     )
    //     .expect("failed while verifying");

    //     assert!(verified);
    // }
}
