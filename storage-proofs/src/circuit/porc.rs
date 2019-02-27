use std::marker::PhantomData;

use bellman::{Circuit, ConstraintSystem, SynthesisError};
use pairing::bls12_381::{Bls12, Fr};
use pairing::{Engine, Field};
use sapling_crypto::circuit::boolean::Boolean;
use sapling_crypto::circuit::num::{AllocatedNum, Num};
use sapling_crypto::circuit::{boolean, num, pedersen_hash};
use sapling_crypto::jubjub::JubjubEngine;

use crate::circuit::constraint;
use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::drgraph;
use crate::fr32::u32_into_fr;
use crate::hasher::Hasher;
use crate::parameter_cache::{CacheableParameters, ParameterSetIdentifier};
use crate::porc::PoRC;
use crate::proof::ProofScheme;

/// Takes a sequence of booleans and returns a single `E::Fr` as a packed representation.
/// NOTE: bit length must be less than `Fr::capacity()` for the field, or this will overflow.
pub fn pack_into_allocated_num<E, CS>(
    mut cs: CS,
    bits: &[Boolean],
) -> Result<AllocatedNum<E>, SynthesisError>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    let mut num = Num::<E>::zero();
    let mut coeff = E::Fr::one();

    //    for (i, bits) in bits.chunks(E::Fr::CAPACITY as usize).enumerate() {
    for bit in bits {
        num = num.add_bool_with_coeff(CS::one(), bit, coeff);

        coeff.double();
    }
    let val = num::AllocatedNum::alloc(cs.namespace(|| "val"), || Ok(num.get_value().unwrap()))?;

    Ok(val)
}

/// This is the `PoRC` circuit.
pub struct PoRCCircuit<'a, E: JubjubEngine> {
    /// Paramters for the engine.
    pub params: &'a E::Params,
    pub challenges: Vec<Option<E::Fr>>,
    pub challenged_leafs: Vec<Option<E::Fr>>,
    pub challenged_sectors: Vec<Option<usize>>,
    pub commitments: Vec<Option<E::Fr>>,
    #[allow(clippy::type_complexity)]
    pub paths: Vec<Vec<Option<(E::Fr, bool)>>>,
}

pub struct PoRCCompound<H>
where
    H: Hasher,
{
    _h: PhantomData<H>,
}

impl<E: JubjubEngine, C: Circuit<E>, P: ParameterSetIdentifier, H: Hasher>
    CacheableParameters<E, C, P> for PoRCCompound<H>
{
    fn cache_prefix() -> String {
        String::from("proof-of-retrievable-commitments")
    }
}

#[derive(Clone, Default)]
pub struct ComponentPrivateInputs {}

impl<'a, E: JubjubEngine> CircuitComponent for PoRCCircuit<'a, E> {
    type ComponentPrivateInputs = ComponentPrivateInputs;
}

impl<'a, H> CompoundProof<'a, Bls12, PoRC<'a, H>, PoRCCircuit<'a, Bls12>> for PoRCCompound<H>
where
    H: 'a + Hasher,
{
    fn generate_public_inputs(
        _pub_in: &<PoRC<'a, H> as ProofScheme<'a>>::PublicInputs,
        _pub_params: &<PoRC<'a, H> as ProofScheme<'a>>::PublicParams,
        _partition_k: Option<usize>,
    ) -> Vec<Fr> {
        Vec::new()
    }

    fn circuit(
        pub_in: &<PoRC<'a, H> as ProofScheme<'a>>::PublicInputs,
        _component_private_inputs: <PoRCCircuit<'a, Bls12> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &<PoRC<'a, H> as ProofScheme<'a>>::Proof,
        _pub_params: &<PoRC<'a, H> as ProofScheme<'a>>::PublicParams,
        engine_params: &'a <Bls12 as JubjubEngine>::Params,
    ) -> PoRCCircuit<'a, Bls12> {
        let challenged_leafs = vanilla_proof
            .leafs()
            .iter()
            .map(|l| Some((**l).into()))
            .collect();

        let commitments: Vec<_> = pub_in
            .commitments
            .iter()
            .map(|c| Some((*c).into()))
            .collect();

        let paths: Vec<Vec<_>> = vanilla_proof
            .paths()
            .iter()
            .map(|v| v.iter().map(|p| Some(((*p).0.into(), p.1))).collect())
            .collect();

        let challenges: Vec<_> = pub_in
            .challenges
            .iter()
            .map(|c| Some(u32_into_fr::<Bls12>(*c as u32)))
            .collect();

        let challenged_sectors = pub_in.challenged_sectors.iter().map(|&v| Some(v)).collect();

        PoRCCircuit {
            params: engine_params,
            challenges,
            challenged_leafs,
            commitments,
            challenged_sectors,
            paths,
        }
    }

    fn blank_circuit(
        pub_params: &<PoRC<'a, H> as ProofScheme<'a>>::PublicParams,
        params: &'a <Bls12 as JubjubEngine>::Params,
    ) -> PoRCCircuit<'a, Bls12> {
        let challenges_count = pub_params.challenges_count;
        let height = drgraph::graph_height(pub_params.leaves);
        let challenged_leafs = vec![None; challenges_count];

        let commitments = vec![None; pub_params.sectors_count];
        let paths = vec![vec![None; height]; challenges_count];

        let challenges = vec![None; challenges_count];
        let challenged_sectors = vec![None; challenges_count];

        PoRCCircuit {
            params,
            challenges,
            challenged_leafs,
            commitments,
            challenged_sectors,
            paths,
        }
    }
}

impl<'a, E: JubjubEngine> Circuit<E> for PoRCCircuit<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let params = self.params;
        let challenges = self.challenges;
        let challenged_sectors = self.challenged_sectors;
        let challenged_leafs = self.challenged_leafs;
        let commitments = self.commitments;
        let paths = self.paths;

        assert_eq!(challenged_leafs.len(), paths.len());
        assert_eq!(paths.len(), commitments.len());

        for (i, (challenged_leaf, path)) in challenged_leafs.iter().zip(paths).enumerate() {
            let mut cs = cs.namespace(|| format!("challenge_{}", i));

            let commitment = challenged_sectors[i].and_then(|s| commitments[s]);

            // Allocate the commitment
            let rt = num::AllocatedNum::alloc(cs.namespace(|| "commitment_num"), || {
                commitment.ok_or_else(|| SynthesisError::AssignmentMissing)
            })?;

            let params = params;

            let leaf_num = num::AllocatedNum::alloc(cs.namespace(|| "leaf_num"), || {
                challenged_leaf.ok_or_else(|| SynthesisError::AssignmentMissing)
            })?;

            // This is an injective encoding, as cur is a
            // point in the prime order subgroup.
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
                    pedersen_hash::Personalization::MerkleTree(i),
                    &preimage,
                    params,
                )?
                .get_x()
                .clone(); // Injective encoding

                path_bits.push(cur_is_right);
            }

            let challenge_num =
                num::AllocatedNum::alloc(cs.namespace(|| format!("challenge {}", i)), || {
                    challenges[i].ok_or_else(|| SynthesisError::AssignmentMissing)
                })?;

            // allocate value for is_right path
            let packed = pack_into_allocated_num(cs.namespace(|| "packed path"), &path_bits)?;
            constraint::equal(
                &mut cs,
                || "enforce path equals challenge",
                &packed,
                &challenge_num,
            );
            {
                // Validate that the root of the merkle tree that we calculated is the same as the input.
                constraint::equal(&mut cs, || "enforce commitment correct", &cur, &rt);
            }
        }

        Ok(())
    }
}

impl<'a, E: JubjubEngine> PoRCCircuit<'a, E> {
    #[allow(clippy::type_complexity)]
    pub fn synthesize<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        params: &'a E::Params,
        challenges: Vec<Option<E::Fr>>,
        challenged_sectors: Vec<Option<usize>>,
        challenged_leafs: Vec<Option<E::Fr>>,
        commitments: Vec<Option<E::Fr>>,
        paths: Vec<Vec<Option<(E::Fr, bool)>>>,
    ) -> Result<(), SynthesisError> {
        PoRCCircuit {
            params,
            challenges,
            challenged_leafs,
            challenged_sectors,
            commitments,
            paths,
        }
        .synthesize(cs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use pairing::Field;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::jubjub::JubjubBls12;

    use crate::circuit::test::*;
    use crate::compound_proof;
    use crate::drgraph::{new_seed, BucketGraph, Graph};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::pedersen::*;
    use crate::porc::{self, PoRC};
    use crate::proof::ProofScheme;

    #[test]
    fn test_porc_circuit_with_bls12_381() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let leaves = 32;

        let pub_params = porc::PublicParams {
            leaves,
            sectors_count: 2,
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

        let challenges = vec![rng.gen_range(0, leaves), rng.gen_range(0, leaves)];
        let challenged_sectors = &[0, 0];

        let pub_inputs = porc::PublicInputs {
            challenges: &challenges,
            challenged_sectors,
            commitments: &[tree1.root(), tree2.root()],
        };

        let priv_inputs = porc::PrivateInputs::<PedersenHasher> {
            trees: &[&tree1, &tree2],
        };

        let proof = PoRC::<PedersenHasher>::prove(&pub_params, &pub_inputs, &priv_inputs).unwrap();

        assert!(PoRC::<PedersenHasher>::verify(&pub_params, &pub_inputs, &proof).unwrap());

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
        let challenged_leafs: Vec<_> = proof.leafs().iter().map(|l| Some((**l).into())).collect();
        let commitments: Vec<_> = pub_inputs
            .commitments
            .iter()
            .map(|c| Some((*c).into()))
            .collect();

        let mut cs = TestConstraintSystem::<Bls12>::new();

        let instance = PoRCCircuit {
            params,
            challenges: challenges
                .iter()
                .map(|c| Some(u32_into_fr::<Bls12>(*c as u32)))
                .collect(),
            challenged_sectors: challenged_sectors.iter().map(|&s| Some(s)).collect(),
            challenged_leafs,
            paths,
            commitments,
        };

        instance
            .synthesize(&mut cs)
            .expect("failed to synthesize circuit");

        assert!(cs.is_satisfied(), "constraints not satisfied");

        assert_eq!(cs.num_inputs(), 1, "wrong number of inputs");
        assert_eq!(cs.num_constraints(), 13824, "wrong number of constraints");
        assert_eq!(cs.get_input(0, "ONE"), Fr::one());
    }

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn porc_test_compound() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let leaves = 32;

        let setup_params = compound_proof::SetupParams {
            vanilla_params: &porc::SetupParams {
                leaves,
                sectors_count: 2,
                challenges_count: 2,
            },
            engine_params: params,
            partitions: None,
        };

        let pub_params =
            PoRCCompound::<PedersenHasher>::setup(&setup_params).expect("setup failed");

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

        let pub_inputs = porc::PublicInputs {
            challenges: &vec![rng.gen_range(0, leaves), rng.gen_range(0, leaves)],
            challenged_sectors: &[0, 1],
            commitments: &[tree1.root(), tree2.root()],
        };

        let priv_inputs = porc::PrivateInputs::<PedersenHasher> {
            trees: &[&tree1, &tree2],
        };

        let gparams =
            PoRCCompound::<PedersenHasher>::groth_params(&pub_params.vanilla_params, &params)
                .unwrap();

        let proof =
            PoRCCompound::<PedersenHasher>::prove(&pub_params, &pub_inputs, &priv_inputs, &gparams)
                .expect("failed while proving");

        let (circuit, inputs) = PoRCCompound::<PedersenHasher>::circuit_for_test(
            &pub_params,
            &pub_inputs,
            &priv_inputs,
        );

        let mut cs = TestConstraintSystem::new();

        circuit.synthesize(&mut cs).expect("failed to synthesize");
        assert!(cs.is_satisfied());
        assert!(cs.verify(&inputs));

        let verified = PoRCCompound::<PedersenHasher>::verify(&pub_params, &pub_inputs, &proof)
            .expect("failed while verifying");

        assert!(verified);
    }
}
