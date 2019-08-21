use std::marker::PhantomData;

use algebra::curves::{bls12_381::Bls12_381 as Bls12, jubjub::JubJubProjective as JubJub};
use algebra::fields::bls12_381::Fr;
use dpc::crypto_primitives::crh::pedersen::PedersenParameters;
use snark::{Circuit, ConstraintSystem, SynthesisError};
use snark_gadgets::{
    boolean,
    fields::fp::FpGadget,
    utils::{AllocGadget, CondReverseGadget, ToBytesGadget},
    Assignment,
};

use crate::circuit::multipack::pack_into_allocated;
use crate::circuit::{constraint, pedersen};
use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::drgraph;
use crate::fr32::u32_into_fr;
use crate::hasher::Hasher;
use crate::parameter_cache::{CacheableParameters, ParameterSetMetadata};
use crate::porc::PoRC;
use crate::proof::ProofScheme;
use crate::singletons::PEDERSEN_PARAMS;

/// This is the `PoRC` circuit.
pub struct PoRCCircuit<'a> {
    /// Paramters for the engine.
    pub params: &'a PedersenParameters<JubJub>,
    pub challenges: Vec<Option<Fr>>,
    pub challenged_leafs: Vec<Option<Fr>>,
    pub challenged_sectors: Vec<Option<usize>>,
    pub commitments: Vec<Option<Fr>>,
    #[allow(clippy::type_complexity)]
    pub paths: Vec<Vec<Option<(Fr, bool)>>>,
}

pub struct PoRCCompound<H>
where
    H: Hasher,
{
    _h: PhantomData<H>,
}

impl<C: Circuit<Bls12>, P: ParameterSetMetadata, H: Hasher> CacheableParameters<Bls12, C, P>
    for PoRCCompound<H>
{
    fn cache_prefix() -> String {
        String::from("proof-of-retrievable-commitments")
    }
}

#[derive(Clone, Default)]
pub struct ComponentPrivateInputs {}

impl<'a> CircuitComponent for PoRCCircuit<'a> {
    type ComponentPrivateInputs = ComponentPrivateInputs;
}

impl<'a, H> CompoundProof<'a, Bls12, PoRC<'a, H>, PoRCCircuit<'a>> for PoRCCompound<H>
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
        _component_private_inputs: <PoRCCircuit<'a> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &<PoRC<'a, H> as ProofScheme<'a>>::Proof,
        _pub_params: &<PoRC<'a, H> as ProofScheme<'a>>::PublicParams,
    ) -> PoRCCircuit<'a> {
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
            params: &PEDERSEN_PARAMS,
            challenges,
            challenged_leafs,
            commitments,
            challenged_sectors,
            paths,
        }
    }

    fn blank_circuit(
        pub_params: &<PoRC<'a, H> as ProofScheme<'a>>::PublicParams,
    ) -> PoRCCircuit<'a> {
        let challenges_count = pub_params.challenges_count;
        let height = drgraph::graph_height(pub_params.leaves);
        let challenged_leafs = vec![None; challenges_count];

        let commitments = vec![None; pub_params.sectors_count];
        let paths = vec![vec![None; height]; challenges_count];

        let challenges = vec![None; challenges_count];
        let challenged_sectors = vec![None; challenges_count];

        PoRCCircuit {
            params: &PEDERSEN_PARAMS,
            challenges,
            challenged_leafs,
            commitments,
            challenged_sectors,
            paths,
        }
    }
}

impl<'a> Circuit<Bls12> for PoRCCircuit<'a> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let params = self.params;
        let challenges = self.challenges;
        let challenged_sectors = self.challenged_sectors;
        let challenged_leafs = self.challenged_leafs;
        let commitments = self.commitments;
        let paths = self.paths;

        assert_eq!(challenged_leafs.len(), paths.len());
        assert_eq!(paths.len(), commitments.len());

        for (i, (challenged_leaf, path)) in challenged_leafs.iter().zip(paths).enumerate() {
            let mut cs = cs.ns(|| format!("challenge_{}", i));

            let commitment = challenged_sectors[i].and_then(|s| commitments[s]);

            // Allocate the commitment
            let rt = FpGadget::alloc(cs.ns(|| "commitment_num"), || {
                commitment.ok_or_else(|| SynthesisError::AssignmentMissing)
            })?;

            let leaf_num = FpGadget::alloc(cs.ns(|| "leaf_num"), || {
                challenged_leaf.ok_or_else(|| SynthesisError::AssignmentMissing)
            })?;

            // This is an injective encoding, as cur is a
            // point in the prime order subgroup.
            let mut cur = leaf_num;

            let mut path_bits = Vec::with_capacity(path.len());

            // Ascend the merkle tree authentication path
            for (i, e) in path.iter().enumerate() {
                let cs = &mut cs.ns(|| format!("merkle tree hash {}", i));

                // Determines if the current subtree is the "right" leaf at this
                // depth of the tree.
                let cur_is_right = boolean::Boolean::from(boolean::AllocatedBit::alloc(
                    cs.ns(|| "position bit"),
                    || e.map(|e| e.1).get(),
                )?);

                // Witness the authentication path element adjacent
                // at this depth.
                let path_element = FpGadget::alloc(cs.ns(|| "path element"), || {
                    Ok(e.ok_or_else(|| SynthesisError::AssignmentMissing)?.0)
                })?;

                // Swap the two if the current subtree is on the right
                let (xl, xr) = FpGadget::conditionally_reverse(
                    cs.ns(|| "conditional reversal of preimage"),
                    &cur_is_right,
                    &cur,
                    &path_element,
                )?;

                let mut preimage = vec![];
                let xl_bytes = xl.to_bytes(cs.ns(|| "xl into bytes"))?;
                let xr_bytes = xr.to_bytes(cs.ns(|| "xr into bytes"))?;

                preimage.extend(xl_bytes);
                preimage.extend(xr_bytes);

                // Compute the new subtree value
                cur = pedersen::pedersen_compression_num(
                    cs.ns(|| "computation of pedersen hash"),
                    &preimage[..],
                    params,
                )?
                .clone(); // Injective encoding

                path_bits.push(cur_is_right);
            }

            let challenge_num = FpGadget::alloc(cs.ns(|| format!("challenge_{}", i)), || {
                challenges[i].ok_or_else(|| SynthesisError::AssignmentMissing)
            })?;

            // allocate value for is_right path
            let packed = pack_into_allocated(cs.ns(|| "packed path"), &path_bits)?;
            constraint::equal(
                cs.ns(|| "enforce path equals challenge"),
                &packed,
                &challenge_num,
            )?;

            {
                // Validate that the root of the merkle tree that we calculated is the same as the input.
                constraint::equal(cs.ns(|| "enforce commitment correct"), &cur, &rt)?;
            }
        }

        Ok(())
    }
}

impl<'a> PoRCCircuit<'a> {
    #[allow(clippy::type_complexity)]
    pub fn synthesize<CS: ConstraintSystem<Bls12>>(
        cs: &mut CS,
        challenges: Vec<Option<Fr>>,
        challenged_sectors: Vec<Option<usize>>,
        challenged_leafs: Vec<Option<Fr>>,
        commitments: Vec<Option<Fr>>,
        paths: Vec<Vec<Option<(Fr, bool)>>>,
    ) -> Result<(), SynthesisError> {
        PoRCCircuit {
            params: &PEDERSEN_PARAMS,
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

    use algebra::fields::Field;
    use rand::{Rng, SeedableRng, XorShiftRng};

    use crate::circuit::test::*;
    use crate::compound_proof;
    use crate::drgraph::{new_seed, BucketGraph, Graph};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::pedersen::*;
    use crate::porc::{self, PoRC};
    use crate::proof::{NoRequirements, ProofScheme};

    #[test]
    fn test_porc_circuit_with_bls12_381() {
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

        let proof = PoRC::<PedersenHasher>::prove(&pub_params, &pub_inputs, &priv_inputs)
            .expect("proving failed");

        let is_valid = PoRC::<PedersenHasher>::verify(&pub_params, &pub_inputs, &proof)
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
        let challenged_leafs: Vec<_> = proof.leafs().iter().map(|l| Some((**l).into())).collect();
        let commitments: Vec<_> = pub_inputs
            .commitments
            .iter()
            .map(|c| Some((*c).into()))
            .collect();

        let mut cs = TestConstraintSystem::<Bls12>::new();

        let instance = PoRCCircuit {
            params: &PEDERSEN_PARAMS,
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
        assert_eq!(cs.num_constraints(), 46136, "wrong number of constraints");
        assert_eq!(cs.get_input(0, "ONE"), Fr::one());
    }

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn porc_test_compound() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let leaves = 32;

        let setup_params = compound_proof::SetupParams {
            vanilla_params: &porc::SetupParams {
                leaves,
                sectors_count: 2,
                challenges_count: 2,
            },
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

        let gparams = PoRCCompound::<PedersenHasher>::groth_params(&pub_params.vanilla_params)
            .expect("failed to create groth params");

        let proof =
            PoRCCompound::<PedersenHasher>::prove(&pub_params, &pub_inputs, &priv_inputs, &gparams)
                .expect("proving failed");

        let (circuit, inputs) = PoRCCompound::<PedersenHasher>::circuit_for_test(
            &pub_params,
            &pub_inputs,
            &priv_inputs,
        );

        let mut cs = TestConstraintSystem::new();

        circuit.synthesize(&mut cs).expect("failed to synthesize");
        assert!(cs.is_satisfied());
        assert!(cs.verify(&inputs));

        let verified = PoRCCompound::<PedersenHasher>::verify(
            &pub_params,
            &pub_inputs,
            &proof,
            &NoRequirements,
        )
        .expect("failed while verifying");

        assert!(verified);
    }
}
