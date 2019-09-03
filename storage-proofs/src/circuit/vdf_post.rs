use algebra::curves::{bls12_377::Bls12_377 as Bls12, edwards_bls12::EdwardsProjective};
use algebra::fields::bls12_377::Fr;
use dpc::crypto_primitives::crh::pedersen::PedersenParameters;
use snark::{Circuit, ConstraintSystem, SynthesisError};
use snark_gadgets::{fields::fp::FpGadget, utils::AllocGadget};

use crate::circuit::constraint;
use crate::circuit::porc;
use crate::circuit::sloth;
use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::fr32::u32_into_fr;
use crate::hasher::Hasher;
use crate::parameter_cache::{CacheableParameters, ParameterSetMetadata};
use crate::proof::ProofScheme;
use crate::singletons::PEDERSEN_PARAMS;
use crate::vdf::Vdf;
use crate::vdf_post::{self, compute_root_commitment, VDFPoSt};

/// This is the `VDF-PoSt` circuit.
#[derive(Debug)]
pub struct VDFPoStCircuit<'a> {
    /// Paramters for the engine.
    pub params: &'a PedersenParameters<EdwardsProjective>,

    pub challenge_seed: Option<Fr>,

    // VDF
    pub vdf_key: Option<Fr>,
    pub vdf_ys: Vec<Option<Fr>>,
    pub vdf_xs: Vec<Option<Fr>>,

    // PoRCs
    pub challenges_vec: Vec<Vec<Option<usize>>>,
    pub challenged_sectors_vec: Vec<Vec<Option<usize>>>,
    pub challenged_leafs_vec: Vec<Vec<Option<Fr>>>,
    pub commitments_vec: Vec<Vec<Option<Fr>>>,
    pub root_commitment: Option<Fr>,
    #[allow(clippy::type_complexity)]
    pub paths_vec: Vec<Vec<Vec<Option<(Fr, bool)>>>>,
}

#[derive(Debug)]
pub struct VDFPostCompound {}

impl<C: Circuit<Bls12>, P: ParameterSetMetadata> CacheableParameters<Bls12, C, P>
    for VDFPostCompound
{
    fn cache_prefix() -> String {
        String::from("vdf-post")
    }
}

#[derive(Debug, Clone, Default)]
pub struct ComponentPrivateInputs {}

impl<'a> CircuitComponent for VDFPoStCircuit<'a> {
    type ComponentPrivateInputs = ComponentPrivateInputs;
}

impl<'a, H, V> CompoundProof<'a, VDFPoSt<H, V>, VDFPoStCircuit<'a>> for VDFPostCompound
where
    H: 'static + Hasher,
    V: Vdf<H::Domain> + Sync + Send,
    <V as Vdf<H::Domain>>::PublicParams: Send + Sync,
    <V as Vdf<H::Domain>>::Proof: Send + Sync,
{
    fn generate_public_inputs(
        pub_in: &<VDFPoSt<H, V> as ProofScheme<'a>>::PublicInputs,
        _pub_params: &<VDFPoSt<H, V> as ProofScheme<'a>>::PublicParams,
        _partition_k: Option<usize>,
    ) -> Vec<Fr> {
        let mut inputs: Vec<Fr> = Vec::new();
        inputs.push(pub_in.challenge_seed.into());
        inputs.push(compute_root_commitment(&pub_in.commitments).into());
        inputs
    }

    fn circuit(
        pub_in: &<VDFPoSt<H, V> as ProofScheme<'a>>::PublicInputs,
        _component_private_inputs: <VDFPoStCircuit<'a> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &<VDFPoSt<H, V> as ProofScheme<'a>>::Proof,
        pub_params: &<VDFPoSt<H, V> as ProofScheme<'a>>::PublicParams,
    ) -> VDFPoStCircuit<'a> {
        let post_epochs = pub_params.post_epochs;
        let challenge_count = pub_params.challenge_count;

        assert_eq!(vanilla_proof.porep_proofs.len(), post_epochs);
        assert_eq!(vanilla_proof.ys.len(), post_epochs - 1);
        assert!(
            vanilla_proof.challenges.len() <= challenge_count,
            "too many challenges"
        );

        let vdf_ys = vanilla_proof
            .ys
            .iter()
            .map(|y| Some(y.clone().into()))
            .collect::<Vec<_>>();

        let vdf_xs = vanilla_proof
            .porep_proofs
            .iter()
            .take(vdf_ys.len())
            .map(|p| Some(vdf_post::extract_vdf_input(p).into()))
            .collect();

        let mut paths_vec = Vec::new();
        let mut challenged_leafs_vec = Vec::new();
        let mut commitments_vec = Vec::new();

        for porep_proof in &vanilla_proof.porep_proofs {
            // -- paths
            paths_vec.push(
                porep_proof
                    .paths()
                    .iter()
                    .map(|p| {
                        p.iter()
                            .map(|v| Some((v.0.into(), v.1)))
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>(),
            );

            // -- challenged leafs
            challenged_leafs_vec.push(
                porep_proof
                    .leafs()
                    .iter()
                    .map(|l| Some((**l).into()))
                    .collect::<Vec<_>>(),
            );

            // -- commitments
            commitments_vec.push(
                porep_proof
                    .commitments()
                    .iter()
                    .map(|c| Some((**c).into()))
                    .collect::<Vec<_>>(),
            );
        }

        VDFPoStCircuit {
            params: &PEDERSEN_PARAMS,
            challenges_vec: vanilla_proof
                .challenges
                .iter()
                .map(|v| v.iter().map(|&s| Some(s)).collect())
                .collect(),
            challenged_sectors_vec: vanilla_proof
                .challenged_sectors
                .iter()
                .map(|v| v.iter().map(|&s| Some(s)).collect())
                .collect(),
            challenge_seed: Some(pub_in.challenge_seed.into()),
            vdf_key: Some(V::key(&pub_params.pub_params_vdf).into()),
            vdf_ys,
            vdf_xs,
            challenged_leafs_vec,
            root_commitment: Some(compute_root_commitment(&pub_in.commitments).into()),
            commitments_vec,
            paths_vec,
        }
    }

    fn blank_circuit(
        pub_params: &<VDFPoSt<H, V> as ProofScheme>::PublicParams,
    ) -> VDFPoStCircuit<'a> {
        let post_epochs = pub_params.post_epochs;
        let challenge_bits = pub_params.challenge_bits;
        let challenge_count = pub_params.challenge_count;

        let challenges_vec = vec![vec![None; challenge_count]; post_epochs];
        let challenged_sectors_vec = vec![vec![None; challenge_count]; post_epochs];
        let challenged_leafs_vec = vec![vec![None; challenge_count]; post_epochs];
        let commitments_vec = vec![vec![None; challenge_count]; post_epochs];
        let vdf_xs = vec![None; post_epochs - 1];
        let vdf_ys = vec![None; post_epochs - 1];
        let paths_vec = vec![vec![vec![None; challenge_bits]; challenge_count]; post_epochs];

        VDFPoStCircuit {
            params: &PEDERSEN_PARAMS,
            challenges_vec,
            challenged_sectors_vec,
            challenge_seed: None,
            vdf_key: None,
            vdf_xs,
            vdf_ys,
            challenged_leafs_vec,
            paths_vec,
            root_commitment: None,
            commitments_vec,
        }
    }
}

impl<'a> Circuit<Bls12> for VDFPoStCircuit<'a> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let vdf_key = self.vdf_key;
        let vdf_ys = self.vdf_ys.clone();
        let vdf_xs = self.vdf_xs.clone();
        let challenges_vec = self.challenges_vec.clone();
        let challenged_sectors_vec = self.challenged_sectors_vec.clone();
        let challenged_leafs_vec = self.challenged_leafs_vec.clone();
        let commitments_vec = self.commitments_vec.clone();
        let paths_vec = self.paths_vec.clone();

        let challenge_seed = cs.alloc_input(
            || "challenge_seed",
            || {
                self.challenge_seed
                    .ok_or_else(|| SynthesisError::AssignmentMissing)
            },
        )?;
        cs.alloc_input(
            || "root_commitment",
            || {
                self.root_commitment
                    .ok_or_else(|| SynthesisError::AssignmentMissing)
            },
        )?;

        // FIXME:
        // API tests pass with input verification only, but fail when any constraints are added
        // below. CompoundProof tests pass, though — so the problem may be with how the proof
        // is assembled or verification requested in the API tests. Debugging circuits is not fun.

        // VDF Output Verification
        assert_eq!(vdf_xs.len(), vdf_ys.len());

        let vdf_key = FpGadget::alloc(cs.ns(|| "vdf_key"), || {
            vdf_key.ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        for (i, (y, x)) in vdf_ys.iter().zip(vdf_xs.iter()).enumerate() {
            {
                // VDF Verification
                let mut cs = cs.ns(|| format!("vdf_verification_round_{}", i));
                //
                //                // FIXME: make this a generic call to Vdf proof circuit function.
                let decoded = sloth::decode(cs.ns(|| "sloth_decode"), &vdf_key, *y)?;

                let x_alloc = FpGadget::alloc(cs.ns(|| "x"), || {
                    x.ok_or_else(|| SynthesisError::AssignmentMissing)
                })?;

                constraint::equal(cs.ns(|| "equality"), &x_alloc, &decoded)?;

                let partial_challenge = x;

                // Challenge Verification
                if i == 0 {
                    verify_challenges(
                        &mut cs,
                        // Should be CHALLENGES, not CHALLENGED_LEAFS.
                        challenged_leafs_vec[i].iter().collect::<Vec<_>>(),
                        partial_challenge,
                        Some(challenge_seed), // First iteration uses supplied challenge seed.
                        paths_vec[i][0].len(),
                    );
                } else {
                    verify_challenges(
                        &mut cs,
                        challenged_leafs_vec[i].iter().collect::<Vec<_>>(),
                        partial_challenge,
                        *y, // Subsequent iterations use computed Vdf result
                        paths_vec[i][0].len(),
                    );
                }
            }

            // TODO: VDF Input Verification
            // Verify that proof leaves hash to next vdf input.

            // TODO: Root Commitment verification.
            // Skip for now, but this is an absence that needs to be addressed once we have a vector commitment strategy.
        }

        // PoRC Verification
        assert_eq!(challenged_leafs_vec.len(), commitments_vec.len());
        assert_eq!(paths_vec.len(), commitments_vec.len());

        for (i, (challenged_leafs, (commitments, paths))) in challenged_leafs_vec
            .iter()
            .zip(commitments_vec.iter().zip(paths_vec.iter()))
            .enumerate()
        {
            let mut cs = cs.ns(|| format!("porc_verification_round_{}", i));
            porc::PoRCCircuit::synthesize(
                &mut cs,
                challenges_vec[i]
                    .iter()
                    .map(|c| c.map(|c| u32_into_fr::<Bls12>(c as u32)))
                    .collect(),
                challenged_sectors_vec[i].clone(),
                challenged_leafs.to_vec(),
                commitments.to_vec(),
                paths.to_vec(),
            )?;
        }
        Ok(())
    }
}

fn verify_challenges<CS: ConstraintSystem<Bls12>, T>(
    _cs: &mut CS,
    _challenges: Vec<&Option<Fr>>,
    _partial_challenge: &Option<Fr>,
    // This is generic because it needs to work with a public input (challenge seed) on first iteration
    // then an allocated number subsequently.
    _mix: T,
    _challenge_bits: usize,
) -> bool {
    // TODO: Actually verify that challenges are correctly derived.
    // Verification algorithm is implemented and tested in vdf_post::verify_final_challenge_derivation.
    // NOTE: verification as designed here requires that all challenges (N) extractable from one partial_challenge
    // are used. If challenge_count is not a multiple of this N, the surplus challenges will still be needed for verification,
    // even if unused.
    true
}

impl<'a> VDFPoStCircuit<'a> {
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    pub fn synthesize<CS: ConstraintSystem<Bls12>>(
        cs: &mut CS,
        params: &PedersenParameters<EdwardsProjective>,
        challenge_seed: Option<Fr>,
        vdf_key: Option<Fr>,
        vdf_ys: Vec<Option<Fr>>,
        vdf_xs: Vec<Option<Fr>>,
        challenges_vec: Vec<Vec<Option<usize>>>,
        challenged_sectors_vec: Vec<Vec<Option<usize>>>,
        challenged_leafs_vec: Vec<Vec<Option<Fr>>>,
        root_commitment: Option<Fr>,
        commitments_vec: Vec<Vec<Option<Fr>>>,
        paths_vec: Vec<Vec<Vec<Option<(Fr, bool)>>>>,
    ) -> Result<(), SynthesisError> {
        VDFPoStCircuit {
            params,
            challenges_vec,
            challenged_sectors_vec,
            challenge_seed,
            vdf_key,
            vdf_ys,
            vdf_xs,
            challenged_leafs_vec,
            root_commitment,
            commitments_vec,
            paths_vec,
        }
        .synthesize(cs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use algebra::fields::Field;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use snark::groth16;

    use crate::circuit::test::*;
    use crate::compound_proof;
    use crate::drgraph::{new_seed, BucketGraph, Graph};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::pedersen::*;
    use crate::proof::{NoRequirements, ProofScheme};
    use crate::vdf_post;
    use crate::vdf_sloth;

    #[test]
    fn test_vdf_post_circuit_with_bls12_377() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let lambda = 32;

        let sp = vdf_post::SetupParams::<PedersenDomain, vdf_sloth::Sloth> {
            challenge_count: 10,
            sector_size: 128 * lambda,
            post_epochs: 3,
            setup_params_vdf: vdf_sloth::SetupParams { key: rng.gen() },
            sectors_count: 2,
        };

        let pub_params = vdf_post::VDFPoSt::<PedersenHasher, vdf_sloth::Sloth>::setup(&sp)
            .expect("setup failed");

        let data0: Vec<u8> = (0..128)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        let data1: Vec<u8> = (0..128)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let graph0 = BucketGraph::<PedersenHasher>::new(128, 5, 0, new_seed());
        let tree0 = graph0.merkle_tree(data0.as_slice()).unwrap();
        let graph1 = BucketGraph::<PedersenHasher>::new(128, 5, 0, new_seed());
        let tree1 = graph1.merkle_tree(data1.as_slice()).unwrap();

        let pub_inputs = vdf_post::PublicInputs {
            challenge_seed: rng.gen(),
            commitments: vec![tree0.root(), tree1.root()],
            faults: Vec::new(),
        };

        let trees = [&tree0, &tree1];
        let priv_inputs = vdf_post::PrivateInputs::new(&trees[..]);

        let proof = vdf_post::VDFPoSt::<PedersenHasher, vdf_sloth::Sloth>::prove(
            &pub_params,
            &pub_inputs,
            &priv_inputs,
        )
        .expect("proving failed");

        let is_valid = vdf_post::VDFPoSt::<PedersenHasher, vdf_sloth::Sloth>::verify(
            &pub_params,
            &pub_inputs,
            &proof,
        )
        .expect("verification failed");

        assert!(is_valid);

        // actual circuit test

        let vdf_ys = proof
            .ys
            .iter()
            .map(|y| Some(y.clone().into()))
            .collect::<Vec<_>>();
        let vdf_xs = proof
            .porep_proofs
            .iter()
            .take(vdf_ys.len())
            .map(|p| Some(vdf_post::extract_vdf_input::<PedersenHasher>(p).into()))
            .collect();

        let mut paths_vec = Vec::new();
        let mut challenged_leafs_vec = Vec::new();
        let mut commitments_vec = Vec::new();

        for porep_proof in &proof.porep_proofs {
            // -- paths
            paths_vec.push(
                porep_proof
                    .paths()
                    .iter()
                    .map(|p| {
                        p.iter()
                            .map(|v| Some((v.0.into(), v.1)))
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>(),
            );

            // -- challenged leafs
            challenged_leafs_vec.push(
                porep_proof
                    .leafs()
                    .iter()
                    .map(|l| Some((**l).into()))
                    .collect::<Vec<_>>(),
            );

            // -- commitments
            commitments_vec.push(
                porep_proof
                    .commitments()
                    .iter()
                    .map(|c| Some((**c).into()))
                    .collect::<Vec<_>>(),
            );
        }

        let mut cs = TestConstraintSystem::<Bls12>::new();

        let instance = VDFPoStCircuit {
            params: &PEDERSEN_PARAMS,
            challenges_vec: proof
                .challenges
                .iter()
                .map(|v| v.iter().map(|&s| Some(s)).collect())
                .collect(),
            challenged_sectors_vec: proof
                .challenged_sectors
                .iter()
                .map(|v| v.iter().map(|&s| Some(s)).collect())
                .collect(),
            challenge_seed: Some(pub_inputs.challenge_seed.into()),
            vdf_key: Some(pub_params.pub_params_vdf.key.into()),
            vdf_xs,
            vdf_ys,
            challenged_leafs_vec,
            paths_vec,
            root_commitment: Some(compute_root_commitment(&pub_inputs.commitments).into()),
            commitments_vec,
        };

        instance
            .synthesize(&mut cs)
            .expect("failed to synthesize circuit");

        assert!(cs.is_satisfied(), "constraints not satisfied");

        assert_eq!(cs.num_inputs(), 3, "wrong number of inputs");
        assert_eq!(cs.num_constraints(), 968824, "wrong number of constraints");
        assert_eq!(cs.get_input(0, "ONE"), Fr::one());
    }

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn test_vdf_post_compound() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let lambda = 32;

        let setup_params = compound_proof::SetupParams {
            vanilla_params: &vdf_post::SetupParams::<PedersenDomain, vdf_sloth::Sloth> {
                challenge_count: 3,
                sector_size: 128 * lambda,
                post_epochs: 3,
                setup_params_vdf: vdf_sloth::SetupParams { key: rng.gen() },
                sectors_count: 2,
            },
            partitions: None,
        };

        let pub_params: compound_proof::PublicParams<
            vdf_post::VDFPoSt<PedersenHasher, vdf_sloth::Sloth>,
        > = VDFPostCompound::setup(&setup_params).expect("setup failed");

        let data0: Vec<u8> = (0..128)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        let data1: Vec<u8> = (0..128)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let graph0 = BucketGraph::<PedersenHasher>::new(128, 5, 0, new_seed());
        let tree0 = graph0.merkle_tree(data0.as_slice()).unwrap();
        let graph1 = BucketGraph::<PedersenHasher>::new(128, 5, 0, new_seed());
        let tree1 = graph1.merkle_tree(data1.as_slice()).unwrap();

        let pub_inputs = vdf_post::PublicInputs {
            challenge_seed: rng.gen(),
            commitments: vec![tree0.root(), tree1.root()],
            faults: Vec::new(),
        };

        let trees = [&tree0, &tree1];
        let priv_inputs = //: vdf_post::PrivateInputs<PedersenHasher> =
            vdf_post::PrivateInputs::<PedersenHasher>::new(&trees[..]);

        let gparams: groth16::Parameters<_> = <VDFPostCompound as CompoundProof<
            '_,
            VDFPoSt<PedersenHasher, _>,
            VDFPoStCircuit,
        >>::groth_params(&pub_params.vanilla_params)
        .expect("failed to create groth params");

        let proof = VDFPostCompound::prove(&pub_params, &pub_inputs, &priv_inputs, &gparams, false)
            .expect("failed while proving");

        let (circuit, inputs) =
            VDFPostCompound::circuit_for_test(&pub_params, &pub_inputs, &priv_inputs);

        let mut cs = TestConstraintSystem::new();

        circuit.synthesize(&mut cs).expect("failed to synthesize");
        assert!(cs.is_satisfied());
        assert!(cs.verify(&inputs));

        // Use this to debug differences between blank and regular circuit generation.
        // {
        //     let blank_circuit = <VDFPostCompound as CompoundProof<
        //         Bls12,
        //         VDFPoSt<PedersenHasher, _>,
        //         VDFPoStCircuit<Bls12>,
        //     >>::blank_circuit(&pub_params.vanilla_params, params);
        //     let (circuit1, _inputs) =
        //         VDFPostCompound::circuit_for_test(&pub_params, &pub_inputs, &priv_inputs);

        //     let mut cs_blank = TestConstraintSystem::new();
        //     blank_circuit
        //         .synthesize(&mut cs_blank)
        //         .expect("failed to synthesize");

        //     let a = cs_blank.pretty_print();

        //     let mut cs1 = TestConstraintSystem::new();
        //     circuit1.synthesize(&mut cs1).expect("failed to synthesize");
        //     let b = cs1.pretty_print();

        //     let a_vec = a.split("\n").collect::<Vec<_>>();
        //     let b_vec = b.split("\n").collect::<Vec<_>>();

        //     for (i, (a, b)) in a_vec.chunks(100).zip(b_vec.chunks(100)).enumerate() {
        //         println!("chunk {}", i);
        //         assert_eq!(a, b);
        //     }
        // }

        let verified = VDFPostCompound::verify(&pub_params, &pub_inputs, &proof, &NoRequirements)
            .expect("failed while verifying");

        assert!(verified);
    }
}
