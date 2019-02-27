use bellman::{Circuit, ConstraintSystem, SynthesisError};
use pairing::bls12_381::{Bls12, Fr};
use pairing::Engine;
use sapling_crypto::circuit::num;
use sapling_crypto::jubjub::JubjubEngine;

use crate::circuit::constraint;
use crate::circuit::porc;
use crate::circuit::sloth;
use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::fr32::u32_into_fr;
use crate::hasher::Hasher;
use crate::parameter_cache::{CacheableParameters, ParameterSetIdentifier};
use crate::proof::ProofScheme;
use crate::vdf::Vdf;
use crate::vdf_post::{self, compute_root_commitment, VDFPoSt};

/// This is the `VDF-PoSt` circuit.
#[derive(Debug)]
pub struct VDFPoStCircuit<'a, E: JubjubEngine> {
    /// Paramters for the engine.
    pub params: &'a E::Params,

    pub challenge_seed: Option<E::Fr>,

    // VDF
    pub vdf_key: Option<E::Fr>,
    pub vdf_ys: Vec<Option<E::Fr>>,
    pub vdf_xs: Vec<Option<E::Fr>>,
    pub vdf_sloth_rounds: usize,

    // PoRCs
    pub challenges_vec: Vec<Vec<Option<usize>>>,
    pub challenged_sectors_vec: Vec<Vec<Option<usize>>>,
    pub challenged_leafs_vec: Vec<Vec<Option<E::Fr>>>,
    pub commitments_vec: Vec<Vec<Option<E::Fr>>>,
    pub root_commitment: Option<E::Fr>,
    #[allow(clippy::type_complexity)]
    pub paths_vec: Vec<Vec<Vec<Option<(E::Fr, bool)>>>>,
}

#[derive(Debug)]
pub struct VDFPostCompound {}

impl<E: JubjubEngine, C: Circuit<E>, P: ParameterSetIdentifier> CacheableParameters<E, C, P>
    for VDFPostCompound
{
    fn cache_prefix() -> String {
        String::from("vdf-post")
    }
}

#[derive(Debug, Clone, Default)]
pub struct ComponentPrivateInputs {}

impl<'a, E: JubjubEngine> CircuitComponent for VDFPoStCircuit<'a, E> {
    type ComponentPrivateInputs = ComponentPrivateInputs;
}

impl<'a, H, V> CompoundProof<'a, Bls12, VDFPoSt<H, V>, VDFPoStCircuit<'a, Bls12>>
    for VDFPostCompound
where
    H: 'static + Hasher,
    V: Vdf<H::Domain>,
    <V as Vdf<H::Domain>>::PublicParams: Send + Sync,
    <V as Vdf<H::Domain>>::Proof: Send + Sync,
    V: Sync + Send,
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
        _component_private_inputs:<VDFPoStCircuit<'a, Bls12> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &<VDFPoSt<H, V> as ProofScheme<'a>>::Proof,
        pub_params: &<VDFPoSt<H, V> as ProofScheme<'a>>::PublicParams,
        engine_params: &'a <Bls12 as JubjubEngine>::Params,
    ) -> VDFPoStCircuit<'a, Bls12> {
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
            params: engine_params,
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
            vdf_sloth_rounds: V::rounds(&pub_params.pub_params_vdf),
            challenged_leafs_vec,
            root_commitment: Some(compute_root_commitment(&pub_in.commitments).into()),
            commitments_vec,
            paths_vec,
        }
    }

    fn blank_circuit(
        pub_params: &<VDFPoSt<H, V> as ProofScheme>::PublicParams,
        engine_params: &'a <Bls12 as JubjubEngine>::Params,
    ) -> VDFPoStCircuit<'a, Bls12> {
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
            params: engine_params,
            challenges_vec,
            challenged_sectors_vec,
            challenge_seed: None,
            vdf_key: None,
            vdf_xs,
            vdf_ys,
            vdf_sloth_rounds: V::rounds(&pub_params.pub_params_vdf),
            challenged_leafs_vec,
            paths_vec,
            root_commitment: None,
            commitments_vec,
        }
    }
}

impl<'a, E: JubjubEngine> Circuit<E> for VDFPoStCircuit<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let params = self.params;
        let vdf_key = self.vdf_key;
        let vdf_ys = self.vdf_ys.clone();
        let vdf_xs = self.vdf_xs.clone();
        let vdf_sloth_rounds = self.vdf_sloth_rounds;
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

        let vdf_key = num::AllocatedNum::alloc(cs.namespace(|| "vdf_key"), || {
            vdf_key.ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        for (i, (y, x)) in vdf_ys.iter().zip(vdf_xs.iter()).enumerate() {
            {
                // VDF Verification
                let mut cs = cs.namespace(|| format!("vdf_verification_round_{}", i));
                //
                //                // FIXME: make this a generic call to Vdf proof circuit function.
                let decoded = sloth::decode(
                    cs.namespace(|| "sloth_decode"),
                    &vdf_key,
                    *y,
                    vdf_sloth_rounds,
                )?;

                let x_alloc = num::AllocatedNum::alloc(cs.namespace(|| "x"), || {
                    x.ok_or_else(|| SynthesisError::AssignmentMissing)
                })?;

                constraint::equal(&mut cs, || "equality", &x_alloc, &decoded);

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
            let mut cs = cs.namespace(|| format!("porc_verification_round_{}", i));
            porc::PoRCCircuit::synthesize(
                &mut cs,
                params,
                challenges_vec[i]
                    .iter()
                    .map(|c| c.map(|c| u32_into_fr::<E>(c as u32)))
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

fn verify_challenges<E: Engine, CS: ConstraintSystem<E>, T>(
    _cs: &mut CS,
    _challenges: Vec<&Option<E::Fr>>,
    _partial_challenge: &Option<E::Fr>,
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

impl<'a, E: JubjubEngine> VDFPoStCircuit<'a, E> {
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    pub fn synthesize<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        params: &E::Params,
        challenge_seed: Option<E::Fr>,
        vdf_key: Option<E::Fr>,
        vdf_ys: Vec<Option<E::Fr>>,
        vdf_xs: Vec<Option<E::Fr>>,
        vdf_sloth_rounds: usize,
        challenges_vec: Vec<Vec<Option<usize>>>,
        challenged_sectors_vec: Vec<Vec<Option<usize>>>,
        challenged_leafs_vec: Vec<Vec<Option<E::Fr>>>,
        root_commitment: Option<E::Fr>,
        commitments_vec: Vec<Vec<Option<E::Fr>>>,
        paths_vec: Vec<Vec<Vec<Option<(E::Fr, bool)>>>>,
    ) -> Result<(), SynthesisError> {
        VDFPoStCircuit {
            params,
            challenges_vec,
            challenged_sectors_vec,
            challenge_seed,
            vdf_key,
            vdf_ys,
            vdf_xs,
            vdf_sloth_rounds,
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

    use bellman::groth16;
    use pairing::Field;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::jubjub::JubjubBls12;

    use crate::circuit::test::*;
    use crate::compound_proof;
    use crate::drgraph::{new_seed, BucketGraph, Graph};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::pedersen::*;
    use crate::proof::ProofScheme;
    use crate::vdf_post;
    use crate::vdf_sloth;

    #[test]
    fn test_vdf_post_circuit_with_bls12_381() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let lambda = 32;

        let sp = vdf_post::SetupParams::<PedersenDomain, vdf_sloth::Sloth> {
            challenge_count: 10,
            sector_size: 1024 * lambda,
            post_epochs: 3,
            setup_params_vdf: vdf_sloth::SetupParams {
                key: rng.gen(),
                rounds: 1,
            },
            sectors_count: 2,
        };

        let pub_params = vdf_post::VDFPoSt::<PedersenHasher, vdf_sloth::Sloth>::setup(&sp).unwrap();

        let data0: Vec<u8> = (0..1024)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        let data1: Vec<u8> = (0..1024)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let graph0 = BucketGraph::<PedersenHasher>::new(1024, 5, 0, new_seed());
        let tree0 = graph0.merkle_tree(data0.as_slice()).unwrap();
        let graph1 = BucketGraph::<PedersenHasher>::new(1024, 5, 0, new_seed());
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
        .unwrap();

        assert!(
            vdf_post::VDFPoSt::<PedersenHasher, vdf_sloth::Sloth>::verify(
                &pub_params,
                &pub_inputs,
                &proof
            )
            .unwrap()
        );

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
            params,
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
            vdf_sloth_rounds: pub_params.pub_params_vdf.rounds,
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
        assert_eq!(cs.num_constraints(), 414670, "wrong number of constraints");
        assert_eq!(cs.get_input(0, "ONE"), Fr::one());
    }

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn test_vdf_post_compound() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let lambda = 32;

        let setup_params = compound_proof::SetupParams {
            vanilla_params: &vdf_post::SetupParams::<PedersenDomain, vdf_sloth::Sloth> {
                challenge_count: 3,
                sector_size: 1024 * lambda,
                post_epochs: 3,
                setup_params_vdf: vdf_sloth::SetupParams {
                    key: rng.gen(),
                    rounds: 1,
                },
                sectors_count: 2,
            },
            engine_params: params,
            partitions: None,
        };

        let pub_params: compound_proof::PublicParams<
            _,
            vdf_post::VDFPoSt<PedersenHasher, vdf_sloth::Sloth>,
        > = VDFPostCompound::setup(&setup_params).expect("setup failed");

        let data0: Vec<u8> = (0..1024)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        let data1: Vec<u8> = (0..1024)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let graph0 = BucketGraph::<PedersenHasher>::new(1024, 5, 0, new_seed());
        let tree0 = graph0.merkle_tree(data0.as_slice()).unwrap();
        let graph1 = BucketGraph::<PedersenHasher>::new(1024, 5, 0, new_seed());
        let tree1 = graph1.merkle_tree(data1.as_slice()).unwrap();

        let pub_inputs = vdf_post::PublicInputs {
            challenge_seed: rng.gen(),
            commitments: vec![tree0.root(), tree1.root()],
            faults: Vec::new(),
        };

        let trees = [&tree0, &tree1];
        let priv_inputs = //: vdf_post::PrivateInputs<PedersenHasher> =
            vdf_post::PrivateInputs::<PedersenHasher>::new(&trees[..]);

        let gparams: groth16::Parameters<_> =
            <VDFPostCompound as CompoundProof<
                '_,
                Bls12,
                VDFPoSt<PedersenHasher, _>,
                VDFPoStCircuit<_>,
            >>::groth_params(&pub_params.vanilla_params, &params)
            .unwrap();

        let proof = VDFPostCompound::prove(&pub_params, &pub_inputs, &priv_inputs, &gparams)
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

        let verified = VDFPostCompound::verify(&pub_params, &pub_inputs, &proof)
            .expect("failed while verifying");

        assert!(verified);
    }
}
