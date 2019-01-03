use bellman::{Circuit, ConstraintSystem, SynthesisError};
use pairing::bls12_381::{Bls12, Fr};
use sapling_crypto::jubjub::JubjubEngine;

use crate::bacon_post::BaconPoSt;
use crate::circuit::hvh_post;
use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::hasher::Hasher;
use crate::parameter_cache::{CacheableParameters, ParameterSetIdentifier};
use crate::proof::ProofScheme;
use crate::vdf::Vdf;

/// This is the `BACON-PoSt` circuit.
pub struct BaconPoStCircuit<'a, E: JubjubEngine> {
    /// Parameters for the engine.
    pub params: &'a E::Params,

    // Beacon
    // TODO:
    // pub beacon_randomness_vec: Vec<Option<E::Fr>>,
    // pub challenges_vec: Vec<Vec<Option<E::Fr>>>,

    // HVH-PoSt
    pub vdf_key: Option<E::Fr>,
    pub vdf_ys_vec: Vec<Vec<Option<E::Fr>>>,
    pub vdf_xs_vec: Vec<Vec<Option<E::Fr>>>,
    pub vdf_sloth_rounds: usize,
    pub challenged_leafs_vec_vec: Vec<Vec<Vec<Option<E::Fr>>>>,
    pub commitments_vec_vec: Vec<Vec<Vec<Option<E::Fr>>>>,
    pub paths_vec_vec: Vec<Vec<Vec<Vec<Option<(E::Fr, bool)>>>>>,
}

pub struct BaconPoStCompound {}

#[derive(Clone, Default)]
pub struct ComponentPrivateInputs {}

impl<'a, E: JubjubEngine> CircuitComponent for BaconPoStCircuit<'a, E> {
    type ComponentPrivateInputs = ComponentPrivateInputs;
}

impl<'a, H: Hasher, V: Vdf<H::Domain>>
    CompoundProof<'a, Bls12, BaconPoSt<H, V>, BaconPoStCircuit<'a, Bls12>> for BaconPoStCompound
where
    <V as Vdf<H::Domain>>::PublicParams: Send + Sync,
    <V as Vdf<H::Domain>>::Proof: Send + Sync,
    H: 'a,
{
    fn generate_public_inputs(
        _pub_in: &<BaconPoSt<H, V> as ProofScheme<'a>>::PublicInputs,
        _pub_params: &<BaconPoSt<H, V> as ProofScheme<'a>>::PublicParams,
        _partition_k: Option<usize>,
    ) -> Vec<Fr> {
        unimplemented!();
    }
    fn circuit(
        _pub_in: &<BaconPoSt<H, V> as ProofScheme<'a>>::PublicInputs,
        _component_private_inputs:<BaconPoStCircuit<'a, Bls12> as CircuitComponent>::ComponentPrivateInputs,
        _vanilla_proof: &<BaconPoSt<H, V> as ProofScheme<'a>>::Proof,
        _pub_params: &<BaconPoSt<H, V> as ProofScheme<'a>>::PublicParams,
        _engine_params: &'a <Bls12 as JubjubEngine>::Params,
    ) -> BaconPoStCircuit<'a, Bls12> {
        unimplemented!()
    }
}

impl<E: JubjubEngine, C: Circuit<E>, P: ParameterSetIdentifier> CacheableParameters<E, C, P>
    for BaconPoStCompound
{
    fn cache_prefix() -> String {
        String::from("bacon-post")
    }
}

// fn extract_post_input<E: JubjubEngine, CS: ConstraintSystem<E>>(
//     _cs: &mut CS,
//     _params: &E::Params,
// ) -> Result<num::AllocatedNum<E>, SynthesisError> {
//     unimplemented!()
// }

// fn derive_challenges<E: JubjubEngine, CS: ConstraintSystem<E>>(
//     cs: &mut CS,
//     params: &E::Params,
//     count: usize,
//     t: usize,
//     x: Option<&num::AllocatedNum<E>>,
//     r: &num::AllocatedNum<E>,
// ) -> Result<Vec<num::AllocatedNum<E>>, SynthesisError> {
//     let t_u32 = uint32::UInt32::alloc(cs.namespace(|| "t_u32"), Some(t as u32))?;
//     let t_bits = t_u32.into_bits();
//     let x_bits = x.map(|x| x.into_bits_le(cs.namespace(|| "x_bits")));

//     let mut res = Vec::new();
//     for i in 0..count {
//         let mut cs = cs.namespace(|| format!("count_{}", i));
//         let i_u32 = uint32::UInt32::alloc(cs.namespace(|| "i_u32"), Some(i as u32))?;

//         let mut bits: Vec<Boolean> = Vec::new();

//         if let Some(x_bits) = x_bits {
//             bits.extend(x_bits.as_ref()?);
//         }

//         bits.extend(r.into_bits_le(cs.namespace(|| "r_bits"))?);
//         bits.extend(&t_bits);
//         bits.extend(i_u32.into_bits());

//         let h =
//             pedersen_compression_num(cs.namespace(|| format!("hash_{}", i)), params, &bits[..])?;
//         res.push(h);
//     }

//     Ok(res)
// }

impl<'a, E: JubjubEngine> Circuit<E> for BaconPoStCircuit<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let post_periods_count = self.vdf_ys_vec.len();

        assert_eq!(self.vdf_xs_vec.len(), post_periods_count);
        assert_eq!(self.challenged_leafs_vec_vec.len(), post_periods_count);
        assert_eq!(self.commitments_vec_vec.len(), post_periods_count);
        assert_eq!(self.paths_vec_vec.len(), post_periods_count);
        // assert_eq!(self.beacon_randomness_vec.len(), post_periods_count);
        // assert_eq!(self.challenges_vec.len(), post_periods_count);

        // t = 0
        {
            // let mut cs = cs.namespace(|| "t_0");
            // let r = num::AllocatedNum::alloc(cs.namespace(|| "r"), || {
            //     self.beacon_randomness_vec[0].ok_or_else(|| SynthesisError::AssignmentMissing)
            // })?;

            // let challenges = derive_challenges(
            //     cs.namespace(|| "derive_challenge"),
            //     self.params,
            //     0,
            //     None,
            //     &r,
            // )?;
            // for (actual, expected) in challenges.iter().zip(self.challenges_vec[0].iter()) {
            //     let mut cs = cs.namespace(|| format!("challenge_check_{}", i));

            //     let expected_num = num::AllocatedNum::alloc(cs.namespace(|| "expected"), || {
            //         expected.ok_or_else(|| SynthesisError::AssignmentMissing)
            //     })?;

            //     constraint::equal(&mut cs, || "challenge_equality", actual, expected_num);
            // }

            hvh_post::HvhPostCircuit::synthesize(
                &mut cs.namespace(|| "hvh_post"),
                self.params,
                self.vdf_key,
                self.vdf_ys_vec[0].clone(),
                self.vdf_xs_vec[0].clone(),
                self.vdf_sloth_rounds,
                self.challenged_leafs_vec_vec[0].clone(),
                self.commitments_vec_vec[0].clone(),
                self.paths_vec_vec[0].clone(),
            )?;
        }

        // t = 1..periods_count
        for t in 1..post_periods_count {
            let mut cs = cs.namespace(|| format!("t_{}", t));

            // let r = num::AllocatedNum::alloc(cs.namespace(|| "r"), || {
            //     self.beacon_randomness_vec[t].ok_or_else(|| SynthesisError::AssignmentMissing)
            // })?;

            // let x = extract_post_input(cs.namespace(|| "extract_post_input"), self.params)?;

            // let challenges = derive_challenges(
            //     cs.namespace(|| "derive_challenge"),
            //     self.params,
            //     t,
            //     Some(&x),
            //     &r,
            // )?;
            // for (actual, expected) in challenges.iter().zip(self.challenges_vec[t].iter()) {
            //     let mut cs = cs.namespace(|| format!("challenge_check_{}", i));

            //     let expected_num = num::AllocatedNum::alloc(cs.namespace(|| "expected"), || {
            //         expected.ok_or_else(|| SynthesisError::AssignmentMissing)
            //     })?;

            //     constraint::equal(&mut cs, || "challenge_equality", actual, expected_num);
            // }

            hvh_post::HvhPostCircuit::synthesize(
                &mut cs.namespace(|| "hvh_post"),
                self.params,
                self.vdf_key,
                self.vdf_ys_vec[t].clone(),
                self.vdf_xs_vec[t].clone(),
                self.vdf_sloth_rounds,
                self.challenged_leafs_vec_vec[t].clone(),
                self.commitments_vec_vec[t].clone(),
                self.paths_vec_vec[t].clone(),
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use pairing::Field;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::jubjub::JubjubBls12;

    use crate::bacon_post;
    use crate::circuit::test::*;
    use crate::drgraph::{new_seed, BucketGraph, Graph};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::pedersen::*;
    use crate::hvh_post;
    //use crate::proof::ProofScheme;
    use crate::vdf_sloth;

    #[test]
    fn test_bacon_post_circuit_with_bls12_381() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let lambda = 32;

        let sp = bacon_post::SetupParams::<PedersenDomain, vdf_sloth::Sloth> {
            setup_params_hvh_post: hvh_post::SetupParams::<PedersenDomain, vdf_sloth::Sloth> {
                challenge_count: 4,
                sector_size: 256 * lambda,
                post_epochs: 3,
                setup_params_vdf: vdf_sloth::SetupParams {
                    key: rng.gen(),
                    rounds: 1,
                },
                sectors_count: 2,
            },
            post_periods_count: 3,
        };

        let pub_params =
            bacon_post::BaconPoSt::<PedersenHasher, vdf_sloth::Sloth>::setup(&sp).unwrap();

        let data0: Vec<u8> = (0..256)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        let data1: Vec<u8> = (0..256)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let graph0 = BucketGraph::<PedersenHasher>::new(256, 5, 0, new_seed());
        let tree0 = graph0.merkle_tree(data0.as_slice()).unwrap();
        let graph1 = BucketGraph::<PedersenHasher>::new(256, 5, 0, new_seed());
        let tree1 = graph1.merkle_tree(data1.as_slice()).unwrap();

        let pub_inputs = bacon_post::PublicInputs {
            commitments: vec![tree0.root(), tree1.root()],
        };
        let replicas = [&data0[..], &data1[..]];
        let trees = [&tree0, &tree1];
        let priv_inputs = bacon_post::PrivateInputs::new(&replicas[..], &trees[..]);

        let proof = BaconPoSt::prove(&pub_params, &pub_inputs, &priv_inputs).unwrap();

        assert!(BaconPoSt::verify(&pub_params, &pub_inputs, &proof).unwrap());

        // actual circuit test

        let vdf_ys_vec = proof
            .proofs()
            .iter()
            .map(|proof| {
                proof
                    .ys
                    .iter()
                    .map(|y: &PedersenDomain| Some(y.clone().into()))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let vdf_xs_vec = proof
            .proofs()
            .iter()
            .map(|proof| {
                proof
                    .porep_proofs
                    .iter()
                    .take(vdf_ys_vec[0].len())
                    .map(|p| Some(hvh_post::extract_vdf_input::<PedersenHasher>(p).into()))
                    .collect()
            })
            .collect::<Vec<_>>();

        let mut paths_vec_vec = Vec::new();
        let mut challenged_leafs_vec_vec = Vec::new();
        let mut commitments_vec_vec = Vec::new();

        for p in proof.proofs() {
            let mut paths_vec = Vec::new();
            let mut challenged_leafs_vec = Vec::new();
            let mut commitments_vec = Vec::new();

            for porep_proof in &p.porep_proofs {
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

            paths_vec_vec.push(paths_vec);
            challenged_leafs_vec_vec.push(challenged_leafs_vec);
            commitments_vec_vec.push(commitments_vec);
        }

        let mut cs = TestConstraintSystem::<Bls12>::new();

        let instance = BaconPoStCircuit {
            params,
            // beacon_randomness_vec,
            // challenges_vec,
            vdf_key: Some(pub_params.pub_params_hvh_post.pub_params_vdf.key.into()),
            vdf_xs_vec,
            vdf_ys_vec,
            vdf_sloth_rounds: pub_params.pub_params_hvh_post.pub_params_vdf.rounds,
            challenged_leafs_vec_vec,
            paths_vec_vec,
            commitments_vec_vec,
        };

        instance
            .synthesize(&mut cs)
            .expect("failed to synthesize circuit");

        assert!(cs.is_satisfied(), "constraints not satisfied");

        assert_eq!(cs.num_inputs(), 115, "wrong number of inputs");
        assert_eq!(cs.num_constraints(), 398196, "wrong number of constraints");
        assert_eq!(cs.get_input(0, "ONE"), Fr::one());
    }
}
