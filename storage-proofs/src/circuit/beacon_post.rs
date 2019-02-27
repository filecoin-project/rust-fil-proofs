use std::marker::PhantomData;

use bellman::{Circuit, ConstraintSystem, SynthesisError};
use pairing::bls12_381::{Bls12, Fr};
use sapling_crypto::jubjub::JubjubEngine;

use crate::beacon_post::BeaconPoSt;
use crate::circuit::vdf_post;
use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::hasher::Hasher;
use crate::parameter_cache::{CacheableParameters, ParameterSetIdentifier};
use crate::proof::ProofScheme;
use crate::vdf::Vdf;

/// This is the `Beacon-PoSt` circuit.
pub struct BeaconPoStCircuit<'a, E: JubjubEngine, H: Hasher, V: Vdf<H::Domain>> {
    /// Parameters for the engine.
    pub params: &'a E::Params,

    // VDF-PoSt
    pub challenge_seed: Option<E::Fr>,
    pub vdf_key: Option<E::Fr>,
    pub vdf_ys_vec: Vec<Vec<Option<E::Fr>>>,
    pub vdf_xs_vec: Vec<Vec<Option<E::Fr>>>,
    pub vdf_sloth_rounds: usize,
    pub challenges_vec_vec: Vec<Vec<Vec<Option<usize>>>>,
    pub challenged_sectors_vec_vec: Vec<Vec<Vec<Option<usize>>>>,
    pub challenged_leafs_vec_vec: Vec<Vec<Vec<Option<E::Fr>>>>,
    pub root_commitment: Option<E::Fr>,
    pub commitments_vec_vec: Vec<Vec<Vec<Option<E::Fr>>>>,
    #[allow(clippy::type_complexity)]
    pub paths_vec_vec: Vec<Vec<Vec<Vec<Option<(E::Fr, bool)>>>>>,
    _h: PhantomData<H>,
    _v: PhantomData<V>,
}

pub struct BeaconPoStCompound {}

#[derive(Clone, Default)]
pub struct ComponentPrivateInputs {}

impl<'a, E: JubjubEngine, H: Hasher, V: Vdf<H::Domain>> CircuitComponent
    for BeaconPoStCircuit<'a, E, H, V>
{
    type ComponentPrivateInputs = ComponentPrivateInputs;
}

impl<'a, H: Hasher, V: Vdf<H::Domain>>
    CompoundProof<'a, Bls12, BeaconPoSt<H, V>, BeaconPoStCircuit<'a, Bls12, H, V>>
    for BeaconPoStCompound
where
    <V as Vdf<H::Domain>>::PublicParams: Send + Sync,
    <V as Vdf<H::Domain>>::Proof: Send + Sync,
    V: Sync + Send,
    H: 'a,
{
    fn generate_public_inputs(
        _pub_in: &<BeaconPoSt<H, V> as ProofScheme<'a>>::PublicInputs,
        _pub_params: &<BeaconPoSt<H, V> as ProofScheme<'a>>::PublicParams,
        _partition_k: Option<usize>,
    ) -> Vec<Fr> {
        unimplemented!();
    }
    fn circuit(
        _pub_in: &<BeaconPoSt<H, V> as ProofScheme<'a>>::PublicInputs,
        _component_private_inputs:<BeaconPoStCircuit<'a, Bls12,H,V> as CircuitComponent>::ComponentPrivateInputs,
        _vanilla_proof: &<BeaconPoSt<H, V> as ProofScheme<'a>>::Proof,
        _pub_params: &<BeaconPoSt<H, V> as ProofScheme<'a>>::PublicParams,
        _engine_params: &'a <Bls12 as JubjubEngine>::Params,
    ) -> BeaconPoStCircuit<'a, Bls12, H, V> {
        unimplemented!()
    }

    fn blank_circuit(
        _public_params: &<BeaconPoSt<H, V> as ProofScheme<'a>>::PublicParams,
        _engine_params: &'a <Bls12 as JubjubEngine>::Params,
    ) -> BeaconPoStCircuit<'a, Bls12, H, V> {
        unimplemented!("")
    }
}

impl<E: JubjubEngine, C: Circuit<E>, P: ParameterSetIdentifier> CacheableParameters<E, C, P>
    for BeaconPoStCompound
{
    fn cache_prefix() -> String {
        String::from("beacon-post")
    }
}

impl<'a, E: JubjubEngine, H: Hasher, V: Vdf<H::Domain>> Circuit<E>
    for BeaconPoStCircuit<'a, E, H, V>
{
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let post_periods_count = self.vdf_ys_vec.len();

        assert_eq!(self.vdf_xs_vec.len(), post_periods_count);
        assert_eq!(self.challenged_leafs_vec_vec.len(), post_periods_count);
        assert_eq!(self.commitments_vec_vec.len(), post_periods_count);
        assert_eq!(self.paths_vec_vec.len(), post_periods_count);

        for t in 0..post_periods_count {
            let mut cs = cs.namespace(|| format!("t_{}", t));
            vdf_post::VDFPoStCircuit::synthesize(
                &mut cs.namespace(|| "vdf_post"),
                self.params,
                self.challenge_seed,
                self.vdf_key,
                self.vdf_ys_vec[t].clone(),
                self.vdf_xs_vec[t].clone(),
                self.vdf_sloth_rounds,
                self.challenges_vec_vec[t].clone(),
                self.challenged_sectors_vec_vec[t].clone(),
                self.challenged_leafs_vec_vec[t].clone(),
                self.root_commitment,
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

    use crate::beacon_post::{self, Beacon};
    use crate::circuit::test::*;
    use crate::drgraph::{new_seed, BucketGraph, Graph};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::pedersen::*;
    use crate::vdf_post::{self, compute_root_commitment};
    use crate::vdf_sloth;

    #[test]
    fn test_beacon_post_circuit_with_bls12_381() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let lambda = 32;

        let sp = beacon_post::SetupParams::<PedersenDomain, vdf_sloth::Sloth> {
            vdf_post_setup_params: vdf_post::SetupParams::<PedersenDomain, vdf_sloth::Sloth> {
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
            beacon_post::BeaconPoSt::<PedersenHasher, vdf_sloth::Sloth>::setup(&sp).unwrap();

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

        let pub_inputs = beacon_post::PublicInputs {
            commitments: vec![tree0.root(), tree1.root()],
        };
        let replicas = [&data0[..], &data1[..]];
        let trees = [&tree0, &tree1];
        let priv_inputs = beacon_post::PrivateInputs::new(&replicas[..], &trees[..]);

        let proof = BeaconPoSt::prove(&pub_params, &pub_inputs, &priv_inputs).unwrap();

        assert!(BeaconPoSt::verify(&pub_params, &pub_inputs, &proof).unwrap());

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
                    .map(|p| Some(vdf_post::extract_vdf_input::<PedersenHasher>(p).into()))
                    .collect()
            })
            .collect::<Vec<_>>();

        let mut paths_vec_vec = Vec::new();
        let mut challenged_leafs_vec_vec = Vec::new();
        let mut commitments_vec_vec = Vec::new();
        let mut challenges_vec_vec = Vec::new();
        let mut challenged_sectors_vec_vec = Vec::new();
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
            challenges_vec_vec.push(
                p.challenges
                    .iter()
                    .map(|v| v.iter().map(|&s| Some(s)).collect())
                    .collect(),
            );
            challenged_sectors_vec_vec.push(
                p.challenged_sectors
                    .iter()
                    .map(|v| v.iter().map(|&s| Some(s)).collect())
                    .collect(),
            )
        }

        let mut cs = TestConstraintSystem::<Bls12>::new();

        let mut beacon = Beacon::default();

        let instance = BeaconPoStCircuit::<Bls12, PedersenHasher, vdf_sloth::Sloth> {
            params,
            // beacon_randomness_vec,
            // challenges_vec,
            challenges_vec_vec,
            challenged_sectors_vec_vec,
            challenge_seed: Some(beacon.get::<PedersenDomain>(0).into()),
            vdf_key: Some(pub_params.vdf_post_pub_params.pub_params_vdf.key.into()),
            vdf_xs_vec,
            vdf_ys_vec,
            vdf_sloth_rounds: pub_params.vdf_post_pub_params.pub_params_vdf.rounds,
            challenged_leafs_vec_vec,
            paths_vec_vec,
            root_commitment: Some(compute_root_commitment(&pub_inputs.commitments).into()),
            commitments_vec_vec,
            _h: PhantomData,
            _v: PhantomData,
        };

        instance
            .synthesize(&mut cs)
            .expect("failed to synthesize circuit");

        assert!(cs.is_satisfied(), "constraints not satisfied");

        assert_eq!(cs.num_inputs(), 7, "wrong number of inputs");
        assert_eq!(cs.num_constraints(), 398118, "wrong number of constraints");
        assert_eq!(cs.get_input(0, "ONE"), Fr::one());
    }
}
