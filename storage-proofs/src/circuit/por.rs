use std::marker::PhantomData;

use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use fil_sapling_crypto::circuit::boolean::{AllocatedBit, Boolean};
use fil_sapling_crypto::circuit::multipack;
use fil_sapling_crypto::circuit::num::AllocatedNum;
use fil_sapling_crypto::jubjub::{JubjubBls12, JubjubEngine};
use paired::bls12_381::{Bls12, Fr};

use crate::circuit::constraint;
use crate::circuit::variables::Root;
use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::drgraph::graph_height;
use crate::hasher::{HashFunction, Hasher};
use crate::hybrid_merklepor::HybridMerklePoR;
use crate::parameter_cache::{CacheableParameters, ParameterSetMetadata};
use crate::proof::ProofScheme;

/// Proof of retrievability.
///
/// # Fields
///
/// * `params` - The params for the bls curve.
/// * `value` - The value of the leaf.
/// * `auth_path` - The authentication path of the leaf in the tree.
/// * `root` - The merkle root of the tree.
///
pub struct PoRCircuit<'a, E, AH, BH>
where
    E: JubjubEngine,
    AH: Hasher,
    BH: Hasher,
{
    params: &'a E::Params,
    value: Option<E::Fr>,
    auth_path: Vec<Option<(E::Fr, bool)>>,
    root: Root<E>,
    beta_height: usize,
    private: bool,
    _ah: PhantomData<AH>,
    _bh: PhantomData<BH>,
}

impl<'a, E, AH, BH> CircuitComponent for PoRCircuit<'a, E, AH, BH>
where
    E: JubjubEngine,
    AH: Hasher,
    BH: Hasher,
{
    type ComponentPrivateInputs = Option<Root<E>>;
}

pub struct PoRCompound<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    _ah: PhantomData<AH>,
    _bh: PhantomData<BH>,
}

pub fn challenge_into_auth_path_bits(challenge: usize, leaves: usize) -> Vec<bool> {
    let height = graph_height(leaves);
    let mut bits = Vec::new();
    let mut n = challenge;
    for _ in 0..height {
        bits.push(n & 1 == 1);
        n >>= 1;
    }
    bits
}

impl<E, C, P, AH, BH> CacheableParameters<E, C, P> for PoRCompound<AH, BH>
where
    E: JubjubEngine,
    C: Circuit<E>,
    P: ParameterSetMetadata,
    AH: Hasher,
    BH: Hasher,
{
    fn cache_prefix() -> String {
        format!("proof-of-retrievability-{}-{}", AH::name(), BH::name())
    }
}

// Can only implement for `Bls12` because `HybridMerklePoR` is not generic over the engine.
impl<'a, AH, BH> CompoundProof<'a, Bls12, HybridMerklePoR<AH, BH>, PoRCircuit<'a, Bls12, AH, BH>>
    for PoRCompound<AH, BH>
where
    AH: 'static + Hasher,
    BH: 'static + Hasher,
{
    fn circuit<'b>(
        public_inputs: &<HybridMerklePoR<AH, BH> as ProofScheme<'a>>::PublicInputs,
        _component_private_inputs: <PoRCircuit<'a, Bls12, AH, BH> as CircuitComponent>::ComponentPrivateInputs,
        proof: &'b <HybridMerklePoR<AH, BH> as ProofScheme<'a>>::Proof,
        public_params: &'b <HybridMerklePoR<AH, BH> as ProofScheme<'a>>::PublicParams,
        engine_params: &'a JubjubBls12,
    ) -> PoRCircuit<'a, Bls12, AH, BH> {
        let (root, private) = match (*public_inputs).commitment {
            None => {
                let root: Fr = (*proof.proof.root()).into();
                (Root::Val(Some(root)), true)
            }
            Some(commitment) => (Root::Val(Some(commitment.into())), false),
        };

        // Ensure inputs are consistent with public params.
        assert_eq!(private, public_params.private);

        PoRCircuit {
            params: engine_params,
            value: Some(proof.data.into()),
            auth_path: proof.proof.as_options(),
            root,
            beta_height: public_params.beta_height,
            private,
            _ah: PhantomData,
            _bh: PhantomData,
        }
    }

    fn blank_circuit(
        public_params: &<HybridMerklePoR<AH, BH> as ProofScheme<'a>>::PublicParams,
        params: &'a JubjubBls12,
    ) -> PoRCircuit<'a, Bls12, AH, BH> {
        PoRCircuit {
            params,
            value: None,
            auth_path: vec![None; graph_height(public_params.leaves)],
            root: Root::Val(None),
            beta_height: public_params.beta_height,
            private: public_params.private,
            _ah: PhantomData,
            _bh: PhantomData,
        }
    }

    fn generate_public_inputs(
        pub_inputs: &<HybridMerklePoR<AH, BH> as ProofScheme<'a>>::PublicInputs,
        pub_params: &<HybridMerklePoR<AH, BH> as ProofScheme<'a>>::PublicParams,
        _k: Option<usize>,
    ) -> Vec<Fr> {
        let auth_path_bits = challenge_into_auth_path_bits(pub_inputs.challenge, pub_params.leaves);
        let packed_auth_path = multipack::compute_multipacking::<Bls12>(&auth_path_bits);

        let mut inputs = Vec::new();
        inputs.extend(packed_auth_path);

        if let Some(commitment) = pub_inputs.commitment {
            assert!(!pub_params.private);
            inputs.push(commitment.into());
        } else {
            assert!(pub_params.private);
        }

        inputs
    }
}

impl<'a, E, AH, BH> Circuit<E> for PoRCircuit<'a, E, AH, BH>
where
    E: JubjubEngine,
    AH: Hasher,
    BH: Hasher,
{
    /// # Public Inputs
    ///
    /// This circuit expects the following public inputs.
    ///
    /// * [0] - packed version of the `is_right` components of the auth_path.
    /// * [1] - the merkle root of the tree.
    ///
    /// This circuit derives the following private inputs from its fields:
    /// * value_num - packed version of `value` as bits. (might be more than one Fr)
    ///
    /// Note: All public inputs must be provided as `E::Fr`.
    fn synthesize<CS>(self, cs: &mut CS) -> Result<(), SynthesisError>
    where
        E: JubjubEngine,
        CS: ConstraintSystem<E>,
    {
        // Allocate the leaf value.
        let value = AllocatedNum::alloc(cs.namespace(|| "value"), || {
            self.value.ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        let params = self.params;
        let auth_path = self.auth_path;
        let root = self.root;

        let auth_path_len = auth_path.len();
        let mut auth_path_bits: Vec<Boolean> = Vec::with_capacity(auth_path_len);

        let mut cur = value;

        for (i, opt) in auth_path.into_iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("merkle tree hash {}", i));

            // Allocate a bit which describes if `cur` is a right input to the Merkle hash. If `cur`
            // is the right input then `path_elem` is the left input.
            let cur_is_right = Boolean::from(AllocatedBit::alloc(
                cs.namespace(|| "position bit"),
                opt.map(|(_path_elem, path_elem_is_left)| path_elem_is_left),
            )?);

            // Allocate the path element.
            let path_elem = AllocatedNum::alloc(cs.namespace(|| "path element"), || {
                opt.map(|(path_elem, _path_elem_is_left)| path_elem)
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

            // Determine the left and right Merkle hash inputs. Swap `cur` with `path_elem` if `cur`
            // is the right Merkle hash input.
            let (left_input, right_input) = AllocatedNum::conditionally_reverse(
                cs.namespace(|| "conditional reversal of preimage"),
                &cur,
                &path_elem,
                &cur_is_right,
            )?;

            let left_input_bits =
                left_input.into_bits_le(cs.namespace(|| "left input into bits"))?;

            let right_input_bits =
                right_input.into_bits_le(cs.namespace(|| "right input into bits"))?;

            cur = if i < self.beta_height {
                BH::Function::hash_leaf_circuit(
                    cs.namespace(|| "computation of beta hash"),
                    &left_input_bits,
                    &right_input_bits,
                    i,
                    params,
                )?
            } else {
                AH::Function::hash_leaf_circuit(
                    cs.namespace(|| "computation of alpha hash"),
                    &left_input_bits,
                    &right_input_bits,
                    i,
                    params,
                )?
            };

            auth_path_bits.push(cur_is_right);
        }

        // Compactly allocate `auth_path_bits` as inputs (each bit is not allocated individually,
        // many bits are allocated using a single `Fr` allocation).
        multipack::pack_into_inputs(cs.namespace(|| "path"), &auth_path_bits)?;

        // Validate that the calculated Merkle Tree root is the same as the input (`self.root`).
        let calculated_root = cur;
        let input_root = root.allocated(cs.namespace(|| "root_value"))?;
        constraint::equal(
            cs,
            || "enforce root is correct",
            &calculated_root,
            &input_root,
        );

        // If `private` is not set, expose the root as a public input.
        if !self.private {
            input_root.inputize(cs.namespace(|| "root"))?;
        }

        Ok(())
    }
}

impl<'a, E, AH, BH> PoRCircuit<'a, E, AH, BH>
where
    E: JubjubEngine,
    AH: Hasher,
    BH: Hasher,
{
    pub fn synthesize<CS>(
        mut cs: CS,
        params: &E::Params,
        value: Option<E::Fr>,
        auth_path: Vec<Option<(E::Fr, bool)>>,
        root: Root<E>,
        beta_height: usize,
        private: bool,
    ) -> Result<(), SynthesisError>
    where
        E: JubjubEngine,
        CS: ConstraintSystem<E>,
    {
        let por = PoRCircuit::<E, AH, BH> {
            params,
            value,
            auth_path,
            root,
            beta_height,
            private,
            _ah: PhantomData,
            _bh: PhantomData,
        };

        por.synthesize(&mut cs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::proof::NoRequirements;
    use ff::Field;
    use fil_sapling_crypto::circuit::multipack;
    use fil_sapling_crypto::jubjub::JubjubBls12;
    use rand::{Rng, SeedableRng, XorShiftRng};

    use crate::circuit::test::*;
    use crate::compound_proof::{self, CompoundProof};
    use crate::drgraph::{new_seed, BucketGraph, Graph};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::blake2s::Blake2sDomain;
    use crate::hasher::hybrid::HybridDomain;
    use crate::hasher::{Blake2sHasher, Domain, Hasher, PedersenHasher};
    use crate::hybrid_merklepor;
    use crate::proof::ProofScheme;
    use crate::settings;
    use crate::util::data_at_node;

    #[test]
    #[ignore] // Slow test – run only when compiled for release.
    fn por_test_compound() {
        const N_LEAVES: usize = 8;
        const BETA_HEIGHT: usize = 1;

        let window_size = settings::SETTINGS
            .lock()
            .unwrap()
            .pedersen_hash_exp_window_size;

        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let data: Vec<u8> = (0..N_LEAVES)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        let graph = BucketGraph::<PedersenHasher, Blake2sHasher>::new(N_LEAVES, 16, 0, new_seed());
        let tree = graph
            .hybrid_merkle_tree(data.as_slice(), BETA_HEIGHT)
            .unwrap();

        for i in 0..3 {
            let public_inputs = hybrid_merklepor::PublicInputs {
                challenge: i,
                commitment: Some(tree.root()),
            };

            let setup_params = compound_proof::SetupParams {
                vanilla_params: &hybrid_merklepor::SetupParams {
                    leaves: N_LEAVES,
                    beta_height: BETA_HEIGHT,
                    private: false,
                },
                engine_params: &JubjubBls12::new_with_window_size(window_size),
                partitions: None,
            };
            let public_params = PoRCompound::<PedersenHasher, Blake2sHasher>::setup(&setup_params)
                .expect("setup failed");

            // Convert the challenge's bytes into a `HybridDomain`. Because `BETA_HEIGHT` is set to
            // `1` the leaves in the tree will be `HybridDomain::Beta`s.
            let leaf = {
                let leaf_bytes = data_at_node(data.as_slice(), public_inputs.challenge).unwrap();
                let leaf_beta = Blake2sDomain::try_from_bytes(&leaf_bytes).unwrap();
                HybridDomain::Beta(leaf_beta)
            };

            let private_inputs =
                hybrid_merklepor::PrivateInputs::<PedersenHasher, Blake2sHasher>::new(leaf, &tree);

            let gparams = PoRCompound::<PedersenHasher, Blake2sHasher>::groth_params(
                &public_params.vanilla_params,
                setup_params.engine_params,
            )
            .expect("failed to generate groth params");

            let proof = PoRCompound::<PedersenHasher, Blake2sHasher>::prove(
                &public_params,
                &public_inputs,
                &private_inputs,
                &gparams,
            )
            .expect("failed while proving");

            let verified = PoRCompound::<PedersenHasher, Blake2sHasher>::verify(
                &public_params,
                &public_inputs,
                &proof,
                &NoRequirements,
            )
            .expect("failed while verifying");
            assert!(verified);

            let (circuit, inputs) = PoRCompound::<PedersenHasher, Blake2sHasher>::circuit_for_test(
                &public_params,
                &public_inputs,
                &private_inputs,
            );

            let mut cs = TestConstraintSystem::new();

            circuit.synthesize(&mut cs).expect("failed to synthesize");
            assert!(cs.is_satisfied());
            assert!(cs.verify(&inputs));
        }
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_pedersen() {
        test_por_input_circuit_with_bls12_381::<PedersenHasher, Blake2sHasher>(24272);
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_blake2s() {
        test_por_input_circuit_with_bls12_381::<Blake2sHasher, Blake2sHasher>(64566);
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_pedersen_blake2s() {
        test_por_input_circuit_with_bls12_381::<PedersenHasher, Blake2sHasher>(24272);
    }

    fn test_por_input_circuit_with_bls12_381<AH, BH>(num_constraints: usize)
    where
        AH: 'static + Hasher,
        BH: 'static + Hasher,
    {
        const N_LEAVES: usize = 8;
        const BETA_HEIGHT: usize = 1;

        let window_size = settings::SETTINGS
            .lock()
            .unwrap()
            .pedersen_hash_exp_window_size;
        let params = &JubjubBls12::new_with_window_size(window_size);

        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for challenge_index in 0..N_LEAVES {
            // -- Basic Setup

            let data: Vec<u8> = (0..N_LEAVES)
                .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
                .collect();

            let graph = BucketGraph::<AH, BH>::new(N_LEAVES, 16, 0, new_seed());
            let tree = graph
                .hybrid_merkle_tree(data.as_slice(), BETA_HEIGHT)
                .unwrap();

            // -- HybridMerklePoR

            let pub_params = hybrid_merklepor::PublicParams {
                leaves: N_LEAVES,
                beta_height: BETA_HEIGHT,
                private: true,
            };
            let pub_inputs = hybrid_merklepor::PublicInputs::<AH::Domain, BH::Domain> {
                challenge: challenge_index,
                commitment: Some(tree.root()),
            };

            // Convert the challenge's bytes into a `HybridDomain`. Because `BETA_HEIGHT` is set to
            // `1` the leaves in the tree will be `HybridDomain::Beta`s.
            let leaf = {
                let leaf_bytes = data_at_node(data.as_slice(), pub_inputs.challenge).unwrap();
                let leaf_beta = BH::Domain::try_from_bytes(&leaf_bytes).unwrap();
                HybridDomain::Beta(leaf_beta)
            };

            let priv_inputs = hybrid_merklepor::PrivateInputs::<AH, BH>::new(leaf, &tree);

            // create a non circuit proof
            let proof = hybrid_merklepor::HybridMerklePoR::<AH, BH>::prove(
                &pub_params,
                &pub_inputs,
                &priv_inputs,
            )
            .expect("proving failed");

            // make sure it verifies
            let is_valid = hybrid_merklepor::HybridMerklePoR::<AH, BH>::verify(
                &pub_params,
                &pub_inputs,
                &proof,
            )
            .expect("verification failed");
            assert!(is_valid, "failed to verify hybrid merklepor proof");

            // -- Circuit

            let mut cs = TestConstraintSystem::<Bls12>::new();
            let por = PoRCircuit::<Bls12, AH, BH> {
                params,
                value: Some(proof.data.into()),
                auth_path: proof.proof.as_options(),
                root: Root::Val(Some(pub_inputs.commitment.unwrap().into())),
                beta_height: BETA_HEIGHT,
                private: false,
                _ah: PhantomData,
                _bh: PhantomData,
            };

            por.synthesize(&mut cs).expect("circuit synthesis failed");
            assert!(cs.is_satisfied(), "constraints not satisfied");

            assert_eq!(cs.num_inputs(), 3, "wrong number of inputs");
            assert_eq!(
                cs.num_constraints(),
                num_constraints,
                "wrong number of constraints"
            );

            let auth_path_bits: Vec<bool> = proof
                .proof
                .path()
                .iter()
                .map(|(_, is_right)| *is_right)
                .collect();
            let packed_auth_path = multipack::compute_multipacking::<Bls12>(&auth_path_bits);

            let mut expected_inputs = Vec::new();
            expected_inputs.extend(packed_auth_path);
            expected_inputs.push(pub_inputs.commitment.unwrap().into());

            assert_eq!(cs.get_input(0, "ONE"), Fr::one(), "wrong input 0");

            assert_eq!(
                cs.get_input(1, "path/input 0"),
                expected_inputs[0],
                "wrong packed_auth_path"
            );

            assert_eq!(
                cs.get_input(2, "root/input variable"),
                expected_inputs[1],
                "wrong root input"
            );

            assert!(cs.is_satisfied(), "constraints are not all satisfied");
            assert!(cs.verify(&expected_inputs), "failed to verify inputs");
        }
    }

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn test_private_por_compound_pedersen() {
        private_por_test_compound::<PedersenHasher, PedersenHasher>();
    }

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn test_private_por_compound_blake2s() {
        private_por_test_compound::<Blake2sHasher, Blake2sHasher>();
    }

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn test_private_por_compound_pedersen_blake2s() {
        private_por_test_compound::<PedersenHasher, Blake2sHasher>();
    }

    fn private_por_test_compound<AH, BH>()
    where
        AH: 'static + Hasher,
        BH: 'static + Hasher,
    {
        const N_LEAVES: usize = 8;
        const BETA_HEIGHT: usize = 1;

        let window_size = settings::SETTINGS
            .lock()
            .unwrap()
            .pedersen_hash_exp_window_size;

        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let data: Vec<u8> = (0..N_LEAVES)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        let graph = BucketGraph::<AH, BH>::new(N_LEAVES, 16, 0, new_seed());
        let tree = graph
            .hybrid_merkle_tree(data.as_slice(), BETA_HEIGHT)
            .unwrap();

        for i in 0..3 {
            let public_inputs = hybrid_merklepor::PublicInputs {
                challenge: i,
                commitment: None,
            };

            let setup_params = compound_proof::SetupParams {
                vanilla_params: &hybrid_merklepor::SetupParams {
                    leaves: N_LEAVES,
                    beta_height: BETA_HEIGHT,
                    private: true,
                },
                engine_params: &JubjubBls12::new_with_window_size(window_size),
                partitions: None,
            };
            let public_params = PoRCompound::<AH, BH>::setup(&setup_params).expect("setup failed");

            // Convert the challenge's bytes into a `HybridDomain`. Because `BETA_HEIGHT` is set to
            // `1` the leaves in the tree will be `HybridDomain::Beta`s.
            let leaf = {
                let leaf_bytes = data_at_node(data.as_slice(), public_inputs.challenge).unwrap();
                let leaf_beta = BH::Domain::try_from_bytes(&leaf_bytes).unwrap();
                HybridDomain::Beta(leaf_beta)
            };

            let private_inputs = hybrid_merklepor::PrivateInputs::<AH, BH>::new(leaf, &tree);

            let groth_params = PoRCompound::<AH, BH>::groth_params(
                &public_params.vanilla_params,
                setup_params.engine_params,
            )
            .expect("failed to generate groth params");

            let proof = PoRCompound::<AH, BH>::prove(
                &public_params,
                &public_inputs,
                &private_inputs,
                &groth_params,
            )
            .expect("proving failed");

            {
                let (circuit, inputs) = PoRCompound::<AH, BH>::circuit_for_test(
                    &public_params,
                    &public_inputs,
                    &private_inputs,
                );

                let mut cs = TestConstraintSystem::new();

                circuit.synthesize(&mut cs).expect("failed to synthesize");

                assert!(cs.is_satisfied());
                assert!(cs.verify(&inputs));
            }

            let verified = PoRCompound::<AH, BH>::verify(
                &public_params,
                &public_inputs,
                &proof,
                &NoRequirements,
            )
            .expect("failed while verifying");
            assert!(verified);
        }
    }

    #[test]
    fn test_private_por_input_circuit_with_bls12_381() {
        const N_LEAVES: usize = 8;
        const BETA_HEIGHT: usize = 1;

        let window_size = settings::SETTINGS
            .lock()
            .unwrap()
            .pedersen_hash_exp_window_size;
        let params = &JubjubBls12::new_with_window_size(window_size);

        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for i in 0..N_LEAVES {
            // -- Basic Setup

            let data: Vec<u8> = (0..N_LEAVES)
                .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
                .collect();

            let graph =
                BucketGraph::<PedersenHasher, Blake2sHasher>::new(N_LEAVES, 16, 0, new_seed());
            let tree = graph
                .hybrid_merkle_tree(data.as_slice(), BETA_HEIGHT)
                .unwrap();

            // -- HybridMerklePoR

            let pub_params = hybrid_merklepor::PublicParams {
                leaves: N_LEAVES,
                beta_height: BETA_HEIGHT,
                private: true,
            };
            let pub_inputs = hybrid_merklepor::PublicInputs {
                challenge: i,
                commitment: None,
            };

            // Convert the challenge's bytes into a `HybridDomain`. Because `BETA_HEIGHT` is set to
            // `1` the leaves in the tree will be `HybridDomain::Beta`s.
            let leaf = {
                let leaf_bytes = data_at_node(data.as_slice(), pub_inputs.challenge).unwrap();
                let leaf_beta = Blake2sDomain::try_from_bytes(&leaf_bytes).unwrap();
                HybridDomain::Beta(leaf_beta)
            };

            let priv_inputs =
                hybrid_merklepor::PrivateInputs::<PedersenHasher, Blake2sHasher>::new(leaf, &tree);

            // create a non circuit proof
            let proof = hybrid_merklepor::HybridMerklePoR::<PedersenHasher, Blake2sHasher>::prove(
                &pub_params,
                &pub_inputs,
                &priv_inputs,
            )
            .expect("proving failed");

            // make sure it verifies
            let is_valid =
                hybrid_merklepor::HybridMerklePoR::<PedersenHasher, Blake2sHasher>::verify(
                    &pub_params,
                    &pub_inputs,
                    &proof,
                )
                .expect("verification failed");
            assert!(is_valid, "failed to verify hybrid_merklepor proof");

            // -- Circuit

            let mut cs = TestConstraintSystem::<Bls12>::new();

            let por = PoRCircuit::<Bls12, PedersenHasher, Blake2sHasher> {
                params,
                value: Some(proof.data.into()),
                auth_path: proof.proof.as_options(),
                root: Root::Val(Some(tree.root().into())),
                beta_height: BETA_HEIGHT,
                private: true,
                _ah: PhantomData,
                _bh: PhantomData,
            };

            por.synthesize(&mut cs).expect("circuit synthesis failed");
            assert!(cs.is_satisfied(), "constraints not satisfied");

            assert_eq!(cs.num_inputs(), 2, "wrong number of inputs");
            assert_eq!(cs.num_constraints(), 24271, "wrong number of constraints");

            let auth_path_bits: Vec<bool> = proof
                .proof
                .path()
                .iter()
                .map(|(_, is_right)| *is_right)
                .collect();
            let packed_auth_path = multipack::compute_multipacking::<Bls12>(&auth_path_bits);

            let mut expected_inputs = Vec::new();
            expected_inputs.extend(packed_auth_path);

            assert_eq!(cs.get_input(0, "ONE"), Fr::one(), "wrong input 0");

            assert_eq!(
                cs.get_input(1, "path/input 0"),
                expected_inputs[0],
                "wrong packed_auth_path"
            );

            assert!(cs.is_satisfied(), "constraints are not all satisfied");
            assert!(cs.verify(&expected_inputs), "failed to verify inputs");
        }
    }
}
