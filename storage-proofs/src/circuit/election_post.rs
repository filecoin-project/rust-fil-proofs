use std::marker::PhantomData;

use bellperson::gadgets::{
    boolean::{AllocatedBit, Boolean},
    num,
};
use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use fil_sapling_crypto::jubjub::JubjubEngine;
use paired::bls12_381::{Bls12, Fr};

use crate::circuit::constraint;
use crate::circuit::pedersen::pedersen_md_no_padding;
use crate::circuit::por::{PoRCircuit, PoRCompound};
use crate::circuit::stacked::hash::hash3;
use crate::circuit::uint64::UInt64;
use crate::circuit::variables::Root;
use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::crypto::pedersen::JJ_PARAMS;
use crate::drgraph;
use crate::election_post::{self, ElectionPoSt};
use crate::error::Result;
use crate::fr32::fr_into_bytes;
use crate::hasher::Hasher;
use crate::merklepor;
use crate::parameter_cache::{CacheableParameters, ParameterSetMetadata};
use crate::proof::ProofScheme;
use crate::util::bytes_into_bits_opt;
use crate::util::NODE_SIZE;

/// This is the `ElectionPoSt` circuit.
pub struct ElectionPoStCircuit<'a, E: JubjubEngine, H: Hasher> {
    /// Paramters for the engine.
    pub params: &'a E::Params,
    pub comm_r: Option<E::Fr>,
    pub comm_c: Option<E::Fr>,
    pub comm_q: Option<E::Fr>,
    pub comm_r_last: Option<E::Fr>,
    pub leafs: Vec<Option<E::Fr>>,
    #[allow(clippy::type_complexity)]
    pub paths: Vec<Vec<Option<(E::Fr, bool)>>>,
    pub partial_ticket: Option<E::Fr>,
    pub randomness: Vec<Option<bool>>,
    pub prover_id: Vec<Option<bool>>,
    pub sector_id: Option<u64>,
    _h: PhantomData<H>,
}

pub struct ElectionPoStCompound<H>
where
    H: Hasher,
{
    _h: PhantomData<H>,
}

impl<E: JubjubEngine, C: Circuit<E>, P: ParameterSetMetadata, H: Hasher>
    CacheableParameters<E, C, P> for ElectionPoStCompound<H>
{
    fn cache_prefix() -> String {
        String::from("proof-of-spacetime-election")
    }
}

#[derive(Clone, Default)]
pub struct ComponentPrivateInputs {}

impl<'a, E: JubjubEngine, H: Hasher> CircuitComponent for ElectionPoStCircuit<'a, E, H> {
    type ComponentPrivateInputs = ComponentPrivateInputs;
}

impl<'a, H> CompoundProof<'a, Bls12, ElectionPoSt<'a, H>, ElectionPoStCircuit<'a, Bls12, H>>
    for ElectionPoStCompound<H>
where
    H: 'a + Hasher,
{
    fn generate_public_inputs(
        pub_inputs: &<ElectionPoSt<'a, H> as ProofScheme<'a>>::PublicInputs,
        pub_params: &<ElectionPoSt<'a, H> as ProofScheme<'a>>::PublicParams,
        _partition_k: Option<usize>,
    ) -> Result<Vec<Fr>> {
        let mut inputs = Vec::new();

        let por_pub_params = merklepor::PublicParams {
            leaves: (pub_params.sector_size as usize / NODE_SIZE),
            private: true,
        };

        // 1. Inputs for verifying comm_r = H(comm_c || comm_q || comm_r_last)

        inputs.push(pub_inputs.comm_r.into());

        // 2. Inputs for verifying inclusion paths

        for n in 0..election_post::POST_CHALLENGE_COUNT {
            let challenged_leaf_start = election_post::generate_leaf_challenge(
                &pub_inputs.randomness,
                pub_inputs.sector_challenge_index,
                n as u64,
                pub_params.sector_size,
            )?;
            for i in 0..election_post::POST_CHALLENGED_NODES {
                let por_pub_inputs = merklepor::PublicInputs {
                    commitment: None,
                    challenge: challenged_leaf_start as usize + i,
                };
                let por_inputs = PoRCompound::<H>::generate_public_inputs(
                    &por_pub_inputs,
                    &por_pub_params,
                    None,
                )?;

                inputs.extend(por_inputs);
            }
        }

        // 3. Inputs for verifying partial_ticket generation
        inputs.push(pub_inputs.partial_ticket);

        Ok(inputs)
    }

    fn circuit(
        pub_in: &<ElectionPoSt<'a, H> as ProofScheme<'a>>::PublicInputs,
        _priv_in: <ElectionPoStCircuit<'a, Bls12, H> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &<ElectionPoSt<'a, H> as ProofScheme<'a>>::Proof,
        _pub_params: &<ElectionPoSt<'a, H> as ProofScheme<'a>>::PublicParams,
    ) -> Result<ElectionPoStCircuit<'a, Bls12, H>> {
        let comm_r = pub_in.comm_r.into();
        let comm_c = vanilla_proof.comm_c.into();
        let comm_q = vanilla_proof.comm_q.into();
        let comm_r_last = vanilla_proof.comm_r_last().into();

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

        Ok(ElectionPoStCircuit {
            params: &*JJ_PARAMS,
            leafs,
            comm_r: Some(comm_r),
            comm_c: Some(comm_c),
            comm_q: Some(comm_q),
            comm_r_last: Some(comm_r_last),
            paths,
            partial_ticket: Some(pub_in.partial_ticket),
            randomness: bytes_into_bits_opt(&pub_in.randomness[..]),
            prover_id: bytes_into_bits_opt(&pub_in.prover_id[..]),
            sector_id: Some(u64::from(pub_in.sector_id)),
            _h: PhantomData,
        })
    }

    fn blank_circuit(
        pub_params: &<ElectionPoSt<'a, H> as ProofScheme<'a>>::PublicParams,
    ) -> ElectionPoStCircuit<'a, Bls12, H> {
        let challenges_count =
            election_post::POST_CHALLENGED_NODES * election_post::POST_CHALLENGE_COUNT;
        let height = drgraph::graph_height(pub_params.sector_size as usize / NODE_SIZE);

        let leafs = vec![None; challenges_count];
        let paths = vec![vec![None; height]; challenges_count];

        ElectionPoStCircuit {
            params: &*JJ_PARAMS,
            comm_r: None,
            comm_c: None,
            comm_q: None,
            comm_r_last: None,
            partial_ticket: None,
            leafs,
            paths,
            randomness: vec![None; 32 * 8],
            prover_id: vec![None; 32 * 8],
            sector_id: None,
            _h: PhantomData,
        }
    }
}

impl<'a, E: JubjubEngine, H: Hasher> Circuit<E> for ElectionPoStCircuit<'a, E, H> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let params = self.params;
        let comm_r = self.comm_r;
        let comm_c = self.comm_c;
        let comm_q = self.comm_q;
        let comm_r_last = self.comm_r_last;
        let leafs = self.leafs;
        let paths = self.paths;
        let partial_ticket = self.partial_ticket;

        assert_eq!(paths.len(), leafs.len());
        assert_eq!(
            paths.len(),
            election_post::POST_CHALLENGED_NODES * election_post::POST_CHALLENGE_COUNT
        );

        // 1. Verify comm_r

        let comm_r_last_num = num::AllocatedNum::alloc(cs.namespace(|| "comm_r_last"), || {
            comm_r_last
                .map(Into::into)
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        let comm_c_num = num::AllocatedNum::alloc(cs.namespace(|| "comm_c"), || {
            comm_c
                .map(Into::into)
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        let comm_q_num = num::AllocatedNum::alloc(cs.namespace(|| "comm_q"), || {
            comm_q
                .map(Into::into)
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        let comm_r_num = num::AllocatedNum::alloc(cs.namespace(|| "comm_r"), || {
            comm_r
                .map(Into::into)
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        comm_r_num.inputize(cs.namespace(|| "comm_r_input"))?;

        // Verify H(Comm_C || comm_q || comm_r_last) == comm_r
        {
            // Allocate comm_c as booleans
            let comm_c_bits = comm_c_num.to_bits_le(cs.namespace(|| "comm_c_bits"))?;

            // Allocate comm_q as booleans
            let comm_q_bits = comm_q_num.to_bits_le(cs.namespace(|| "comm_q_bits"))?;

            // Allocate comm_r_last as booleans
            let comm_r_last_bits =
                comm_r_last_num.to_bits_le(cs.namespace(|| "comm_r_last_bits"))?;

            let hash_num = hash3(
                cs.namespace(|| "H_comm_c_comm_q_comm_r_last"),
                params,
                &comm_c_bits,
                &comm_q_bits,
                &comm_r_last_bits,
            )?;

            // Check actual equality
            constraint::equal(
                cs,
                || "enforce_comm_c_comm_q_comm_r_last_hash_comm_r",
                &comm_r_num,
                &hash_num,
            );
        }

        // 2. Verify Inclusion Paths
        for (i, (leaf, path)) in leafs.iter().zip(paths.iter()).enumerate() {
            PoRCircuit::<E, H>::synthesize(
                cs.namespace(|| format!("challenge_inclusion{}", i)),
                &params,
                Root::Val(*leaf),
                path.clone(),
                Root::from_allocated::<CS>(comm_r_last_num.clone()),
                true,
            )?;
        }

        // 3. Verify partial ticket

        let mut partial_ticket_bits = Vec::new();

        // randomness
        for (i, bit) in self.randomness.iter().enumerate() {
            let bit_alloc = Boolean::from(AllocatedBit::alloc(
                cs.namespace(|| format!("randomness_bit_{}", i)),
                *bit,
            )?);
            partial_ticket_bits.push(bit_alloc);
        }

        // prover_id
        for (i, bit) in self.prover_id.iter().enumerate() {
            let bit_alloc = Boolean::from(AllocatedBit::alloc(
                cs.namespace(|| format!("prover_id_bit_{}", i)),
                *bit,
            )?);
            partial_ticket_bits.push(bit_alloc);
        }

        // sector_id
        let sector_id_num = UInt64::alloc(cs.namespace(|| "sector_id"), self.sector_id)?;
        partial_ticket_bits.extend(sector_id_num.to_bits_le());

        // pad to pedersen_md blocksize
        while partial_ticket_bits.len() % crate::crypto::pedersen::PEDERSEN_BLOCK_SIZE != 0 {
            partial_ticket_bits.push(Boolean::Constant(false));
        }

        // data
        for (i, leaf) in leafs.iter().enumerate() {
            let bits = match *leaf {
                Some(leaf) => {
                    let bytes = fr_into_bytes::<E>(&leaf);
                    bytes_into_bits_opt(&bytes)
                }
                None => vec![None; 32 * 8],
            };
            for (j, bit) in bits.into_iter().enumerate() {
                let bit_alloc = Boolean::from(AllocatedBit::alloc(
                    cs.namespace(|| format!("data_bit_{}_{}", j, i)),
                    bit,
                )?);
                partial_ticket_bits.push(bit_alloc);
            }
        }

        // hash it
        let partial_ticket_num = pedersen_md_no_padding(
            cs.namespace(|| "partial_ticket_hash"),
            self.params,
            &partial_ticket_bits,
        )?;

        // allocate expected input
        let expected_partial_ticket_num =
            num::AllocatedNum::alloc(cs.namespace(|| "partial_ticket"), || {
                partial_ticket
                    .map(Into::into)
                    .ok_or_else(|| SynthesisError::AssignmentMissing)
            })?;

        expected_partial_ticket_num.inputize(cs.namespace(|| "partial_ticket_input"))?;

        // check equality
        constraint::equal(
            cs,
            || "enforce partial_ticket is correct",
            &partial_ticket_num,
            &expected_partial_ticket_num,
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use ff::Field;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    use crate::circuit::test::*;
    use crate::compound_proof;
    use crate::crypto::pedersen::JJ_PARAMS;
    use crate::drgraph::{new_seed, BucketGraph, Graph, BASE_DEGREE};
    use crate::election_post::{self, ElectionPoSt};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::{pedersen::*, Domain};
    use crate::proof::{NoRequirements, ProofScheme};
    use crate::sector::SectorId;
    use crate::stacked::hash::hash3;

    #[test]
    fn test_election_post_circuit() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 32;
        let sector_size = leaves * 32;

        let randomness: [u8; 32] = rng.gen();
        let prover_id: [u8; 32] = rng.gen();

        let pub_params = election_post::PublicParams { sector_size };

        let mut sectors: Vec<SectorId> = Vec::new();
        let mut trees = BTreeMap::new();
        for i in 0..5 {
            sectors.push(i.into());
            let data: Vec<u8> = (0..leaves)
                .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
                .collect();

            let graph = BucketGraph::<PedersenHasher>::new(32, BASE_DEGREE, 0, new_seed()).unwrap();
            let tree = graph.merkle_tree(data.as_slice()).unwrap();
            trees.insert(i.into(), tree);
        }

        let candidates = election_post::generate_candidates::<PedersenHasher>(
            sector_size,
            &sectors,
            &trees,
            &prover_id,
            &randomness,
        )
        .unwrap();

        let candidate = &candidates[0];
        let tree = trees.remove(&candidate.sector_id).unwrap();
        let comm_r_last = tree.root();
        let comm_c = PedersenDomain::random(rng);
        let comm_q = PedersenDomain::random(rng);
        let comm_r = Fr::from(hash3(comm_c, comm_q, comm_r_last)).into();

        let pub_inputs = election_post::PublicInputs {
            randomness,
            sector_id: candidate.sector_id,
            prover_id,
            comm_r,
            partial_ticket: candidate.partial_ticket,
            sector_challenge_index: 0,
        };

        let priv_inputs = election_post::PrivateInputs::<PedersenHasher> {
            tree,
            comm_c,
            comm_q,
            comm_r_last,
        };

        let proof = ElectionPoSt::<PedersenHasher>::prove(&pub_params, &pub_inputs, &priv_inputs)
            .expect("proving failed");

        let is_valid = ElectionPoSt::<PedersenHasher>::verify(&pub_params, &pub_inputs, &proof)
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

        let instance = ElectionPoStCircuit::<_, PedersenHasher> {
            params: &*JJ_PARAMS,
            leafs,
            paths,
            comm_r: Some(comm_r.into()),
            comm_c: Some(comm_c.into()),
            comm_q: Some(comm_q.into()),
            comm_r_last: Some(comm_r_last.into()),
            partial_ticket: Some(candidate.partial_ticket.into()),
            randomness: bytes_into_bits_opt(&randomness[..]),
            prover_id: bytes_into_bits_opt(&prover_id[..]),
            sector_id: Some(u64::from(candidate.sector_id)),
            _h: PhantomData,
        };

        instance
            .synthesize(&mut cs)
            .expect("failed to synthesize circuit");

        assert!(cs.is_satisfied(), "constraints not satisfied");

        assert_eq!(cs.num_inputs(), 43, "wrong number of inputs");
        assert_eq!(cs.num_constraints(), 335_127, "wrong number of constraints");
        assert_eq!(cs.get_input(0, "ONE"), Fr::one());

        let generated_inputs = ElectionPoStCompound::<PedersenHasher>::generate_public_inputs(
            &pub_inputs,
            &pub_params,
            None,
        )
        .unwrap();
        let expected_inputs = cs.get_inputs();

        for ((input, label), generated_input) in
            expected_inputs.iter().skip(1).zip(generated_inputs.iter())
        {
            assert_eq!(input, generated_input, "{}", label);
        }

        assert_eq!(
            generated_inputs.len(),
            expected_inputs.len() - 1,
            "inputs are not the same length"
        );
    }

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn election_post_test_compound() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 32;
        let sector_size = leaves * 32;
        let randomness: [u8; 32] = rng.gen();
        let prover_id: [u8; 32] = rng.gen();

        let setup_params = compound_proof::SetupParams {
            vanilla_params: election_post::SetupParams { sector_size },
            partitions: None,
        };

        let mut sectors: Vec<SectorId> = Vec::new();
        let mut trees = BTreeMap::new();
        for i in 0..5 {
            sectors.push(i.into());
            let data: Vec<u8> = (0..leaves)
                .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
                .collect();

            let graph = BucketGraph::<PedersenHasher>::new(32, BASE_DEGREE, 0, new_seed()).unwrap();
            let tree = graph.merkle_tree(data.as_slice()).unwrap();
            trees.insert(i.into(), tree);
        }

        let candidates = election_post::generate_candidates::<PedersenHasher>(
            sector_size,
            &sectors,
            &trees,
            &prover_id,
            &randomness,
        )
        .unwrap();

        let candidate = &candidates[0];
        let tree = trees.remove(&candidate.sector_id).unwrap();
        let comm_r_last = tree.root();
        let comm_c = PedersenDomain::random(rng);
        let comm_q = PedersenDomain::random(rng);
        let comm_r = Fr::from(hash3(comm_c, comm_q, comm_r_last)).into();

        let pub_inputs = election_post::PublicInputs {
            randomness,
            sector_id: candidate.sector_id,
            prover_id,
            comm_r,
            partial_ticket: candidate.partial_ticket,
            sector_challenge_index: 0,
        };

        let priv_inputs = election_post::PrivateInputs::<PedersenHasher> {
            tree,
            comm_c,
            comm_q,
            comm_r_last,
        };

        let pub_params =
            ElectionPoStCompound::<PedersenHasher>::setup(&setup_params).expect("setup failed");

        {
            let (circuit, inputs) =
                ElectionPoStCompound::circuit_for_test(&pub_params, &pub_inputs, &priv_inputs)
                    .unwrap();

            let mut cs = TestConstraintSystem::new();

            circuit.synthesize(&mut cs).expect("failed to synthesize");

            if !cs.is_satisfied() {
                panic!(
                    "failed to satisfy: {:?}",
                    cs.which_is_unsatisfied().unwrap()
                );
            }
            assert!(
                cs.verify(&inputs),
                "verification failed with TestContraintSystem and generated inputs"
            );
        }

        // Use this to debug differences between blank and regular circuit generation.
        {
            let (circuit1, _inputs) =
                ElectionPoStCompound::circuit_for_test(&pub_params, &pub_inputs, &priv_inputs)
                    .unwrap();
            let blank_circuit =
                ElectionPoStCompound::<PedersenHasher>::blank_circuit(&pub_params.vanilla_params);

            let mut cs_blank = TestConstraintSystem::new();
            blank_circuit
                .synthesize(&mut cs_blank)
                .expect("failed to synthesize");

            let a = cs_blank.pretty_print_list();

            let mut cs1 = TestConstraintSystem::new();
            circuit1.synthesize(&mut cs1).expect("failed to synthesize");
            let b = cs1.pretty_print_list();

            for (i, (a, b)) in a.chunks(100).zip(b.chunks(100)).enumerate() {
                assert_eq!(a, b, "failed at chunk {}", i);
            }
        }
        let blank_groth_params = ElectionPoStCompound::<PedersenHasher>::groth_params(
            Some(rng),
            &pub_params.vanilla_params,
        )
        .expect("failed to generate groth params");

        let proof = ElectionPoStCompound::prove(
            &pub_params,
            &pub_inputs,
            &priv_inputs,
            &blank_groth_params,
        )
        .expect("failed while proving");

        let verified =
            ElectionPoStCompound::verify(&pub_params, &pub_inputs, &proof, &NoRequirements)
                .expect("failed while verifying");

        assert!(verified);
    }
}
