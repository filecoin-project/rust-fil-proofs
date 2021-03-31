use std::marker::PhantomData;

use anyhow::ensure;
use bellperson::{
    bls::{Bls12, Fr},
    gadgets::num::AllocatedNum,
    Circuit, ConstraintSystem, SynthesisError,
};
use filecoin_hashers::{HashFunction, Hasher};
use fr32::u64_into_fr;
use storage_proofs_core::{
    compound_proof::{CircuitComponent, CompoundProof},
    drgraph::Graph,
    error::Result,
    gadgets::{constraint, por::PoRCompound},
    merkle::{BinaryMerkleTree, MerkleTreeTrait},
    parameter_cache::{CacheableParameters, ParameterSetMetadata},
    por::{self, PoR},
    proof::ProofScheme,
    util::reverse_bit_numbering,
};

use crate::stacked::{circuit::params::Proof, StackedDrg};

/// Stacked DRG based Proof of Replication.
///
/// # Fields
///
/// * `params` - parameters for the curve
///
pub struct StackedCircuit<'a, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher> {
    public_params: <StackedDrg<'a, Tree, G> as ProofScheme<'a>>::PublicParams,
    replica_id: Option<<Tree::Hasher as Hasher>::Domain>,
    comm_d: Option<G::Domain>,
    comm_r: Option<<Tree::Hasher as Hasher>::Domain>,
    comm_r_last: Option<<Tree::Hasher as Hasher>::Domain>,
    comm_c: Option<<Tree::Hasher as Hasher>::Domain>,

    // one proof per challenge
    proofs: Vec<Proof<Tree, G>>,
}

// We must manually implement Clone for all types generic over MerkleTreeTrait (instead of using
// #[derive(Clone)]) because derive(Clone) will only expand for MerkleTreeTrait types that also
// implement Clone. Not every MerkleTreeTrait type is Clone-able because not all merkel Store's are
// Clone-able, therefore deriving Clone would impl Clone for less than all possible Tree types.
impl<'a, Tree: MerkleTreeTrait, G: Hasher> Clone for StackedCircuit<'a, Tree, G> {
    fn clone(&self) -> Self {
        StackedCircuit {
            public_params: self.public_params.clone(),
            replica_id: self.replica_id,
            comm_d: self.comm_d,
            comm_r: self.comm_r,
            comm_r_last: self.comm_r_last,
            comm_c: self.comm_c,
            proofs: self.proofs.clone(),
        }
    }
}

impl<'a, Tree: MerkleTreeTrait, G: Hasher> CircuitComponent for StackedCircuit<'a, Tree, G> {
    type ComponentPrivateInputs = ();
}

impl<'a, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher> StackedCircuit<'a, Tree, G> {
    #[allow(clippy::too_many_arguments)]
    pub fn synthesize<CS>(
        mut cs: CS,
        public_params: <StackedDrg<'a, Tree, G> as ProofScheme<'a>>::PublicParams,
        replica_id: Option<<Tree::Hasher as Hasher>::Domain>,
        comm_d: Option<G::Domain>,
        comm_r: Option<<Tree::Hasher as Hasher>::Domain>,
        comm_r_last: Option<<Tree::Hasher as Hasher>::Domain>,
        comm_c: Option<<Tree::Hasher as Hasher>::Domain>,
        proofs: Vec<Proof<Tree, G>>,
    ) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<Bls12>,
    {
        let circuit = StackedCircuit::<'a, Tree, G> {
            public_params,
            replica_id,
            comm_d,
            comm_r,
            comm_r_last,
            comm_c,
            proofs,
        };

        circuit.synthesize(&mut cs)
    }
}

impl<'a, Tree: MerkleTreeTrait, G: Hasher> Circuit<Bls12> for StackedCircuit<'a, Tree, G> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let StackedCircuit {
            public_params,
            proofs,
            replica_id,
            comm_r,
            comm_d,
            comm_r_last,
            comm_c,
            ..
        } = self;

        // Allocate replica_id
        let replica_id_num = AllocatedNum::alloc(cs.namespace(|| "replica_id"), || {
            replica_id
                .map(Into::into)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // make replica_id a public input
        replica_id_num.inputize(cs.namespace(|| "replica_id_input"))?;

        let replica_id_bits =
            reverse_bit_numbering(replica_id_num.to_bits_le(cs.namespace(|| "replica_id_bits"))?);

        // Allocate comm_d as Fr
        let comm_d_num = AllocatedNum::alloc(cs.namespace(|| "comm_d"), || {
            comm_d
                .map(Into::into)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // make comm_d a public input
        comm_d_num.inputize(cs.namespace(|| "comm_d_input"))?;

        // Allocate comm_r as Fr
        let comm_r_num = AllocatedNum::alloc(cs.namespace(|| "comm_r"), || {
            comm_r
                .map(Into::into)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // make comm_r a public input
        comm_r_num.inputize(cs.namespace(|| "comm_r_input"))?;

        // Allocate comm_r_last as Fr
        let comm_r_last_num = AllocatedNum::alloc(cs.namespace(|| "comm_r_last"), || {
            comm_r_last
                .map(Into::into)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate comm_c as Fr
        let comm_c_num = AllocatedNum::alloc(cs.namespace(|| "comm_c"), || {
            comm_c
                .map(Into::into)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Verify comm_r = H(comm_c || comm_r_last)
        {
            let hash_num = <Tree::Hasher as Hasher>::Function::hash2_circuit(
                cs.namespace(|| "H_comm_c_comm_r_last"),
                &comm_c_num,
                &comm_r_last_num,
            )?;

            // Check actual equality
            constraint::equal(
                cs,
                || "enforce comm_r = H(comm_c || comm_r_last)",
                &comm_r_num,
                &hash_num,
            );
        }

        for (i, proof) in proofs.into_iter().enumerate() {
            proof.synthesize(
                &mut cs.namespace(|| format!("challenge_{}", i)),
                public_params.layer_challenges.layers(),
                &comm_d_num,
                &comm_c_num,
                &comm_r_last_num,
                &replica_id_bits,
            )?;
        }

        Ok(())
    }
}

#[allow(dead_code)]
pub struct StackedCompound<Tree: MerkleTreeTrait, G: Hasher> {
    partitions: Option<usize>,
    _t: PhantomData<Tree>,
    _g: PhantomData<G>,
}

impl<C: Circuit<Bls12>, P: ParameterSetMetadata, Tree: MerkleTreeTrait, G: Hasher>
    CacheableParameters<C, P> for StackedCompound<Tree, G>
{
    fn cache_prefix() -> String {
        format!(
            "stacked-proof-of-replication-{}-{}",
            Tree::display(),
            G::name()
        )
    }
}

impl<'a, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher>
    CompoundProof<'a, StackedDrg<'a, Tree, G>, StackedCircuit<'a, Tree, G>>
    for StackedCompound<Tree, G>
{
    fn generate_public_inputs(
        pub_in: &<StackedDrg<'_, Tree, G> as ProofScheme<'_>>::PublicInputs,
        pub_params: &<StackedDrg<'_, Tree, G> as ProofScheme<'_>>::PublicParams,
        k: Option<usize>,
    ) -> Result<Vec<Fr>> {
        let graph = &pub_params.graph;

        let mut inputs = Vec::new();

        let replica_id = pub_in.replica_id;
        inputs.push(replica_id.into());

        let comm_d = pub_in.tau.as_ref().expect("missing tau").comm_d;
        inputs.push(comm_d.into());

        let comm_r = pub_in.tau.as_ref().expect("missing tau").comm_r;
        inputs.push(comm_r.into());

        let por_setup_params = por::SetupParams {
            leaves: graph.size(),
            private: true,
        };

        let por_params = PoR::<Tree>::setup(&por_setup_params)?;
        let por_params_d = PoR::<BinaryMerkleTree<G>>::setup(&por_setup_params)?;

        let all_challenges = pub_in.challenges(&pub_params.layer_challenges, graph.size(), k);

        for challenge in all_challenges.into_iter() {
            // comm_d inclusion proof for the data leaf
            inputs.extend(generate_inclusion_inputs::<BinaryMerkleTree<G>>(
                &por_params_d,
                challenge,
                k,
            )?);

            // drg parents
            let mut drg_parents = vec![0; graph.base_graph().degree()];
            graph.base_graph().parents(challenge, &mut drg_parents)?;

            // Inclusion Proofs: drg parent node in comm_c
            for parent in drg_parents.into_iter() {
                inputs.extend(generate_inclusion_inputs::<Tree>(
                    &por_params,
                    parent as usize,
                    k,
                )?);
            }

            // exp parents
            let mut exp_parents = vec![0; graph.expansion_degree()];
            graph.expanded_parents(challenge, &mut exp_parents)?;

            // Inclusion Proofs: expander parent node in comm_c
            for parent in exp_parents.into_iter() {
                inputs.extend(generate_inclusion_inputs::<Tree>(
                    &por_params,
                    parent as usize,
                    k,
                )?);
            }

            inputs.push(u64_into_fr(challenge as u64));

            // Inclusion Proof: encoded node in comm_r_last
            inputs.extend(generate_inclusion_inputs::<Tree>(
                &por_params,
                challenge,
                k,
            )?);

            // Inclusion Proof: column hash of the challenged node in comm_c
            inputs.extend(generate_inclusion_inputs::<Tree>(
                &por_params,
                challenge,
                k,
            )?);
        }

        Ok(inputs)
    }

    fn circuit<'b>(
        public_inputs: &'b <StackedDrg<'_, Tree, G> as ProofScheme<'_>>::PublicInputs,
        _component_private_inputs: <StackedCircuit<'a, Tree, G> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &'b <StackedDrg<'_, Tree, G> as ProofScheme<'_>>::Proof,
        public_params: &'b <StackedDrg<'_, Tree, G> as ProofScheme<'_>>::PublicParams,
        _partition_k: Option<usize>,
    ) -> Result<StackedCircuit<'a, Tree, G>> {
        ensure!(
            !vanilla_proof.is_empty(),
            "Cannot create a circuit with no vanilla proofs"
        );

        let comm_r_last = vanilla_proof[0].comm_r_last();
        let comm_c = vanilla_proof[0].comm_c();

        // ensure consistency
        ensure!(
            vanilla_proof.iter().all(|p| p.comm_r_last() == comm_r_last),
            "inconsistent comm_r_lasts"
        );
        ensure!(
            vanilla_proof.iter().all(|p| p.comm_c() == comm_c),
            "inconsistent comm_cs"
        );

        Ok(StackedCircuit {
            public_params: public_params.clone(),
            replica_id: Some(public_inputs.replica_id),
            comm_d: public_inputs.tau.as_ref().map(|t| t.comm_d),
            comm_r: public_inputs.tau.as_ref().map(|t| t.comm_r),
            comm_r_last: Some(comm_r_last),
            comm_c: Some(comm_c),
            proofs: vanilla_proof.iter().cloned().map(|p| p.into()).collect(),
        })
    }

    fn blank_circuit(
        public_params: &<StackedDrg<'_, Tree, G> as ProofScheme<'_>>::PublicParams,
    ) -> StackedCircuit<'a, Tree, G> {
        StackedCircuit {
            public_params: public_params.clone(),
            replica_id: None,
            comm_d: None,
            comm_r: None,
            comm_r_last: None,
            comm_c: None,
            proofs: (0..public_params.layer_challenges.challenges_count_all())
                .map(|_challenge_index| Proof::empty(public_params))
                .collect(),
        }
    }
}

/// Helper to generate public inputs for inclusion proofs.
fn generate_inclusion_inputs<Tree: 'static + MerkleTreeTrait>(
    por_params: &por::PublicParams,
    challenge: usize,
    k: Option<usize>,
) -> Result<Vec<Fr>> {
    let pub_inputs = por::PublicInputs::<<Tree::Hasher as Hasher>::Domain> {
        challenge,
        commitment: None,
    };

    PoRCompound::<Tree>::generate_public_inputs(&pub_inputs, por_params, k)
}
