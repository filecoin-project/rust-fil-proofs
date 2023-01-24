use std::marker::PhantomData;

use bellperson::Circuit;
use blstrs::Scalar as Fr;
use ff::PrimeField;
use filecoin_hashers::R1CSHasher;
use generic_array::typenum::Unsigned;
use storage_proofs_core::{
    compound_proof::{CircuitComponent, CompoundProof},
    drgraph::graph_height,
    error::Result,
    merkle::MerkleTreeTrait,
    parameter_cache::{CacheableParameters, ParameterSetMetadata},
    proof::ProofScheme,
    util::NODE_SIZE,
};

use crate::election::{ElectionPoSt, ElectionPoStCircuit};

pub struct ElectionPoStCompound<Tree>
where
    Tree: MerkleTreeTrait,
    Tree::Hasher: R1CSHasher,
{
    _t: PhantomData<Tree>,
}

// Only implement for `Fr` as `CacheableParameters` is Groth16 specific.
impl<C, P, Tree> CacheableParameters<C, P> for ElectionPoStCompound<Tree>
where
    C: Circuit<Fr>,
    P: ParameterSetMetadata,
    Tree: MerkleTreeTrait<Field = Fr>,
    Tree::Hasher: R1CSHasher,
{
    fn cache_prefix() -> String {
        format!("proof-of-spacetime-election-{}", Tree::display())
    }
}

// Only implement for `Fr` as `CompoundProof` is Groth16 specific.
impl<'a, Tree> CompoundProof<'a, ElectionPoSt<'a, Tree>, ElectionPoStCircuit<Tree>>
    for ElectionPoStCompound<Tree>
where
    Tree: 'static + MerkleTreeTrait<Field = Fr>,
    Tree::Hasher: R1CSHasher,
{
    #[inline]
    fn generate_public_inputs(
        pub_inputs: &<ElectionPoSt<'a, Tree> as ProofScheme<'a>>::PublicInputs,
        pub_params: &<ElectionPoSt<'a, Tree> as ProofScheme<'a>>::PublicParams,
        _partition_k: Option<usize>,
    ) -> Result<Vec<Fr>> {
        ElectionPoStCircuit::<Tree>::generate_public_inputs(pub_params, pub_inputs)
    }

    fn circuit(
        pub_in: &<ElectionPoSt<'a, Tree> as ProofScheme<'a>>::PublicInputs,
        _priv_in: <ElectionPoStCircuit<Tree> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &<ElectionPoSt<'a, Tree> as ProofScheme<'a>>::Proof,
        _pub_params: &<ElectionPoSt<'a, Tree> as ProofScheme<'a>>::PublicParams,
        _partition_k: Option<usize>,
    ) -> Result<ElectionPoStCircuit<Tree>> {
        let comm_r = pub_in.comm_r.into();
        let comm_c = vanilla_proof.comm_c.into();
        let comm_r_last = vanilla_proof.comm_r_last().into();

        let leafs: Vec<_> = vanilla_proof
            .leafs()
            .iter()
            .map(|c| Some((*c).into()))
            .collect();

        let paths: Vec<Vec<_>> = vanilla_proof
            .paths()
            .iter()
            .map(|v| {
                v.iter()
                    .map(|p| {
                        (
                            (*p).0.iter().copied().map(Into::into).map(Some).collect(),
                            Some(p.1),
                        )
                    })
                    .collect()
            })
            .collect();

        Ok(ElectionPoStCircuit {
            leafs,
            comm_r: Some(comm_r),
            comm_c: Some(comm_c),
            comm_r_last: Some(comm_r_last),
            paths,
            partial_ticket: Some(
                Fr::from_repr_vartime(pub_in.partial_ticket).expect("from_repr failure"),
            ),
            randomness: Some(pub_in.randomness.into()),
            prover_id: Some(pub_in.prover_id.into()),
            sector_id: Some(pub_in.sector_id.into()),
            _t: PhantomData,
        })
    }

    fn blank_circuit(
        pub_params: &<ElectionPoSt<'a, Tree> as ProofScheme<'a>>::PublicParams,
    ) -> ElectionPoStCircuit<Tree> {
        let challenges_count = pub_params.challenged_nodes * pub_params.challenge_count;
        let height = graph_height::<Tree::Arity>(pub_params.sector_size as usize / NODE_SIZE);

        let leafs = vec![None; challenges_count];
        let paths = vec![
            vec![(vec![None; Tree::Arity::to_usize() - 1], None); height - 1];
            challenges_count
        ];

        ElectionPoStCircuit {
            comm_r: None,
            comm_c: None,
            comm_r_last: None,
            partial_ticket: None,
            leafs,
            paths,
            randomness: None,
            prover_id: None,
            sector_id: None,
            _t: PhantomData,
        }
    }
}
