use std::marker::PhantomData;

use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use blstrs::Scalar as Fr;
use filecoin_hashers::R1CSHasher;
use generic_array::typenum::U2;
use storage_proofs_core::{
    compound_proof::{CircuitComponent, CompoundProof},
    drgraph::graph_height,
    error::Result,
    merkle::MerkleTreeTrait,
    parameter_cache::{CacheableParameters, ParameterSetMetadata},
    proof::ProofScheme,
    util::NODE_SIZE,
};

use crate::rational::{RationalPoSt, RationalPoStCircuit};

pub struct RationalPoStCompound<Tree>
where
    Tree: MerkleTreeTrait,
    Tree::Hasher: R1CSHasher,
{
    _t: PhantomData<Tree>,
}

// Only implement for `Fr` as `CacheableParameters` is Groth16 specific.
impl<C, P, Tree> CacheableParameters<C, P> for RationalPoStCompound<Tree>
where
    C: Circuit<Fr>,
    P: ParameterSetMetadata,
    Tree: MerkleTreeTrait<Field = Fr>,
    Tree::Hasher: R1CSHasher,
{
    fn cache_prefix() -> String {
        format!("proof-of-spacetime-rational-{}", Tree::display())
    }
}

// Only implement for `Fr` as `CompoundProof` is Groth16 specific.
impl<'a, Tree> CompoundProof<'a, RationalPoSt<'a, Tree>, RationalPoStCircuit<Tree>>
    for RationalPoStCompound<Tree>
where
    Tree: 'static + MerkleTreeTrait<Field = Fr>,
    Tree::Hasher: R1CSHasher,
{
    #[inline]
    fn generate_public_inputs(
        pub_in: &<RationalPoSt<'a, Tree> as ProofScheme<'a>>::PublicInputs,
        pub_params: &<RationalPoSt<'a, Tree> as ProofScheme<'a>>::PublicParams,
        _partition_k: Option<usize>,
    ) -> Result<Vec<Fr>> {
        RationalPoStCircuit::<Tree>::generate_public_inputs(pub_params, pub_in)
    }

    fn circuit(
        pub_in: &<RationalPoSt<'a, Tree> as ProofScheme<'a>>::PublicInputs,
        _priv_in: <RationalPoStCircuit<Tree> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &<RationalPoSt<'a, Tree> as ProofScheme<'a>>::Proof,
        _pub_params: &<RationalPoSt<'a, Tree> as ProofScheme<'a>>::PublicParams,
        _partition_k: Option<usize>,
    ) -> Result<RationalPoStCircuit<Tree>> {
        let comm_rs: Vec<_> = pub_in.comm_rs.iter().map(|c| Some((*c).into())).collect();
        let comm_cs: Vec<_> = vanilla_proof
            .comm_cs
            .iter()
            .map(|c| Some((*c).into()))
            .collect();

        let comm_r_lasts: Vec<_> = vanilla_proof
            .commitments()
            .into_iter()
            .map(|c| Some(c.into()))
            .collect();

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

        Ok(RationalPoStCircuit {
            leafs,
            comm_rs,
            comm_cs,
            comm_r_lasts,
            paths,
            _t: PhantomData,
        })
    }

    fn blank_circuit(
        pub_params: &<RationalPoSt<'a, Tree> as ProofScheme<'a>>::PublicParams,
    ) -> RationalPoStCircuit<Tree> {
        let challenges_count = pub_params.challenges_count;
        let height = graph_height::<U2>(pub_params.sector_size as usize / NODE_SIZE);

        let comm_rs = vec![None; challenges_count];
        let comm_cs = vec![None; challenges_count];
        let comm_r_lasts = vec![None; challenges_count];
        let leafs = vec![None; challenges_count];
        let paths = vec![vec![(vec![None; 1], None); height - 1]; challenges_count];

        RationalPoStCircuit {
            comm_rs,
            comm_cs,
            comm_r_lasts,
            leafs,
            paths,
            _t: PhantomData,
        }
    }
}

impl<Tree> RationalPoStCircuit<Tree>
where
    Tree: MerkleTreeTrait,
    Tree::Hasher: R1CSHasher,
{
    #[allow(clippy::type_complexity)]
    pub fn synthesize<CS: ConstraintSystem<Tree::Field>>(
        cs: &mut CS,
        leafs: Vec<Option<Tree::Field>>,
        comm_rs: Vec<Option<Tree::Field>>,
        comm_cs: Vec<Option<Tree::Field>>,
        comm_r_lasts: Vec<Option<Tree::Field>>,
        paths: Vec<Vec<(Vec<Option<Tree::Field>>, Option<usize>)>>,
    ) -> Result<(), SynthesisError> {
        Self {
            leafs,
            comm_rs,
            comm_cs,
            comm_r_lasts,
            paths,
            _t: PhantomData,
        }
        .synthesize(cs)
    }
}
