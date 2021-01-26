use std::marker::PhantomData;

use anyhow::ensure;
use bellperson::bls::{Bls12, Fr};
use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use generic_array::typenum::U2;
use storage_proofs_core::{
    compound_proof::{CircuitComponent, CompoundProof},
    drgraph::graph_height,
    error::Result,
    gadgets::por::PoRCompound,
    merkle::MerkleTreeTrait,
    parameter_cache::{CacheableParameters, ParameterSetMetadata},
    por,
    proof::ProofScheme,
    util::NODE_SIZE,
};

use crate::rational::{RationalPoSt, RationalPoStCircuit};

pub struct RationalPoStCompound<Tree>
where
    Tree: MerkleTreeTrait,
{
    _t: PhantomData<Tree>,
}

impl<C: Circuit<Bls12>, P: ParameterSetMetadata, Tree: MerkleTreeTrait> CacheableParameters<C, P>
    for RationalPoStCompound<Tree>
{
    fn cache_prefix() -> String {
        format!("proof-of-spacetime-rational-{}", Tree::display())
    }
}

impl<'a, Tree: 'static + MerkleTreeTrait>
    CompoundProof<'a, RationalPoSt<'a, Tree>, RationalPoStCircuit<Tree>>
    for RationalPoStCompound<Tree>
where
    Tree: 'static + MerkleTreeTrait,
{
    fn generate_public_inputs(
        pub_in: &<RationalPoSt<'a, Tree> as ProofScheme<'a>>::PublicInputs,
        pub_params: &<RationalPoSt<'a, Tree> as ProofScheme<'a>>::PublicParams,
        _partition_k: Option<usize>,
    ) -> Result<Vec<Fr>> {
        let mut inputs = Vec::new();

        let por_pub_params = por::PublicParams {
            leaves: (pub_params.sector_size as usize / NODE_SIZE),
            private: true,
        };

        ensure!(
            pub_in.challenges.len() == pub_in.comm_rs.len(),
            "Missmatch in challenges and comm_rs"
        );

        for (challenge, comm_r) in pub_in.challenges.iter().zip(pub_in.comm_rs.iter()) {
            inputs.push((*comm_r).into());

            let por_pub_inputs = por::PublicInputs {
                commitment: None,
                challenge: challenge.leaf as usize,
            };
            let por_inputs = PoRCompound::<Tree>::generate_public_inputs(
                &por_pub_inputs,
                &por_pub_params,
                None,
            )?;

            inputs.extend(por_inputs);
        }

        Ok(inputs)
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

impl<'a, Tree: 'static + MerkleTreeTrait> RationalPoStCircuit<Tree> {
    #[allow(clippy::type_complexity)]
    pub fn synthesize<CS: ConstraintSystem<Bls12>>(
        cs: &mut CS,
        leafs: Vec<Option<Fr>>,
        comm_rs: Vec<Option<Fr>>,
        comm_cs: Vec<Option<Fr>>,
        comm_r_lasts: Vec<Option<Fr>>,
        paths: Vec<Vec<(Vec<Option<Fr>>, Option<usize>)>>,
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
