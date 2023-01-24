use std::marker::PhantomData;

use anyhow::{anyhow, ensure};
use bellperson::Circuit;
use blstrs::Scalar as Fr;
use filecoin_hashers::R1CSHasher;
use storage_proofs_core::{
    compound_proof::{CircuitComponent, CompoundProof},
    error::Result,
    merkle::MerkleTreeTrait,
    parameter_cache::{CacheableParameters, ParameterSetMetadata},
    proof::ProofScheme,
};

use crate::fallback::{FallbackPoSt, FallbackPoStCircuit, Sector};

pub struct FallbackPoStCompound<Tree>
where
    Tree: MerkleTreeTrait,
    Tree::Hasher: R1CSHasher,
{
    _t: PhantomData<Tree>,
}

// Only implement for `Fr` as `CacheableParameters` is Groth16 specific.
impl<C, P, Tree> CacheableParameters<C, P> for FallbackPoStCompound<Tree>
where
    C: Circuit<Fr>,
    P: ParameterSetMetadata,
    Tree: MerkleTreeTrait<Field = Fr>,
    Tree::Hasher: R1CSHasher,
{
    fn cache_prefix() -> String {
        format!("proof-of-spacetime-fallback-{}", Tree::display())
    }
}

// Only implement for `Fr` as `CompoundProof` is Groth16 specific.
impl<'a, Tree> CompoundProof<'a, FallbackPoSt<'a, Tree>, FallbackPoStCircuit<Tree>>
    for FallbackPoStCompound<Tree>
where
    Tree: 'static + MerkleTreeTrait<Field = Fr>,
    Tree::Hasher: R1CSHasher,
{
    #[inline]
    fn generate_public_inputs(
        pub_inputs: &<FallbackPoSt<'a, Tree> as ProofScheme<'a>>::PublicInputs,
        pub_params: &<FallbackPoSt<'a, Tree> as ProofScheme<'a>>::PublicParams,
        partition_k: Option<usize>,
    ) -> Result<Vec<Fr>> {
        FallbackPoStCircuit::<Tree>::generate_public_inputs(pub_params, pub_inputs, partition_k)
    }

    fn circuit(
        pub_in: &<FallbackPoSt<'a, Tree> as ProofScheme<'a>>::PublicInputs,
        _priv_in: <FallbackPoStCircuit<Tree> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &<FallbackPoSt<'a, Tree> as ProofScheme<'a>>::Proof,
        pub_params: &<FallbackPoSt<'a, Tree> as ProofScheme<'a>>::PublicParams,
        partition_k: Option<usize>,
    ) -> Result<FallbackPoStCircuit<Tree>> {
        let num_sectors_per_chunk = pub_params.sector_count;
        ensure!(
            pub_params.sector_count == vanilla_proof.sectors.len(),
            "vanilla proofs must equal sector_count: {} != {}",
            num_sectors_per_chunk,
            vanilla_proof.sectors.len(),
        );

        let partition_index = partition_k.unwrap_or(0);
        let sectors = pub_in
            .sectors
            .chunks(num_sectors_per_chunk)
            .nth(partition_index)
            .ok_or_else(|| anyhow!("invalid number of sectors/partition index"))?;

        let mut res_sectors = Vec::with_capacity(vanilla_proof.sectors.len());

        for (i, vanilla_proof) in vanilla_proof.sectors.iter().enumerate() {
            let pub_sector = if i < sectors.len() {
                &sectors[i]
            } else {
                // Repeat the last sector, iff there are too little inputs to fill the circuit.
                &sectors[sectors.len() - 1]
            };

            res_sectors.push(Sector::circuit(pub_sector, vanilla_proof)?);
        }

        assert_eq!(res_sectors.len(), num_sectors_per_chunk);

        Ok(FallbackPoStCircuit {
            prover_id: Some(pub_in.prover_id.into()),
            sectors: res_sectors,
        })
    }

    fn blank_circuit(
        pub_params: &<FallbackPoSt<'a, Tree> as ProofScheme<'a>>::PublicParams,
    ) -> FallbackPoStCircuit<Tree> {
        let sectors = (0..pub_params.sector_count)
            .map(|_| Sector::blank_circuit(pub_params))
            .collect();

        FallbackPoStCircuit {
            prover_id: None,
            sectors,
        }
    }
}
