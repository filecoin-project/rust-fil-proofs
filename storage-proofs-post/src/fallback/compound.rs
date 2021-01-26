use std::marker::PhantomData;

use anyhow::{anyhow, ensure};
use bellperson::{
    bls::{Bls12, Fr},
    Circuit,
};
use filecoin_hashers::Hasher;
use sha2::{Digest, Sha256};
use storage_proofs_core::{
    compound_proof::{CircuitComponent, CompoundProof},
    error::Result,
    gadgets::por::PoRCompound,
    merkle::MerkleTreeTrait,
    parameter_cache::{CacheableParameters, ParameterSetMetadata},
    por,
    proof::ProofScheme,
    util::NODE_SIZE,
};

use crate::fallback::{generate_leaf_challenge_inner, FallbackPoSt, FallbackPoStCircuit, Sector};

pub struct FallbackPoStCompound<Tree>
where
    Tree: MerkleTreeTrait,
{
    _t: PhantomData<Tree>,
}

impl<C: Circuit<Bls12>, P: ParameterSetMetadata, Tree: MerkleTreeTrait> CacheableParameters<C, P>
    for FallbackPoStCompound<Tree>
{
    fn cache_prefix() -> String {
        format!("proof-of-spacetime-fallback-{}", Tree::display())
    }
}

impl<'a, Tree: 'static + MerkleTreeTrait>
    CompoundProof<'a, FallbackPoSt<'a, Tree>, FallbackPoStCircuit<Tree>>
    for FallbackPoStCompound<Tree>
{
    fn generate_public_inputs(
        pub_inputs: &<FallbackPoSt<'a, Tree> as ProofScheme<'a>>::PublicInputs,
        pub_params: &<FallbackPoSt<'a, Tree> as ProofScheme<'a>>::PublicParams,
        partition_k: Option<usize>,
    ) -> Result<Vec<Fr>> {
        let mut inputs = Vec::new();

        let por_pub_params = por::PublicParams {
            leaves: (pub_params.sector_size as usize / NODE_SIZE),
            private: true,
        };

        let num_sectors_per_chunk = pub_params.sector_count;

        let partition_index = partition_k.unwrap_or(0);

        let sectors = pub_inputs
            .sectors
            .chunks(num_sectors_per_chunk)
            .nth(partition_index)
            .ok_or_else(|| anyhow!("invalid number of sectors/partition index"))?;

        for (i, sector) in sectors.iter().enumerate() {
            // 1. Inputs for verifying comm_r = H(comm_c || comm_r_last)
            inputs.push(sector.comm_r.into());

            // avoid rehashing fixed inputs
            let mut challenge_hasher = Sha256::new();
            challenge_hasher.update(AsRef::<[u8]>::as_ref(&pub_inputs.randomness));
            challenge_hasher.update(&u64::from(sector.id).to_le_bytes()[..]);

            // 2. Inputs for verifying inclusion paths
            for n in 0..pub_params.challenge_count {
                let challenge_index = ((partition_index * pub_params.sector_count + i)
                    * pub_params.challenge_count
                    + n) as u64;
                let challenged_leaf = generate_leaf_challenge_inner::<
                    <Tree::Hasher as Hasher>::Domain,
                >(
                    challenge_hasher.clone(), &pub_params, challenge_index
                );

                let por_pub_inputs = por::PublicInputs {
                    commitment: None,
                    challenge: challenged_leaf as usize,
                };
                let por_inputs = PoRCompound::<Tree>::generate_public_inputs(
                    &por_pub_inputs,
                    &por_pub_params,
                    partition_k,
                )?;

                inputs.extend(por_inputs);
            }
        }
        let num_inputs_per_sector = inputs.len() / sectors.len();

        // duplicate last one if too little sectors available
        while inputs.len() / num_inputs_per_sector < num_sectors_per_chunk {
            let s = inputs[inputs.len() - num_inputs_per_sector..].to_vec();
            inputs.extend_from_slice(&s);
        }
        assert_eq!(inputs.len(), num_inputs_per_sector * num_sectors_per_chunk);

        Ok(inputs)
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
