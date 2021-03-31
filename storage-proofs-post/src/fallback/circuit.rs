use bellperson::{
    bls::{Bls12, Fr},
    gadgets::num::AllocatedNum,
    Circuit, ConstraintSystem, SynthesisError,
};
use ff::Field;
use filecoin_hashers::{HashFunction, Hasher};
use rayon::prelude::{ParallelIterator, ParallelSlice};
use storage_proofs_core::{
    compound_proof::CircuitComponent,
    error::Result,
    gadgets::{
        constraint,
        por::{AuthPath, PoRCircuit},
        variables::Root,
    },
    merkle::MerkleTreeTrait,
    por,
    settings::SETTINGS,
    util::NODE_SIZE,
};

use crate::fallback::{PublicParams, PublicSector, SectorProof};

/// This is the `FallbackPoSt` circuit.
pub struct FallbackPoStCircuit<Tree: MerkleTreeTrait> {
    pub prover_id: Option<Fr>,
    pub sectors: Vec<Sector<Tree>>,
}

// We must manually implement Clone for all types generic over MerkleTreeTrait (instead of using
// #[derive(Clone)]) because derive(Clone) will only expand for MerkleTreeTrait types that also
// implement Clone. Not every MerkleTreeTrait type is Clone-able because not all merkel Store's are
// Clone-able, therefore deriving Clone would impl Clone for less than all possible Tree types.
impl<Tree: 'static + MerkleTreeTrait> Clone for FallbackPoStCircuit<Tree> {
    fn clone(&self) -> Self {
        FallbackPoStCircuit {
            prover_id: self.prover_id,
            sectors: self.sectors.clone(),
        }
    }
}

pub struct Sector<Tree: MerkleTreeTrait> {
    pub comm_r: Option<Fr>,
    pub comm_c: Option<Fr>,
    pub comm_r_last: Option<Fr>,
    pub leafs: Vec<Option<Fr>>,
    pub paths: Vec<AuthPath<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>,
    pub id: Option<Fr>,
}

// We must manually implement Clone for all types generic over MerkleTreeTrait (instead of using
// #derive(Clone)).
impl<Tree: MerkleTreeTrait> Clone for Sector<Tree> {
    fn clone(&self) -> Self {
        Sector {
            comm_r: self.comm_r,
            comm_c: self.comm_c,
            comm_r_last: self.comm_r_last,
            leafs: self.leafs.clone(),
            paths: self.paths.clone(),
            id: self.id,
        }
    }
}

impl<Tree: 'static + MerkleTreeTrait> Sector<Tree> {
    pub fn circuit(
        sector: &PublicSector<<Tree::Hasher as Hasher>::Domain>,
        vanilla_proof: &SectorProof<Tree::Proof>,
    ) -> Result<Self> {
        let leafs = vanilla_proof
            .leafs()
            .iter()
            .map(|l| Some((*l).into()))
            .collect();

        let paths = vanilla_proof
            .as_options()
            .into_iter()
            .map(Into::into)
            .collect();

        Ok(Sector {
            leafs,
            id: Some(sector.id.into()),
            comm_r: Some(sector.comm_r.into()),
            comm_c: Some(vanilla_proof.comm_c.into()),
            comm_r_last: Some(vanilla_proof.comm_r_last.into()),
            paths,
        })
    }

    pub fn blank_circuit(pub_params: &PublicParams) -> Self {
        let challenges_count = pub_params.challenge_count;
        let leaves = pub_params.sector_size as usize / NODE_SIZE;

        let por_params = por::PublicParams {
            leaves,
            private: true,
        };
        let leafs = vec![None; challenges_count];
        let paths = vec![AuthPath::blank(por_params.leaves); challenges_count];

        Sector {
            id: None,
            comm_r: None,
            comm_c: None,
            comm_r_last: None,
            leafs,
            paths,
        }
    }
}

impl<Tree: 'static + MerkleTreeTrait> Circuit<Bls12> for &Sector<Tree> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let Sector {
            comm_r,
            comm_c,
            comm_r_last,
            leafs,
            paths,
            ..
        } = self;

        assert_eq!(paths.len(), leafs.len());

        // 1. Verify comm_r
        let comm_r_last_num = AllocatedNum::alloc(cs.namespace(|| "comm_r_last"), || {
            comm_r_last
                .map(Into::into)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let comm_c_num = AllocatedNum::alloc(cs.namespace(|| "comm_c"), || {
            comm_c
                .map(Into::into)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let comm_r_num = AllocatedNum::alloc(cs.namespace(|| "comm_r"), || {
            comm_r
                .map(Into::into)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        comm_r_num.inputize(cs.namespace(|| "comm_r_input"))?;

        // 1. Verify H(Comm_C || comm_r_last) == comm_r
        {
            let hash_num = <Tree::Hasher as Hasher>::Function::hash2_circuit(
                cs.namespace(|| "H_comm_c_comm_r_last"),
                &comm_c_num,
                &comm_r_last_num,
            )?;

            // Check actual equality
            constraint::equal(
                cs,
                || "enforce_comm_c_comm_r_last_hash_comm_r",
                &comm_r_num,
                &hash_num,
            );
        }

        // 2. Verify Inclusion Paths
        for (i, (leaf, path)) in leafs.iter().zip(paths.iter()).enumerate() {
            PoRCircuit::<Tree>::synthesize(
                cs.namespace(|| format!("challenge_inclusion_{}", i)),
                Root::Val(*leaf),
                path.clone(),
                Root::from_allocated::<CS>(comm_r_last_num.clone()),
                true,
            )?;
        }

        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct ComponentPrivateInputs {}

impl<Tree: MerkleTreeTrait> CircuitComponent for FallbackPoStCircuit<Tree> {
    type ComponentPrivateInputs = ComponentPrivateInputs;
}

impl<Tree: 'static + MerkleTreeTrait> Circuit<Bls12> for FallbackPoStCircuit<Tree> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        if CS::is_extensible() {
            return self.synthesize_extendable(cs);
        }

        self.synthesize_default(cs)
    }
}

impl<Tree: 'static + MerkleTreeTrait> FallbackPoStCircuit<Tree> {
    fn synthesize_default<CS: ConstraintSystem<Bls12>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let cs = &mut cs.namespace(|| "outer namespace".to_string());

        for (i, sector) in self.sectors.iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("sector_{}", i));
            sector.synthesize(cs)?;
        }
        Ok(())
    }

    fn synthesize_extendable<CS: ConstraintSystem<Bls12>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let FallbackPoStCircuit { sectors, .. } = self;

        let num_chunks = SETTINGS.window_post_synthesis_num_cpus as usize;

        let chunk_size = (sectors.len() / num_chunks).max(1);
        let css = sectors
            .par_chunks(chunk_size)
            .map(|sector_group| {
                let mut cs = CS::new();
                cs.alloc_input(|| "temp ONE", || Ok(Fr::one()))?;

                for (i, sector) in sector_group.iter().enumerate() {
                    let mut cs = cs.namespace(|| format!("sector_{}", i));

                    sector.synthesize(&mut cs)?;
                }
                Ok(cs)
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        for sector_cs in css.into_iter() {
            cs.extend(sector_cs);
        }

        Ok(())
    }
}
