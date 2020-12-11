use bellperson::bls::{Bls12, Fr};
use bellperson::gadgets::num;
use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use ff::Field;
use filecoin_hashers::{HashFunction, Hasher};
use rayon::prelude::*;
use storage_proofs_core::{
    compound_proof::CircuitComponent,
    error::Result,
    gadgets::constraint,
    gadgets::por::{AuthPath, PoRCircuit},
    gadgets::variables::Root,
    merkle::MerkleTreeTrait,
    por, settings,
    util::NODE_SIZE,
};

use super::vanilla::{PublicParams, PublicSector, SectorProof};

/// This is the `FallbackPoSt` circuit.
pub struct FallbackPoStCircuit<Tree: MerkleTreeTrait> {
    pub prover_id: Option<Fr>,
    pub sectors: Vec<Sector<Tree>>,
}

#[derive(Clone)]
pub struct Sector<Tree: MerkleTreeTrait> {
    pub comm_r: Option<Fr>,
    pub comm_c: Option<Fr>,
    pub comm_r_last: Option<Fr>,
    pub leafs: Vec<Option<Fr>>,
    pub paths: Vec<AuthPath<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>,
    pub id: Option<Fr>,
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

        let comm_r_num = num::AllocatedNum::alloc(cs.namespace(|| "comm_r"), || {
            comm_r
                .map(Into::into)
                .ok_or_else(|| SynthesisError::AssignmentMissing)
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

        let num_chunks = settings::SETTINGS.window_post_synthesis_num_cpus as usize;

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
