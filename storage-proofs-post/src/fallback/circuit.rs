use anyhow::anyhow;
use bellperson::{gadgets::num::AllocatedNum, Circuit, ConstraintSystem, SynthesisError};
use ff::Field;
use filecoin_hashers::{Hasher, R1CSHasher};
use rayon::prelude::{ParallelIterator, ParallelSlice};
use sha2::{Digest, Sha256};
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

use crate::fallback::{
    self as vanilla, generate_leaf_challenge_inner, PublicParams, PublicSector, SectorProof,
};

/// This is the `FallbackPoSt` circuit.
pub struct FallbackPoStCircuit<Tree>
where
    Tree: MerkleTreeTrait,
    Tree::Hasher: R1CSHasher,
{
    pub prover_id: Option<Tree::Field>,
    pub sectors: Vec<Sector<Tree>>,
}

// We must manually implement Clone for all types generic over MerkleTreeTrait (instead of using
// #[derive(Clone)]) because derive(Clone) will only expand for MerkleTreeTrait types that also
// implement Clone. Not every MerkleTreeTrait type is Clone-able because not all merkel Store's are
// Clone-able, therefore deriving Clone would impl Clone for less than all possible Tree types.
impl<Tree> Clone for FallbackPoStCircuit<Tree>
where
    Tree: MerkleTreeTrait,
    Tree::Hasher: R1CSHasher,
{
    fn clone(&self) -> Self {
        FallbackPoStCircuit {
            prover_id: self.prover_id,
            sectors: self.sectors.clone(),
        }
    }
}

pub struct Sector<Tree>
where
    Tree: MerkleTreeTrait,
    Tree::Hasher: R1CSHasher,
{
    pub comm_r: Option<Tree::Field>,
    pub comm_c: Option<Tree::Field>,
    pub comm_r_last: Option<Tree::Field>,
    pub leafs: Vec<Option<Tree::Field>>,
    pub paths: Vec<AuthPath<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>,
    pub id: Option<Tree::Field>,
}

// We must manually implement Clone for all types generic over MerkleTreeTrait (instead of using
// #derive(Clone)).
impl<Tree> Clone for Sector<Tree>
where
    Tree: MerkleTreeTrait,
    Tree::Hasher: R1CSHasher,
{
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

impl<Tree> Sector<Tree>
where
    Tree: MerkleTreeTrait,
    Tree::Hasher: R1CSHasher,
{
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
            id: Some(Tree::Field::from(sector.id.into())),
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

impl<Tree> Circuit<Tree::Field> for &Sector<Tree>
where
    Tree: MerkleTreeTrait,
    Tree::Hasher: R1CSHasher,
{
    fn synthesize<CS>(self, cs: &mut CS) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<Tree::Field>,
    {
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
            let hash_num = Tree::Hasher::hash2_circuit(
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

impl<Tree> CircuitComponent for FallbackPoStCircuit<Tree>
where
    Tree: MerkleTreeTrait,
    Tree::Hasher: R1CSHasher,
{
    type ComponentPrivateInputs = ComponentPrivateInputs;
}

impl<Tree> Circuit<Tree::Field> for FallbackPoStCircuit<Tree>
where
    Tree: MerkleTreeTrait,
    Tree::Hasher: R1CSHasher,
{
    fn synthesize<CS>(self, cs: &mut CS) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<Tree::Field>,
    {
        if CS::is_extensible() {
            return self.synthesize_extendable(cs);
        }

        self.synthesize_default(cs)
    }
}

impl<Tree> FallbackPoStCircuit<Tree>
where
    Tree: MerkleTreeTrait,
    Tree::Hasher: R1CSHasher,
{
    fn synthesize_default<CS: ConstraintSystem<Tree::Field>>(
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

    fn synthesize_extendable<CS: ConstraintSystem<Tree::Field>>(
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
                cs.alloc_input(|| "temp ONE", || Ok(Tree::Field::one()))?;

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

    pub fn generate_public_inputs(
        pub_params: &vanilla::PublicParams,
        pub_inputs: &vanilla::PublicInputs<<Tree::Hasher as Hasher>::Domain>,
        partition_k: Option<usize>,
    ) -> Result<Vec<Tree::Field>> {
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
                    challenge_hasher.clone(), pub_params, challenge_index
                );

                let por_pub_inputs = por::PublicInputs {
                    commitment: None,
                    challenge: challenged_leaf as usize,
                };
                let por_inputs =
                    PoRCircuit::<Tree>::generate_public_inputs(&por_pub_params, &por_pub_inputs)?;

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
}
