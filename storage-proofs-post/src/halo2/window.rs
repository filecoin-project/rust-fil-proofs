use std::convert::TryInto;

use filecoin_hashers::{get_poseidon_constants, poseidon::PoseidonHasher, Hasher, PoseidonArity};
use generic_array::typenum::U2;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use sha2::{Digest, Sha256};
use storage_proofs_core::{halo2::CircuitRows, merkle::MerkleProofTrait};

use crate::{
    fallback as vanilla,
    halo2::{
        circuit::{PostConfig, SectorProof},
        constants::{SECTOR_NODES_32_GIB, SECTOR_NODES_64_GIB},
    },
};

// The number of Merkle challenges per challenged sector.
pub const SECTOR_CHALLENGES: usize = 10;

// The number of challenged sectors per partition.
pub const fn sectors_challenged_per_partition<const SECTOR_NODES: usize>() -> usize {
    match SECTOR_NODES {
        SECTOR_NODES_32_GIB => 2349,
        SECTOR_NODES_64_GIB => 2300,
        _ => 2,
    }
}

// Absolute row of a challenged sector's `comm_r` public input.
const fn comm_r_row(sector_index: usize) -> usize {
    sector_index * (1 + SECTOR_CHALLENGES)
}

// Absolute row of a challenged sector's Merkle challenge public input.
const fn challenge_row(sector_index: usize, challenge_index: usize) -> usize {
    comm_r_row(sector_index) + 1 + challenge_index
}

#[allow(clippy::unwrap_used)]
pub fn generate_challenges<F: FieldExt, const SECTOR_NODES: usize>(
    randomness: F,
    k: usize,
    // Sector's index in partition `k`.
    sector_index: usize,
    sector_id: u64,
) -> [u32; SECTOR_CHALLENGES] {
    let sector_nodes = SECTOR_NODES as u64;
    let mut hasher = Sha256::new();
    hasher.update(randomness.to_repr().as_ref());
    hasher.update(sector_id.to_le_bytes());

    let mut challenges = [0u32; SECTOR_CHALLENGES];
    let partition_sectors = sectors_challenged_per_partition::<SECTOR_NODES>();
    let mut challenge_index = (k * partition_sectors + sector_index) * SECTOR_CHALLENGES;

    for challenge in challenges.iter_mut() {
        let mut hasher = hasher.clone();
        hasher.update(&challenge_index.to_le_bytes());
        let digest = hasher.finalize();
        let uint64 = u64::from_le_bytes(digest[..8].try_into().unwrap());
        *challenge = (uint64 % sector_nodes) as u32;
        challenge_index += 1;
    }

    challenges
}

#[derive(Clone)]
pub struct PublicInputs<F, const SECTOR_NODES: usize>
where
    F: FieldExt,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    // Each challenged sector's `comm_r`.
    pub comms_r: Vec<Option<F>>,
    // Each challenged sector's Merkle challenges.
    pub challenges: Vec<[Option<u32>; SECTOR_CHALLENGES]>,
}

impl<F, const SECTOR_NODES: usize>
    From<vanilla::PublicInputs<<PoseidonHasher<F> as Hasher>::Domain>>
    for PublicInputs<F, SECTOR_NODES>
where
    F: FieldExt,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    #[allow(clippy::unwrap_used)]
    fn from(
        vanilla_pub_inputs: vanilla::PublicInputs<<PoseidonHasher<F> as Hasher>::Domain>,
    ) -> Self {
        let total_prover_sectors = vanilla_pub_inputs.sectors.len();
        let sectors_challenged_per_partition = sectors_challenged_per_partition::<SECTOR_NODES>();
        assert_eq!(total_prover_sectors % sectors_challenged_per_partition, 0);
        let partition_count = total_prover_sectors / sectors_challenged_per_partition;

        assert!(vanilla_pub_inputs.k.is_some());
        let k = vanilla_pub_inputs.k.unwrap();
        assert!(k < partition_count);

        let randomness: F = vanilla_pub_inputs.randomness.into();

        let partition_sectors = vanilla_pub_inputs
            .sectors
            .chunks(sectors_challenged_per_partition)
            .nth(k)
            .unwrap_or_else(|| {
                panic!(
                    "prover's sector set does not contain enough sectors for partition `k = {}`",
                    k,
                )
            });

        let mut pub_inputs = PublicInputs {
            comms_r: Vec::with_capacity(sectors_challenged_per_partition),
            challenges: Vec::with_capacity(sectors_challenged_per_partition),
        };

        for (sector_index, sector) in partition_sectors.iter().enumerate() {
            let sector_id: u64 = sector.id.into();
            let comm_r: F = sector.comm_r.into();
            let challenges =
                generate_challenges::<F, SECTOR_NODES>(randomness, k, sector_index, sector_id)
                    .iter()
                    .copied()
                    .map(Some)
                    .collect::<Vec<Option<u32>>>()
                    .try_into()
                    .unwrap();
            pub_inputs.comms_r.push(Some(comm_r));
            pub_inputs.challenges.push(challenges);
        }

        pub_inputs
    }
}

impl<F, const SECTOR_NODES: usize> PublicInputs<F, SECTOR_NODES>
where
    F: FieldExt,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    pub fn empty() -> Self {
        let challenged_sectors = sectors_challenged_per_partition::<SECTOR_NODES>();
        PublicInputs {
            comms_r: vec![None; challenged_sectors],
            challenges: vec![[None; SECTOR_CHALLENGES]; challenged_sectors],
        }
    }

    #[allow(clippy::unwrap_used)]
    pub fn to_vec(&self) -> Vec<Vec<F>> {
        let num_sectors = self.comms_r.len();
        assert_eq!(self.challenges.len(), num_sectors);
        assert!(
            self.comms_r.iter().all(Option::is_some)
                && self
                    .challenges
                    .iter()
                    .all(|challenges| challenges.iter().all(Option::is_some))
        );
        let mut pub_inputs = Vec::with_capacity(num_sectors * (1 + SECTOR_CHALLENGES));
        for (comm_r, challenges) in self.comms_r.iter().zip(self.challenges.iter()) {
            pub_inputs.push(comm_r.unwrap());
            for c in challenges {
                pub_inputs.push(F::from(c.unwrap() as u64));
            }
        }
        vec![pub_inputs]
    }
}

#[derive(Clone)]
pub struct PrivateInputs<F, U, V, W, const SECTOR_NODES: usize>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    pub sector_proofs: Vec<SectorProof<F, U, V, W, SECTOR_NODES, SECTOR_CHALLENGES>>,
}

impl<F, P, const SECTOR_NODES: usize> From<&[vanilla::SectorProof<P>]>
    for PrivateInputs<F, P::Arity, P::SubTreeArity, P::TopTreeArity, SECTOR_NODES>
where
    F: FieldExt,
    P: MerkleProofTrait<Hasher = PoseidonHasher<F>>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    fn from(sector_proofs: &[vanilla::SectorProof<P>]) -> Self {
        PrivateInputs {
            sector_proofs: sector_proofs.iter().map(SectorProof::from).collect(),
        }
    }
}

impl<F, P, const SECTOR_NODES: usize> From<&Vec<vanilla::SectorProof<P>>>
    for PrivateInputs<F, P::Arity, P::SubTreeArity, P::TopTreeArity, SECTOR_NODES>
where
    F: FieldExt,
    P: MerkleProofTrait<Hasher = PoseidonHasher<F>>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    fn from(sector_proofs: &Vec<vanilla::SectorProof<P>>) -> Self {
        Self::from(sector_proofs.as_slice())
    }
}

impl<F, U, V, W, const SECTOR_NODES: usize> PrivateInputs<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    pub fn empty() -> Self {
        let challenged_sectors = sectors_challenged_per_partition::<SECTOR_NODES>();
        PrivateInputs {
            sector_proofs: vec![SectorProof::empty(); challenged_sectors],
        }
    }
}

#[derive(Clone)]
pub struct WindowPostCircuit<F, U, V, W, const SECTOR_NODES: usize>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    pub pub_inputs: PublicInputs<F, SECTOR_NODES>,
    pub priv_inputs: PrivateInputs<F, U, V, W, SECTOR_NODES>,
}

impl<F, U, V, W, const SECTOR_NODES: usize> Circuit<F>
    for WindowPostCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    type Config = PostConfig<F, U, V, W, SECTOR_NODES>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        WindowPostCircuit {
            pub_inputs: PublicInputs::empty(),
            priv_inputs: PrivateInputs::empty(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        PostConfig::configure(meta)
    }

    #[allow(clippy::unwrap_used)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let WindowPostCircuit { priv_inputs, .. } = self;

        let challenged_sectors = sectors_challenged_per_partition::<SECTOR_NODES>();
        assert_eq!(priv_inputs.sector_proofs.len(), challenged_sectors);

        let advice = config.advice;
        let pi_col = config.pi;

        let (uint32_chip, poseidon_2_chip, tree_r_merkle_chip) = config.construct_chips();

        for (sector_index, sector_proof) in priv_inputs.sector_proofs.iter().enumerate() {
            // Witness the sector's `comm_c` and `root_r`.
            let (comm_c, root_r) = layouter.assign_region(
                || format!("witness sector {} comm_c and root_r", sector_index),
                |mut region| {
                    let offset = 0;
                    let comm_c = region.assign_advice(
                        || "comm_c",
                        advice[0],
                        offset,
                        || sector_proof.comm_c.ok_or(Error::Synthesis),
                    )?;
                    let root_r = region.assign_advice(
                        || "root_r",
                        advice[1],
                        offset,
                        || sector_proof.root_r.ok_or(Error::Synthesis),
                    )?;
                    Ok((comm_c, root_r))
                },
            )?;

            // Compute `comm_r = H(comm_c, root_r)` and constrain with public input.
            let comm_r = poseidon_2_chip.hash(
                layouter.namespace(|| "calculate comm_r"),
                &[comm_c, root_r.clone()],
                get_poseidon_constants::<F, U2>(),
            )?;
            layouter.constrain_instance(comm_r.cell(), pi_col, comm_r_row(sector_index))?;

            for (i, (leaf_r, path_r)) in sector_proof
                .leafs_r
                .iter()
                .zip(sector_proof.paths_r.iter())
                .enumerate()
            {
                // Assign the challenge as 32 bits and constrain with public input.
                let challenge_bits = uint32_chip.pi_assign_bits(
                    layouter.namespace(|| {
                        format!(
                            "sector {} challenge {} assign challenge public input as 32 bits",
                            sector_index, i,
                        )
                    }),
                    pi_col,
                    challenge_row(sector_index, i),
                )?;

                // Verify the challenge's TreeR Merkle proof.
                let root_r_calc = tree_r_merkle_chip.compute_root(
                    layouter.namespace(|| {
                        format!(
                            "sector {} challenge {} calculate comm_r from merkle proof",
                            sector_index, i,
                        )
                    }),
                    &challenge_bits,
                    leaf_r,
                    path_r,
                )?;
                layouter.assign_region(
                    || {
                        format!(
                            "sector {} challenge {} constrain root_r_calc",
                            sector_index, i
                        )
                    },
                    |mut region| region.constrain_equal(root_r_calc.cell(), root_r.cell()),
                )?;
            }
        }

        Ok(())
    }
}

impl<F, U, V, W, const SECTOR_NODES: usize> CircuitRows
    for WindowPostCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    fn k(&self) -> u32 {
        use crate::halo2::constants::*;
        match SECTOR_NODES {
            SECTOR_NODES_2_KIB => 11,
            SECTOR_NODES_4_KIB => 12,
            SECTOR_NODES_16_KIB => 12,
            SECTOR_NODES_32_KIB => 12,
            SECTOR_NODES_512_MIB => 13,
            SECTOR_NODES_32_GIB => 24,
            SECTOR_NODES_64_GIB => 24,
            _ => unimplemented!(),
        }
    }
}

impl<F, U, V, W, const SECTOR_NODES: usize> WindowPostCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    pub fn blank_circuit() -> Self {
        WindowPostCircuit {
            pub_inputs: PublicInputs::empty(),
            priv_inputs: PrivateInputs::empty(),
        }
    }
}
