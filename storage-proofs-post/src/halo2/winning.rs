use std::convert::TryInto;
use std::ops::RangeInclusive;

use filecoin_hashers::{
    poseidon::PoseidonHasher, Domain, FieldArity, Hasher, PoseidonArity, POSEIDON_CONSTANTS,
};
use generic_array::typenum::U2;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use sha2::{Digest, Sha256};
use storage_proofs_core::halo2::CircuitRows;

use crate::{
    fallback as vanilla,
    halo2::circuit::{PostConfig, SectorProof},
};

pub const CHALLENGE_COUNT: usize = 66;

// Absolute rows of public inputs.
const COMM_R_ROW: usize = 0;
const CHALLENGE_ROWS: RangeInclusive<usize> = 1..=CHALLENGE_COUNT;

#[allow(clippy::unwrap_used)]
pub fn generate_challenges<F: FieldExt, const SECTOR_NODES: usize>(
    randomness: F,
    sector_id: u64,
    k: usize,
) -> [u32; CHALLENGE_COUNT] {
    let sector_nodes = SECTOR_NODES as u64;
    let mut hasher = Sha256::new();
    hasher.update(randomness.to_repr().as_ref());
    hasher.update(sector_id.to_le_bytes());

    let mut challenges = [0u32; CHALLENGE_COUNT];

    for (i, challenge) in challenges.iter_mut().enumerate() {
        let challenge_index = (k * CHALLENGE_COUNT + i) as u64;
        let mut hasher = hasher.clone();
        hasher.update(&challenge_index.to_le_bytes());
        let digest = hasher.finalize();
        let uint64 = u64::from_le_bytes(digest[..8].try_into().unwrap());
        *challenge = (uint64 % sector_nodes) as u32;
    }

    challenges
}

#[derive(Clone)]
pub struct PublicInputs<F, const SECTOR_NODES: usize>
where
    F: FieldExt,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
{
    pub comm_r: Option<F>,
    pub challenges: [Option<u32>; CHALLENGE_COUNT],
}

impl<F, const SECTOR_NODES: usize>
    From<vanilla::PublicInputs<<PoseidonHasher<F> as Hasher>::Domain>>
    for PublicInputs<F, SECTOR_NODES>
where
    F: FieldExt,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
{
    #[allow(clippy::unwrap_used)]
    fn from(
        vanilla_pub_inputs: vanilla::PublicInputs<<PoseidonHasher<F> as Hasher>::Domain>,
    ) -> Self {
        assert_eq!(vanilla_pub_inputs.sectors.len(), 1);
        assert_eq!(vanilla_pub_inputs.k, Some(0));

        let randomness: F = vanilla_pub_inputs.randomness.into();
        let sector_id: u64 = vanilla_pub_inputs.sectors[0].id.into();
        let comm_r: F = vanilla_pub_inputs.sectors[0].comm_r.into();
        let k = vanilla_pub_inputs.k.unwrap();

        let challenges = generate_challenges::<F, SECTOR_NODES>(randomness, sector_id, k)
            .iter()
            .copied()
            .map(Some)
            .collect::<Vec<Option<u32>>>()
            .try_into()
            .unwrap();

        PublicInputs {
            comm_r: Some(comm_r),
            challenges,
        }
    }
}

impl<F, const SECTOR_NODES: usize> PublicInputs<F, SECTOR_NODES>
where
    F: FieldExt,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
{
    pub fn empty() -> Self {
        PublicInputs {
            comm_r: None,
            challenges: [None; CHALLENGE_COUNT],
        }
    }

    #[allow(clippy::unwrap_used)]
    pub fn to_vec(&self) -> Vec<Vec<F>> {
        assert!(self.comm_r.is_some() && self.challenges.iter().all(Option::is_some));
        let mut pub_inputs = Vec::with_capacity(1 + CHALLENGE_COUNT);
        pub_inputs.push(self.comm_r.unwrap());
        for c in &self.challenges {
            pub_inputs.push(F::from(c.unwrap() as u64));
        }
        vec![pub_inputs]
    }
}

pub type PrivateInputs<F, U, V, W, const SECTOR_NODES: usize> =
    SectorProof<F, U, V, W, SECTOR_NODES, CHALLENGE_COUNT>;

#[derive(Clone)]
pub struct WinningPostCircuit<F, U, V, W, const SECTOR_NODES: usize>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
{
    pub pub_inputs: PublicInputs<F, SECTOR_NODES>,
    pub priv_inputs: PrivateInputs<F, U, V, W, SECTOR_NODES>,
}

impl<F, U, V, W, const SECTOR_NODES: usize> Circuit<F>
    for WinningPostCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
{
    type Config = PostConfig<F, U, V, W, SECTOR_NODES>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        WinningPostCircuit {
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
        let WinningPostCircuit { priv_inputs, .. } = self;

        let advice = config.advice;
        let pi_col = config.pi;

        let (uint32_chip, poseidon_2_chip, tree_r_merkle_chip) = config.construct_chips();

        // Witness `comm_c` and `root_r`.
        let (comm_c, root_r) = layouter.assign_region(
            || "witness comm_c and root_r",
            |mut region| {
                let offset = 0;
                let comm_c = region.assign_advice(
                    || "comm_c",
                    advice[0],
                    offset,
                    || priv_inputs.comm_c.ok_or(Error::Synthesis),
                )?;

                let root_r = region.assign_advice(
                    || "root_r",
                    advice[1],
                    offset,
                    || priv_inputs.root_r.ok_or(Error::Synthesis),
                )?;

                Ok((comm_c, root_r))
            },
        )?;

        // Compute `comm_r = H(comm_c, root_r)` and constrain with public input.
        let comm_r = poseidon_2_chip.hash(
            layouter.namespace(|| "calculate comm_r"),
            &[comm_c, root_r.clone()],
            POSEIDON_CONSTANTS.get::<FieldArity<F, U2>>().unwrap(),
        )?;
        layouter.constrain_instance(comm_r.cell(), pi_col, COMM_R_ROW)?;

        for (i, ((leaf_r, path_r), challenge_row)) in priv_inputs
            .leafs_r
            .iter()
            .zip(priv_inputs.paths_r.iter())
            .zip(CHALLENGE_ROWS)
            .enumerate()
        {
            // Assign the challenge as 32 bits and constrain with public input.
            let challenge_bits = uint32_chip.pi_assign_bits(
                layouter.namespace(|| {
                    format!("challenge {} assign challenge public input as 32 bits", i,)
                }),
                pi_col,
                challenge_row,
            )?;

            // Verify the challenge's TreeR Merkle proof.
            let root_r_calc = tree_r_merkle_chip.compute_root(
                layouter
                    .namespace(|| format!("challenge {} calculate comm_r from merkle proof", i)),
                &challenge_bits,
                leaf_r,
                path_r,
            )?;
            layouter.assign_region(
                || format!("challenge {} constrain root_r_calc", i),
                |mut region| region.constrain_equal(root_r_calc.cell(), root_r.cell()),
            )?;
        }

        Ok(())
    }
}

impl<F, U, V, W, const SECTOR_NODES: usize> CircuitRows
    for WinningPostCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
{
    fn k(&self) -> u32 {
        use crate::halo2::constants::*;
        match SECTOR_NODES {
            SECTOR_NODES_2_KIB => 13,
            SECTOR_NODES_4_KIB => 13,
            SECTOR_NODES_16_KIB => 13,
            SECTOR_NODES_32_KIB => 14,
            // TODO (jake): add more sector sizes
            _ => unimplemented!(),
        }
    }
}

impl<F, U, V, W, const SECTOR_NODES: usize> WinningPostCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
{
    pub fn blank_circuit() -> Self {
        WinningPostCircuit {
            pub_inputs: PublicInputs::empty(),
            priv_inputs: PrivateInputs::empty(),
        }
    }
}
