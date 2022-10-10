use std::convert::TryInto;
use std::ops::RangeInclusive;

use filecoin_hashers::{
    get_poseidon_constants, poseidon::PoseidonHasher, Hasher, PoseidonArity, HALO2_STRENGTH_IS_STD,
};
use generic_array::typenum::U2;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use sha2::{Digest, Sha256};
use storage_proofs_core::{
    halo2::CircuitRows, util::NODE_SIZE, SECTOR_NODES_16_KIB, SECTOR_NODES_2_KIB,
    SECTOR_NODES_32_GIB, SECTOR_NODES_32_KIB, SECTOR_NODES_4_KIB, SECTOR_NODES_512_MIB,
    SECTOR_NODES_64_GIB,
};

use crate::{
    fallback as vanilla,
    halo2::circuit::{PostConfig, SectorProof},
};

// The number of partitions per Winning-PoSt proof.
pub const PARTITION_COUNT: usize = 1;
// The number of sectors challenged per partition.
pub const SECTORS_CHALLENGED: usize = 1;
// The number of Merkle challenges per sector.
pub const CHALLENGE_COUNT: usize = 66;

// Absolute rows of public inputs.
const COMM_R_ROW: usize = 0;
const CHALLENGE_ROWS: RangeInclusive<usize> = 1..=CHALLENGE_COUNT;

#[allow(clippy::unwrap_used)]
pub fn generate_challenges<F: FieldExt, const SECTOR_NODES: usize>(
    randomness: F,
    sector_id: u64,
) -> [u32; CHALLENGE_COUNT] {
    let sector_nodes = SECTOR_NODES as u64;
    let mut hasher = Sha256::new();
    hasher.update(randomness.to_repr().as_ref());
    hasher.update(sector_id.to_le_bytes());

    let mut challenges = [0u32; CHALLENGE_COUNT];

    for (challenge_index, challenge) in challenges.iter_mut().enumerate() {
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
    PoseidonHasher<F>: Hasher<Field = F>,
{
    pub comm_r: Option<F>,
    pub challenges: [Option<u32>; CHALLENGE_COUNT],
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
        assert_eq!(vanilla_pub_inputs.sectors.len(), SECTORS_CHALLENGED);
        assert_eq!(vanilla_pub_inputs.k, Some(0));

        let randomness: F = vanilla_pub_inputs.randomness.into();
        let sector_id: u64 = vanilla_pub_inputs.sectors[0].id.into();
        let comm_r: F = vanilla_pub_inputs.sectors[0].comm_r.into();

        let challenges = generate_challenges::<F, SECTOR_NODES>(randomness, sector_id)
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
    PoseidonHasher<F>: Hasher<Field = F>,
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
    PoseidonHasher<F>: Hasher<Field = F>,
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
    PoseidonHasher<F>: Hasher<Field = F>,
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
                let comm_c =
                    region.assign_advice(|| "comm_c", advice[0], offset, || priv_inputs.comm_c)?;

                let root_r =
                    region.assign_advice(|| "root_r", advice[1], offset, || priv_inputs.root_r)?;

                Ok((comm_c, root_r))
            },
        )?;

        // Compute `comm_r = H(comm_c, root_r)` and constrain with public input.
        let comm_r = poseidon_2_chip.hash(
            layouter.namespace(|| "calculate comm_r"),
            &[comm_c, root_r.clone()],
            get_poseidon_constants::<F, U2>(),
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
                *leaf_r,
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
    PoseidonHasher<F>: Hasher<Field = F>,
{
    fn id(&self) -> String {
        use super::circuit::WINNING_POST_CIRCUIT_ID;
        WINNING_POST_CIRCUIT_ID.to_string()
    }

    fn k(&self) -> u32 {
        // Values were computed using `get_k` test.
        match HALO2_STRENGTH_IS_STD {
            true => match SECTOR_NODES {
                SECTOR_NODES_2_KIB => 14,
                SECTOR_NODES_4_KIB => 14,
                SECTOR_NODES_16_KIB => 14,
                SECTOR_NODES_32_KIB => 15,
                SECTOR_NODES_512_MIB => 16,
                SECTOR_NODES_32_GIB => 16,
                SECTOR_NODES_64_GIB => 16,
                _ => unimplemented!(),
            },
            false => match SECTOR_NODES {
                SECTOR_NODES_2_KIB => 13,
                SECTOR_NODES_4_KIB => 13,
                SECTOR_NODES_16_KIB => 13,
                SECTOR_NODES_32_KIB => 14,
                SECTOR_NODES_512_MIB => 15,
                SECTOR_NODES_32_GIB => 15,
                SECTOR_NODES_64_GIB => 15,
                _ => unimplemented!(),
            },
        }
    }

    fn sector_size(&self) -> usize {
        (SECTOR_NODES * NODE_SIZE) / 1024
    }
}

impl<F, U, V, W, const SECTOR_NODES: usize> WinningPostCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    pub fn blank_circuit() -> Self {
        WinningPostCircuit {
            pub_inputs: PublicInputs::empty(),
            priv_inputs: PrivateInputs::empty(),
        }
    }

    #[allow(clippy::unwrap_used)]
    pub fn compute_k(k_start: Option<u32>) -> u32 {
        use halo2_proofs::{circuit::Value, dev::MockProver};
        use storage_proofs_core::halo2::gadgets::por;

        let pub_inputs = PublicInputs {
            comm_r: Some(F::zero()),
            challenges: [Some(0); CHALLENGE_COUNT],
        };
        let pub_inputs_vec = pub_inputs.to_vec();

        let priv_inputs = {
            let mut path_r = por::empty_path::<F, U, V, W, SECTOR_NODES>();
            for sibs in path_r.iter_mut() {
                *sibs = vec![Value::known(F::zero()); sibs.len()];
            }
            SectorProof {
                comm_c: Value::known(F::zero()),
                root_r: Value::known(F::zero()),
                leafs_r: [Value::known(F::zero()); CHALLENGE_COUNT],
                paths_r: vec![path_r; CHALLENGE_COUNT].try_into().unwrap(),
                _tree_r: std::marker::PhantomData,
            }
        };

        let circ = WinningPostCircuit::<F, U, V, W, SECTOR_NODES> {
            pub_inputs,
            priv_inputs,
        };

        // If a minimum `k` value is not supplied, use poseidon's.
        let mut k = k_start.unwrap_or(7);
        loop {
            // println!("Trying k = {}", k);
            match MockProver::run(k, &circ, pub_inputs_vec.clone()) {
                Ok(_) => return k,
                Err(Error::NotEnoughRowsAvailable { .. }) | Err(Error::InstanceTooLarge) => k += 1,
                err => panic!("Unexpected error: {:?}", err),
            };
        }
    }
}

#[test]
#[ignore]
fn get_k() {
    use generic_array::typenum::{U0, U8};
    use halo2_proofs::pasta::Fp;

    let mut k = WinningPostCircuit::<Fp, U8, U0, U0, SECTOR_NODES_2_KIB>::compute_k(None);
    println!("Found k = {} (sector-size = 2kib)", k);

    k = WinningPostCircuit::<Fp, U8, U2, U0, SECTOR_NODES_4_KIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 4kib)", k);

    /*
    use generic_array::typenum::U4;
    k = WinningPostCircuit::<Fp, U8, U4, U0, SECTOR_NODES_8_KIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 8kib)", k);
    */

    k = WinningPostCircuit::<Fp, U8, U8, U0, SECTOR_NODES_16_KIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 16kib)", k);

    k = WinningPostCircuit::<Fp, U8, U8, U2, SECTOR_NODES_32_KIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 32kib)", k);

    /*
    k = WinningPostCircuit::<Fp, U8, U0, U0, SECTOR_NODES_8_MIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 8mib)", k);

    k = WinningPostCircuit::<Fp, U8, U2, U0, SECTOR_NODES_16_MIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 16mib)", k);
    */

    k = WinningPostCircuit::<Fp, U8, U0, U0, SECTOR_NODES_512_MIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 512mib)", k);

    k = WinningPostCircuit::<Fp, U8, U8, U0, SECTOR_NODES_32_GIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 32gib)", k);

    k = WinningPostCircuit::<Fp, U8, U8, U2, SECTOR_NODES_64_GIB>::compute_k(Some(k));
    println!("Found k = {} (sector-size = 64gib)", k);
}
