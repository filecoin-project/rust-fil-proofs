use std::fmt;
use std::iter;
use std::marker::PhantomData;

use bellperson::{gadgets::num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;
use filecoin_hashers::{poseidon::PoseidonHasher, Domain, Hasher, HashFunction, PoseidonArity};
use nova_snark::traits::circuit::StepCircuit;
use sha2::{Digest, Sha256};
use storage_proofs_core::{
    gadgets::{
        boolean::assign_bits,
        por::{assign_path, blank_merkle_path, por_no_challenge_input},
    },
    merkle::{LCTree, MerkleProofTrait, MerkleTreeTrait},
    util::pretty_print_sector_size,
    nova::{CycleScalar, NovaCircuit},
};

use crate::fallback::{self as vanilla, generate_leaf_challenge_inner, get_challenge_index};

// The number of Merkle challenges per Winning/Window-PoSt sector.
const WINNING_SECTOR_CHALLENGES: usize = 66;
const WINDOW_SECTOR_CHALLENGES: usize = 10;

#[derive(Clone, Copy, PartialEq)]
pub enum PostType {
    Winning,
    Window,
}

impl fmt::Display for PostType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PostType::Winning => write!(f, "Winning"),
            PostType::Window => write!(f, "Window"),
        }
    }
}

#[derive(Clone, Copy)]
pub struct SetupParams {
    pub sector_nodes: usize,
    pub post_type: PostType,
    pub total_sectors_challenged: usize,
    pub sectors_per_step: usize,
    pub sector_pad_len: usize,
    pub challenges_per_sector: usize,
    pub num_steps: usize,
}

impl SetupParams {
    pub fn winning(sector_nodes: usize, challenges_per_step: usize) -> Self {
        assert_eq!(WINNING_SECTOR_CHALLENGES % challenges_per_step, 0);
        SetupParams {
            sector_nodes,
            post_type: PostType::Winning,
            total_sectors_challenged: 1,
            sectors_per_step: 1,
            sector_pad_len: 0,
            challenges_per_sector: WINNING_SECTOR_CHALLENGES,
            num_steps: WINNING_SECTOR_CHALLENGES / challenges_per_step,
        }
    }

    pub fn window(
        sector_nodes: usize,
        total_sectors_challenged: usize,
        sectors_per_step: usize,
    ) -> Self {
        let sector_pad_len = match total_sectors_challenged % sectors_per_step {
            0 => 0,
            last_step_sectors => sectors_per_step - last_step_sectors,
        };
        let num_steps = (total_sectors_challenged + sector_pad_len) / sectors_per_step;
        SetupParams {
            sector_nodes,
            post_type: PostType::Window,
            total_sectors_challenged,
            sectors_per_step,
            sector_pad_len,
            challenges_per_sector: WINDOW_SECTOR_CHALLENGES,
            num_steps,
        }
    }

    // Winning-PoSt distributes a single sector's challenges across multiple steps; this method
    // Returns the number of Merkle challenges per sector in a step, for Window-PoSt this is just
    // the number of Merkle challenges per sectors, whereas a Winning-PoSt sector's Merkle
    // challenges may be distributed across multiple steps.
    #[inline]
    fn step_challenges_per_sector(&self) -> usize {
        match self.post_type {
            PostType::Winning => self.challenges_per_sector / self.num_steps,
            PostType::Window => self.challenges_per_sector,
        }
    }

    // Each sector in a step is associated with the sector's merkle challenges and CommR.
    #[inline]
    fn pub_inputs_per_sector(&self) -> usize {
        self.step_challenges_per_sector() + 1
    }

    #[inline]
    pub fn is_winning(&self) -> bool {
        self.post_type == PostType::Winning
    }

    #[inline]
    pub fn is_window(&self) -> bool {
        !self.is_winning()
    }
}

#[derive(Clone)]
pub struct PublicInputs<F: PrimeField> {
    // Each sector's CommR.
    pub comms_r: Vec<F>,
    // Each sector's challenges.
    pub challenges: Vec<Vec<u32>>,
}

impl<F: PrimeField> PublicInputs<F> {
    pub fn blank(sp: &SetupParams) -> Self {
        PublicInputs {
            comms_r: vec![F::zero(); sp.total_sectors_challenged],
            challenges: vec![vec![0; sp.challenges_per_sector]; sp.total_sectors_challenged],
        }
    }
}

#[derive(Clone)]
pub struct SectorProof<F: PrimeField> {
    pub comm_c: F,
    pub root_r: F,
    pub leafs_r: Vec<F>,
    pub paths_r: Vec<Vec<Vec<F>>>,
}

#[derive(Clone)]
pub struct PrivateInputs<F: PrimeField> {
    pub sector_proofs: Vec<SectorProof<F>>,
}

impl<F: PrimeField> PrivateInputs<F> {
    pub fn blank<U, V, W>(sp: &SetupParams) -> Self
    where
        U: PoseidonArity<F>,
        V: PoseidonArity<F>,
        W: PoseidonArity<F>,
    {
        let path_r = blank_merkle_path::<F, U, V, W>(sp.sector_nodes);
        let sector_proof = SectorProof {
            comm_c: F::zero(),
            root_r: F::zero(),
            leafs_r: vec![F::zero(); sp.challenges_per_sector],
            paths_r: vec![path_r; sp.challenges_per_sector],
        };
        PrivateInputs {
            sector_proofs: vec![sector_proof; sp.total_sectors_challenged],
        }
    }
}

#[derive(Clone)]
pub struct PostCircuit<F, U, V, W>
where
    F: PrimeField,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
{
    pub sp: SetupParams,
    pub step_index: usize,
    pub pub_inputs: PublicInputs<F>,
    pub priv_inputs: PrivateInputs<F>,
    pub _a: PhantomData<(U, V, W)>,
}

impl<F, U, V, W> StepCircuit<F> for PostCircuit<F, U, V, W>
where
    F: CycleScalar,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    #[inline]
    fn arity(&self) -> usize {
        self.sp.sectors_per_step * self.sp.pub_inputs_per_sector()
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        assert_eq!(z.len(), self.arity());
        assert_eq!(self.priv_inputs.sector_proofs.len(), self.sp.total_sectors_challenged);

        let challenge_bit_len = self.sp.sector_nodes.trailing_zeros() as usize;

        let sector_offset =
            self.sp.is_window() as usize * self.step_index * self.sp.sectors_per_step;

        let sector_proofs = self.priv_inputs.sector_proofs
            .iter()
            .skip(sector_offset)
            .chain(iter::repeat(self.priv_inputs.sector_proofs.last().unwrap()))
            .take(self.sp.sectors_per_step);

        let challenge_offset =
            self.sp.is_winning() as usize * self.step_index * self.sp.step_challenges_per_sector();

        for (sector_index, (sector_inputs, sector_proof)) in z
            .chunks(self.sp.pub_inputs_per_sector())
            .zip(sector_proofs)
            .enumerate()
        {
            let sector_name = format!("sector_{}", sector_index);
            let (comm_r, challenges) = (&sector_inputs[0], &sector_inputs[1..]);

            // Verify sector's CommR.
            let comm_c = AllocatedNum::alloc(cs.namespace(|| format!("{} comm_c", sector_name)), || {
                Ok(sector_proof.comm_c)
            })?;
            let root_r = AllocatedNum::alloc(cs.namespace(|| format!("{} root_r", sector_name)), || {
                Ok(sector_proof.root_r)
            })?;
            let comm_r_calc = <PoseidonHasher<F> as Hasher>::Function::hash2_circuit(
                cs.namespace(|| format!("{} comm_r_calc", sector_name)),
                &comm_c,
                &root_r,
            )?;

            // Mock CommR validation if testing without valid TreeRs.
            let comm_r = if cfg!(all(test, feature = "mock-test-circ")) {
                &comm_r_calc
            } else {
                comm_r
            };

            cs.enforce(
                || format!("{} verify comm_r", sector_name),
                |lc| lc + comm_r.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + comm_r_calc.get_variable(),
            );

            // Verify each sector's TreeR merkle proofs.
            for (i, ((challenge, leaf_r), path_r)) in challenges
                .iter()
                .zip(&sector_proof.leafs_r[challenge_offset..])
                .zip(&sector_proof.paths_r[challenge_offset..])
                .enumerate()
            {
                let challenge_name = format!("{} challenge_{}", sector_name, i);

                let challenge_bits =
                    assign_bits(cs, &challenge_name, challenge, challenge_bit_len)?;

                let leaf_r = AllocatedNum::alloc(
                    cs.namespace(|| format!("{} leaf_r", challenge_name)),
                    || Ok(*leaf_r)
                )?;

                let path_r = assign_path(cs, &format!("{} path_r", challenge_name), path_r)?;

                por_no_challenge_input::<LCTree<PoseidonHasher<F>, U, V, W>, _>(
                    cs.namespace(|| format!("{} proof_r", challenge_name)),
                    challenge_bits,
                    leaf_r,
                    path_r,
                    root_r.clone(),
                )?;
            }
        }

        // Assign next step's inputs.
        self
            .step_outputs()
            .into_iter()
            .enumerate()
            .map(|(i, output)| {
                AllocatedNum::alloc(cs.namespace(|| format!("output_{}", i)), || Ok(output))
            })
            .collect()
    }

    #[inline]
    fn output(&self, _z: &[F]) -> Vec<F> {
        self.step_outputs()
    }
}

impl<F, U, V, W> NovaCircuit<F::G> for PostCircuit<F, U, V, W>
where
    F: CycleScalar,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    #[inline]
    fn circ_name(&self) -> String {
        format!(
            "{}-PoSt-{} {{ sectors_per_step: {}, challenges_per_sector: {} }}",
            self.sp.post_type,
            pretty_print_sector_size(self.sp.sector_nodes),
            self.sp.sectors_per_step,
            self.sp.step_challenges_per_sector(),
        )
    }

    #[inline]
    fn step_index(&self) -> usize {
        self.step_index
    }

    #[inline]
    fn num_steps(&self) -> usize {
        self.sp.num_steps
    }

    #[inline]
    fn next_step(&mut self) {
        self.step_index += 1;
    }

    fn step_inputs(&self) -> Vec<F> {
        assert!(self.step_index < self.sp.num_steps);
        assert_eq!(self.pub_inputs.comms_r.len(), self.sp.total_sectors_challenged);
        assert_eq!(self.pub_inputs.challenges.len(), self.sp.total_sectors_challenged);
        assert!(self.pub_inputs.challenges
            .iter()
            .all(|challenges| challenges.len() == self.sp.challenges_per_sector));

        let num_inputs = self.arity();
        let mut inputs = Vec::<F>::with_capacity(num_inputs);

        let comms_r = self.pub_inputs.comms_r
            .iter()
            .chain(iter::repeat(self.pub_inputs.comms_r.last().unwrap()));

        let challenges = self.pub_inputs.challenges
            .iter()
            .chain(iter::repeat(self.pub_inputs.challenges.last().unwrap()));

        let sectors_per_step = self.sp.sectors_per_step;
        let sector_offset = self.step_index * sectors_per_step;
        let challenges_per_sector = self.sp.step_challenges_per_sector();
        let challenge_offset =
            self.sp.is_winning() as usize * self.step_index * challenges_per_sector;

        for (comm_r, challenges) in
            comms_r.zip(challenges).skip(sector_offset).take(sectors_per_step)
        {
            inputs.push(*comm_r);
            for challenge in challenges.iter().skip(challenge_offset).take(challenges_per_sector) {
                inputs.push(F::from(*challenge as u64));
            }
        }

        assert_eq!(inputs.len(), num_inputs);
        inputs
    }

    fn step_outputs(&self) -> Vec<F> {
        assert!(self.step_index < self.sp.num_steps);
        assert_eq!(self.pub_inputs.comms_r.len(), self.sp.total_sectors_challenged);
        assert_eq!(self.pub_inputs.challenges.len(), self.sp.total_sectors_challenged);
        assert!(self.pub_inputs.challenges
            .iter()
            .all(|challenges| challenges.len() == self.sp.challenges_per_sector));

        let num_outputs = self.arity();
        if self.step_index == self.sp.num_steps - 1 {
            return vec![F::zero(); num_outputs];
        }
        let mut outputs = Vec::<F>::with_capacity(num_outputs);

        let comms_r = self.pub_inputs.comms_r
            .iter()
            .chain(iter::repeat(self.pub_inputs.comms_r.last().unwrap()));

        let challenges = self.pub_inputs.challenges
            .iter()
            .chain(iter::repeat(self.pub_inputs.challenges.last().unwrap()));

        let next_step_index = self.step_index + 1;
        let sectors_per_step = self.sp.sectors_per_step;
        let sector_offset = next_step_index * sectors_per_step;
        let challenges_per_sector = self.sp.step_challenges_per_sector();
        let challenge_offset =
            self.sp.is_winning() as usize * next_step_index * challenges_per_sector;

        for (comm_r, challenges) in
            comms_r.zip(challenges).skip(sector_offset).take(sectors_per_step)
        {
            outputs.push(*comm_r);
            for challenge in challenges.iter().skip(challenge_offset).take(challenges_per_sector) {
                outputs.push(F::from(*challenge as u64));
            }
        }

        assert_eq!(outputs.len(), num_outputs);
        outputs
    }
}

impl<F, U, V, W> PostCircuit<F, U, V, W>
where
    F: PrimeField,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    pub fn blank(sp: &SetupParams) -> Self {
        PostCircuit {
            sp: sp.clone(),
            step_index: 0,
            pub_inputs: PublicInputs::blank(sp),
            priv_inputs: PrivateInputs::blank::<U, V, W>(sp),
            _a: PhantomData,
        }
    }

    pub fn from_vanilla<Tree>(
        sp: SetupParams,
        vanilla_pub_inputs: &vanilla::PublicInputs<<PoseidonHasher<F> as Hasher>::Domain>,
        vanilla_partition_proofs: &[vanilla::Proof<Tree::Proof>],
    ) -> Self
    where
        Tree: MerkleTreeTrait<
            Field = F,
            Hasher = PoseidonHasher<F>,
            Arity = U,
            SubTreeArity = V,
            TopTreeArity = W,
        >,
    {
        let num_sectors_challenged = vanilla_pub_inputs.sectors.len();
        let num_sectors_proved: usize = vanilla_partition_proofs
            .iter()
            .map(|partition_proof| partition_proof.sectors.len())
            .sum();

        assert_eq!(num_sectors_challenged, num_sectors_proved);
        assert_eq!(num_sectors_challenged, sp.total_sectors_challenged);

        assert!(vanilla_partition_proofs
            .iter()
            .flat_map(|partition_proof| &partition_proof.sectors)
            .all(|sector_proof| sector_proof.inclusion_proofs.len() == sp.challenges_per_sector));

        let comms_r: Vec<F> =
            vanilla_pub_inputs.sectors.iter().map(|sector| sector.comm_r.into()).collect();

        let mut challenges = Vec::<Vec<u32>>::with_capacity(sp.total_sectors_challenged);
        let mut sector_proofs = Vec::<SectorProof<F>>::with_capacity(sp.total_sectors_challenged);

        for partition_proof in vanilla_partition_proofs {
            for sector_proof in &partition_proof.sectors {
                let comm_c: F = sector_proof.comm_c.into();
                let root_r: F = sector_proof.comm_r_last.into();

                let mut sector_challenges = Vec::<u32>::with_capacity(sp.challenges_per_sector);
                let mut leafs_r = Vec::<F>::with_capacity(sp.challenges_per_sector);
                let mut paths_r = Vec::<Vec<Vec<F>>>::with_capacity(sp.challenges_per_sector);

                for proof_r in &sector_proof.inclusion_proofs {
                    sector_challenges.push(proof_r.path_index() as u32);
                    leafs_r.push(proof_r.leaf().into());
                    let path_r: Vec<Vec<F>> = proof_r
                        .path()
                        .iter()
                        .map(|(sibs, _)| sibs.iter().map(|&sib| sib.into()).collect())
                        .collect();
                    paths_r.push(path_r);
                }

                challenges.push(sector_challenges);
                sector_proofs.push(SectorProof {
                    comm_c,
                    root_r,
                    leafs_r,
                    paths_r,
                });
            }
        }

        PostCircuit {
            sp,
            step_index: 0,
            pub_inputs: PublicInputs {
                comms_r,
                challenges,
            },
            priv_inputs: PrivateInputs { sector_proofs },
            _a: PhantomData,
        }
    }

    pub fn verifier_from_vanilla(
        sp: SetupParams,
        vanilla_sp: &vanilla::SetupParams,
        vanilla_pub_inputs: &vanilla::PublicInputs<<PoseidonHasher<F> as Hasher>::Domain>,
    ) -> Self {
        assert_eq!(vanilla_sp.sector_size as usize >> 5, sp.sector_nodes);
        assert_eq!(vanilla_sp.challenge_count, sp.challenges_per_sector);
        assert_eq!(vanilla_pub_inputs.sectors.len(), sp.total_sectors_challenged);

        let vanilla_pp = vanilla::PublicParams {
            sector_size: vanilla_sp.sector_size,
            challenge_count: vanilla_sp.challenge_count,
            sector_count: vanilla_sp.sector_count,
            api_version: vanilla_sp.api_version,
        };

        let mut comms_r = Vec::<F>::with_capacity(sp.total_sectors_challenged);
        let mut challenges = Vec::<Vec<u32>>::with_capacity(sp.total_sectors_challenged);

        for (sector_index, sector) in vanilla_pub_inputs.sectors.iter().enumerate() {
            comms_r.push(sector.comm_r.into());

            let mut sector_hasher = Sha256::new();
            sector_hasher.update(&vanilla_pub_inputs.randomness.into_bytes());
            sector_hasher.update(&u64::from(sector.id).to_le_bytes());

            let sector_challenges: Vec<u32> = (0..sp.challenges_per_sector)
                .map(|i| {
                    let challenge_index = get_challenge_index(
                        vanilla_sp.api_version,
                        sector_index,
                        sp.challenges_per_sector,
                        i,
                    );
                    generate_leaf_challenge_inner::<<PoseidonHasher<F> as Hasher>::Domain>(
                        sector_hasher.clone(),
                        &vanilla_pp,
                        challenge_index,
                    ) as u32
                })
                .collect();

            challenges.push(sector_challenges);
        }

        PostCircuit {
            sp,
            step_index: 0,
            pub_inputs: PublicInputs {
                comms_r,
                challenges,
            },
            priv_inputs: PrivateInputs {
                sector_proofs: vec![],
            },
            _a: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use generic_array::typenum::{U0, U2, U4, U8};
    use pasta_curves::Fp;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::{
        api_version::ApiVersion,
        merkle::{generate_tree, DiskTree},
        proof::ProofScheme,
        SECTOR_NODES_16_KIB, SECTOR_NODES_2_KIB, SECTOR_NODES_32_KIB, SECTOR_NODES_4_KIB,
        SECTOR_NODES_8_KIB, TEST_SEED,
    };
    use tempfile::tempdir;

    use crate::fallback::FallbackPoSt;

    // Configuration parameters for tests; these values can be changed.
    const WINNING_CHALLENGES_PER_STEP: usize = 1;
    const WINDOW_TOTAL_SECTORS: usize = 5;
    const WINDOW_SECTORS_PER_STEP: usize = 3;

    type TreeR<F, U, V, W> = DiskTree<PoseidonHasher<F>, U, V, W>;

    fn test_inner<F, U, V, W>(sector_nodes: usize, post_type: PostType)
    where
        F: CycleScalar,
        U: PoseidonArity<F>,
        V: PoseidonArity<F>,
        W: PoseidonArity<F>,
        PoseidonHasher<F>: Hasher<Field = F>,
    {
        fil_logger::maybe_init();

        let sp = match post_type {
            PostType::Winning => SetupParams::winning(sector_nodes, WINNING_CHALLENGES_PER_STEP),
            PostType::Window => SetupParams::window(
                sector_nodes,
                WINDOW_TOTAL_SECTORS,
                WINDOW_SECTORS_PER_STEP,
            ),
        };

        let mut circ = if cfg!(feature = "mock-test-circ") {
            PostCircuit::<F, U, V, W>::blank(&sp)
        } else {
            let mut rng = XorShiftRng::from_seed(TEST_SEED);
            let challenge_gen_randomness = F::random(&mut rng);

            let temp_dir = tempdir().expect("tempdir failure");
            let temp_path = temp_dir.path().to_path_buf();

            let vanilla_pub_params = vanilla::PublicParams {
                sector_size: (sector_nodes as u64) << 5,
                challenge_count: sp.challenges_per_sector,
                sector_count: sp.total_sectors_challenged,
                api_version: ApiVersion::V1_2_0,
            };

            let mut trees_r = Vec::<TreeR<F, U, V, W>>::with_capacity(sp.total_sectors_challenged);
            let mut comms_c = Vec::<<PoseidonHasher<F> as Hasher>::Domain>::with_capacity(
                sp.total_sectors_challenged,
            );
            let mut pub_sectors =
                Vec::<vanilla::PublicSector<<PoseidonHasher<F> as Hasher>::Domain>>::with_capacity(
                    sp.total_sectors_challenged,
                );

            for sector_id in 0..sp.total_sectors_challenged {
                let comm_c = F::random(&mut rng).into();
                let (_, tree_r) = generate_tree::<TreeR<F, U, V, W>, _>(
                    &mut rng,
                    sector_nodes,
                    Some(temp_path.clone()),
                );
                let root_r = tree_r.root();
                let comm_r = <PoseidonHasher<F> as Hasher>::Function::hash2(&comm_c, &root_r);
                pub_sectors.push(vanilla::PublicSector {
                    id: (sector_id as u64).into(),
                    comm_r,
                });
                trees_r.push(tree_r);
                comms_c.push(comm_c);
            }

            let vanilla_pub_inputs = vanilla::PublicInputs {
                randomness: challenge_gen_randomness.into(),
                prover_id: F::from(55).into(),
                sectors: pub_sectors,
                k: Some(0),
            };

            let mut priv_sectors = Vec::<vanilla::PrivateSector<'_, TreeR<F, U, V, W>>>::with_capacity(
                sp.total_sectors_challenged,
            );

            for (tree_r, comm_c) in trees_r.iter().zip(comms_c) {
                let root_r = tree_r.root();
                priv_sectors.push(vanilla::PrivateSector {
                    tree: tree_r,
                    comm_c,
                    comm_r_last: root_r,
                });
            }

            let vanilla_priv_inputs = vanilla::PrivateInputs {
                sectors: &priv_sectors,
            };

            // Prove all sectors in a single vanilla partition proof.
            let vanilla_partition_proof = FallbackPoSt::prove(
                &vanilla_pub_params,
                &vanilla_pub_inputs,
                &vanilla_priv_inputs,
            )
            .expect("failed to generate vanilla partition proof");

            assert_eq!(
                vanilla_partition_proof.sectors.len(),
                sp.total_sectors_challenged,
            );
            assert!(vanilla_partition_proof
                .sectors
                .iter()
                .all(|sector_proof| sector_proof.inclusion_proofs.len() == sp.challenges_per_sector));

            let vanilla_is_valid = FallbackPoSt::<'_, TreeR<F, U, V, W>>::verify(
                &vanilla_pub_params,
                &vanilla_pub_inputs,
                &vanilla_partition_proof,
            )
            .expect("failed to verify vanilla partition proof");
            assert!(vanilla_is_valid);

            // Create Nova circuits from vanilla artifacts.
            PostCircuit::<F, U, V, W>::from_vanilla::<TreeR<F, U, V, W>>(
                sp,
                &vanilla_pub_inputs,
                &[vanilla_partition_proof],
            )
        };

        let params = circ.gen_params();

        let r_proof =
            circ.gen_recursive_proof(&params).expect("failed to generate recursive proof");
        assert!(r_proof.verify(&params).expect("failed to verify recursive proof"));

        let (cpk, cvk) = circ.gen_compression_keypair(&params);

        let c_proof =
            r_proof.compress(&params, &cpk).expect("failed to generated compressed proof");
        /*
        let proof_size = c_proof.proof_bytes().expect("failed to serialize compressed proof").len();
        println!("compressed proof size: {} bytes", proof_size);
        */
        assert!(c_proof.verify(&cvk).expect("failed to verify compressed proof"));
    }

    #[test]
    fn test_winning_post_2kib_nova() {
        test_inner::<Fp, U8, U0, U0>(SECTOR_NODES_2_KIB, PostType::Winning);
    }

    #[test]
    fn test_winning_post_4kib_nova() {
        test_inner::<Fp, U8, U2, U0>(SECTOR_NODES_4_KIB, PostType::Winning);
    }

    #[test]
    fn test_winning_post_8kib_nova() {
        test_inner::<Fp, U8, U4, U0>(SECTOR_NODES_8_KIB, PostType::Winning);
    }

    #[test]
    fn test_winning_post_16kib_nova() {
        test_inner::<Fp, U8, U8, U0>(SECTOR_NODES_16_KIB, PostType::Winning);
    }

    #[test]
    fn test_winning_post_32kib_nova() {
        test_inner::<Fp, U8, U8, U2>(SECTOR_NODES_32_KIB, PostType::Winning);
    }

    #[test]
    fn test_window_post_2kib_nova() {
        test_inner::<Fp, U8, U0, U0>(SECTOR_NODES_2_KIB, PostType::Window);
    }

    #[test]
    fn test_window_post_4kib_nova() {
        test_inner::<Fp, U8, U2, U0>(SECTOR_NODES_4_KIB, PostType::Window);
    }

    #[test]
    fn test_window_post_8kib_nova() {
        test_inner::<Fp, U8, U4, U0>(SECTOR_NODES_8_KIB, PostType::Window);
    }

    #[test]
    fn test_window_post_16kib_nova() {
        test_inner::<Fp, U8, U8, U0>(SECTOR_NODES_16_KIB, PostType::Window);
    }

    #[test]
    fn test_window_post_32kib_nova() {
        test_inner::<Fp, U8, U8, U2>(SECTOR_NODES_32_KIB, PostType::Window);
    }
}
