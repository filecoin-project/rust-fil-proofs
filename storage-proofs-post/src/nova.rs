use std::marker::PhantomData;

use bellperson::{
    gadgets::{boolean::AllocatedBit, num::AllocatedNum},
    ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::PrimeField;
use filecoin_hashers::{poseidon::PoseidonHasher, Hasher, R1CSHasher};
use nova_snark::{errors::NovaError, traits::circuit::StepCircuit};
use storage_proofs_core::{
    gadgets::por::por_no_challenge_input,
    merkle::{Arity, LCTree, MerkleProofTrait, MerkleTreeTrait},
    nova::{self, gen_recursive_proof, CompressedProof, CycleScalar, RecursiveProof, StepExt},
    util::field_le_bits,
    SECTOR_NODES_32_KIB,
};

use crate::fallback as vanilla;

#[derive(Clone, Copy)]
pub struct SetupParams {
    pub sector_nodes: usize,
    pub total_sectors_challenged: usize,
    pub sectors_per_step: usize,
    pub challenges_per_sector: usize,
    pub num_steps: usize,
    pub sector_pad_len: usize,
}

impl SetupParams {
    #[inline]
    pub fn default_winning(sector_nodes: usize) -> Self {
        SetupParams {
            sector_nodes,
            total_sectors_challenged: 1,
            sectors_per_step: 1,
            challenges_per_sector: 66,
            num_steps: 1,
            sector_pad_len: 0,
        }
    }

    pub fn default_window(sector_nodes: usize, total_sectors_challenged: usize) -> Self {
        let sectors_per_step = if sector_nodes < SECTOR_NODES_32_KIB {
            2
        } else {
            // TODO: find an optimal value for sectors challenged per step.
            2
        };
        let num_steps = (total_sectors_challenged as f32 / sectors_per_step as f32).ceil() as usize;
        let sector_pad_len = sectors_per_step - (total_sectors_challenged % sectors_per_step);
        SetupParams {
            sector_nodes,
            total_sectors_challenged,
            sectors_per_step,
            challenges_per_sector: 10,
            num_steps,
            sector_pad_len,
        }
    }

    pub fn custom(
        sector_nodes: usize,
        total_sectors_challenged: usize,
        sectors_per_step: usize,
        challenges_per_sector: usize,
    ) -> Self {
        let num_steps = (total_sectors_challenged as f32 / sectors_per_step as f32).ceil() as usize;
        let sector_pad_len = sectors_per_step - (total_sectors_challenged % sectors_per_step);
        SetupParams {
            sector_nodes,
            total_sectors_challenged,
            sectors_per_step,
            challenges_per_sector,
            num_steps,
            sector_pad_len,
        }
    }
}

#[derive(Clone)]
pub struct PublicInputs<F: PrimeField> {
    // Each sector's CommR.
    pub comms_r: Vec<Option<F>>,
    // Each sector's challenges.
    pub challenges: Vec<Vec<Option<u32>>>,
}

impl<F: PrimeField> PublicInputs<F> {
    pub fn blank(sp: &SetupParams) -> Self {
        PublicInputs {
            comms_r: vec![None; sp.total_sectors_challenged],
            challenges: vec![vec![None; sp.challenges_per_sector]; sp.total_sectors_challenged],
        }
    }

    pub fn blank_keygen(sp: &SetupParams) -> Self {
        PublicInputs {
            comms_r: vec![Some(F::zero()); sp.total_sectors_challenged],
            challenges: vec![vec![Some(0); sp.challenges_per_sector]; sp.total_sectors_challenged],
        }
    }

    fn values_are_set(&self, sp: &SetupParams) -> bool {
        assert_eq!(self.comms_r.len(), sp.total_sectors_challenged);
        assert_eq!(self.challenges.len(), sp.total_sectors_challenged);
        if !self.comms_r.iter().all(Option::is_some) {
            return false;
        }
        for sector_challenges in &self.challenges {
            assert_eq!(sector_challenges.len(), sp.challenges_per_sector);
            if !sector_challenges.iter().all(Option::is_some) {
                return false;
            }
        }
        true
    }
}

#[derive(Clone)]
pub struct SectorProof<F: PrimeField> {
    pub comm_c: Option<F>,
    pub root_r: Option<F>,
    pub leafs_r: Vec<Option<F>>,
    pub paths_r: Vec<Vec<Vec<Option<F>>>>,
}

#[derive(Clone)]
pub struct PrivateInputs<F: PrimeField> {
    pub sector_proofs: Vec<SectorProof<F>>,
}

impl<F: PrimeField> PrivateInputs<F> {
    pub fn blank<A: Arity<F>>(sp: &SetupParams) -> Self {
        let sector_proof = SectorProof {
            comm_c: None,
            root_r: None,
            leafs_r: vec![None; sp.challenges_per_sector],
            paths_r: vec![A::blank_merkle_path(); sp.challenges_per_sector],
        };
        PrivateInputs {
            sector_proofs: vec![sector_proof; sp.total_sectors_challenged],
        }
    }

    pub fn blank_keygen<A: Arity<F>>(sp: &SetupParams) -> Self {
        let path_r: Vec<Vec<Option<F>>> = A::blank_merkle_path()
            .iter()
            .map(|sibs| vec![Some(F::zero()); sibs.len()])
            .collect();
        let sector_proof = SectorProof {
            comm_c: Some(F::zero()),
            root_r: Some(F::zero()),
            leafs_r: vec![Some(F::zero()); sp.challenges_per_sector],
            paths_r: vec![path_r; sp.challenges_per_sector],
        };
        PrivateInputs {
            sector_proofs: vec![sector_proof; sp.total_sectors_challenged],
        }
    }
}

#[derive(Clone)]
pub struct PostCircuit<F, A>
where
    F: CycleScalar,
    A: Arity<F>,
    PoseidonHasher<F>: R1CSHasher<Field = F>,
{
    pub sp: SetupParams,
    pub i: usize,
    pub pub_inputs: PublicInputs<F>,
    pub priv_inputs: PrivateInputs<F>,
    pub _a: PhantomData<A>,
}

impl<F, A> StepCircuit<F> for PostCircuit<F, A>
where
    F: CycleScalar,
    A: Arity<F>,
    PoseidonHasher<F>: R1CSHasher<Field = F>,
{
    fn arity(&self) -> usize {
        // Each sector proof proved in a step is associated with one input for the sector's CommR
        // and one input for each of the sector's merkle challenges.
        self.sp.sectors_per_step * (1 + self.sp.challenges_per_sector)
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let num_inputs = self.arity();
        assert_eq!(z.len(), num_inputs);

        let challenge_bit_len = self.sp.sector_nodes.trailing_zeros() as usize;
        let num_inputs_per_sector = 1 + self.sp.challenges_per_sector;
        let sector_inputs = z.chunks(num_inputs_per_sector);
        let sector_proofs_pad = self.sector_proofs_pad();
        let sector_proofs = self.sector_proofs().iter().chain(&sector_proofs_pad);

        for (sector_index, (sector_inputs, sector_proof)) in
            sector_inputs.zip(sector_proofs).enumerate()
        {
            let sector_name = format!("sector_{}", sector_index);
            let (comm_r, challenges) = (&sector_inputs[0], &sector_inputs[1..]);

            // Witness sector's TreeC and TreeR roots.
            let comm_c =
                AllocatedNum::alloc(cs.namespace(|| format!("{} comm_c", sector_name)), || {
                    sector_proof.comm_c.ok_or(SynthesisError::AssignmentMissing)
                })?;
            let root_r =
                AllocatedNum::alloc(cs.namespace(|| format!("{} root_r", sector_name)), || {
                    sector_proof.root_r.ok_or(SynthesisError::AssignmentMissing)
                })?;

            // Verify sector's CommR.
            let comm_r_calc = PoseidonHasher::hash2_circuit(
                cs.namespace(|| format!("{} comm_r_calc", sector_name)),
                &comm_c,
                &root_r,
            )?;
            cs.enforce(
                || format!("{} verify comm_r", sector_name),
                |lc| lc + comm_r.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + comm_r_calc.get_variable(),
            );

            // Verify each of the sector's TreeR merkle proofs.
            for (i, ((challenge, leaf_r), path_r)) in challenges
                .iter()
                .zip(&sector_proof.leafs_r)
                .zip(&sector_proof.paths_r)
                .enumerate()
            {
                let challenge_name = format!("{} challenge_{}", sector_name, i);

                let challenge_bits =
                    assign_challenge_bits(cs, &challenge_name, challenge, challenge_bit_len)?;

                let leaf_r = AllocatedNum::alloc(
                    cs.namespace(|| format!("{} leaf_r", challenge_name)),
                    || leaf_r.ok_or(SynthesisError::AssignmentMissing),
                )?;

                let path_r = path_r
                    .iter()
                    .enumerate()
                    .map(|(height, sibs)| {
                        sibs.iter()
                            .enumerate()
                            .map(|(sib_index, sib)| {
                                AllocatedNum::alloc(
                                    cs.namespace(|| {
                                        format!(
                                            "{} path_r height_{} sib_{}",
                                            challenge_name, height, sib_index,
                                        )
                                    }),
                                    || sib.ok_or(SynthesisError::AssignmentMissing),
                                )
                            })
                            .collect::<Result<Vec<AllocatedNum<F>>, SynthesisError>>()
                    })
                    .collect::<Result<Vec<Vec<AllocatedNum<F>>>, SynthesisError>>()?;

                por_no_challenge_input::<LCTree<PoseidonHasher<F>, A::U, A::V, A::W>, _>(
                    cs.namespace(|| format!("{} proof_r", challenge_name)),
                    challenge_bits.to_vec(),
                    leaf_r,
                    path_r,
                    root_r.clone(),
                )?;
            }
        }

        // Assign next circuit's inputs.
        self.outputs()
            .into_iter()
            .enumerate()
            .map(|(i, output)| {
                AllocatedNum::alloc(cs.namespace(|| format!("output_{}", i)), || Ok(output))
            })
            .collect()
    }

    #[inline]
    fn output(&self, _z: &[F]) -> Vec<F> {
        self.outputs()
    }
}

impl<F, A> StepExt<F> for PostCircuit<F, A>
where
    F: CycleScalar,
    A: Arity<F>,
    PoseidonHasher<F>: R1CSHasher<Field = F>,
{
    #[inline]
    fn step_index(&self) -> usize {
        self.i
    }

    #[inline]
    fn num_steps(&self) -> usize {
        self.sp.num_steps
    }

    #[inline]
    fn next_step(&mut self) {
        self.i += 1;
    }

    #[allow(clippy::unwrap_used)]
    fn inputs(&self) -> Vec<F> {
        assert!(self.i < self.sp.num_steps);
        assert!(self.pub_inputs.values_are_set(&self.sp));

        let num_inputs = self.num_inputs();
        let mut inputs = Vec::<F>::with_capacity(num_inputs);
        let sector_offset = self.i * self.sp.sectors_per_step;

        for (comm_r, challenges) in self
            .pub_inputs
            .comms_r
            .iter()
            .zip(&self.pub_inputs.challenges)
            .skip(sector_offset)
            .take(self.sp.sectors_per_step)
        {
            inputs.push(comm_r.unwrap());
            for challenge in challenges {
                inputs.push(F::from(challenge.unwrap() as u64));
            }
        }

        if self.is_last_step() && self.sp.sector_pad_len != 0 {
            let pad_comm_r = self.pub_inputs.comms_r.last().unwrap();
            let pad_challenges = self.pub_inputs.challenges.last().unwrap();
            for _ in 0..self.sp.sector_pad_len {
                inputs.push(pad_comm_r.unwrap());
                for challenge in pad_challenges {
                    inputs.push(F::from(challenge.unwrap() as u64));
                }
            }
        }

        assert_eq!(inputs.len(), num_inputs);
        inputs
    }

    #[allow(clippy::unwrap_used)]
    fn outputs(&self) -> Vec<F> {
        assert!(self.i < self.sp.num_steps);
        assert!(self.pub_inputs.values_are_set(&self.sp));

        let num_inputs = self.num_inputs();

        // Last step has no outputs.
        if self.is_last_step() {
            return vec![F::zero(); num_inputs];
        }

        let mut inputs = Vec::<F>::with_capacity(num_inputs);
        let next_step = self.i + 1;
        let sector_offset = next_step * self.sp.sectors_per_step;

        for (comm_r, challenges) in self
            .pub_inputs
            .comms_r
            .iter()
            .zip(&self.pub_inputs.challenges)
            .skip(sector_offset)
            .take(self.sp.sectors_per_step)
        {
            inputs.push(comm_r.unwrap());
            for challenge in challenges {
                inputs.push(F::from(challenge.unwrap() as u64));
            }
        }

        let next_step_is_last = next_step == self.sp.num_steps - 1;
        if next_step_is_last && self.sp.sector_pad_len != 0 {
            let pad_comm_r = self.pub_inputs.comms_r.last().unwrap();
            let pad_challenges = self.pub_inputs.challenges.last().unwrap();
            for _ in 0..self.sp.sector_pad_len {
                inputs.push(pad_comm_r.unwrap());
                for challenge in pad_challenges {
                    inputs.push(F::from(challenge.unwrap() as u64));
                }
            }
        }

        assert_eq!(inputs.len(), num_inputs);
        inputs
    }
}

impl<F, A> PostCircuit<F, A>
where
    F: CycleScalar,
    A: Arity<F>,
    PoseidonHasher<F>: R1CSHasher<Field = F>,
{
    pub fn blank(sp: &SetupParams) -> Self {
        PostCircuit {
            sp: sp.clone(),
            i: 0,
            pub_inputs: PublicInputs::blank(sp),
            priv_inputs: PrivateInputs::blank::<A>(sp),
            _a: PhantomData,
        }
    }

    pub fn blank_keygen(sp: &SetupParams) -> Self {
        PostCircuit {
            sp: sp.clone(),
            i: 0,
            pub_inputs: PublicInputs::blank_keygen(sp),
            priv_inputs: PrivateInputs::blank_keygen::<A>(sp),
            _a: PhantomData,
        }
    }

    pub fn sector_proofs(&self) -> &[SectorProof<F>] {
        assert!(self.i < self.sp.num_steps);
        let sector_offset = self.i * self.sp.sectors_per_step;
        if self.is_last_step() {
            &self.priv_inputs.sector_proofs[sector_offset..]
        } else {
            &self.priv_inputs.sector_proofs[sector_offset..sector_offset + self.sp.sectors_per_step]
        }
    }

    #[allow(clippy::unwrap_used)]
    pub fn sector_proofs_pad(&self) -> Vec<SectorProof<F>> {
        if self.is_last_step() && self.sp.sector_pad_len != 0 {
            let pad_sector_proof = self.priv_inputs.sector_proofs.last().unwrap().clone();
            vec![pad_sector_proof; self.sp.sector_pad_len]
        } else {
            vec![]
        }
    }

    #[inline]
    pub fn gen_params(&self) -> PostParams<F, A> {
        nova::gen_params(self.clone())
    }

    #[inline]
    pub fn load_params(&self) -> anyhow::Result<PostParams<F, A>> {
        nova::ParamStore::entry(self.clone())
    }
}

pub type PostParams<F, A> = nova::Params<<F as CycleScalar>::G1, PostCircuit<F, A>>;
pub type PostProof<F, A> = RecursiveProof<<F as CycleScalar>::G1, PostCircuit<F, A>>;
pub type PostCompressedProof<F, A> = CompressedProof<<F as CycleScalar>::G1, PostCircuit<F, A>>;

fn assign_challenge_bits<F, CS>(
    cs: &mut CS,
    challenge_name: &str,
    challenge: &AllocatedNum<F>,
    challenge_bit_len: usize,
) -> Result<Vec<AllocatedBit>, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    let bit_values: Vec<Option<bool>> = match challenge.get_value() {
        Some(ref f) => field_le_bits(f)
            .into_iter()
            .map(Some)
            .take(challenge_bit_len)
            .collect(),
        None => vec![None; challenge_bit_len],
    };

    let bits = bit_values
        .into_iter()
        .enumerate()
        .map(|(bit_index, bit)| {
            AllocatedBit::alloc(
                cs.namespace(|| format!("{} bit_{}", challenge_name, bit_index)),
                bit,
            )
        })
        .collect::<Result<Vec<AllocatedBit>, SynthesisError>>()?;

    let mut lc = LinearCombination::zero();
    let mut coeff = F::one();
    for bit in &bits {
        lc = lc + (coeff, bit.get_variable());
        coeff = coeff.double();
    }
    cs.enforce(
        || format!("{} binary decomp", challenge_name),
        |_| lc,
        |lc| lc + CS::one(),
        |lc| lc + challenge.get_variable(),
    );

    Ok(bits)
}

pub struct PostCompound<F, A>(PhantomData<(F, A)>)
where
    F: PrimeField,
    A: Arity<F>,
    PoseidonHasher<F>: R1CSHasher<Field = F>;

impl<F, A> PostCompound<F, A>
where
    F: CycleScalar,
    A: Arity<F>,
    PoseidonHasher<F>: R1CSHasher<Field = F>,
{
    pub fn create_recursive_circuit<TreeR>(
        sp: SetupParams,
        vanilla_pub_inputs: &vanilla::PublicInputs<<PoseidonHasher<F> as Hasher>::Domain>,
        vanilla_partition_proofs: &[vanilla::Proof<TreeR::Proof>],
    ) -> PostCircuit<F, A>
    where
        TreeR: MerkleTreeTrait<
            Field = F,
            Hasher = PoseidonHasher<F>,
            Arity = A::U,
            SubTreeArity = A::V,
            TopTreeArity = A::W,
        >,
    {
        let num_sectors_challenged = vanilla_pub_inputs.sectors.len();
        let num_sectors_proved: usize = vanilla_partition_proofs
            .iter()
            .map(|partition_proof| partition_proof.sectors.len())
            .sum();
        assert_eq!(num_sectors_challenged, sp.total_sectors_challenged);
        assert_eq!(num_sectors_proved, sp.total_sectors_challenged);

        let comms_r: Vec<Option<F>> = vanilla_pub_inputs
            .sectors
            .iter()
            .map(|sector| Some(sector.comm_r.into()))
            .collect();

        let mut challenges = Vec::<Vec<Option<u32>>>::with_capacity(sp.total_sectors_challenged);
        let mut sector_proofs = Vec::<SectorProof<F>>::with_capacity(sp.total_sectors_challenged);

        for partition_proof in vanilla_partition_proofs {
            for sector_proof in &partition_proof.sectors {
                assert_eq!(
                    sector_proof.inclusion_proofs.len(),
                    sp.challenges_per_sector
                );

                let comm_c: F = sector_proof.comm_c.into();
                let root_r: F = sector_proof.comm_r_last.into();

                let mut sector_challenges =
                    Vec::<Option<u32>>::with_capacity(sp.challenges_per_sector);
                let mut leafs_r = Vec::<Option<F>>::with_capacity(sp.challenges_per_sector);
                let mut paths_r =
                    Vec::<Vec<Vec<Option<F>>>>::with_capacity(sp.challenges_per_sector);

                for proof_r in &sector_proof.inclusion_proofs {
                    sector_challenges.push(Some(proof_r.path_index() as u32));
                    leafs_r.push(Some(proof_r.leaf().into()));
                    let path_r: Vec<Vec<Option<F>>> = proof_r
                        .path()
                        .iter()
                        .map(|(sibs, _)| sibs.iter().map(|&sib| Some(sib.into())).collect())
                        .collect();
                    paths_r.push(path_r);
                }

                challenges.push(sector_challenges);
                sector_proofs.push(SectorProof {
                    comm_c: Some(comm_c),
                    root_r: Some(root_r),
                    leafs_r,
                    paths_r,
                })
            }
        }

        PostCircuit {
            sp,
            i: 0,
            pub_inputs: PublicInputs {
                comms_r,
                challenges,
            },
            priv_inputs: PrivateInputs { sector_proofs },
            _a: PhantomData,
        }
    }

    #[inline]
    pub fn gen_params(sp: &SetupParams) -> PostParams<F, A> {
        nova::gen_params(PostCircuit::blank_keygen(sp))
    }

    #[inline]
    pub fn load_params(sp: &SetupParams) -> anyhow::Result<PostParams<F, A>> {
        nova::ParamStore::entry(PostCircuit::blank_keygen(sp))
    }

    #[inline]
    pub fn gen_recursive_proof(
        params: &PostParams<F, A>,
        circ: PostCircuit<F, A>,
    ) -> Result<PostProof<F, A>, NovaError> {
        gen_recursive_proof(params, circ)
    }

    #[inline]
    pub fn verify_recursive_proof(
        params: &PostParams<F, A>,
        proof: &PostProof<F, A>,
    ) -> Result<bool, NovaError> {
        proof.verify(params)
    }

    #[inline]
    pub fn gen_compressed_proof(
        params: &PostParams<F, A>,
        rec_proof: &PostProof<F, A>,
    ) -> Result<PostCompressedProof<F, A>, NovaError> {
        rec_proof.gen_compressed_proof(params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use filecoin_hashers::HashFunction;
    use pasta_curves::Fp;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::{
        api_version::ApiVersion,
        merkle::{generate_tree, Arity16K, Arity1K, Arity2K, Arity32K, Arity4K, Arity8K, DiskTree},
        proof::ProofScheme,
        TEST_SEED,
    };
    use tempfile::tempdir;

    use crate::fallback::{self as vanilla, FallbackPoSt};

    type TreeR<F, A> =
        DiskTree<PoseidonHasher<F>, <A as Arity<F>>::U, <A as Arity<F>>::V, <A as Arity<F>>::W>;

    enum PostType {
        Winning,
        Window,
    }

    fn test_inner<F, A>(post_type: PostType)
    where
        F: CycleScalar,
        A: Arity<F>,
        PoseidonHasher<F>: R1CSHasher<Field = F>,
    {
        let sector_nodes = A::SECTOR_NODES;
        let sector_bytes = sector_nodes << 5;
        let sp = match post_type {
            PostType::Winning => SetupParams::default_winning(sector_nodes),
            PostType::Window => SetupParams::default_window(sector_nodes, 5),
        };

        let mut rng = XorShiftRng::from_seed(TEST_SEED);
        let challenge_gen_randomness = F::random(&mut rng);

        let temp_dir = tempdir().expect("tempdir failure");
        let temp_path = temp_dir.path().to_path_buf();

        let vanilla_pub_params = vanilla::PublicParams {
            sector_size: sector_bytes as u64,
            challenge_count: sp.challenges_per_sector,
            sector_count: sp.total_sectors_challenged,
            api_version: ApiVersion::V1_1_0,
        };

        let mut trees_r = Vec::<TreeR<F, A>>::with_capacity(sp.total_sectors_challenged);
        let mut comms_c = Vec::<<PoseidonHasher<F> as Hasher>::Domain>::with_capacity(
            sp.total_sectors_challenged,
        );
        let mut pub_sectors =
            Vec::<vanilla::PublicSector<<PoseidonHasher<F> as Hasher>::Domain>>::with_capacity(
                sp.total_sectors_challenged,
            );

        for sector_id in 0..sp.total_sectors_challenged {
            let comm_c = F::random(&mut rng).into();
            let (_, tree_r) =
                generate_tree::<TreeR<F, A>, _>(&mut rng, sector_nodes, Some(temp_path.clone()));
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

        let mut priv_sectors = Vec::<vanilla::PrivateSector<'_, TreeR<F, A>>>::with_capacity(
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

        let vanilla_is_valid = FallbackPoSt::<'_, TreeR<F, A>>::verify(
            &vanilla_pub_params,
            &vanilla_pub_inputs,
            &vanilla_partition_proof,
        )
        .expect("failed to verify vanilla partition proof");
        assert!(vanilla_is_valid);

        // Create Nova circuits from vanilla artifacts.
        let circ = PostCompound::<F, A>::create_recursive_circuit::<TreeR<F, A>>(
            sp,
            &vanilla_pub_inputs,
            &[vanilla_partition_proof],
        );

        let nova_params = PostCompound::<F, A>::gen_params(&sp);
        /*
        let nova_params =
            PostCompound::<F, A>::load_params(&sp).expect("failed to load nova params");
        */

        // Generate and verify recursive proof.
        let rec_proof = PostCompound::gen_recursive_proof(&nova_params, circ)
            .expect("failed to generate recursive proof");
        assert!(rec_proof
            .verify(&nova_params)
            .expect("failed to verify recursive proof"));

        // Generate and verify compressed proof.
        let cmpr_proof = rec_proof
            .gen_compressed_proof(&nova_params)
            .expect("failed to generate compressed proof");
        assert!(cmpr_proof
            .verify(&nova_params)
            .expect("failed to verify compressed proof"));
    }

    #[test]
    fn test_winning_post_1kib_nova() {
        test_inner::<Fp, Arity1K>(PostType::Winning);
    }

    #[test]
    fn test_winning_post_2kib_nova() {
        test_inner::<Fp, Arity2K>(PostType::Winning);
    }

    #[test]
    fn test_winning_post_4kib_nova() {
        test_inner::<Fp, Arity4K>(PostType::Winning);
    }

    #[test]
    fn test_winning_post_8kib_nova() {
        test_inner::<Fp, Arity8K>(PostType::Winning);
    }

    #[test]
    fn test_winning_post_16kib_nova() {
        test_inner::<Fp, Arity16K>(PostType::Winning);
    }

    #[test]
    fn test_winning_post_32kib_nova() {
        test_inner::<Fp, Arity32K>(PostType::Winning);
    }

    #[test]
    fn test_window_post_1kib_nova() {
        test_inner::<Fp, Arity1K>(PostType::Window);
    }

    #[test]
    fn test_window_post_2kib_nova() {
        test_inner::<Fp, Arity2K>(PostType::Window);
    }

    #[test]
    fn test_window_post_4kib_nova() {
        test_inner::<Fp, Arity4K>(PostType::Window);
    }

    #[test]
    fn test_window_post_8kib_nova() {
        test_inner::<Fp, Arity8K>(PostType::Window);
    }

    #[test]
    fn test_window_post_16kib_nova() {
        test_inner::<Fp, Arity16K>(PostType::Window);
    }

    #[test]
    fn test_window_post_32kib_nova() {
        test_inner::<Fp, Arity32K>(PostType::Window);
    }
}
