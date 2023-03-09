use std::marker::PhantomData;

pub use storage_proofs_core::drgraph::BASE_DEGREE as DRG_PARENTS;

use bellperson::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        num::AllocatedNum,
    },
    ConstraintSystem, SynthesisError,
};
use ff::{PrimeField, PrimeFieldBits};
use filecoin_hashers::{poseidon::PoseidonHasher, sha256::Sha256Hasher, Hasher, R1CSHasher};
use nova_snark::{errors::NovaError, traits::circuit::StepCircuit};
use storage_proofs_core::{
    gadgets::encode::encode,
    merkle::{Arity, MerkleProofTrait, MerkleTreeTrait},
    nova::{
        self, gen_compression_keypair, gen_recursive_proof, CompressedProof, CompressionKeypair,
        CompressionPk, CompressionVk, CycleScalar, RecursiveProof, StepExt,
    },
    SECTOR_NODES_32_KIB,
};

pub use crate::stacked::{EXP_DEGREE as EXP_PARENTS, TOTAL_PARENTS as REPEATED_PARENTS};

use crate::stacked::{
    nova::gadgets::{
        assign_challenge_bits, assign_parent_proofs, assign_proof_d, assign_path_c,
        assign_path_r, create_label, hash_column, hash_parent_columns, verify_proof_c,
        verify_proof_d, verify_proof_r, 
    },
    vanilla,
};

pub const TOTAL_PARENTS: usize = DRG_PARENTS + EXP_PARENTS;
const MERKLE_CHALLENGES_PER_POREP_CHALLENGE: usize = TOTAL_PARENTS + 1;

#[derive(Clone, Copy)]
pub struct SetupParams {
    pub sector_nodes: usize,
    pub num_layers: usize,
    pub total_challenge_count: usize,
    pub challenges_per_step: usize,
    pub num_steps: usize,
}

impl SetupParams {
    #[inline]
    pub fn default(sector_nodes: usize) -> Self {
        if sector_nodes < SECTOR_NODES_32_KIB {
            SetupParams {
                sector_nodes,
                num_layers: 2,
                total_challenge_count: 4,
                challenges_per_step: 2,
                num_steps: 2,
            }
        } else {
            SetupParams {
                sector_nodes,
                num_layers: 11,
                total_challenge_count: 176,
                challenges_per_step: 1,
                num_steps: 176,
            }
        }
    }

    pub fn custom(
        sector_nodes: usize,
        num_layers: usize,
        total_challenge_count: usize,
        challenges_per_step: usize,
    ) -> Self {
        assert_eq!(total_challenge_count % challenges_per_step, 0);
        let num_steps = total_challenge_count / challenges_per_step;

        SetupParams {
            sector_nodes,
            num_layers,
            total_challenge_count,
            challenges_per_step,
            num_steps,
        }
    }
}

#[derive(Clone)]
pub struct PublicInputs<F: PrimeField> {
    pub replica_id: Option<F>,
    pub comm_d: Option<F>,
    pub comm_r: Option<F>,
    // All porep challenges.
    pub challenges: Vec<Option<u32>>,
    pub parents: Vec<Vec<Option<u32>>>,
}

impl<F: PrimeField> PublicInputs<F> {
    pub fn blank(sp: &SetupParams) -> Self {
        PublicInputs {
            replica_id: None,
            comm_d: None,
            comm_r: None,
            challenges: vec![None; sp.total_challenge_count],
            parents: vec![vec![None; TOTAL_PARENTS]; sp.total_challenge_count],
        }
    }

    pub fn blank_keygen(sp: &SetupParams) -> Self {
        PublicInputs {
            replica_id: Some(F::zero()),
            comm_d: Some(F::zero()),
            comm_r: Some(F::zero()),
            challenges: vec![Some(0); sp.total_challenge_count],
            parents: vec![vec![Some(0); TOTAL_PARENTS]; sp.total_challenge_count],
        }
    }

    fn values_are_set(&self, total_challenge_count: usize) -> bool {
        assert_eq!(self.challenges.len(), total_challenge_count);
        assert_eq!(self.parents.len(), total_challenge_count);
        let mut has_values = self.replica_id.is_some();
        has_values |= self.comm_d.is_some();
        has_values |= self.comm_r.is_some();
        has_values |= self.challenges.iter().all(Option::is_some);
        for parents in &self.parents {
            assert_eq!(parents.len(), TOTAL_PARENTS);
            has_values |= parents.iter().all(Option::is_some);
        }
        has_values
    }
}

#[derive(Clone, Debug)]
pub struct ParentProof<F: PrimeField> {
    pub column: Vec<Option<F>>,
    pub path_c: Vec<Vec<Option<F>>>,
}

#[derive(Clone)]
pub struct ChallengeProof<F: PrimeField> {
    pub leaf_d: Option<F>,
    pub path_d: Vec<Option<F>>,
    pub path_c: Vec<Vec<Option<F>>>,
    pub path_r: Vec<Vec<Option<F>>>,
    pub drg_parent_proofs: Vec<ParentProof<F>>,
    pub exp_parent_proofs: Vec<ParentProof<F>>,
}

#[derive(Clone)]
pub struct PrivateInputs<F: PrimeField> {
    pub comm_c: Option<F>,
    pub root_r: Option<F>,
    // All porep challenge proofs.
    pub challenge_proofs: Vec<ChallengeProof<F>>,
}

impl<F: PrimeField> PrivateInputs<F> {
    pub fn blank<A: Arity<F>>(sp: &SetupParams) -> Self {
        let challenge_bit_len = sp.sector_nodes.trailing_zeros() as usize;
        let path_r = A::blank_merkle_path();

        let parent_proof = ParentProof {
            column: vec![None; sp.num_layers],
            path_c: path_r.clone(),
        };

        let challenge_proof = ChallengeProof {
            leaf_d: None,
            path_d: vec![None; challenge_bit_len],
            path_c: path_r.clone(),
            path_r: path_r.clone(),
            drg_parent_proofs: vec![parent_proof.clone(); DRG_PARENTS],
            exp_parent_proofs: vec![parent_proof; EXP_PARENTS],
        };

        PrivateInputs {
            comm_c: None,
            root_r: None,
            challenge_proofs: vec![challenge_proof; sp.total_challenge_count],
        }
    }

    pub fn blank_keygen<A: Arity<F>>(sp: &SetupParams) -> Self {
        let challenge_bit_len = sp.sector_nodes.trailing_zeros() as usize;

        let path_r: Vec<Vec<Option<F>>> = A::blank_merkle_path()
            .iter()
            .map(|sibs| vec![Some(F::zero()); sibs.len()])
            .collect();

        let parent_proof = ParentProof {
            column: vec![Some(F::zero()); sp.num_layers],
            path_c: path_r.clone(),
        };

        let challenge_proof = ChallengeProof {
            leaf_d: Some(F::zero()),
            path_d: vec![Some(F::zero()); challenge_bit_len],
            path_c: path_r.clone(),
            path_r: path_r.clone(),
            drg_parent_proofs: vec![parent_proof.clone(); DRG_PARENTS],
            exp_parent_proofs: vec![parent_proof; EXP_PARENTS],
        };

        PrivateInputs {
            comm_c: Some(F::zero()),
            root_r: Some(F::zero()),
            challenge_proofs: vec![challenge_proof; sp.total_challenge_count],
        }
    }
}

#[derive(Clone)]
pub struct SdrPorepCircuit<F, A>
where
    F: CycleScalar + PrimeFieldBits,
    A: Arity<F>,
    Sha256Hasher<F>: R1CSHasher<Field = F>,
    PoseidonHasher<F>: R1CSHasher<Field = F>,
{
    pub sp: SetupParams,
    pub i: usize,
    pub pub_inputs: PublicInputs<F>,
    pub priv_inputs: PrivateInputs<F>,
    pub _a: PhantomData<A>,
}

impl<F, A> StepCircuit<F> for SdrPorepCircuit<F, A>
where
    F: CycleScalar + PrimeFieldBits,
    A: Arity<F>,
    Sha256Hasher<F>: R1CSHasher<Field = F>,
    PoseidonHasher<F>: R1CSHasher<Field = F>,
{
    fn arity(&self) -> usize {
        3 + self.sp.challenges_per_step * MERKLE_CHALLENGES_PER_POREP_CHALLENGE
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        assert_eq!(self.sp.sector_nodes, A::SECTOR_NODES);
        let num_inputs = self.arity();
        assert_eq!(z.len(), num_inputs);

        let SdrPorepCircuit {
            sp,
            priv_inputs: PrivateInputs { comm_c, root_r, .. },
            ..
        } = self;

        let challenge_bit_len = sp.sector_nodes.trailing_zeros() as usize;

        let (replica_id, comm_d, comm_r) = (&z[0], &z[1], &z[2]);
        let mut challenges = Vec::<AllocatedNum<F>>::with_capacity(sp.challenges_per_step);
        let mut parents = Vec::<Vec<AllocatedNum<F>>>::with_capacity(sp.challenges_per_step);
        for challenge_and_parents in z[3..].chunks(MERKLE_CHALLENGES_PER_POREP_CHALLENGE) {
            challenges.push(challenge_and_parents[0].clone());
            parents.push(challenge_and_parents[1..].to_vec());
        }

        let replica_id_bits = replica_id.to_bits_le(cs.namespace(|| "replica_id bits"))?;

        // Witness roots of TreeC and TreeR.
        let comm_c = AllocatedNum::alloc(cs.namespace(|| "comm_c"), || {
            comm_c.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let root_r = AllocatedNum::alloc(cs.namespace(|| "root_r"), || {
            root_r.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Verify `comm_r == H(comm_c || root_r)`.
        let comm_r_calc =
            PoseidonHasher::hash2_circuit(cs.namespace(|| "comm_r_calc"), &comm_c, &root_r)?;
        cs.enforce(
            || "verify comm_r",
            |lc| lc + comm_r.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + comm_r_calc.get_variable(),
        );

        for (i, ((challenge, parents), challenge_proof)) in challenges
            .iter()
            .zip(&parents)
            .zip(self.challenge_proofs())
            .enumerate()
        {
            let challenge_name = format!("challenge_{}", i);

            let challenge_bits =
                assign_challenge_bits(cs, &challenge_name, challenge, challenge_bit_len)?;

            let parents_bits = parents
                .iter()
                .enumerate()
                .map(|(parent_index, parent)| {
                    let parent_name = format!("{} parent_{}", challenge_name, parent_index);
                    assign_challenge_bits(cs, &parent_name, parent, challenge_bit_len)
                })
                .collect::<Result<Vec<Vec<AllocatedBit>>, SynthesisError>>()?;

            // Verify challenge's TreeD merkle proof.
            let (leaf_d, path_d) = assign_proof_d(
                cs,
                &challenge_name,
                &challenge_proof.leaf_d,
                &challenge_proof.path_d,
            )?;
            verify_proof_d(cs, &challenge_name, &challenge_bits, &leaf_d, path_d, &comm_d)?;

            let (drg_bits, exp_bits) = parents_bits.split_at(DRG_PARENTS);

            // Assign parent columns and TreeC merkle paths.
            let (drg_columns, exp_columns, drg_paths_c, exp_paths_c) = assign_parent_proofs(
                cs,
                &challenge_name,
                &challenge_proof.drg_parent_proofs,
                &challenge_proof.exp_parent_proofs,
            )?;

            // Hash parent columns.
            let (drg_leafs_c, exp_leafs_c) =
                hash_parent_columns(cs, &challenge_name, &drg_columns, &exp_columns)?;

            // Verify parents' TreeC merkle proofs.
            for (drg_index, ((parent_bits, leaf_c), path_c)) in
                drg_bits.iter().zip(&drg_leafs_c).zip(drg_paths_c).enumerate()
            {
                let parent_name = format!("{} drg_parent_{}", challenge_name, drg_index);
                verify_proof_c::<F, A, _>(cs, &parent_name, parent_bits, leaf_c, path_c, &comm_c)?;
            }
            for (exp_index, ((parent_bits, leaf_c), path_c)) in
                exp_bits.iter().zip(&exp_leafs_c).zip(exp_paths_c).enumerate()
            {
                let parent_name = format!("{} exp_parent_{}", challenge_name, exp_index);
                verify_proof_c::<F, A, _>(cs, &parent_name, parent_bits, leaf_c, path_c, &comm_c)?;
            }

            let mut column = Vec::<AllocatedNum<F>>::with_capacity(sp.num_layers);

            // Compute the challenge's label in each layer, i.e. the challenge's column.
            for layer_index in 0..sp.num_layers {
                let mut parent_label_bits = Vec::<Vec<Boolean>>::with_capacity(TOTAL_PARENTS);

                // Allocate each parent's label's bits.
                for (drg_index, drg_column) in drg_columns.iter().enumerate() {
                    let label_name = format!(
                        "{} drg_parent_{} layer_{} label bits",
                        challenge_name, drg_index, layer_index,
                    );
                    let label_bits =
                        drg_column[layer_index].to_bits_le(cs.namespace(|| label_name))?;
                    parent_label_bits.push(label_bits);
                }
                if layer_index != 0 {
                    for (exp_index, exp_column) in exp_columns.iter().enumerate() {
                        let label_name = format!(
                            "{} exp_parent_{} layer_{} label bits",
                            challenge_name, exp_index, layer_index - 1,
                        );
                        let label_bits =
                            exp_column[layer_index - 1].to_bits_le(cs.namespace(|| label_name))?;
                        parent_label_bits.push(label_bits);
                    }
                }

                let label = create_label(
                    cs.namespace(|| format!("{} layer_{} label", challenge_name, layer_index)),
                    &replica_id_bits,
                    &parent_label_bits,
                    layer_index,
                    &challenge_bits,
                )?;
                column.push(label);
            }

            // Compute the challenge column hash.
            let leaf_c = hash_column(cs, &challenge_name, &column)?;

            // Verify the challenge's TreeC merkle proof.
            let path_c = assign_path_c(cs, &challenge_name, &challenge_proof.path_c)?;
            verify_proof_c::<F, A, _>(
                cs,
                &challenge_name,
                &challenge_bits,
                &leaf_c,
                path_c,
                &comm_c,
            )?;

            // Compute the challenge's encoding.
            let key = &column[sp.num_layers - 1];
            let leaf_r =
                encode(cs.namespace(|| format!("{} leaf_r", challenge_name)), key, &leaf_d)?;

            // Verify the challenge's TreeR merkle proof.
            let path_r = assign_path_r(cs, &challenge_name, &challenge_proof.path_r)?;
            verify_proof_r::<F, A, _>(
                cs,
                &challenge_name,
                &challenge_bits,
                &leaf_r,
                path_r,
                &root_r,
            )?;
        }

        // Assign next circuit's inputs.
        self
            .outputs()
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

impl<F, A> StepExt<F> for SdrPorepCircuit<F, A>
where
    F: CycleScalar + PrimeFieldBits,
    A: Arity<F>,
    Sha256Hasher<F>: R1CSHasher<Field = F>,
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
        assert!(self.pub_inputs.values_are_set(self.sp.total_challenge_count));

        let num_inputs = self.num_inputs();
        let mut inputs = Vec::<F>::with_capacity(num_inputs);
        inputs.push(self.pub_inputs.replica_id.unwrap());
        inputs.push(self.pub_inputs.comm_d.unwrap());
        inputs.push(self.pub_inputs.comm_r.unwrap());

        let step_offset = self.i * self.sp.challenges_per_step;
        for i in step_offset..step_offset + self.sp.challenges_per_step {
            inputs.push(F::from(self.pub_inputs.challenges[i].unwrap() as u64));
            for parent in &self.pub_inputs.parents[i] {
                inputs.push(F::from(parent.unwrap() as u64));
            }
        }

        assert_eq!(inputs.len(), num_inputs);
        inputs
    }

    #[allow(clippy::unwrap_used)]
    fn outputs(&self) -> Vec<F> {
        assert!(self.i < self.sp.num_steps);
        assert!(self.pub_inputs.values_are_set(self.sp.total_challenge_count));

        let num_inputs = self.num_inputs();
        let mut inputs = Vec::<F>::with_capacity(num_inputs);
        inputs.push(self.pub_inputs.replica_id.unwrap());
        inputs.push(self.pub_inputs.comm_d.unwrap());
        inputs.push(self.pub_inputs.comm_r.unwrap());

        if self.i == self.sp.num_steps - 1 {
            inputs.resize(num_inputs, F::zero());
        } else {
            let step_offset = (self.i + 1) * self.sp.challenges_per_step;
            for i in step_offset..step_offset + self.sp.challenges_per_step {
                inputs.push(F::from(self.pub_inputs.challenges[i].unwrap() as u64));
                for parent in &self.pub_inputs.parents[i] {
                    inputs.push(F::from(parent.unwrap() as u64));
                }
            }
        }

        assert_eq!(inputs.len(), num_inputs);
        inputs
    }
}

impl<F, A> SdrPorepCircuit<F, A>
where
    F: CycleScalar + PrimeFieldBits,
    A: Arity<F>,
    Sha256Hasher<F>: R1CSHasher<Field = F>,
    PoseidonHasher<F>: R1CSHasher<Field = F>,
{
    pub fn blank(sp: &SetupParams) -> Self {
        assert_eq!(sp.sector_nodes, A::SECTOR_NODES);
        SdrPorepCircuit {
            sp: sp.clone(),
            i: 0,
            pub_inputs: PublicInputs::blank(sp),
            priv_inputs: PrivateInputs::blank::<A>(sp),
            _a: PhantomData,
        }
    }

    pub fn blank_keygen(sp: &SetupParams) -> Self {
        assert_eq!(sp.sector_nodes, A::SECTOR_NODES);
        SdrPorepCircuit {
            sp: sp.clone(),
            i: 0,
            pub_inputs: PublicInputs::blank_keygen(sp),
            priv_inputs: PrivateInputs::blank_keygen::<A>(sp),
            _a: PhantomData,
        }
    }

    // Returns the current step's challenge proofs.
    pub fn challenge_proofs(&self) -> &[ChallengeProof<F>] {
        assert!(self.i < self.sp.num_steps);
        let step_offset = self.i * self.sp.challenges_per_step;
        &self.priv_inputs.challenge_proofs[step_offset..step_offset + self.sp.challenges_per_step]
    }

    #[inline]
    pub fn gen_params(&self) -> SdrPorepParams<F, A> {
        nova::gen_params(self.clone())
    }

    #[inline]
    pub fn load_params(&self) -> anyhow::Result<SdrPorepParams<F, A>> {
        nova::ParamStore::params(self.clone())
    }

    #[inline]
    pub fn gen_compression_keypair(
        params: &SdrPorepParams<F, A>,
    ) -> SdrPorepCompressionKeypair<F, A> {
        gen_compression_keypair(params)
    }

    #[inline]
    pub fn load_compression_keypair(
        &self,
        params: &SdrPorepParams<F, A>,
    ) -> anyhow::Result<SdrPorepCompressionKeypair<F, A>> {
        nova::ParamStore::compression_keypair(self, params)
    }
}

pub type SdrPorepParams<F, A> = nova::Params<<F as CycleScalar>::G1, SdrPorepCircuit<F, A>>;
pub type SdrPorepCompressionPk<F, A> = CompressionPk<<F as CycleScalar>::G1, SdrPorepCircuit<F, A>>;
pub type SdrPorepCompressionVk<F, A> = CompressionVk<<F as CycleScalar>::G1, SdrPorepCircuit<F, A>>;
pub type SdrPorepCompressionKeypair<F, A> = CompressionKeypair<<F as CycleScalar>::G1, SdrPorepCircuit<F, A>>;
pub type SdrPorepProof<F, A> = RecursiveProof<<F as CycleScalar>::G1, SdrPorepCircuit<F, A>>;
pub type SdrPorepCompressedProof<F, A> =
    CompressedProof<<F as CycleScalar>::G1, SdrPorepCircuit<F, A>>;

pub struct SdrPorepCompound<F, A>(PhantomData<(F, A)>)
where
    F: PrimeField + PrimeFieldBits,
    A: Arity<F>,
    Sha256Hasher<F>: R1CSHasher<Field = F>,
    PoseidonHasher<F>: R1CSHasher<Field = F>;

impl<F, A> SdrPorepCompound<F, A>
where
    F: CycleScalar + PrimeFieldBits,
    A: Arity<F>,
    Sha256Hasher<F>: R1CSHasher<Field = F>,
    PoseidonHasher<F>: R1CSHasher<Field = F>
{
    pub fn create_recursive_circuit<Tree>(
        sp: SetupParams,
        vanilla_pub_inputs: &vanilla::PublicInputs<
            <PoseidonHasher<F> as Hasher>::Domain,
            <Sha256Hasher<F> as Hasher>::Domain,
        >,
        vanilla_partition_proofs: &[Vec<vanilla::Proof<Tree, Sha256Hasher<F>>>],
    ) -> SdrPorepCircuit<F, A>
    where
        Tree: MerkleTreeTrait<
            Field = F,
            Hasher = PoseidonHasher<F>,
            Arity = A::U,
            SubTreeArity = A::V,
            TopTreeArity = A::W,
        >,
    {
        assert_eq!(sp.sector_nodes, A::SECTOR_NODES);
        assert_eq!(sp.total_challenge_count % sp.challenges_per_step, 0);
        assert!(
            vanilla_pub_inputs.tau.is_some(),
            "vanilla public inputs do not contain comm_d and comm_r",
        );
        let challenge_bit_len = sp.sector_nodes.trailing_zeros() as usize;

        let replica_id: F = vanilla_pub_inputs.replica_id.into();

        let (comm_d, comm_r): (F, F) = vanilla_pub_inputs.tau
            .clone()
            .map(|tau| (tau.comm_d.into(), tau.comm_r.into()))
            .expect("vanilla public inputs do not contain comm_d and comm_r");

        let comm_c: F = vanilla_partition_proofs[0][0].comm_c().into();
        let root_r: F = vanilla_partition_proofs[0][0].comm_r_last().into();

        let mut challenges = Vec::<Option<u32>>::with_capacity(sp.total_challenge_count);
        let mut parents = Vec::<Vec<Option<u32>>>::with_capacity(sp.total_challenge_count);
        let all_parents = &mut parents;
        let mut challenge_proofs =
            Vec::<ChallengeProof<F>>::with_capacity(sp.total_challenge_count);

        for partition_proof in vanilla_partition_proofs {
            for challenge_proof in partition_proof {
                let proof_d = &challenge_proof.comm_d_proofs;
                let proof_c = &challenge_proof.replica_column_proofs.c_x.inclusion_proof;
                let proof_r = &challenge_proof.comm_r_last_proof;
                let drg_proofs = &challenge_proof.replica_column_proofs.drg_parents;
                let exp_proofs = &challenge_proof.replica_column_proofs.exp_parents;

                assert_eq!(drg_proofs.len(), DRG_PARENTS);
                assert_eq!(exp_proofs.len(), EXP_PARENTS);

                let challenge = proof_d.path_index() as u32;
                challenges.push(Some(challenge));

                let leaf_d: F = proof_d.leaf().into();
                let path_d: Vec<Option<F>> = proof_d
                    .path()
                    .iter()
                    .map(|(sibs, _)| Some(sibs[0].into()))
                    .collect();
                assert_eq!(path_d.len(), challenge_bit_len);

                let path_c: Vec<Vec<Option<F>>> = proof_c
                    .path()
                    .iter()
                    .map(|(sibs, _)| sibs.iter().map(|&sib| Some(sib.into())).collect())
                    .collect();

                let path_r: Vec<Vec<Option<F>>> = proof_r
                    .path()
                    .iter()
                    .map(|(sibs, _)| sibs.iter().map(|&sib| Some(sib.into())).collect())
                    .collect();

                let parents: Vec<Option<u32>> = drg_proofs
                    .iter()
                    .chain(exp_proofs)
                    .map(|parent_proof| Some(parent_proof.inclusion_proof.path_index() as u32))
                    .collect();
                all_parents.push(parents);

                let mut parent_proofs = drg_proofs
                    .iter()
                    .chain(exp_proofs)
                    .map(|parent_proof| {
                        let (column, proof_c) =
                            (&parent_proof.column.rows, &parent_proof.inclusion_proof);
                        assert_eq!(column.len(), sp.num_layers);

                        let column: Vec<Option<F>> =
                            column.iter().map(|&label| Some(label.into())).collect();

                        let path_c: Vec<Vec<Option<F>>> = proof_c
                            .path()
                            .iter()
                            .map(|(sibs, _)| sibs.iter().map(|&sib| Some(sib.into())).collect())
                            .collect();

                        ParentProof { column, path_c }
                    });

                challenge_proofs.push(ChallengeProof {
                    leaf_d: Some(leaf_d),
                    path_d,
                    path_c,
                    path_r,
                    drg_parent_proofs: (&mut parent_proofs).take(DRG_PARENTS).collect(),
                    exp_parent_proofs: parent_proofs.collect(),
                });
            }
        }

        assert_eq!(challenges.len(), sp.total_challenge_count);

        SdrPorepCircuit {
            sp,
            i: 0,
            pub_inputs: PublicInputs {
                replica_id: Some(replica_id),
                comm_d: Some(comm_d),
                comm_r: Some(comm_r),
                challenges,
                parents,
            },
            priv_inputs: PrivateInputs {
                comm_c: Some(comm_c),
                root_r: Some(root_r),
                challenge_proofs,
            },
            _a: PhantomData,
        }
    }

    #[inline]
    pub fn gen_params(sp: &SetupParams) -> SdrPorepParams<F, A> {
        nova::gen_params(SdrPorepCircuit::blank_keygen(sp))
    }

    #[inline]
    pub fn load_params(sp: &SetupParams) -> anyhow::Result<SdrPorepParams<F, A>> {
        nova::ParamStore::params(SdrPorepCircuit::blank_keygen(sp))
    }

    #[inline]
    pub fn gen_compression_keypair(
        params: &SdrPorepParams<F, A>,
    ) -> SdrPorepCompressionKeypair<F, A> {
        SdrPorepCircuit::<F, A>::gen_compression_keypair(params)
    }

    #[inline]
    pub fn load_compression_keypair(
        sp: &SetupParams,
        params: &SdrPorepParams<F, A>,
    ) -> anyhow::Result<SdrPorepCompressionKeypair<F, A>> {
        nova::ParamStore::compression_keypair(&SdrPorepCircuit::blank_keygen(sp), params)
    }

    #[inline]
    pub fn gen_recursive_proof(
        params: &SdrPorepParams<F, A>,
        circ: SdrPorepCircuit<F, A>,
    ) -> Result<SdrPorepProof<F, A>, NovaError> {
        gen_recursive_proof(params, circ)
    }

    #[inline]
    pub fn verify_recursive_proof(
        params: &SdrPorepParams<F, A>,
        proof: &SdrPorepProof<F, A>,
    ) -> Result<bool, NovaError> {
        proof.verify(params)
    }

    #[inline]
    pub fn gen_compressed_proof(
        params: &SdrPorepParams<F, A>,
        pk: &SdrPorepCompressionPk<F, A>,
        rec_proof: &SdrPorepProof<F, A>,
    ) -> Result<SdrPorepCompressedProof<F, A>, NovaError> {
        rec_proof.gen_compressed_proof(params, pk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use merkletree::store::StoreConfig;
    use pasta_curves::Fp;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::{
        api_version::ApiVersion,
        cache_key::CacheKey,
        merkle::{Arity1K, Arity2K, Arity4K, Arity8K, Arity16K, Arity32K, DiskTree},
        proof::ProofScheme,
        test_helper::setup_replica,
        util::default_rows_to_discard,
        TEST_SEED,
    };
    use tempfile::tempdir;

    use crate::{
        stacked::{LayerChallenges, StackedDrg, TemporaryAux, TemporaryAuxCache, BINARY_ARITY},
        PoRep,
    };

    type TreeR<F, A> =
        DiskTree<PoseidonHasher<F>, <A as Arity<F>>::U, <A as Arity<F>>::V, <A as Arity<F>>::W>;

    fn test_inner<F, A>()
    where
        F: CycleScalar + PrimeFieldBits,
        A: Arity<F>,
        PoseidonHasher<F>: R1CSHasher<Field = F>,
        Sha256Hasher<F>: R1CSHasher<Field = F>,
    {
        let sector_nodes = A::SECTOR_NODES;
        let sp = SetupParams::default(sector_nodes);

        let mut rng = XorShiftRng::from_seed(TEST_SEED);
        let replica_id = F::random(&mut rng);

        let sector_bytes = sector_nodes << 5;
        let mut data = Vec::<u8>::with_capacity(sector_bytes);
        for _ in 0..sector_nodes {
            data.extend_from_slice(F::random(&mut rng).to_repr().as_ref());
        }

        let cache_dir = tempdir().expect("failed to create tmp dir");

        // TreeD config.
        let config = StoreConfig::new(
            cache_dir.path(),
            CacheKey::CommDTree.to_string(),
            default_rows_to_discard(sector_nodes, BINARY_ARITY),
        );

        let replica_path = cache_dir.path().join("replica-path");
        let mut mmapped_data = setup_replica(&data, &replica_path);

        let vanilla_setup_params = vanilla::SetupParams {
            nodes: sector_nodes,
            degree: DRG_PARENTS,
            expansion_degree: EXP_PARENTS,
            porep_id: [1; 32],
            // Generate one vanilla partition proof for all challenges.
            layer_challenges: LayerChallenges::new(sp.num_layers, sp.total_challenge_count),
            api_version: ApiVersion::V1_1_0,
        };

        let vanilla_pub_params =
            StackedDrg::<TreeR<F, A>, Sha256Hasher<F>>::setup(&vanilla_setup_params)
                .expect("failed to create vanilla public params");

        // Create replica.
        let (tau, (p_aux, t_aux)) = StackedDrg::<TreeR<F, A>, Sha256Hasher<F>>::replicate(
            &vanilla_pub_params,
            &replica_id.into(),
            (mmapped_data.as_mut()).into(),
            None,
            config,
            replica_path.clone(),
        )
        .expect("replication failed");

        // Store copy of original t_aux for later resource deletion.
        let t_aux_orig = t_aux.clone();

        // Convert TemporaryAux to TemporaryAuxCache, which instantiates all elements based on the
        // configs stored in TemporaryAux.
        let t_aux = TemporaryAuxCache::new(&t_aux, replica_path)
            .expect("failed to restore contents of t_aux");

        let vanilla_pub_inputs = vanilla::PublicInputs {
            replica_id: replica_id.into(),
            seed: rng.gen(),
            tau: Some(tau),
            k: Some(0),
        };

        let vanilla_priv_inputs = vanilla::PrivateInputs { p_aux, t_aux };

        let vanilla_partition_proof = StackedDrg::prove(
            &vanilla_pub_params,
            &vanilla_pub_inputs,
            &vanilla_priv_inputs,
        )
        .expect("failed to generate vanilla partition proofs");

        let vanilla_is_valid = StackedDrg::verify_all_partitions(
            &vanilla_pub_params,
            &vanilla_pub_inputs,
            &[vanilla_partition_proof.clone()],
        )
        .expect("failed to verify vanilla proof");
        assert!(vanilla_is_valid);

        // Discard cached Merkle trees that are no longer needed.
        TemporaryAux::clear_temp(t_aux_orig).expect("t_aux delete failed");

        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        dbg!("using: Pasta-MSM crate");
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        dbg!("using: parallel CPU Pasta-MSM");

        // Create Nova circuits from vanilla artifacts.
        let start = std::time::Instant::now();
        let circ = SdrPorepCompound::<F, A>::create_recursive_circuit(
            sp,
            &vanilla_pub_inputs,
            &[vanilla_partition_proof],
        );
        let create_circ_secs = start.elapsed().as_secs_f32();
        dbg!(create_circ_secs);

        let start = std::time::Instant::now();
        let nova_params = SdrPorepCompound::<F, A>::gen_params(&sp);
        let param_gen_secs = start.elapsed().as_secs_f32();
        dbg!(param_gen_secs);
        /*
        let nova_params =
            SdrPorepCompound::<F, A>::load_params(&sp).expect("failed to load nova params");
        */

        // Generate and verify recursive proof.
        let start = std::time::Instant::now();
        let rec_proof = SdrPorepCompound::gen_recursive_proof(&nova_params, circ)
            .expect("failed to generate recursive proof");
        let rec_proving_secs = start.elapsed().as_secs_f32();
        dbg!(rec_proving_secs);
        let start = std::time::Instant::now();
        assert!(rec_proof.verify(&nova_params).expect("failed to verify recursive proof"));
        let rec_verifying_secs = start.elapsed().as_secs_f32();
        dbg!(rec_verifying_secs);

        let start = std::time::Instant::now();
        let (cpk, cvk) = SdrPorepCompound::gen_compression_keypair(&nova_params);
        let cmpr_keygen_secs = start.elapsed().as_secs_f32();
        dbg!(cmpr_keygen_secs);
        /*
        let (cpk, cvk) = SdrPorepCompound::load_compression_keypair(&sp, &nova_params)
            .expect("failed to load nova params");
        */

        let start = std::time::Instant::now();
        // Generate and verify compressed proof.
        let cmpr_proof = rec_proof.gen_compressed_proof(&nova_params, &cpk)
            .expect("failed to generate compressed proof");
        let cmpr_proving_secs = start.elapsed().as_secs_f32();
        dbg!(cmpr_proving_secs);
        let start = std::time::Instant::now();
        assert!(cmpr_proof.verify(&cvk).expect("failed to verify compressed proof"));
        let cmpr_verifying_secs = start.elapsed().as_secs_f32();
        dbg!(cmpr_verifying_secs);
    }

    #[test]
    fn test_sdr_porep_1kib_nova() {
        test_inner::<Fp, Arity1K>();
    }

    #[test]
    fn test_sdr_porep_2kib_nova() {
        test_inner::<Fp, Arity2K>();
    }

    #[test]
    fn test_sdr_porep_4kib_nova() {
        test_inner::<Fp, Arity4K>();
    }

    #[test]
    fn test_sdr_porep_8kib_nova() {
        test_inner::<Fp, Arity8K>();
    }

    #[test]
    fn test_sdr_porep_16kib_nova() {
        test_inner::<Fp, Arity16K>();
    }

    #[test]
    fn test_sdr_porep_32kib_nova() {
        test_inner::<Fp, Arity32K>();
    }
}
