use std::marker::PhantomData;

use bellperson::{
    gadgets::num::AllocatedNum,
    ConstraintSystem, SynthesisError,
};
use ff::{PrimeField, PrimeFieldBits};
use filecoin_hashers::{poseidon::PoseidonHasher, sha256::Sha256Hasher, Hasher, HashFunction, PoseidonArity};
use log::info;
use nova_snark::traits::circuit::StepCircuit;
use storage_proofs_core::{
    api_version::ApiVersion,
    drgraph::Graph,
    gadgets::{boolean::assign_bits, por::blank_merkle_path},
    merkle::{MerkleProofTrait, MerkleTreeTrait},
    nova::{CycleScalar, NovaCircuit},
    util::{pretty_print_sector_size, reverse_bit_numbering},
    SECTOR_NODES_32_KIB,
};

use crate::stacked::{nova::gadgets::ChallengeCircuit, vanilla, LayerChallenges, StackedBucketGraph};

pub const DRG_PARENTS: usize = storage_proofs_core::drgraph::BASE_DEGREE;
pub const EXP_PARENTS: usize = vanilla::EXP_DEGREE;
pub const TOTAL_PARENTS: usize = vanilla::DEGREE;
pub const REPEATED_PARENTS: usize = vanilla::TOTAL_PARENTS;

// Each PoRep challenge is associated with one public input for itself and one public inputs for
// each of its parents.
const PUB_INPUTS_PER_CHALLENGE: usize = 1 + TOTAL_PARENTS;

type VanillaPublicInputs<F> = vanilla::PublicInputs<
    <PoseidonHasher<F> as Hasher>::Domain,
    <Sha256Hasher<F> as Hasher>::Domain,
>;
type VanillaChallengeProof<Tree> =
    vanilla::Proof<Tree, Sha256Hasher<<Tree as MerkleTreeTrait>::Field>>;
type VanillaPartitionProof<Tree> = Vec<VanillaChallengeProof<Tree>>;
type VanillaPartitionProofs<Tree> = Vec<VanillaPartitionProof<Tree>>;

#[derive(Clone, Copy)]
pub struct SetupParams {
    pub sector_nodes: usize,
    pub num_layers: usize,
    pub porep_challenge_count: usize,
    pub challenges_per_step: usize,
}

impl SetupParams {
    #[inline]
    pub fn new(
        sector_nodes: usize,
        num_layers: usize,
        porep_challenge_count: usize,
        challenges_per_step: usize,
    ) -> Self {
        assert_eq!(porep_challenge_count % challenges_per_step, 0);
        SetupParams {
            sector_nodes,
            num_layers,
            porep_challenge_count,
            challenges_per_step,
        }
    }

    pub fn default(sector_nodes: usize) -> Self {
        let (num_layers, porep_challenge_count, challenges_per_step);
        if sector_nodes < SECTOR_NODES_32_KIB {
            num_layers = 2;
            porep_challenge_count = 4;
            challenges_per_step = 2;
        } else {
            num_layers = 11;
            porep_challenge_count = 176;
            challenges_per_step = 1;
        }
        Self::new(sector_nodes, num_layers, porep_challenge_count, challenges_per_step)
    }

    // The number of step circuits required to recursively prove a single sector's PoRep challenges.
    const fn steps_per_sector(&self) -> usize {
        self.porep_challenge_count / self.challenges_per_step
    }

    // Each step has public inputs: ReplicaID, CommD, CommR, and Merkle challenges.
    const fn pub_inputs_per_step(&self) -> usize {
        3 + self.challenges_per_step * PUB_INPUTS_PER_CHALLENGE
    }
}

#[derive(Clone)]
pub struct SectorPublicInputs<F: PrimeField> {
    pub replica_id: F,
    pub comm_d: F,
    pub comm_r: F,
    // All porep challenges (not just current step's).
    pub challenges: Vec<u32>,
    pub parents: Vec<Vec<u32>>,
}

impl<F: PrimeField> SectorPublicInputs<F> {
    #[inline]
    fn blank(sp: &SetupParams) -> Self {
        SectorPublicInputs {
            replica_id: F::zero(),
            comm_d: F::zero(),
            comm_r: F::zero(),
            challenges: vec![0; sp.porep_challenge_count],
            parents: vec![vec![0; TOTAL_PARENTS]; sp.porep_challenge_count],
        }
    }

    pub fn from_vanilla(
        sp: &SetupParams,
        porep_id: [u8; 32],
        api_version: ApiVersion,
        vanilla_pub_inputs: &VanillaPublicInputs<F>,
    ) -> Self
    where
        Sha256Hasher<F>: Hasher<Field = F>,
        PoseidonHasher<F>: Hasher<Field = F>,
    {
        let (comm_d, comm_r) = vanilla_pub_inputs.tau
            .clone()
            .map(|tau| (tau.comm_d.into(), tau.comm_r.into()))
            .expect("public inputs do not contain CommD and CommR");

        let layer_challenges = LayerChallenges::new(sp.num_layers, sp.porep_challenge_count);
        let graph = StackedBucketGraph::<PoseidonHasher<F>>::new_stacked(
            sp.sector_nodes,
            DRG_PARENTS,
            EXP_PARENTS,
            porep_id,
            api_version,
        )
        .expect("graph construction should not fail");

        let challenges = vanilla_pub_inputs.challenges(&layer_challenges, sp.sector_nodes, Some(0));
        assert_eq!(challenges.len(), sp.porep_challenge_count);

        let parents = challenges
            .iter()
            .map(|c| {
                let mut parents = vec![0u32; TOTAL_PARENTS];
                graph.parents(*c, &mut parents).expect("failed to generate parents");
                parents
            })
            .collect();

        SectorPublicInputs {
            replica_id: vanilla_pub_inputs.replica_id.into(),
            comm_d,
            comm_r,
            challenges: challenges.into_iter().map(|c| c as u32).collect(),
            parents,
        }
    }

    pub fn to_vec(&self, sp: &SetupParams) -> Vec<Vec<F>> {
        assert_eq!(self.challenges.len(), sp.porep_challenge_count);
        assert_eq!(self.parents.len(), sp.porep_challenge_count);
        assert!(self.parents.iter().map(Vec::len).all(|len| len == TOTAL_PARENTS));

        self.challenges
            .chunks(sp.challenges_per_step)
            .zip(self.parents.chunks(sp.challenges_per_step))
            .map(|(challenges, parents)| {
                let mut step_inputs = Vec::with_capacity(sp.pub_inputs_per_step());
                step_inputs.push(self.replica_id);
                step_inputs.push(self.comm_d);
                step_inputs.push(self.comm_r);
                for (challenge, parents) in challenges.iter().zip(parents) {
                    step_inputs.push(F::from(*challenge as u64));
                    for parent in parents {
                        step_inputs.push(F::from(*parent as u64));
                    }
                }
                step_inputs
            })
            .collect()
    }
}

#[derive(Clone)]
pub struct PublicInputs<F: PrimeField> {
    sectors: Vec<SectorPublicInputs<F>>,
}

impl<F: PrimeField> PublicInputs<F> {
    #[inline]
    fn blank(sp: &SetupParams) -> Self {
        PublicInputs {
            sectors: vec![SectorPublicInputs::blank(sp)],
        }
    }

    #[inline]
    pub fn from_vanilla(
        sp: &SetupParams,
        porep_id: [u8; 32],
        api_version: ApiVersion,
        vanilla_pub_inputs: &[VanillaPublicInputs<F>],
    ) -> Self
    where
        Sha256Hasher<F>: Hasher<Field = F>,
        PoseidonHasher<F>: Hasher<Field = F>,
    {
        PublicInputs {
            sectors: vanilla_pub_inputs
                .iter()
                .map(|vanilla_pub_inputs| {
                    SectorPublicInputs::from_vanilla(sp, porep_id, api_version, vanilla_pub_inputs)
                })
                .collect(),
        }
    }

    #[inline]
    pub fn to_vec(&self, sp: &SetupParams) -> Vec<Vec<F>> {
        self.sectors
            .iter()
            .flat_map(|sector| sector.to_vec(sp))
            .collect()
    }
}

#[derive(Clone)]
pub struct ParentProof<F: PrimeField> {
    pub column: Vec<F>,
    pub path_c: Vec<Vec<F>>,
}

#[derive(Clone)]
pub struct ChallengeProof<F: PrimeField> {
    pub leaf_d: F,
    pub path_d: Vec<F>,
    pub path_c: Vec<Vec<F>>,
    pub path_r: Vec<Vec<F>>,
    pub drg_parent_proofs: Vec<ParentProof<F>>,
    pub exp_parent_proofs: Vec<ParentProof<F>>,
}

#[derive(Clone)]
pub struct SectorPrivateInputs<F: PrimeField> {
    pub comm_c: F,
    pub root_r: F,
    // All porep challenge proofs.
    pub challenge_proofs: Vec<ChallengeProof<F>>,
}

impl<F: PrimeField> SectorPrivateInputs<F> {
    fn blank<U, V, W>(sp: &SetupParams) -> Self
    where
        U: PoseidonArity<F>,
        V: PoseidonArity<F>,
        W: PoseidonArity<F>,
    {
        let challenge_bit_len = sp.sector_nodes.trailing_zeros() as usize;
        let path_d = vec![F::zero(); challenge_bit_len];

        let path_cr = blank_merkle_path::<F, U, V, W>(sp.sector_nodes);

        let parent_proof = ParentProof {
            column: vec![F::zero(); sp.num_layers],
            path_c: path_cr.clone(),
        };

        let challenge_proof = ChallengeProof {
            leaf_d: F::zero(),
            path_d,
            path_c: path_cr.clone(),
            path_r: path_cr,
            drg_parent_proofs: vec![parent_proof.clone(); DRG_PARENTS],
            exp_parent_proofs: vec![parent_proof; EXP_PARENTS],
        };

        SectorPrivateInputs {
            comm_c: F::zero(),
            root_r: F::zero(),
            challenge_proofs: vec![challenge_proof; sp.porep_challenge_count],
        }
    }
}

#[derive(Clone)]
pub struct PrivateInputs<F: PrimeField> {
    sectors: Vec<SectorPrivateInputs<F>>,
}

impl<F: PrimeField> PrivateInputs<F> {
    #[inline]
    fn blank<U, V, W>(sp: &SetupParams) -> Self
    where
        U: PoseidonArity<F>,
        V: PoseidonArity<F>,
        W: PoseidonArity<F>,
    {
        PrivateInputs {
            sectors: vec![SectorPrivateInputs::blank::<U, V, W>(sp)],
        }
    }
}

#[derive(Clone)]
pub struct SdrPorepCircuit<F, U, V, W>
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

impl<F, U, V, W> StepCircuit<F> for SdrPorepCircuit<F, U, V, W>
where
    Self: NovaCircuit<F::G>,
    F: CycleScalar + PrimeFieldBits,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    Sha256Hasher<F>: Hasher<Field = F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    #[inline]
    fn arity(&self) -> usize {
        self.sp.pub_inputs_per_step()
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        assert_eq!(z.len(), self.arity());

        let SetupParams {
            sector_nodes,
            num_layers,
            challenges_per_step,
            ..
        } = self.sp;
        let priv_inputs = &self.priv_inputs.sectors[0];

        let challenge_bit_len = sector_nodes.trailing_zeros() as usize;

        let (replica_id, comm_d, comm_r) = (&z[0], &z[1], &z[2]);
        let (challenges, parents): (Vec<&AllocatedNum<F>>, Vec<&[AllocatedNum<F>]>) = z[3..]
            .chunks(PUB_INPUTS_PER_CHALLENGE)
            .map(|challenge_inputs| (&challenge_inputs[0], &challenge_inputs[1..]))
            .unzip();

        assert_eq!(challenges.len(), challenges_per_step);
        assert_eq!(parents.len(), challenges_per_step);
        assert!(parents.iter().all(|challenge_parents| challenge_parents.len() == TOTAL_PARENTS));

        let is_keygen = z.iter().any(|input| input.get_value().is_none());
        if !is_keygen {
            let steps_per_sector = self.sp.steps_per_sector();
            let sector_index = self.step_index / steps_per_sector;
            let challenge_offset = self.step_index % steps_per_sector * self.sp.challenges_per_step;
            info!(
                "synthesizing step circuit sector={}, replica_id={:?}, challenges=[{},{})",
                sector_index,
                replica_id.get_value().expect("replica_id input should be set"),
                challenge_offset,
                challenge_offset + self.sp.challenges_per_step,
            );
        }

        let replica_id_bits = {
            let bits = assign_bits(cs, "replica_id", replica_id, F::NUM_BITS as usize)?;
            reverse_bit_numbering(bits.into_iter().map(Into::into).collect())
        };

        let comm_c = AllocatedNum::alloc(cs.namespace(|| "comm_c"), || Ok(priv_inputs.comm_c))?;
        let root_r = AllocatedNum::alloc(cs.namespace(|| "root_r"), || Ok(priv_inputs.root_r))?;
        let comm_r_calc = <PoseidonHasher<F> as Hasher>::Function::hash2_circuit(
            cs.namespace(|| "comm_r_calc"), 
            &comm_c,
            &root_r,
        )?;

        // Mock CommR validation if testing without first running vanilla sealing.
        let comm_r = if cfg!(all(test, feature = "mock-test-circ")) {
            &comm_r_calc
        } else {
            comm_r
        };

        cs.enforce(
            || "verify comm_r",
            |lc| lc + comm_r.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + comm_r_calc.get_variable(),
        );

        for (i, ((challenge, parents), challenge_proof)) in challenges
            .iter()
            .zip(&parents)
            .zip(&priv_inputs.challenge_proofs)
            .enumerate()
        {
            let challenge_circ =
                ChallengeCircuit::<F, U, V, W>::new(i, challenge, parents, challenge_proof);

            let challenge_bits = challenge_circ.assign_challenge_bits(cs, challenge_bit_len)?;
            let parents_bits = challenge_circ.assign_parents_bits(cs, challenge_bit_len)?;

            let leaf_d = challenge_circ.assign_leaf_d(cs)?;
            let path_d = challenge_circ.assign_path_d(cs)?;
            challenge_circ.verify_proof_d(cs, &challenge_bits, &leaf_d, &path_d, &comm_d)?;

            let parent_cols = challenge_circ.assign_parent_cols(cs)?;
            let parent_leafs_c = challenge_circ.hash_parent_cols(cs, &parent_cols)?;
            let parent_paths_c = challenge_circ.assign_parent_paths_c(cs)?;
            challenge_circ.verify_parent_proofs_c(
                cs,
                &parents_bits,
                &parent_leafs_c,
                &parent_paths_c,
                &comm_c,
            )?;

            let col =
                challenge_circ.create_labels(cs, &replica_id_bits, &challenge_bits, &parent_cols)?;
            let leaf_c = challenge_circ.hash_col(cs, &col)?;
            let path_c = challenge_circ.assign_path_c(cs)?;
            challenge_circ.verify_proof_c(cs, &challenge_bits, &leaf_c, &path_c, &comm_c)?;

            let key = &col[num_layers - 1];
            let leaf_r = challenge_circ.encode(cs, key, &leaf_d)?;
            let path_r = challenge_circ.assign_path_r(cs)?;
            challenge_circ.verify_proof_r(cs, &challenge_bits, &leaf_r, &path_r, &root_r)?;
        }

        self
            .step_outputs()
            .into_iter()
            .enumerate()
            .map(|(i, output)| {
                AllocatedNum::alloc(cs.namespace(|| format!("output_{}", i)), || Ok(output))
            })
            .collect()
    }

    fn output(&self, _z: &[F]) -> Vec<F> {
        self.step_outputs()
    }
}

impl<F, U, V, W> NovaCircuit<F::G> for SdrPorepCircuit<F, U, V, W>
where
    F: CycleScalar + PrimeFieldBits,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    Sha256Hasher<F>: Hasher<Field = F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    #[inline]
    fn circ_name(&self) -> String {
        format!(
            "SDR-PoRep-{} {{ layers: {}, step_challenges: {} }}",
            pretty_print_sector_size(self.sp.sector_nodes),
            self.sp.num_layers,
            self.sp.challenges_per_step,
        )
    }

    #[inline]
    fn step_index(&self) -> usize {
        self.step_index
    }

    #[inline]
    fn num_steps(&self) -> usize {
        self.pub_inputs.sectors.len() * self.sp.steps_per_sector()
    }

    fn next_step(&mut self) {
        assert!(
            !self.pub_inputs.sectors.is_empty() && !self.priv_inputs.sectors.is_empty(),
            "recursive circuit contains no remaining sectors",
        );

        self.pub_inputs.sectors[0].challenges.drain(..self.sp.challenges_per_step);
        self.pub_inputs.sectors[0].parents.drain(..self.sp.challenges_per_step);
        self.priv_inputs.sectors[0].challenge_proofs.drain(..self.sp.challenges_per_step);

        if self.pub_inputs.sectors[0].challenges.is_empty() {
            self.pub_inputs.sectors.remove(0);
            self.priv_inputs.sectors.remove(0);
        }

        self.step_index += 1;
    }

    fn step_inputs(&self) -> Vec<F> {
        assert!(
            !self.pub_inputs.sectors.is_empty(),
            "recursive circuit's public inputs contains no sectors",
        );
        let sector = &self.pub_inputs.sectors[0];
        let challenges_rem = sector.challenges.len();
        assert_ne!(
            challenges_rem,
            0,
            "current sector's public inputs contains no challenges",
        );
        assert_eq!(
            challenges_rem % self.sp.challenges_per_step,
            0,
            "current sector's public inputs contains unexpected number of challenges",
        );
        assert_eq!(
            challenges_rem,
            sector.parents.len(),
            "current sector's public inputs contains differing numbers of challenges and parents",
        );
        assert!(
            sector.parents.iter().all(|parents| parents.len() == TOTAL_PARENTS),
            "current sector's public inputs contains invalid number of parents for challenge",
        );

        let num_inputs = self.arity();
        let mut inputs = Vec::<F>::with_capacity(num_inputs);

        inputs.push(sector.replica_id);
        inputs.push(sector.comm_d);
        inputs.push(sector.comm_r);

        for (challenge, parents) in
            sector.challenges.iter().zip(&sector.parents).take(self.sp.challenges_per_step)
        {
            inputs.push(F::from(*challenge as u64));
            for parent in parents {
                inputs.push(F::from(*parent as u64));
            }
        }

        assert_eq!(inputs.len(), num_inputs);
        inputs
    }

    fn step_outputs(&self) -> Vec<F> {
        assert!(
            !self.pub_inputs.sectors.is_empty(),
            "recursive circuit's public inputs contains no sectors",
        );

        let mut sector = &self.pub_inputs.sectors[0];
        let mut challenges_rem = sector.challenges.len();
        let mut challenges_offset = self.sp.challenges_per_step;
        let sector_done = challenges_rem == self.sp.challenges_per_step;
        let num_inputs = self.arity();

        if sector_done {
            let proving_done = self.pub_inputs.sectors.len() == 1;
            if proving_done {
                return vec![F::zero(); num_inputs];
            }
            sector = &self.pub_inputs.sectors[1];
            challenges_rem = sector.challenges.len();
            challenges_offset = 0;
        }

        assert_ne!(
            challenges_rem,
            0,
            "current sector's public inputs contains no challenges",
        );
        assert_eq!(
            challenges_rem % self.sp.challenges_per_step,
            0,
            "current sector's public inputs contains unexpected number of challenges",
        );
        assert_eq!(
            challenges_rem,
            sector.parents.len(),
            "current sector's public inputs contains differing numbers of challenges and parents",
        );
        assert!(
            sector.parents.iter().all(|parents| parents.len() == TOTAL_PARENTS),
            "current sector's public inputs contains invalid number of parents for challenge",
        );

        let mut inputs = Vec::<F>::with_capacity(num_inputs);
        inputs.push(sector.replica_id);
        inputs.push(sector.comm_d);
        inputs.push(sector.comm_r);

        for (challenge, parents) in sector.challenges
            .iter()
            .zip(&sector.parents)
            .skip(challenges_offset)
            .take(self.sp.challenges_per_step)
        {
            inputs.push(F::from(*challenge as u64));
            for parent in parents {
                inputs.push(F::from(*parent as u64));
            }
        }

        assert_eq!(inputs.len(), num_inputs);
        inputs
    }
}

impl<F, U, V, W> SdrPorepCircuit<F, U, V, W>
where
    F: PrimeField,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    Sha256Hasher<F>: Hasher<Field = F>,
    PoseidonHasher<F>: Hasher<Field = F>,
{
    // Creates a mock circuit which can be used to generate nova params and keys for any circuit
    // having the same `SetupParams`.
    #[inline]
    pub fn blank(sp: &SetupParams) -> Self {
        SdrPorepCircuit {
            sp: *sp,
            step_index: 0,
            pub_inputs: PublicInputs::blank(sp),
            priv_inputs: PrivateInputs::blank::<U, V, W>(sp),
            _a: PhantomData,
        }
    }

    pub fn from_vanilla<Tree>(
        sp: SetupParams,
        sectors: &[(VanillaPublicInputs<F>, VanillaPartitionProofs<Tree>)],
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
        let challenge_bit_len = sp.sector_nodes.trailing_zeros() as usize;

        let num_sectors = sectors.len();
        let mut pub_inputs = PublicInputs {
            sectors: Vec::with_capacity(num_sectors),
        };
        let mut priv_inputs = PrivateInputs {
            sectors: Vec::with_capacity(num_sectors),
        };

        for (vanilla_pub_inputs, vanilla_partition_proofs) in sectors.iter() {
            let replica_id: F = vanilla_pub_inputs.replica_id.into();

            let (comm_d, comm_r): (F, F) = vanilla_pub_inputs.tau
                .clone()
                .map(|tau| (tau.comm_d.into(), tau.comm_r.into()))
                .expect("vanilla public inputs missing comm_d and comm_r");

            let comm_c: F = vanilla_partition_proofs[0][0].comm_c().into();
            let root_r: F = vanilla_partition_proofs[0][0].comm_r_last().into();

            let mut challenges = Vec::<u32>::with_capacity(sp.porep_challenge_count);
            let mut parents = Vec::<Vec<u32>>::with_capacity(sp.porep_challenge_count);
            let mut challenge_proofs =
                Vec::<ChallengeProof<F>>::with_capacity(sp.porep_challenge_count);

            for partition_proof in vanilla_partition_proofs {
                for challenge_proof in partition_proof {
                    let proof_d = &challenge_proof.comm_d_proofs;
                    let proof_r = &challenge_proof.comm_r_last_proof;
                    let proof_c = &challenge_proof.replica_column_proofs.c_x.inclusion_proof;
                    let drg_proofs = &challenge_proof.replica_column_proofs.drg_parents;
                    let exp_proofs = &challenge_proof.replica_column_proofs.exp_parents;

                    assert_eq!(drg_proofs.len(), DRG_PARENTS);
                    assert_eq!(exp_proofs.len(), EXP_PARENTS);

                    challenges.push(proof_d.path_index() as u32);

                    let leaf_d: F = proof_d.leaf().into();
                    let path_d: Vec<F> =
                        proof_d.path().iter().map(|(sibs, _)| sibs[0].into()).collect();
                    assert_eq!(path_d.len(), challenge_bit_len);

                    let path_c: Vec<Vec<F>> = proof_c
                        .path()
                        .iter()
                        .map(|(sibs, _)| sibs.iter().copied().map(Into::into).collect())
                        .collect();

                    let path_r: Vec<Vec<F>> = proof_r
                        .path()
                        .iter()
                        .map(|(sibs, _)| sibs.iter().copied().map(Into::into).collect())
                        .collect();

                    let mut challenge_parents = Vec::<u32>::with_capacity(TOTAL_PARENTS);

                    let mut parent_proofs = drg_proofs.iter().chain(exp_proofs).map(|parent_proof| {
                        let (column, proof_c) =
                            (&parent_proof.column.rows, &parent_proof.inclusion_proof);

                        assert_eq!(column.len(), sp.num_layers);

                        challenge_parents.push(proof_c.path_index() as u32);

                        let column: Vec<F> = column.iter().copied().map(Into::into).collect();

                        let path_c: Vec<Vec<F>> = proof_c
                            .path()
                            .iter()
                            .map(|(sibs, _)| sibs.iter().copied().map(Into::into).collect())
                            .collect();

                        ParentProof { column, path_c }
                    });

                    let drg_parent_proofs = (&mut parent_proofs).take(DRG_PARENTS).collect();
                    let exp_parent_proofs = parent_proofs.collect();
                    parents.push(challenge_parents);

                    challenge_proofs.push(ChallengeProof {
                        leaf_d,
                        path_d,
                        path_c,
                        path_r,
                        drg_parent_proofs,
                        exp_parent_proofs,
                    });
                }
            }

            assert_eq!(challenges.len(), sp.porep_challenge_count);
            assert_eq!(parents.len(), sp.porep_challenge_count);
            assert!(parents.iter().all(|parents| parents.len() == TOTAL_PARENTS));
            assert_eq!(challenge_proofs.len(), sp.porep_challenge_count);

            pub_inputs.sectors.push(SectorPublicInputs {
                replica_id,
                comm_d,
                comm_r,
                challenges,
                parents,
            });
            priv_inputs.sectors.push(SectorPrivateInputs {
                comm_c,
                root_r,
                challenge_proofs,
            });
        }

        SdrPorepCircuit {
            sp,
            step_index: 0,
            pub_inputs,
            priv_inputs,
            _a: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use generic_array::typenum::{U0, U2, U4, U8};
    use merkletree::store::StoreConfig;
    use pasta_curves::Fp;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::{
        api_version::ApiVersion,
        cache_key::CacheKey,
        merkle::DiskTree,
        proof::ProofScheme,
        test_helper::setup_replica,
        util::default_rows_to_discard,
        SECTOR_NODES_16_KIB, SECTOR_NODES_16_MIB, SECTOR_NODES_2_KIB, SECTOR_NODES_4_KIB,
        SECTOR_NODES_32_GIB, SECTOR_NODES_512_MIB, SECTOR_NODES_64_GIB, SECTOR_NODES_8_KIB,
        SECTOR_NODES_8_MIB, TEST_SEED,
    };
    use tempfile::tempdir;

    use crate::{
        stacked::{LayerChallenges, StackedDrg, TemporaryAux, TemporaryAuxCache, BINARY_ARITY},
        PoRep,
    };

    // Configures the number of sectors proved via a single recursive PoRep proof; this
    // parameter can be changed.
    const NUM_SECTORS: usize = 1;

    type TreeR<F, U, V, W> = DiskTree<PoseidonHasher<F>, U, V, W>;

    fn test_inner<F, U, V, W>(sector_nodes: usize)
    where
        F: CycleScalar + PrimeFieldBits,
        U: PoseidonArity<F>,
        V: PoseidonArity<F>,
        W: PoseidonArity<F>,
        PoseidonHasher<F>: Hasher<Field = F>,
        Sha256Hasher<F>: Hasher<Field = F>,
    {
        fil_logger::maybe_init();

        let sp = SetupParams::default(sector_nodes);

        let mut circ = if cfg!(feature = "mock-test-circ") {
            let mut circ = SdrPorepCircuit::<F, U, V, W>::blank(&sp);
            circ.pub_inputs.sectors.resize(NUM_SECTORS, circ.pub_inputs.sectors[0].clone());
            circ.priv_inputs.sectors.resize(NUM_SECTORS, circ.priv_inputs.sectors[0].clone());
            circ
        } else {
            let mut rng = XorShiftRng::from_seed(TEST_SEED);

            let sector_bytes = sector_nodes << 5;

            let vanilla_sp = vanilla::SetupParams {
                nodes: sector_nodes,
                degree: DRG_PARENTS,
                expansion_degree: EXP_PARENTS,
                porep_id: [1; 32],
                // Generate one vanilla partition proof for all challenges.
                layer_challenges: LayerChallenges::new(sp.num_layers, sp.porep_challenge_count),
                api_version: ApiVersion::V1_1_0,
            };

            let vanilla_pub_params =
                StackedDrg::<TreeR<F, U, V, W>, Sha256Hasher<F>>::setup(&vanilla_sp)
                    .expect("failed to create vanilla public params");

            let sectors = (0..NUM_SECTORS)
                .map(|_| {
                    let replica_id = F::random(&mut rng);

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

                    // Create replica.
                    let (tau, (p_aux, t_aux)) =
                        StackedDrg::<TreeR<F, U, V, W>, Sha256Hasher<F>>::replicate(
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

                    // Convert TemporaryAux to TemporaryAuxCache, which instantiates all elements
                    // based on the configs stored in TemporaryAux.
                    let t_aux = TemporaryAuxCache::new(&t_aux, replica_path)
                        .expect("failed to restore contents of t_aux");

                    let vanilla_pub_inputs = vanilla::PublicInputs {
                        replica_id: replica_id.into(),
                        seed: rng.gen(),
                        tau: Some(tau),
                        k: Some(0),
                    };

                    let vanilla_priv_inputs = vanilla::PrivateInputs { p_aux, t_aux };

                    let vanilla_partition_proofs = StackedDrg::prove(
                        &vanilla_pub_params,
                        &vanilla_pub_inputs,
                        &vanilla_priv_inputs,
                    )
                    .map(|partition_proof| vec![partition_proof])
                    .expect("failed to generate vanilla partition proofs");

                    assert!(
                        StackedDrg::verify_all_partitions(
                            &vanilla_pub_params,
                            &vanilla_pub_inputs,
                            &vanilla_partition_proofs,
                        )
                        .expect("failed to verify vanilla proof")
                    );

                    // Discard cached Merkle trees that are no longer needed.
                    TemporaryAux::clear_temp(t_aux_orig).expect("t_aux delete failed");

                    (vanilla_pub_inputs, vanilla_partition_proofs)
                })
                .collect::<Vec<_>>();

            SdrPorepCircuit::<F, U, V, W>::from_vanilla(sp, &sectors)
        };

        let params = circ.gen_params();

        let r_proof =
            circ.gen_recursive_proof(&params).expect("failed to generate recursive proof");
        assert!(r_proof.verify(&params).expect("failed to verify recursive proof"));

        let (cpk, cvk) = circ.gen_compression_keypair(&params);

        let c_proof =
            r_proof.compress(&params, &cpk).expect("failed to generated compressed proof");
        assert!(c_proof.verify(&cvk).expect("failed to verify compressed proof"));
        info!(
            "nova compressed proof size: {} bytes",
            c_proof.proof_bytes().expect("failed to serialize compressed proof").len(),
        );
    }

    #[test]
    fn test_sdr_porep_2kib_nova() {
        test_inner::<Fp, U8, U0, U0>(SECTOR_NODES_2_KIB);
    }

    #[test]
    fn test_sdr_porep_4kib_nova() {
        test_inner::<Fp, U8, U2, U0>(SECTOR_NODES_4_KIB);
    }

    #[test]
    fn test_sdr_porep_8kib_nova() {
        test_inner::<Fp, U8, U4, U0>(SECTOR_NODES_8_KIB);
    }

    #[test]
    fn test_sdr_porep_16kib_nova() {
        test_inner::<Fp, U8, U8, U0>(SECTOR_NODES_16_KIB);
    }

    #[test]
    fn test_sdr_porep_32kib_nova() {
        test_inner::<Fp, U8, U8, U2>(SECTOR_NODES_32_KIB);
    }

    #[test]
    #[ignore]
    fn test_sdr_porep_8mib_nova() {
        test_inner::<Fp, U8, U0, U0>(SECTOR_NODES_8_MIB);
    }

    #[test]
    #[ignore]
    fn test_sdr_porep_16mib_nova() {
        test_inner::<Fp, U8, U2, U0>(SECTOR_NODES_16_MIB);
    }

    #[test]
    #[ignore]
    fn test_sdr_porep_512mib_nova() {
        test_inner::<Fp, U8, U0, U0>(SECTOR_NODES_512_MIB);
    }

    #[test]
    #[ignore]
    fn test_sdr_porep_32gib_nova() {
        test_inner::<Fp, U8, U8, U0>(SECTOR_NODES_32_GIB);
    }

    #[test]
    #[ignore]
    fn test_sdr_porep_64gib_nova() {
        test_inner::<Fp, U8, U8, U0>(SECTOR_NODES_64_GIB);
    }
}
