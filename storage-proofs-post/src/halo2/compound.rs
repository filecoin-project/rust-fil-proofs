use filecoin_hashers::{poseidon::PoseidonHasher, Domain, Hasher, PoseidonArity};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use rand::rngs::OsRng;
use storage_proofs_core::{
    halo2_proofs::{create_proof, CircuitRows, CompoundProof, FieldProvingCurves, Halo2Proof},
    merkle::MerkleTreeTrait,
};

use crate::{
    fallback::FallbackPoSt,
    halo2::{
        constants::SECTOR_NODES_2_KIB,
        shared::CircuitConfig,
        window::{self, WindowPostCircuit},
        winning::{self, WinningPostCircuit},
    },
};

#[derive(Clone)]
pub enum PostCircuit<F, U, V, W, const SECTOR_NODES: usize>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
{
    Winning(WinningPostCircuit<F, U, V, W, SECTOR_NODES>),
    Window(WindowPostCircuit<F, U, V, W, SECTOR_NODES>),
}

impl<F, U, V, W, const SECTOR_NODES: usize> From<WinningPostCircuit<F, U, V, W, SECTOR_NODES>>
    for PostCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
{
    fn from(circ: WinningPostCircuit<F, U, V, W, SECTOR_NODES>) -> Self {
        PostCircuit::Winning(circ)
    }
}

impl<F, U, V, W, const SECTOR_NODES: usize> From<WindowPostCircuit<F, U, V, W, SECTOR_NODES>>
    for PostCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
{
    fn from(circ: WindowPostCircuit<F, U, V, W, SECTOR_NODES>) -> Self {
        PostCircuit::Window(circ)
    }
}

impl<F, U, V, W, const SECTOR_NODES: usize> Circuit<F> for PostCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
{
    type Config = CircuitConfig<F, U, V, W, SECTOR_NODES>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        match self {
            PostCircuit::Winning(_) => PostCircuit::Winning(WinningPostCircuit {
                pub_inputs: winning::PublicInputs::empty(),
                priv_inputs: winning::PrivateInputs::empty(),
            }),
            PostCircuit::Window(_) => PostCircuit::Window(WindowPostCircuit {
                pub_inputs: window::PublicInputs::empty(),
                priv_inputs: window::PrivateInputs::empty(),
            }),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        CircuitConfig::configure(meta)
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<F>) -> Result<(), Error> {
        match self {
            PostCircuit::Winning(circ) => circ.synthesize(config, layouter),
            PostCircuit::Window(circ) => circ.synthesize(config, layouter),
        }
    }
}

impl<F, U, V, W, const SECTOR_NODES: usize> CircuitRows for PostCircuit<F, U, V, W, SECTOR_NODES>
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
{
    fn k(&self) -> u32 {
        match self {
            PostCircuit::Winning(circ) => circ.k(),
            PostCircuit::Window(circ) => circ.k(),
        }
    }
}

impl<'a, F, U, V, W, TreeR> CompoundProof<'a, F, SECTOR_NODES_2_KIB> for FallbackPoSt<'a, TreeR>
where
    F: FieldExt + FieldProvingCurves,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
    TreeR:
        MerkleTreeTrait<Hasher = PoseidonHasher<F>, Arity = U, SubTreeArity = V, TopTreeArity = W>,
{
    type Circuit = PostCircuit<F, U, V, W, SECTOR_NODES_2_KIB>;

    fn prove_with_vanilla_partition(
        setup_params: Self::SetupParams,
        vanilla_pub_inputs: Self::PublicInputs,
        partition_proof: Self::Proof,
    ) -> Result<Halo2Proof<<F as FieldProvingCurves>::Affine, Self::Circuit>, Error> {
        let total_prover_sectors = vanilla_pub_inputs.sectors.len();
        assert_eq!(
            total_prover_sectors % setup_params.sector_count,
            0,
            "prover's sector set length is not divisible by the number of sectors challenged per
            partition",
        );

        assert_eq!(partition_proof.sectors.len(), setup_params.sector_count);
        assert!(partition_proof.sectors.iter().all(|sector_proof| {
            sector_proof.inclusion_proofs.len() == setup_params.challenge_count
        }));

        let is_winning = match (setup_params.challenge_count, setup_params.sector_count) {
            (winning::CHALLENGE_COUNT, 1) => true,
            (window::SECTOR_CHALLENGES, sectors)
                if sectors == window::challenged_sector_count::<SECTOR_NODES_2_KIB>() =>
            {
                false
            }
            _ => panic!("setup params do not match winning or window post params"),
        };

        let (circ, pub_inputs_vec) = if is_winning {
            let pub_inputs = winning::PublicInputs::<F, SECTOR_NODES_2_KIB>::from(
                setup_params,
                vanilla_pub_inputs,
            );
            let pub_inputs_vec = pub_inputs.to_vec();

            let priv_inputs = winning::PrivateInputs::<F, U, V, W, SECTOR_NODES_2_KIB>::from(
                &partition_proof.sectors[0],
            );

            let circ = PostCircuit::from(WinningPostCircuit {
                pub_inputs,
                priv_inputs,
            });

            (circ, pub_inputs_vec)
        } else {
            let pub_inputs = window::PublicInputs::<F, SECTOR_NODES_2_KIB>::from(
                setup_params,
                vanilla_pub_inputs,
            );
            let pub_inputs_vec = pub_inputs.to_vec();

            let priv_inputs = window::PrivateInputs::<F, U, V, W, SECTOR_NODES_2_KIB>::from(
                &partition_proof.sectors,
            );

            let circ = PostCircuit::from(WindowPostCircuit {
                pub_inputs,
                priv_inputs,
            });

            (circ, pub_inputs_vec)
        };

        let keypair = Self::keypair(&circ)?;
        create_proof(&keypair, circ, &pub_inputs_vec, &mut OsRng)
    }
}
