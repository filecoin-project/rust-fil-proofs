use filecoin_hashers::{poseidon::PoseidonHasher, Domain, Hasher, PoseidonArity};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use rand::rngs::OsRng;
use storage_proofs_core::{
    halo2::{
        create_proof, verify_proof, CircuitRows, CompoundProof, FieldProvingCurves, Halo2Keypair,
        Halo2Proof,
    },
    merkle::MerkleTreeTrait,
};

use crate::{
    fallback::{FallbackPoSt, SetupParams},
    halo2::{
        constants::{
            SECTOR_NODES_16_KIB, SECTOR_NODES_16_MIB, SECTOR_NODES_1_GIB, SECTOR_NODES_2_KIB,
            SECTOR_NODES_32_GIB, SECTOR_NODES_32_KIB, SECTOR_NODES_4_KIB, SECTOR_NODES_512_MIB,
            SECTOR_NODES_64_GIB, SECTOR_NODES_8_MIB,
        },
        shared::CircuitConfig,
        window::{self, WindowPostCircuit},
        winning::{self, WinningPostCircuit},
    },
};

fn is_winning<const SECTOR_NODES: usize>(setup_params: &SetupParams) -> bool {
    assert_eq!(setup_params.sector_size >> 5, SECTOR_NODES as u64);
    match (setup_params.challenge_count, setup_params.sector_count) {
        (winning::CHALLENGE_COUNT, 1) => true,
        (window::SECTOR_CHALLENGES, sectors)
            if sectors == window::challenged_sector_count::<SECTOR_NODES>() =>
        {
            false
        }
        _ => panic!("setup params do not match winning or window post params"),
    }
}

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

macro_rules! impl_compound_proof {
    ($($sector_nodes:expr),*) => {
        $(
            impl<'a, F, U, V, W, TreeR> CompoundProof<'a, F, $sector_nodes> for FallbackPoSt<'a, TreeR>
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
                type Circuit = PostCircuit<F, U, V, W, $sector_nodes>;

                fn prove_partition_with_vanilla(
                    setup_params: &Self::SetupParams,
                    vanilla_pub_inputs: &Self::PublicInputs,
                    vanilla_partition_proof: &Self::Proof,
                    keypair: &Halo2Keypair<<F as FieldProvingCurves>::Affine, Self::Circuit>,
                ) -> Result<Halo2Proof<<F as FieldProvingCurves>::Affine, Self::Circuit>, Error> {
                    let is_winning = is_winning::<$sector_nodes>(setup_params);

                    let (circ, pub_inputs_vec) = if is_winning {
                        let pub_inputs =
                            winning::PublicInputs::<F, $sector_nodes>::from(vanilla_pub_inputs.clone());

                        let pub_inputs_vec = pub_inputs.to_vec();

                        let priv_inputs = winning::PrivateInputs::<F, U, V, W, $sector_nodes>::from(
                            &vanilla_partition_proof.sectors[0],
                        );

                        let circ = PostCircuit::from(WinningPostCircuit {
                            pub_inputs,
                            priv_inputs,
                        });

                        (circ, pub_inputs_vec)
                    } else {
                        let pub_inputs =
                            window::PublicInputs::<F, $sector_nodes>::from(vanilla_pub_inputs.clone());

                        let pub_inputs_vec = pub_inputs.to_vec();

                        let priv_inputs = window::PrivateInputs::<F, U, V, W, $sector_nodes>::from(
                            &vanilla_partition_proof.sectors,
                        );

                        let circ = PostCircuit::from(WindowPostCircuit {
                            pub_inputs,
                            priv_inputs,
                        });

                        (circ, pub_inputs_vec)
                    };

                    create_proof(keypair, circ, &pub_inputs_vec, &mut OsRng)
                }

                fn prove_all_partitions_with_vanilla(
                    setup_params: &Self::SetupParams,
                    vanilla_pub_inputs: &[&Self::PublicInputs],
                    vanilla_proofs: &[&Self::Proof],
                    keypair: &Halo2Keypair<<F as FieldProvingCurves>::Affine, Self::Circuit>,
                ) -> Result<Vec<Halo2Proof<<F as FieldProvingCurves>::Affine, Self::Circuit>>, Error> {
                    assert_eq!(vanilla_pub_inputs.len(), vanilla_proofs.len());

                    // The only public input field which whould change is `k`.
                    assert!(
                        vanilla_pub_inputs
                            .iter()
                            .enumerate()
                            .all(|(i, partition_pub_inputs)| {
                                partition_pub_inputs.randomness == vanilla_pub_inputs[0].randomness &&
                                    partition_pub_inputs.prover_id == vanilla_pub_inputs[0].prover_id &&
                                    partition_pub_inputs.sectors == vanilla_pub_inputs[0].sectors &&
                                    partition_pub_inputs.k == Some(i)
                            })
                    );

                    vanilla_pub_inputs
                        .iter()
                        .zip(vanilla_proofs.iter())
                        .map(|(pub_inputs, partition_proof)| {
                            <Self as CompoundProof<'_, F, $sector_nodes>>::prove_partition_with_vanilla(
                                setup_params,
                                pub_inputs,
                                partition_proof,
                                keypair,
                            )
                        })
                        .collect()
                }

                fn verify_partition(
                    setup_params: &Self::SetupParams,
                    vanilla_pub_inputs: &Self::PublicInputs,
                    circ_proof: &Halo2Proof<<F as FieldProvingCurves>::Affine, Self::Circuit>,
                    keypair: &Halo2Keypair<<F as FieldProvingCurves>::Affine, Self::Circuit>,
                ) -> Result<(), Error> {
                    let is_winning = is_winning::<$sector_nodes>(setup_params);

                    let pub_inputs_vec = if is_winning {
                        winning::PublicInputs::<F, $sector_nodes>::from(vanilla_pub_inputs.clone())
                            .to_vec()
                    } else {
                        window::PublicInputs::<F, $sector_nodes>::from(vanilla_pub_inputs.clone()).to_vec()
                    };

                    verify_proof(keypair, circ_proof, &pub_inputs_vec)
                }

                fn verify_all_partitions(
                    setup_params: &Self::SetupParams,
                    vanilla_pub_inputs: &[&Self::PublicInputs],
                    circ_proofs: &[&Halo2Proof<<F as FieldProvingCurves>::Affine, Self::Circuit>],
                    keypair: &Halo2Keypair<<F as FieldProvingCurves>::Affine, Self::Circuit>,
                ) -> Result<(), Error> {
                    assert_eq!(vanilla_pub_inputs.len(), circ_proofs.len());

                    // The only public input field which whould change is `k`.
                    assert!(
                        vanilla_pub_inputs
                            .iter()
                            .enumerate()
                            .all(|(i, partition_pub_inputs)| {
                                partition_pub_inputs.randomness == vanilla_pub_inputs[0].randomness &&
                                    partition_pub_inputs.prover_id == vanilla_pub_inputs[0].prover_id &&
                                    partition_pub_inputs.sectors == vanilla_pub_inputs[0].sectors &&
                                    partition_pub_inputs.k == Some(i)
                            })
                    );

                    for (vanilla_pub_inputs, circ_proof) in vanilla_pub_inputs.iter().zip(circ_proofs.iter()) {
                        <Self as CompoundProof<'_, F, $sector_nodes>>::verify_partition(setup_params, vanilla_pub_inputs, circ_proof, keypair)?;
                    }
                    Ok(())
                }
            }
        )*
    }
}

impl_compound_proof!(
    SECTOR_NODES_2_KIB,
    SECTOR_NODES_4_KIB,
    SECTOR_NODES_16_KIB,
    SECTOR_NODES_32_KIB,
    SECTOR_NODES_8_MIB,
    SECTOR_NODES_16_MIB,
    SECTOR_NODES_512_MIB,
    SECTOR_NODES_1_GIB,
    SECTOR_NODES_32_GIB,
    SECTOR_NODES_64_GIB
);
