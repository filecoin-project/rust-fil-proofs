use filecoin_hashers::poseidon::PoseidonHasher;
use generic_array::typenum::{Unsigned, U0};
use halo2_proofs::pasta::Fp;
use log::info;
use rand::thread_rng;
use storage_proofs_core::{
    halo2::{self, gadgets::por::test_circuit::MerkleCircuit, Halo2Field, Halo2Keypair},
    merkle::{MerkleProofTrait, MerkleTree, MerkleTreeTrait},
};

fn main() {
    fil_logger::maybe_init();

    // Configure the tree height, arity, and whether or not to benchmark batch proving here:
    const HEIGHT: u32 = 10;
    type A = generic_array::typenum::U4;
    const ARITY: usize = 4;

    assert_eq!(A::to_usize(), ARITY);

    const NUM_LEAFS: usize = ARITY.pow(HEIGHT);
    const CHALLENGE: usize = NUM_LEAFS / 2;

    info!("halo2: arity: {}, leaves: {}", ARITY, NUM_LEAFS);

    type TreeFp = MerkleTree<PoseidonHasher<Fp>, A>;

    let mut rng = thread_rng();

    info!("halo2: generate leaves");
    let leafs = (0..NUM_LEAFS as u64).map(|i| Fp::from(i).into());
    let leaf = Fp::from(CHALLENGE as u64);
    let tree = TreeFp::new(leafs).expect("failed to create merkle tree");
    let root: Fp = tree.root().into();
    let merkle_proof = tree
        .gen_proof(CHALLENGE)
        .expect("failed to create merkle proof");
    let path: Vec<Vec<Fp>> = merkle_proof
        .path()
        .iter()
        .map(|(sibs, _)| sibs.iter().copied().map(Into::into).collect())
        .collect();

    info!("halo2: generate circuit");
    let circ = MerkleCircuit::<PoseidonHasher<Fp>, A, U0, U0, NUM_LEAFS>::new(leaf, path);
    let pub_inputs = vec![vec![leaf, root]];

    let keypair = Halo2Keypair::<<Fp as Halo2Field>::Affine, _>::create(&circ)
        .expect("failed to create halo2 keypair");

    info!("halo2: start proving");
    let proof = halo2::create_proof(&keypair, circ, &pub_inputs, &mut rng)
        .expect("failed to create halo2 proof");
    info!("halo2: stop proving");

    info!("halo2: start verifying");
    halo2::verify_proof(&keypair, &proof, &pub_inputs).expect("failed to verify halo2 proof");
    info!("halo2: stop verifying");
}
