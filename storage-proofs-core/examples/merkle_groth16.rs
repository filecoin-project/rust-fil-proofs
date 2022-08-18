use bellperson::groth16;
use blstrs::{Bls12, Scalar as Fr};
use filecoin_hashers::poseidon::PoseidonHasher;
use generic_array::typenum::Unsigned;
use log::info;
use rand::thread_rng;
use storage_proofs_core::{
    compound_proof::CompoundProof as _,
    gadgets::por::{PoRCircuit, PoRCompound},
    merkle::{MerkleTree, MerkleTreeTrait},
    por as vanilla,
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

    info!("groth16: arity: {}, leaves: {}", ARITY, NUM_LEAFS);

    type TreeFr = MerkleTree<PoseidonHasher<Fr>, A>;

    let mut rng = thread_rng();

    let vanilla_pub_params = vanilla::PublicParams {
        leaves: NUM_LEAFS,
        // Check the calculated Merkle root against public input.
        private: false,
    };

    let blank_circuit = PoRCompound::<TreeFr>::blank_circuit(&vanilla_pub_params);
    let params = groth16::generate_random_parameters::<Bls12, _, _>(blank_circuit, &mut rng)
        .expect("failed to create groth16 params");
    let vk = groth16::prepare_verifying_key(&params.vk);

    info!("groth16: generate leaves");
    let leafs = (0..NUM_LEAFS as u64).map(|i| Fr::from(i).into());
    let tree = TreeFr::new(leafs).expect("failed to create merkle tree");
    let merkle_proof = tree
        .gen_proof(CHALLENGE)
        .expect("failed to create merkle proof");

    let vanilla_pub_inputs = vanilla::PublicInputs {
        commitment: Some(tree.root()),
        challenge: CHALLENGE,
    };
    let pub_inputs = PoRCompound::<TreeFr>::generate_public_inputs(
        &vanilla_pub_inputs,
        &vanilla_pub_params,
        None,
    )
    .expect("failed to create groth16 public inputs");

    info!("groth16: generate circuit");
    let circ = PoRCircuit::<TreeFr>::new(merkle_proof, false);

    info!("groth16: start proving");
    let proof = groth16::create_random_proof(circ, &params, &mut rng)
        .expect("failed to create groth16 proof");
    info!("groth16: stop proving");

    info!("groth16: start verifying");
    groth16::verify_proof(&vk, &proof, &pub_inputs).expect("failed to verify groth16 proof");
    info!("groth16: stop verifying");
}
