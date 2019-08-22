use rand::SeedableRng;
use rand::XorShiftRng;

use algebra::curves::edwards_bls12::EdwardsProjective;
use dpc::crypto_primitives::crh::pedersen::PedersenParameters;
use dpc::crypto_primitives::crh::{pedersen::PedersenCRH, FixedLengthCRH};

use crate::crypto::pedersen::BigWindow;

lazy_static! {
    pub static ref PEDERSEN_PARAMS: PedersenParameters<EdwardsProjective> = {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        PedersenCRH::<EdwardsProjective, BigWindow>::setup(rng).unwrap()
    };
}
