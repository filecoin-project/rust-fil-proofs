use std::marker::PhantomData;
use snark::{Circuit, ConstraintSystem, SynthesisError, LinearCombination, Index, Variable};
// use bellperson::{Circuit, ConstraintSystem, SynthesisError};


// use fil_sapling_crypto::circuit::{boolean, multipack, num};
use snark_gadgets::bits::boolean::Boolean;
use snark_gadgets::bits::uint8::UInt8;
use snark_gadgets::fields::fp::FpGadget;
// use fil_sapling_crypto::jubjub::{JubjubBls12, JubjubEngine};

// use paired::bls12_381::{Bls12, Fr};
use algebra::PairingEngine as Engine;
use algebra::fields::bls12_381::Fr;
use algebra::curves::bls12_381::Bls12_381 as Bls12;

use crate::circuit::constraint;
use crate::circuit::variables::Root;
use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::drgraph::graph_height;
use crate::hasher::{HashFunction, Hasher};
use crate::merklepor::MerklePoR;
use crate::parameter_cache::{CacheableParameters, ParameterSetIdentifier};
use crate::proof::ProofScheme;


pub struct PoRCircuit<E: Engine, H: Hasher> {
    value: Option<E::Fr>,
    auth_path: Vec<Option<(E::Fr, bool)>>,
    root: Root<E>,
    private: bool,
    _h: PhantomData<H>,
}

impl<E: Engine, H: Hasher> CircuitComponent for PoRCircuit<E, H> {
    type ComponentPrivateInputs = Option<Root<E>>;
}

pub struct PoRCompound<H: Hasher> {
    _h: PhantomData<H>,
}

pub fn challenge_into_auth_path_bits(challenge: usize, leaves: usize) -> Vec<bool> {
    let height = graph_height(leaves);
    let mut bits = Vec::new();
    let mut n = challenge;
    for _ in 0..height {
        bits.push(n & 1 == 1);
        n >>= 1;
    }
    bits
}
