use std::marker::PhantomData;
use algebra::curves::bls12_381::{Bls12_381, Bls12_381Parameters};
use algebra::curves::jubjub::JubJubProjective as JubJub;
use algebra::PairingEngine as Engine;
use snark::{Circuit, ConstraintSystem, SynthesisError};
use crate::circuit::variables::Root;
use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::drgraph::graph_height;
use crate::hasher::{Hasher, HashFunction, Domain};
use crate::parameter_cache::{CacheableParameters, ParameterSetIdentifier};


//pub struct PoRCircuit<E: Engine, H: Hasher> {
//    value: Option<E::Fr>,
//    auth_path: Vec<Option<(E::Fr, bool)>>,
//    root: Root<E>,
//    private: bool,
//    _h: PhantomData<H>,
//}
//
//impl<E: Engine, H: Hasher> CircuitComponent for PoRCircuit<E, H> {
//    type ComponentPrivateInputs = Option<Root<E>>;
//}
//
//pub struct PoRCompound<H: Hasher> {
//    _h: PhantomData<H>,
//}
//
//pub fn challenge_into_auth_path_bits(challenge: usize, leaves: usize) -> Vec<bool> {
//    let height = graph_height(leaves);
//    let mut bits = Vec::new();
//    let mut n = challenge;
//    for _ in 0..height {
//        bits.push(n & 1 == 1);
//        n >>= 1;
//    }
//    bits
//}
