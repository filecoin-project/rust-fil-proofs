use std::marker::PhantomData;
use zexe_algebra::curves::bls12_381::{Bls12_381, Bls12_381Parameters};
use zexe_algebra::curves::jubjub::JubJubProjective as JubJub;
use zexe_algebra::PairingEngine as Engine;
use zexe_snark::{Circuit, ConstraintSystem, SynthesisError};
use crate::circuit::variables_zexe::Root;
use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::drgraph::graph_height;
use crate::hasher::{HasherZexe, HashFunctionZexe, DomainZexe};
use crate::parameter_cache::{CacheableParameters, ParameterSetIdentifier};


pub struct PoRCircuit<E: Engine, H: HasherZexe> {
    value: Option<E::Fr>,
    auth_path: Vec<Option<(E::Fr, bool)>>,
    root: Root<E>,
    private: bool,
    _h: PhantomData<H>,
}

impl<E: Engine, H: HasherZexe> CircuitComponent for PoRCircuit<E, H> {
    type ComponentPrivateInputs = Option<Root<E>>;
}

pub struct PoRCompound<H: HasherZexe> {
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

//impl<E: Engine, C: Circuit<E>, P: ParameterSetIdentifier, H: HasherZexe>
//CacheableParameters<E, C, P> for PoRCompound<H>
//{
//    fn cache_prefix() -> String {
//        format!("proof-of-retrievability-{}", H::name())
//    }
//}
