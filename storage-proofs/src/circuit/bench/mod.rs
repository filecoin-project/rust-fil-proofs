use std::marker::PhantomData;

use bellperson::{ConstraintSystem, Index, LinearCombination, SynthesisError, Variable};
use paired::Engine;

#[derive(Debug)]
pub struct BenchCS<E: Engine> {
    inputs: usize,
    aux: usize,
    a: usize,
    b: usize,
    c: usize,
    _e: PhantomData<E>,
}

impl<E: Engine> BenchCS<E> {
    pub fn new() -> Self {
        BenchCS::default()
    }

    pub fn num_constraints(&self) -> usize {
        self.a
    }

    pub fn num_inputs(&self) -> usize {
        self.inputs
    }
}

impl<E: Engine> Default for BenchCS<E> {
    fn default() -> Self {
        BenchCS {
            inputs: 1,
            aux: 0,
            a: 0,
            b: 0,
            c: 0,
            _e: PhantomData,
        }
    }
}

impl<E: Engine> ConstraintSystem<E> for BenchCS<E> {
    type Root = Self;

    fn alloc<F, A, AR>(&mut self, _: A, f: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let r = match f() {
            Ok(_) => 1,
            Err(SynthesisError::AssignmentMissing) => 1,
            Err(err) => {
                return Err(err);
            }
        };
        self.aux += r;

        Ok(Variable::new_unchecked(Index::Aux(self.aux - 1)))
    }

    fn alloc_input<F, A, AR>(&mut self, _: A, f: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let r = match f() {
            Ok(_) => 1,
            Err(SynthesisError::AssignmentMissing) => 1,
            Err(err) => {
                return Err(err);
            }
        };
        self.inputs += r;

        Ok(Variable::new_unchecked(Index::Input(self.inputs - 1)))
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, _a: LA, _b: LB, _c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
        LB: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
        LC: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
    {
        self.a += 1;
        self.b += 1;
        self.c += 1;
    }

    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
    }

    fn pop_namespace(&mut self) {}

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}
