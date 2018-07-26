use bellman::{ConstraintSystem, Index, LinearCombination, SynthesisError, Variable};
use pairing::{Engine, Field};
use std::cmp::Ordering;

#[derive(Clone, Copy)]
struct OrderedVariable(Variable);

impl Eq for OrderedVariable {}
impl PartialEq for OrderedVariable {
    fn eq(&self, other: &OrderedVariable) -> bool {
        match (self.0.get_unchecked(), other.0.get_unchecked()) {
            (Index::Input(ref a), Index::Input(ref b)) => a == b,
            (Index::Aux(ref a), Index::Aux(ref b)) => a == b,
            _ => false,
        }
    }
}
impl PartialOrd for OrderedVariable {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for OrderedVariable {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.0.get_unchecked(), other.0.get_unchecked()) {
            (Index::Input(ref a), Index::Input(ref b)) => a.cmp(b),
            (Index::Aux(ref a), Index::Aux(ref b)) => a.cmp(b),
            (Index::Input(_), Index::Aux(_)) => Ordering::Less,
            (Index::Aux(_), Index::Input(_)) => Ordering::Greater,
        }
    }
}

fn eval_lc<E: Engine>(terms: &[(Variable, E::Fr)], inputs: &[E::Fr], aux: &[E::Fr]) -> E::Fr {
    let mut acc = E::Fr::zero();

    for &(var, ref coeff) in terms {
        let mut tmp = match var.get_unchecked() {
            Index::Input(index) => inputs[index],
            Index::Aux(index) => aux[index],
        };

        tmp.mul_assign(&coeff);
        acc.add_assign(&tmp);
    }

    acc
}

#[derive(Debug)]
pub struct BenchCS<E: Engine> {
    inputs: Vec<E::Fr>,
    aux: Vec<E::Fr>,
    a: Vec<E::Fr>,
    b: Vec<E::Fr>,
    c: Vec<E::Fr>,
}

impl<E: Engine> BenchCS<E> {
    pub fn new() -> Self {
        BenchCS::default()
    }

    pub fn num_constraints(&self) -> usize {
        self.a.len()
    }
}

impl<E: Engine> Default for BenchCS<E> {
    fn default() -> Self {
        BenchCS {
            inputs: vec![E::Fr::one()],
            aux: vec![],
            a: vec![],
            b: vec![],
            c: vec![],
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
        self.aux.push(f()?);

        Ok(Variable::new_unchecked(Index::Aux(self.aux.len() - 1)))
    }

    fn alloc_input<F, A, AR>(&mut self, _: A, f: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.inputs.push(f()?);

        Ok(Variable::new_unchecked(Index::Input(self.inputs.len() - 1)))
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
        LB: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
        LC: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
    {
        self.a.push(eval_lc::<E>(
            a(LinearCombination::zero()).as_ref(),
            &self.inputs,
            &self.aux,
        ));
        self.b.push(eval_lc::<E>(
            b(LinearCombination::zero()).as_ref(),
            &self.inputs,
            &self.aux,
        ));
        self.c.push(eval_lc::<E>(
            c(LinearCombination::zero()).as_ref(),
            &self.inputs,
            &self.aux,
        ));
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
