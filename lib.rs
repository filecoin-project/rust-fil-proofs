extern crate pairing;
extern crate bellman;

use std::{
    io::{
        self,
        Read,
        BufReader
    },
    fs::{
        File
    },
    sync::{
        Arc
    }
};

use pairing::{
    Engine,
    Field,
    EncodedPoint,
    CurveAffine,
    CurveProjective,
    bls12_381::{
        Bls12,
        Fr,
        G1,
        G2,
        G1Affine,
        G1Uncompressed,
        G2Affine,
        G2Uncompressed
    }
};

use bellman::{
    Circuit,
    SynthesisError,
    Variable,
    Index,
    ConstraintSystem,
    LinearCombination,
    groth16::{
        Parameters,
        VerifyingKey
    },
    multicore::Worker
};

/// This is our assembly structure that we'll use to synthesize the
/// circuit into a QAP.
struct KeypairAssembly<E: Engine> {
    num_inputs: usize,
    num_aux: usize,
    num_constraints: usize,
    at_inputs: Vec<Vec<(E::Fr, usize)>>,
    bt_inputs: Vec<Vec<(E::Fr, usize)>>,
    ct_inputs: Vec<Vec<(E::Fr, usize)>>,
    at_aux: Vec<Vec<(E::Fr, usize)>>,
    bt_aux: Vec<Vec<(E::Fr, usize)>>,
    ct_aux: Vec<Vec<(E::Fr, usize)>>
}

impl<E: Engine> ConstraintSystem<E> for KeypairAssembly<E> {
    type Root = Self;

    fn alloc<F, A, AR>(
        &mut self,
        _: A,
        _: F
    ) -> Result<Variable, SynthesisError>
        where F: FnOnce() -> Result<E::Fr, SynthesisError>, A: FnOnce() -> AR, AR: Into<String>
    {
        // There is no assignment, so we don't even invoke the
        // function for obtaining one.

        let index = self.num_aux;
        self.num_aux += 1;

        self.at_aux.push(vec![]);
        self.bt_aux.push(vec![]);
        self.ct_aux.push(vec![]);

        Ok(Variable::new_unchecked(Index::Aux(index)))
    }

    fn alloc_input<F, A, AR>(
        &mut self,
        _: A,
        _: F
    ) -> Result<Variable, SynthesisError>
        where F: FnOnce() -> Result<E::Fr, SynthesisError>, A: FnOnce() -> AR, AR: Into<String>
    {
        // There is no assignment, so we don't even invoke the
        // function for obtaining one.

        let index = self.num_inputs;
        self.num_inputs += 1;

        self.at_inputs.push(vec![]);
        self.bt_inputs.push(vec![]);
        self.ct_inputs.push(vec![]);

        Ok(Variable::new_unchecked(Index::Input(index)))
    }

    fn enforce<A, AR, LA, LB, LC>(
        &mut self,
        _: A,
        a: LA,
        b: LB,
        c: LC
    )
        where A: FnOnce() -> AR, AR: Into<String>,
              LA: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
              LB: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
              LC: FnOnce(LinearCombination<E>) -> LinearCombination<E>
    {
        fn eval<E: Engine>(
            l: LinearCombination<E>,
            inputs: &mut [Vec<(E::Fr, usize)>],
            aux: &mut [Vec<(E::Fr, usize)>],
            this_constraint: usize
        )
        {
            for &(var, coeff) in l.as_ref() {
                match var.get_unchecked() {
                    Index::Input(id) => inputs[id].push((coeff, this_constraint)),
                    Index::Aux(id) => aux[id].push((coeff, this_constraint))
                }
            }
        }

        eval(a(LinearCombination::zero()), &mut self.at_inputs, &mut self.at_aux, self.num_constraints);
        eval(b(LinearCombination::zero()), &mut self.bt_inputs, &mut self.bt_aux, self.num_constraints);
        eval(c(LinearCombination::zero()), &mut self.ct_inputs, &mut self.ct_aux, self.num_constraints);

        self.num_constraints += 1;
    }

    fn push_namespace<NR, N>(&mut self, _: N)
        where NR: Into<String>, N: FnOnce() -> NR
    {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn pop_namespace(&mut self)
    {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}

pub fn new_parameters<C>(
    circuit: C,
) -> Result<Parameters<Bls12>, SynthesisError>
    where C: Circuit<Bls12>
{
    let mut assembly = KeypairAssembly {
        num_inputs: 0,
        num_aux: 0,
        num_constraints: 0,
        at_inputs: vec![],
        bt_inputs: vec![],
        ct_inputs: vec![],
        at_aux: vec![],
        bt_aux: vec![],
        ct_aux: vec![]
    };

    // Allocate the "one" input variable
    assembly.alloc_input(|| "", || Ok(Fr::one()))?;

    // Synthesize the circuit.
    circuit.synthesize(&mut assembly)?;

    // Input constraints to ensure full density of IC query
    // x * 0 = 0
    for i in 0..assembly.num_inputs {
        assembly.enforce(|| "",
            |lc| lc + Variable::new_unchecked(Index::Input(i)),
            |lc| lc,
            |lc| lc,
        );
    }

    // Compute the size of our evaluation domain
    let mut m = 1;
    let mut exp = 0;
    while m < assembly.num_constraints {
        m *= 2;
        exp += 1;

        // Powers of Tau ceremony can't support more than 2^21
        if exp > 21 {
            return Err(SynthesisError::PolynomialDegreeTooLarge)
        }
    }

    // Try to load "phase1radix2m{}"
    let f = match File::open(format!("phase1radix2m{}", exp)) {
        Ok(f) => f,
        Err(e) => {
            panic!("Couldn't load phase1radix2m{}: {:?}", exp, e);
        }
    };
    let f = &mut BufReader::with_capacity(1024 * 1024, f);

    let read_g1 = |reader: &mut BufReader<File>| -> io::Result<G1Affine> {
        let mut repr = G1Uncompressed::empty();
        reader.read_exact(repr.as_mut())?;

        repr.into_affine_unchecked()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        .and_then(|e| if e.is_zero() {
            Err(io::Error::new(io::ErrorKind::InvalidData, "point at infinity"))
        } else {
            Ok(e)
        })
    };

    let read_g2 = |reader: &mut BufReader<File>| -> io::Result<G2Affine> {
        let mut repr = G2Uncompressed::empty();
        reader.read_exact(repr.as_mut())?;

        repr.into_affine_unchecked()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        .and_then(|e| if e.is_zero() {
            Err(io::Error::new(io::ErrorKind::InvalidData, "point at infinity"))
        } else {
            Ok(e)
        })
    };

    let alpha = read_g1(f)?;
    let beta_g1 = read_g1(f)?;
    let beta_g2 = read_g2(f)?;

    let mut coeffs_g1 = Vec::with_capacity(m);
    for _ in 0..m {
        coeffs_g1.push(read_g1(f)?);
    }

    let mut coeffs_g2 = Vec::with_capacity(m);
    for _ in 0..m {
        coeffs_g2.push(read_g2(f)?);
    }

    let mut alpha_coeffs_g1 = Vec::with_capacity(m);
    for _ in 0..m {
        alpha_coeffs_g1.push(read_g1(f)?);
    }

    let mut beta_coeffs_g1 = Vec::with_capacity(m);
    for _ in 0..m {
        beta_coeffs_g1.push(read_g1(f)?);
    }

    // These are `Arc` so that later it'll be easier
    // to use multiexp during QAP evaluation (which
    // requires a futures-based API)
    let coeffs_g1 = Arc::new(coeffs_g1);
    let coeffs_g2 = Arc::new(coeffs_g2);
    let alpha_coeffs_g1 = Arc::new(alpha_coeffs_g1);
    let beta_coeffs_g1 = Arc::new(beta_coeffs_g1);

    let mut h = Vec::with_capacity(m - 1);
    for _ in 0..(m - 1) {
        h.push(read_g1(f)?);
    }

    let mut ic = vec![G1::zero(); assembly.num_inputs];
    let mut l = vec![G1::zero(); assembly.num_aux];
    let mut a_g1 = vec![G1::zero(); assembly.num_inputs + assembly.num_aux];
    let mut b_g1 = vec![G1::zero(); assembly.num_inputs + assembly.num_aux];
    let mut b_g2 = vec![G2::zero(); assembly.num_inputs + assembly.num_aux];

    fn eval(
        // Lagrange coefficients for tau
        coeffs_g1: Arc<Vec<G1Affine>>,
        coeffs_g2: Arc<Vec<G2Affine>>,
        alpha_coeffs_g1: Arc<Vec<G1Affine>>,
        beta_coeffs_g1: Arc<Vec<G1Affine>>,

        // QAP polynomials
        at: &[Vec<(Fr, usize)>],
        bt: &[Vec<(Fr, usize)>],
        ct: &[Vec<(Fr, usize)>],

        // Resulting evaluated QAP polynomials
        a_g1: &mut [G1],
        b_g1: &mut [G1],
        b_g2: &mut [G2],
        ext: &mut [G1],

        // Worker
        worker: &Worker
    )
    {
        // Sanity check
        assert_eq!(a_g1.len(), at.len());
        assert_eq!(a_g1.len(), bt.len());
        assert_eq!(a_g1.len(), ct.len());
        assert_eq!(a_g1.len(), b_g1.len());
        assert_eq!(a_g1.len(), b_g2.len());
        assert_eq!(a_g1.len(), ext.len());

        // Evaluate polynomials in multiple threads
        worker.scope(a_g1.len(), |scope, chunk| {
            for ((((((a_g1, b_g1), b_g2), ext), at), bt), ct) in
                a_g1.chunks_mut(chunk)
                .zip(b_g1.chunks_mut(chunk))
                .zip(b_g2.chunks_mut(chunk))
                .zip(ext.chunks_mut(chunk))
                .zip(at.chunks(chunk))
                .zip(bt.chunks(chunk))
                .zip(ct.chunks(chunk))
            {
                let coeffs_g1 = coeffs_g1.clone();
                let coeffs_g2 = coeffs_g2.clone();
                let alpha_coeffs_g1 = alpha_coeffs_g1.clone();
                let beta_coeffs_g1 = beta_coeffs_g1.clone();

                scope.spawn(move || {
                    for ((((((a_g1, b_g1), b_g2), ext), at), bt), ct) in
                        a_g1.iter_mut()
                        .zip(b_g1.iter_mut())
                        .zip(b_g2.iter_mut())
                        .zip(ext.iter_mut())
                        .zip(at.iter())
                        .zip(bt.iter())
                        .zip(ct.iter())
                    {
                        for &(coeff, lag) in at {
                            a_g1.add_assign(&coeffs_g1[lag].mul(coeff));
                            ext.add_assign(&beta_coeffs_g1[lag].mul(coeff));
                        }

                        for &(coeff, lag) in bt {
                            b_g1.add_assign(&coeffs_g1[lag].mul(coeff));
                            b_g2.add_assign(&coeffs_g2[lag].mul(coeff));
                            ext.add_assign(&alpha_coeffs_g1[lag].mul(coeff));
                        }

                        for &(coeff, lag) in ct {
                            ext.add_assign(&coeffs_g1[lag].mul(coeff));
                        }
                    }

                    // Batch normalize
                    G1::batch_normalization(a_g1);
                    G1::batch_normalization(b_g1);
                    G2::batch_normalization(b_g2);
                    G1::batch_normalization(ext);
                });
            }
        });
    }

    let worker = Worker::new();

    // Evaluate for inputs.
    eval(
        coeffs_g1.clone(),
        coeffs_g2.clone(),
        alpha_coeffs_g1.clone(),
        beta_coeffs_g1.clone(),
        &assembly.at_inputs,
        &assembly.bt_inputs,
        &assembly.ct_inputs,
        &mut a_g1[0..assembly.num_inputs],
        &mut b_g1[0..assembly.num_inputs],
        &mut b_g2[0..assembly.num_inputs],
        &mut ic,
        &worker
    );

    // Evaluate for auxillary variables.
    eval(
        coeffs_g1.clone(),
        coeffs_g2.clone(),
        alpha_coeffs_g1.clone(),
        beta_coeffs_g1.clone(),
        &assembly.at_aux,
        &assembly.bt_aux,
        &assembly.ct_aux,
        &mut a_g1[assembly.num_inputs..],
        &mut b_g1[assembly.num_inputs..],
        &mut b_g2[assembly.num_inputs..],
        &mut l,
        &worker
    );

    // Don't allow any elements be unconstrained, so that
    // the L query is always fully dense.
    for e in l.iter() {
        if e.is_zero() {
            return Err(SynthesisError::UnconstrainedVariable);
        }
    }

    let vk = VerifyingKey {
        alpha_g1: alpha,
        beta_g1: beta_g1,
        beta_g2: beta_g2,
        gamma_g2: G2Affine::one(),
        delta_g1: G1Affine::one(),
        delta_g2: G2Affine::one(),
        ic: ic.into_iter().map(|e| e.into_affine()).collect()
    };

    Ok(Parameters {
        vk: vk,
        h: Arc::new(h),
        l: Arc::new(l.into_iter().map(|e| e.into_affine()).collect()),

        // Filter points at infinity away from A/B queries
        a: Arc::new(a_g1.into_iter().filter(|e| !e.is_zero()).map(|e| e.into_affine()).collect()),
        b_g1: Arc::new(b_g1.into_iter().filter(|e| !e.is_zero()).map(|e| e.into_affine()).collect()),
        b_g2: Arc::new(b_g2.into_iter().filter(|e| !e.is_zero()).map(|e| e.into_affine()).collect())
    })
}
