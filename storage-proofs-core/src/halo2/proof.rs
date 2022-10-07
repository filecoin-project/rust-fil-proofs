use std::any::TypeId;
use std::io::{self, Write};
use std::path::Path;

use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::{CurveAffine, CurveExt, FieldExt},
    pasta::{Ep, Eq, Fp, Fq},
    plonk::{
        self, keygen_pk, keygen_vk, BatchVerifier, Circuit, Error, ProvingKey, SingleVerifier,
        VerifyingKey,
    },
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use log::{error, info};
use rand::RngCore;

use crate::{
    parameter_cache::{
        parameter_cache_dir, with_exclusive_lock, with_exclusive_read_lock,
        with_exclusive_write_lock, HALO2_PARAMETER_EXT, PROVING_KEY_EXT, VERIFYING_KEY_EXT,
        VERSION,
    },
    settings::SETTINGS,
};

type Challenge<C> = Challenge255<C>;
type TranscriptReader<'proof, C> = Blake2bRead<&'proof [u8], C, Challenge<C>>;
type TranscriptWriter<C> = Blake2bWrite<Vec<u8>, C, Challenge<C>>;

pub trait Halo2Field: FieldExt {
    type Curve: CurveExt<ScalarExt = Self>;
    type Affine: CurveAffine<ScalarExt = Self>;
}

impl Halo2Field for Fp {
    type Curve = Eq;
    type Affine = <Self::Curve as CurveExt>::AffineExt;
}

impl Halo2Field for Fq {
    type Curve = Ep;
    type Affine = <Self::Curve as CurveExt>::AffineExt;
}

pub trait CircuitRows {
    fn id(&self) -> String;
    fn k(&self) -> u32;
    // The sector size in KiB.
    fn sector_size(&self) -> usize;
}

pub struct Halo2Keypair<C, Circ>
where
    C: CurveAffine,
    Circ: Circuit<C::Scalar> + CircuitRows,
{
    params: Params<C>,
    pk: ProvingKey<C>,
    _circ: PhantomData<Circ>,
}

pub fn get_field_from_circuit_scalar<F: FieldExt>() -> String {
    let field = TypeId::of::<F>();
    let fp = TypeId::of::<Fp>();
    let fq = TypeId::of::<Fq>();
    assert!(field == fp || field == fq);
    if field == fp {
        "fp".to_string()
    } else {
        "fq".to_string()
    }
}

fn create_params<C, Circ>(circuit: &Circ) -> Result<Params<C>, Error>
where
    C: CurveAffine,
    Circ: Circuit<C::Scalar> + CircuitRows,
{
    let path = format!(
        "{}v{}-halo2-{}-keypair-params-{}.{}",
        parameter_cache_dir().display(),
        VERSION,
        get_field_from_circuit_scalar::<C::Scalar>(),
        circuit.k(),
        HALO2_PARAMETER_EXT,
    );
    let path = Path::new(&path);
    info!("checking for halo2 params at path {:?}", path);
    if path.exists() {
        info!("reading halo2 params at path {:?}", path);
        let res = with_exclusive_read_lock::<_, io::Error, _>(path, Params::read);
        if let Ok(params) = res {
            info!("successfully read halo2 params at path {:?}", path);
            Ok(params)
        } else {
            // Params for each `k` should not change or need updating.
            error!("failed to read halo2 params at path {:?}", path);
            Err(Error::from(io::Error::new(
                io::ErrorKind::Other,
                format!("Cannot read halo2 params at path {:?}", path),
            )))
        }
    } else {
        info!("halo2 params not found at path {:?}", path);
        info!("generating new halo2 params");
        let params = Params::new(circuit.k());
        info!("successfully generated new halo2 params");
        // Create new params file; fails if file exists.
        with_exclusive_lock::<_, io::Error, _>(path, |mut file| {
            info!("writing generated halo2 params at path {:?}", path);
            params.write(&mut file)?;
            file.flush()?;
            info!(
                "successfully wrote generated halo2 params at path {:?}",
                path
            );
            Ok(())
        })
        .or_else(|io_err| {
            // It's possible that another process wrote the file during paramgen.
            if io_err.kind() == io::ErrorKind::AlreadyExists {
                info!(
                    "failed to write generated halo2 params at path {:?}, file already exists; \
                    returning generated params",
                    path,
                );
                Ok(())
            } else {
                info!("failed to write generated halo2 params at path {:?}", path);
                Err(io_err)
            }
        })?;
        Ok(params)
    }
}

// The returned `bool` is `true` if the verifying key was updated on disk; if the verifying key was
// changed, the proving key will also need to be regenerated and written to disk.
fn create_vk<C, Circ>(params: &Params<C>, circuit: &Circ) -> Result<(VerifyingKey<C>, bool), Error>
where
    C: CurveAffine,
    Circ: Circuit<C::Scalar> + CircuitRows,
{
    let path = format!(
        "{}v{}-halo2-{}-keypair-{}-{}-{}.{}",
        parameter_cache_dir().display(),
        VERSION,
        get_field_from_circuit_scalar::<C::Scalar>(),
        circuit.id(),
        circuit.k(),
        circuit.sector_size(),
        VERIFYING_KEY_EXT,
    );
    let path = Path::new(&path);
    info!("checking for halo2 verifying key at path {:?}", path);
    if path.exists() {
        info!("reading halo2 verifying key at path {:?}", path);
        let res = with_exclusive_read_lock(path, |file| VerifyingKey::read(file, params, circuit));
        if let Ok(vk) = res {
            info!("successfully read halo2 verifying key at path {:?}", path);
            return Ok((vk, false));
        }
        // Key file exists, but is not valid for provided circuit.
        error!("failed to read halo2 verifying key at path {:?}", path);
        if !SETTINGS.halo2_update_keys {
            return Err(Error::from(io::Error::new(
                io::ErrorKind::Other,
                format!("Cannot read halo2 verifying key at path {:?}", path),
            )));
        }
        // Update key file.
        info!("updating halo2 verifying key at path {:?}", path);
        info!("generating new halo2 verifying key");
        let vk = keygen_vk(params, circuit).map_err(|err| {
            error!("faild to generate new halo2 verifying key");
            err
        })?;
        info!("successfully generated new halo2 verifying key");
        // Overwrite existing key file.
        with_exclusive_write_lock::<_, io::Error, _>(path, |mut file| {
            info!("writing new halo2 verifying key at path {:?}", path);
            vk.write(&mut file)?;
            file.flush()?;
            info!(
                "successfully wrote new halo2 verifying key at path {:?}",
                path
            );
            Ok(())
        })
        .map_err(|err| {
            error!("failed to write new halo2 verifying key at path {:?}", path);
            err
        })?;
        Ok((vk, true))
    } else {
        info!("halo2 verifying key not found at path {:?}", path);
        info!("generating new halo2 verifying key");
        let vk = keygen_vk(params, circuit).map_err(|err| {
            error!("faild to generate new halo2 verifying key");
            err
        })?;
        info!("successfully generated new halo2 verifying key");
        // Create new key file; fails if file exists.
        with_exclusive_lock::<_, io::Error, _>(path, |mut file| {
            info!("writing generated halo2 verifying key at path {:?}", path);
            vk.write(&mut file)?;
            file.flush()?;
            info!(
                "successfully wrote generated halo2 verifying key at path {:?}",
                path
            );
            Ok(())
        })
        .or_else(|io_err| {
            // It's possible that another process wrote the key file during keygen.
            if io_err.kind() == io::ErrorKind::AlreadyExists {
                info!(
                    "failed to write generated halo2 verifying key at path {:?}, file already \
                    exists; returning generated verifying key",
                    path,
                );
                Ok(())
            } else {
                info!(
                    "failed to write generated halo2 verifying key at path {:?}",
                    path
                );
                Err(io_err)
            }
        })?;
        Ok((vk, true))
    }
}

fn create_pk<C, Circ>(
    params: &Params<C>,
    vk: VerifyingKey<C>,
    circuit: &Circ,
    new_keypair: bool,
) -> Result<ProvingKey<C>, Error>
where
    C: CurveAffine,
    Circ: Circuit<C::Scalar> + CircuitRows,
{
    let path = format!(
        "{}v{}-halo2-{}-keypair-{}-{}-{}.{}",
        parameter_cache_dir().display(),
        VERSION,
        get_field_from_circuit_scalar::<C::Scalar>(),
        circuit.id(),
        circuit.k(),
        circuit.sector_size(),
        PROVING_KEY_EXT,
    );
    let path = Path::new(&path);

    // If verifying key was changed on disk, generate new proving key.
    if new_keypair {
        info!("new halo2 proving key required");
        info!("generating new halo2 proving key");
        let pk = keygen_pk(params, vk, circuit).map_err(|err| {
            error!("faild to generate new halo2 proving key");
            err
        })?;
        info!("successfully generated new halo2 proving key");
        // Create new key file or overwrite existing file.
        with_exclusive_write_lock::<_, io::Error, _>(path, |mut file| {
            info!("writing new halo2 proving key at path {:?}", path);
            pk.write(&mut file)?;
            file.flush()?;
            info!(
                "successfully wrote new halo2 proving key at path {:?}",
                path
            );
            Ok(())
        })
        .map_err(|err| {
            error!("failed to write new halo2 proving key at path {:?}", path);
            err
        })?;
        return Ok(pk);
    }

    info!("checking for halo2 proving key at path {:?}", path);
    if path.exists() {
        info!("reading halo2 proving key at path {:?}", path);
        let res = with_exclusive_read_lock(path, |file| ProvingKey::read(file, vk));
        if let Ok(pk) = res {
            info!("successfully read halo2 proving key at path {:?}", path);
            Ok(pk)
        } else {
            // If this is not a new kepair (i.e. `new_keypair` is `false`), the existing proving
            // key should be valid.
            error!("failed to read halo2 proving key at path {:?}", path);
            Err(Error::from(io::Error::new(
                io::ErrorKind::Other,
                format!("Cannot read halo2 proving key at path {:?}", path),
            )))
        }
    } else {
        info!("halo2 proving key not found at path {:?}", path);
        info!("generating new halo2 proving key");
        let pk = keygen_pk(params, vk, circuit).map_err(|err| {
            error!("faild to generate new halo2 proving key");
            err
        })?;
        info!("successfully generated new halo2 proving key");
        // Create new key file; fails if file exists.
        with_exclusive_lock::<_, io::Error, _>(path, |mut file| {
            info!("writing generated halo2 proving key at path {:?}", path);
            pk.write(&mut file)?;
            file.flush()?;
            info!(
                "successfully wrote generated halo2 proving key at path {:?}",
                path
            );
            Ok(())
        })
        .or_else(|io_err| {
            // It's possible that another process wrote the key file during keygen.
            if io_err.kind() == io::ErrorKind::AlreadyExists {
                info!(
                    "failed to write generated halo2 proving key at path {:?}, file already \
                    exists; returning generated proving key",
                    path,
                );
                Ok(())
            } else {
                info!(
                    "failed to write generated halo2 proving key at path {:?}",
                    path
                );
                Err(io_err)
            }
        })?;
        Ok(pk)
    }
}

impl<C, Circ> Halo2Keypair<C, Circ>
where
    C: CurveAffine,
    Circ: Circuit<C::Scalar> + CircuitRows,
{
    pub fn create(empty_circuit: &Circ) -> Result<Self, Error> {
        let params = create_params(empty_circuit)?;
        let (vk, new_keypair) = create_vk(&params, empty_circuit)?;
        let pk = create_pk(&params, vk, empty_circuit, new_keypair)?;

        Ok(Halo2Keypair {
            params,
            pk,
            _circ: PhantomData,
        })
    }

    pub fn params(&self) -> &Params<C> {
        &self.params
    }

    pub fn pk(&self) -> &ProvingKey<C> {
        &self.pk
    }

    pub fn vk(&self) -> &VerifyingKey<C> {
        self.pk.get_vk()
    }
}

pub struct Halo2Proof<C, Circ>
where
    C: CurveAffine,
    Circ: Circuit<C::Scalar>,
{
    proof_bytes: Vec<u8>,
    _c: PhantomData<C>,
    _circ: PhantomData<Circ>,
}

impl<C, Circ> From<Vec<u8>> for Halo2Proof<C, Circ>
where
    C: CurveAffine,
    Circ: Circuit<C::Scalar>,
{
    fn from(proof_bytes: Vec<u8>) -> Self {
        Halo2Proof {
            proof_bytes,
            _c: PhantomData,
            _circ: PhantomData,
        }
    }
}

impl<C, Circ> Halo2Proof<C, Circ>
where
    C: CurveAffine,
    Circ: Circuit<C::Scalar>,
{
    pub fn as_bytes(&self) -> &[u8] {
        &self.proof_bytes
    }
}

pub fn create_proof<C, Circ, R>(
    keypair: &Halo2Keypair<C, Circ>,
    circuit: Circ,
    pub_inputs: &[Vec<C::Scalar>],
    rng: R,
) -> Result<Halo2Proof<C, Circ>, Error>
where
    C: CurveAffine,
    Circ: Circuit<C::Scalar> + CircuitRows,
    R: RngCore,
{
    let pub_inputs: Vec<&[C::Scalar]> = pub_inputs.iter().map(Vec::as_slice).collect();
    let mut transcript = TranscriptWriter::init(vec![]);
    plonk::create_proof(
        keypair.params(),
        keypair.pk(),
        &[circuit],
        &[&pub_inputs],
        rng,
        &mut transcript,
    )?;
    let proof_bytes: Vec<u8> = transcript.finalize();
    Ok(Halo2Proof::from(proof_bytes))
}

pub fn create_batch_proof<C, Circ, R>(
    keypair: &Halo2Keypair<C, Circ>,
    circuits: &[Circ],
    pub_inputs: &[Vec<Vec<C::Scalar>>],
    rng: R,
) -> Result<Halo2Proof<C, Circ>, Error>
where
    C: CurveAffine,
    Circ: Circuit<C::Scalar> + CircuitRows,
    R: RngCore,
{
    assert_eq!(circuits.len(), pub_inputs.len());
    let pub_inputs: Vec<Vec<&[C::Scalar]>> = pub_inputs
        .iter()
        .map(|partition_pub_inputs| partition_pub_inputs.iter().map(Vec::as_slice).collect())
        .collect();
    let pub_inputs: Vec<&[&[C::Scalar]]> = pub_inputs.iter().map(Vec::as_slice).collect();
    let mut transcript = TranscriptWriter::init(vec![]);
    plonk::create_proof(
        keypair.params(),
        keypair.pk(),
        circuits,
        &pub_inputs,
        rng,
        &mut transcript,
    )?;
    let proof_bytes: Vec<u8> = transcript.finalize();
    Ok(Halo2Proof::from(proof_bytes))
}

pub fn verify_proof<C, Circ>(
    keypair: &Halo2Keypair<C, Circ>,
    proof: &Halo2Proof<C, Circ>,
    pub_inputs: &[Vec<C::Scalar>],
) -> Result<(), Error>
where
    C: CurveAffine,
    Circ: Circuit<C::Scalar> + CircuitRows,
{
    let strategy = SingleVerifier::new(keypair.params());
    let pub_inputs: Vec<&[C::Scalar]> = pub_inputs.iter().map(Vec::as_slice).collect();
    let mut transcript = TranscriptReader::init(proof.as_bytes());
    plonk::verify_proof(
        keypair.params(),
        keypair.vk(),
        strategy,
        &[&pub_inputs],
        &mut transcript,
    )
}

// Verify multiple proofs (in a single transcript `proofs`) using `SingleVerifier`.
pub fn verify_proofs<C, Circ>(
    keypair: &Halo2Keypair<C, Circ>,
    proofs: &Halo2Proof<C, Circ>,
    pub_inputs: &[Vec<Vec<C::Scalar>>],
) -> Result<(), Error>
where
    C: CurveAffine,
    Circ: Circuit<C::Scalar> + CircuitRows,
{
    let strategy = SingleVerifier::new(keypair.params());
    let pub_inputs: Vec<Vec<&[C::Scalar]>> = pub_inputs
        .iter()
        .map(|pub_inputs| pub_inputs.iter().map(Vec::as_slice).collect())
        .collect();
    let pub_inputs: Vec<&[&[C::Scalar]]> = pub_inputs.iter().map(Vec::as_slice).collect();
    let mut transcript = TranscriptReader::init(proofs.as_bytes());
    plonk::verify_proof(
        keypair.params(),
        keypair.vk(),
        strategy,
        &pub_inputs,
        &mut transcript,
    )
}

// Verify multiple proofs (in a single transcript `proofs`) using `BatchVerifier`.
pub fn verify_batch_proof<C, Circ>(
    keypair: &Halo2Keypair<C, Circ>,
    batch_proof: &Halo2Proof<C, Circ>,
    pub_inputs: &[Vec<Vec<C::Scalar>>],
) -> bool
where
    C: CurveAffine,
    Circ: Circuit<C::Scalar> + CircuitRows,
{
    let mut batch = BatchVerifier::new();
    batch.add_proof(pub_inputs.to_vec(), batch_proof.as_bytes().to_vec());
    batch.finalize(keypair.params(), keypair.vk())
}

pub trait CompoundProof<F: Halo2Field, const SECTOR_NODES: usize> {
    type VanillaSetupParams;
    type VanillaPublicInputs;
    type VanillaPartitionProof;
    type Circuit: Circuit<F> + CircuitRows;

    #[inline]
    fn create_keypair(
        empty_circuit: &Self::Circuit,
    ) -> Result<Halo2Keypair<F::Affine, Self::Circuit>, Error> {
        Halo2Keypair::create(empty_circuit)
    }

    fn prove_partition_with_vanilla(
        setup_params: &Self::VanillaSetupParams,
        vanilla_pub_inputs: &Self::VanillaPublicInputs,
        vanilla_proof: &Self::VanillaPartitionProof,
        keypair: &Halo2Keypair<F::Affine, Self::Circuit>,
    ) -> Result<Halo2Proof<F::Affine, Self::Circuit>, Error>;

    fn prove_all_partitions_with_vanilla(
        setup_params: &Self::VanillaSetupParams,
        vanilla_pub_inputs: &Self::VanillaPublicInputs,
        vanilla_proofs: &[Self::VanillaPartitionProof],
        keypair: &Halo2Keypair<F::Affine, Self::Circuit>,
    ) -> Result<Vec<Halo2Proof<F::Affine, Self::Circuit>>, Error>;

    fn batch_prove_all_partitions_with_vanilla(
        setup_params: &Self::VanillaSetupParams,
        vanilla_pub_inputs: &Self::VanillaPublicInputs,
        vanilla_proofs: &[Self::VanillaPartitionProof],
        keypair: &Halo2Keypair<F::Affine, Self::Circuit>,
    ) -> Result<Halo2Proof<F::Affine, Self::Circuit>, Error>;

    fn verify_partition(
        setup_params: &Self::VanillaSetupParams,
        vanilla_pub_inputs: &Self::VanillaPublicInputs,
        circ_proof: &Halo2Proof<F::Affine, Self::Circuit>,
        keypair: &Halo2Keypair<F::Affine, Self::Circuit>,
    ) -> Result<(), Error>;

    fn verify_all_partitions(
        setup_params: &Self::VanillaSetupParams,
        vanilla_pub_inputs: &Self::VanillaPublicInputs,
        circ_proofs: &[Halo2Proof<F::Affine, Self::Circuit>],
        keypair: &Halo2Keypair<F::Affine, Self::Circuit>,
    ) -> Result<(), Error>;

    fn batch_verify_all_partitions(
        setup_params: &Self::VanillaSetupParams,
        vanilla_pub_inputs: &Self::VanillaPublicInputs,
        circ_proofs: &Halo2Proof<F::Affine, Self::Circuit>,
        keypair: &Halo2Keypair<F::Affine, Self::Circuit>,
    ) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Advice, Column, ConstraintSystem, Selector},
        poly::Rotation,
    };
    use rand::rngs::OsRng;

    #[derive(Clone)]
    struct MyConfig {
        advice: [Column<Advice>; 2],
        s_add: Selector,
    }

    #[derive(Clone)]
    struct MyCircuit {
        a: Value<Fp>,
        b: Value<Fp>,
        c: Value<Fp>,
    }

    impl Circuit<Fp> for MyCircuit {
        type Config = MyConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::blank_circuit()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let advice = [meta.advice_column(), meta.advice_column()];

            let s_add = meta.selector();
            meta.create_gate("add", |meta| {
                let s = meta.query_selector(s_add);
                let a = meta.query_advice(advice[0], Rotation::cur());
                let b = meta.query_advice(advice[1], Rotation::cur());
                let c = meta.query_advice(advice[0], Rotation::next());
                [s * (a + b - c)]
            });

            MyConfig { advice, s_add }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let MyConfig { advice, s_add } = config;

            layouter.assign_region(
                || "assign witness",
                |mut region| {
                    let mut offset = 0;
                    s_add.enable(&mut region, offset)?;
                    region.assign_advice(|| "a", advice[0], offset, || self.a)?;
                    region.assign_advice(|| "b", advice[1], offset, || self.b)?;
                    offset += 1;
                    region.assign_advice(|| "c", advice[0], offset, || self.c)?;
                    Ok(())
                },
            )?;

            Ok(())
        }
    }

    impl CircuitRows for MyCircuit {
        fn id(&self) -> String {
            "mycircuit".to_string()
        }

        fn k(&self) -> u32 {
            4
        }

        fn sector_size(&self) -> usize {
            // This circuit is independent of the sector size, hence it returns 0.
            0
        }
    }

    impl MyCircuit {
        fn blank_circuit() -> Self {
            MyCircuit {
                a: Value::unknown(),
                b: Value::unknown(),
                c: Value::unknown(),
            }
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_halo2_prove_verify() {
        let blank_circuit = MyCircuit::blank_circuit();
        let keypair = Halo2Keypair::<<Fp as Halo2Field>::Affine, _>::create(&blank_circuit)
            .expect("failed to create halo2 keypair");

        // Generate and verify a single proof.
        let circ = MyCircuit {
            a: Value::known(Fp::one()),
            b: Value::known(Fp::from(2)),
            c: Value::known(Fp::from(3)),
        };
        let prover = MockProver::run(circ.k(), &circ, vec![]).unwrap();
        assert!(prover.verify().is_ok());
        let proof = create_proof(&keypair, circ.clone(), &[], &mut OsRng)
            .expect("failed to create halo2 proof");
        verify_proof(&keypair, &proof, &[]).expect("failed to verify halo2 proof");

        // Generate and verify a 2-proof batch proof.
        let circs = [
            circ,
            MyCircuit {
                a: Value::known(Fp::from(55)),
                b: Value::known(Fp::from(100)),
                c: Value::known(Fp::from(155)),
            },
        ];
        let batch_proof = create_batch_proof(&keypair, &circs, &[vec![], vec![]], &mut OsRng)
            .expect("failed to create halo2 batch proof");
        assert!(verify_batch_proof(
            &keypair,
            &batch_proof,
            &[vec![], vec![]]
        ));
    }
}
