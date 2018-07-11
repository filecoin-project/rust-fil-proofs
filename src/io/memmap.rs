use error::Result;
use memmap::MmapMut;
use porep::PoRep;
use std::cell::RefCell;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

fn open_existing(path: &PathBuf) -> Result<MmapMut> {
    let file = OpenOptions::new().read(true).write(true).open(&path)?;

    let res = unsafe { MmapMut::map_mut(&file)? };
    Ok(res)
}

fn open_empty(path: &PathBuf, len: u64) -> Result<MmapMut> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&path)?;
    file.set_len(len)?;

    let res = unsafe { MmapMut::map_mut(&file)? };
    Ok(res)
}

pub struct MemmapWriter<'a, T: PoRep<'a>> {
    public_params: T::PublicParams,
    master: RefCell<MmapMut>,
    prover_id: &'a [u8],
}

impl<'a, T> MemmapWriter<'a, T>
where
    T: PoRep<'a>,
{
    pub fn new(
        setup_params: &T::SetupParams,
        data_path: &PathBuf,
        prover_id: &'a [u8],
    ) -> Result<MemmapWriter<'a, T>> {
        let public_params = T::setup(setup_params)?;
        let master = open_existing(&data_path)?;

        Ok(MemmapWriter {
            public_params,
            master: RefCell::new(master),
            prover_id,
        })
    }

    pub fn replicate<'b: 'a>(&'b self, len: usize) -> Result<(T::Tau, T::ProverAux)> {
        let res = {
            let mut master = self.master.borrow_mut();
            let data = master.get_mut(0..len).unwrap();
            T::replicate(&self.public_params, self.prover_id, data)?
        };

        self.master.borrow().flush()?;

        Ok(res)
    }

    pub fn extract_all<'b: 'a>(&'b self, out_path: &PathBuf, len: usize) -> Result<()> {
        let decoded = {
            let mut master = self.master.borrow_mut();
            let data = master.get(0..len).unwrap();
            T::extract_all(&self.public_params, self.prover_id, data)?
        };

        {
            let mut out = open_empty(out_path, self.master.borrow().len() as u64)?;

            (&mut out[..]).write_all(decoded.as_slice())?;
            out.flush()?;
        }
        Ok(())
    }

    pub fn prove(
        &self,
        public_inputs: &T::PublicInputs,
        private_inputs: &T::PrivateInputs,
    ) -> Result<T::Proof> {
        T::prove(&self.public_params, public_inputs, private_inputs)
    }

    pub fn verify(&self, public_inputs: &T::PublicInputs, proof: &T::Proof) -> Result<bool> {
        T::verify(&self.public_params, public_inputs, proof)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use drgporep::{DrgParams, DrgPoRep, SetupParams};
    use drgraph::BucketGraph;
    use fr32::fr_into_bytes;
    use pairing::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use std::fs::File;
    use std::io::{Read, Write};
    use tempfile;

    #[test]
    fn test_writer() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let lambda = 32;
        let prover_id: Vec<u8> = fr_into_bytes::<Bls12>(&rng.gen());
        let data: Vec<u8> = (0..32)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let dir = tempfile::tempdir().unwrap();
        let data_path = dir.path().join("data01");
        let out_path = dir.path().join("out01");

        {
            let mut file = File::create(&data_path).unwrap();
            file.write_all(&data).unwrap();
        }

        let setup = SetupParams {
            lambda: lambda,
            drg: DrgParams {
                nodes: data.len() / lambda,
                m: 10,
            },
        };

        let writer: MemmapWriter<DrgPoRep<BucketGraph>> =
            MemmapWriter::new(&setup, &data_path, &prover_id).unwrap();

        writer.replicate(data.len()).unwrap();
        writer.extract_all(&out_path, data.len()).unwrap();

        let mut out_file = File::open(&out_path).unwrap();
        let mut out = Vec::new();
        out_file.read_to_end(&mut out).unwrap();
        assert_eq!(data.to_vec(), out);
    }
}
