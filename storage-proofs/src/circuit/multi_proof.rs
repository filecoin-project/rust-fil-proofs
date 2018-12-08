use bellman::groth16;

use crate::error::Result;
use pairing::Engine;
use std::io::{self, Read, Write};

pub struct MultiProof<E: Engine> {
    pub circuit_proofs: Vec<groth16::Proof<E>>,
    pub groth_params: groth16::Parameters<E>,
}

impl<E: Engine> MultiProof<E> {
    pub fn new(
        groth_proofs: Vec<groth16::Proof<E>>,
        groth_params: groth16::Parameters<E>,
    ) -> MultiProof<E> {
        MultiProof {
            circuit_proofs: groth_proofs,
            groth_params,
        }
    }

    pub fn new_from_reader<R: Read>(
        partitions: Option<usize>,
        mut reader: R,
        groth_params: groth16::Parameters<E>,
    ) -> Result<MultiProof<E>> {
        let num_proofs = match partitions {
            Some(n) => n,
            None => 1,
        };
        let proofs = (0..num_proofs)
            .map(|_| groth16::Proof::read(&mut reader))
            .collect::<io::Result<Vec<_>>>()?;

        Ok(Self::new(proofs, groth_params))
    }

    pub fn write<W: Write>(&self, mut writer: W) -> Result<()> {
        for proof in &self.circuit_proofs {
            proof.write(&mut writer)?
        }
        Ok(())
    }
}
