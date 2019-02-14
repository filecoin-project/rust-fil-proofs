use bellman::groth16;

use crate::error::Result;
use pairing::Engine;
use std::io::{self, Read, Write};

pub struct MultiProof<E: Engine> {
    pub circuit_proofs: Vec<groth16::Proof<E>>,
    pub verifying_key: groth16::VerifyingKey<E>,
}

impl<E: Engine> MultiProof<E> {
    pub fn new(
        groth_proofs: Vec<groth16::Proof<E>>,
        verifying_key: groth16::VerifyingKey<E>,
    ) -> MultiProof<E> {
        MultiProof {
            circuit_proofs: groth_proofs,
            verifying_key,
        }
    }

    pub fn new_from_reader<R: Read>(
        partitions: Option<usize>,
        mut reader: R,
        verifying_key: groth16::VerifyingKey<E>,
    ) -> Result<MultiProof<E>> {
        let num_proofs = match partitions {
            Some(n) => n,
            None => 1,
        };
        let proofs = (0..num_proofs)
            .map(|_| groth16::Proof::read(&mut reader))
            .collect::<io::Result<Vec<_>>>()?;

        Ok(Self::new(proofs, verifying_key))
    }

    pub fn write<W: Write>(&self, mut writer: W) -> Result<()> {
        for proof in &self.circuit_proofs {
            proof.write(&mut writer)?
        }
        Ok(())
    }
}
