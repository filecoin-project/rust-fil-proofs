use bellperson::groth16;

use crate::error::Result;
use anyhow::Context;
use paired::Engine;
use std::io::{self, Read, Write};

pub struct MultiProof<'a, E: Engine> {
    pub circuit_proofs: Vec<groth16::Proof<E>>,
    pub verifying_key: &'a groth16::VerifyingKey<E>,
}

impl<'a, E: Engine> MultiProof<'a, E> {
    pub fn new(
        groth_proofs: Vec<groth16::Proof<E>>,
        verifying_key: &'a groth16::VerifyingKey<E>,
    ) -> Self {
        MultiProof {
            circuit_proofs: groth_proofs,
            verifying_key,
        }
    }

    pub fn new_from_reader<R: Read>(
        partitions: Option<usize>,
        mut reader: R,
        verifying_key: &'a groth16::VerifyingKey<E>,
    ) -> Result<Self> {
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

    pub fn to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.write(&mut out).context("known allocation target")?;
        Ok(out)
    }

    pub fn len(&self) -> usize {
        self.circuit_proofs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.circuit_proofs.is_empty()
    }
}
