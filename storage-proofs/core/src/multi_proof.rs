use bellperson::groth16;

use crate::error::Result;
use anyhow::Context;
use paired::bls12_381::Bls12;
use std::io::{self, Read, Write};

pub struct MultiProof<'a> {
    pub circuit_proofs: Vec<groth16::Proof<Bls12>>,
    pub verifying_key: &'a groth16::VerifyingKey<Bls12>,
}

impl<'a> MultiProof<'a> {
    pub fn new(
        groth_proofs: Vec<groth16::Proof<Bls12>>,
        verifying_key: &'a groth16::VerifyingKey<Bls12>,
    ) -> Self {
        MultiProof {
            circuit_proofs: groth_proofs,
            verifying_key,
        }
    }

    pub fn new_from_reader<R: Read>(
        partitions: Option<usize>,
        mut reader: R,
        verifying_key: &'a groth16::VerifyingKey<Bls12>,
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
