use bellperson::groth16;

use crate::error::Result;
use anyhow::{ensure, Context};
use bellperson::bls::Bls12;
use std::io::{Read, Write};

pub struct MultiProof<'a> {
    pub circuit_proofs: Vec<groth16::Proof<Bls12>>,
    pub verifying_key: &'a groth16::PreparedVerifyingKey<Bls12>,
}

const GROTH_PROOF_SIZE: usize = 192;

impl<'a> MultiProof<'a> {
    pub fn new(
        groth_proofs: Vec<groth16::Proof<Bls12>>,
        verifying_key: &'a groth16::PreparedVerifyingKey<Bls12>,
    ) -> Self {
        MultiProof {
            circuit_proofs: groth_proofs,
            verifying_key,
        }
    }

    pub fn new_from_reader<R: Read>(
        partitions: Option<usize>,
        mut reader: R,
        verifying_key: &'a groth16::PreparedVerifyingKey<Bls12>,
    ) -> Result<Self> {
        let num_proofs = partitions.unwrap_or(1);

        let mut proof_vec: Vec<u8> = Vec::with_capacity(num_proofs * GROTH_PROOF_SIZE);
        reader.read_to_end(&mut proof_vec)?;

        Self::new_from_bytes(partitions, &proof_vec, verifying_key)
    }

    // Parallelizing reduces deserialization time for 10 proofs from 13ms to 2ms.
    pub fn new_from_bytes(
        partitions: Option<usize>,
        proof_bytes: &[u8],
        verifying_key: &'a groth16::PreparedVerifyingKey<Bls12>,
    ) -> Result<Self> {
        let num_proofs = partitions.unwrap_or(1);

        let proofs = groth16::Proof::read_many(proof_bytes, num_proofs)?;

        ensure!(
            num_proofs == proofs.len(),
            "expected {} proofs but found only {}",
            num_proofs,
            proofs.len()
        );

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
