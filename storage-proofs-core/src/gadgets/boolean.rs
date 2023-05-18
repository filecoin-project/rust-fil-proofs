use bellperson::{
    gadgets::{boolean::AllocatedBit, num::AllocatedNum},
    ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::PrimeField;

pub fn assign_bits<F, CS>(
    cs: &mut CS,
    name: &str,
    value: &AllocatedNum<F>,
    bit_len: usize,
) -> Result<Vec<AllocatedBit>, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    let repr = value.get_value().unwrap_or_default().to_repr();
    let le_bytes = repr.as_ref();
    let bits = le_bytes
        .into_iter()
        .flat_map(|byte| (0..8).map(|i| byte >> i & 1 == 1).collect::<Vec<bool>>())
        .map(Some)
        .enumerate()
        .map(|(i, bit)| AllocatedBit::alloc(cs.namespace(|| format!("{} bit_{}", name, i)), bit))
        .take(bit_len)
        .collect::<Result<Vec<AllocatedBit>, SynthesisError>>()?;

    let mut lc = LinearCombination::zero();
    let mut coeff = F::one();
    for bit in &bits {
        lc = lc + (coeff, bit.get_variable());
        coeff = coeff.double();
    }

    cs.enforce(
        || format!("{} verify binary decomp", name),
        |_| lc,
        |lc| lc + CS::one(),
        |lc| lc + value.get_variable(),
    );
    Ok(bits)
}
