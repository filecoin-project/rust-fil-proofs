use num_bigint::BigUint;
use num_integer::Integer;

lazy_static! {
    static ref SACRED_P: BigUint = BigUint::parse_bytes(
        b"52435875175126190479447740508185965837690552500527637822603658699938581184513",
        10
    ).unwrap();
}
fn pack(p: &BigUint, bits: u32) -> u32 {
    unimplemented!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack() {
        //assert!(false);
        pack(&SACRED_P, 12345);
    }
}
