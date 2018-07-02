use crypto;
use fr32::{bytes_into_fr, fr_into_bytes};
use pairing::bls12_381::{Bls12, Fr};
use pairing::{BitIterator, PrimeField};
use rand::Rng;
use sapling_crypto::pedersen_hash;
use util::{bits_to_bytes, bytes_into_bits};

#[macro_export]
macro_rules! table_tests {
    ($property_test_func:ident {
        $( $(#[$attr:meta])* $test_name:ident( $( $param:expr ),* ); )+
    }) => {
        $(
            $(#[$attr])*
                #[test]
            fn $test_name() {
                $property_test_func($( $param ),* )
            }
        )+
    }
}

pub fn random_merkle_path<R: Rng>(
    rng: &mut R,
    tree_depth: usize,
) -> (Vec<Option<(Fr, bool)>>, Fr, Fr) {
    let auth_path: Vec<Option<(Fr, bool)>> = vec![Some((rng.gen(), rng.gen())); tree_depth];

    let value: Fr = rng.gen();

    // TODO: cleanup
    let h =
        crypto::pedersen::pedersen_compression(&bytes_into_bits(&fr_into_bytes::<Bls12>(&value)));
    let mut cur = bytes_into_fr::<Bls12>(&bits_to_bytes(&h)).unwrap();

    for (i, p) in auth_path.clone().into_iter().enumerate() {
        let (uncle, is_right) = p.unwrap();
        let mut lhs = cur;
        let mut rhs = uncle;

        if is_right {
            ::std::mem::swap(&mut lhs, &mut rhs);
        }

        let mut lhs: Vec<bool> = BitIterator::new(lhs.into_repr()).collect();
        let mut rhs: Vec<bool> = BitIterator::new(rhs.into_repr()).collect();

        lhs.reverse();
        rhs.reverse();

        cur = pedersen_hash::pedersen_hash::<Bls12, _>(
            pedersen_hash::Personalization::MerkleTree(i),
            lhs.into_iter()
                .take(Fr::NUM_BITS as usize)
                .chain(rhs.into_iter().take(Fr::NUM_BITS as usize)),
            &crypto::pedersen::JJ_PARAMS,
        ).into_xy()
            .0;
    }

    (auth_path, value, cur)
}
