use bellperson::bls::Fr;
use ff::Field;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;

use storage_proofs::fr32::bytes_into_fr;
use storage_proofs::sector::SectorId;

use filecoin_proofs::as_safe_commitment;
use filecoin_proofs::constants::*;
use filecoin_proofs::types::{PoRepConfig, PoRepProofPartitions, SectorSize};
use filecoin_proofs::verify_seal;

#[test]
fn test_verify_seal_fr32_validation() {
    let convertible_to_fr_bytes = [0; 32];
    let out = bytes_into_fr(&convertible_to_fr_bytes);
    assert!(out.is_ok(), "tripwire");

    let not_convertible_to_fr_bytes = [255; 32];
    let out = bytes_into_fr(&not_convertible_to_fr_bytes);
    assert!(out.is_err(), "tripwire");

    let arbitrary_porep_id = [87; 32];
    {
        let result = verify_seal::<DefaultOctLCTree>(
            PoRepConfig {
                sector_size: SectorSize(SECTOR_SIZE_2_KIB),
                partitions: PoRepProofPartitions(
                    *POREP_PARTITIONS
                        .read()
                        .expect("POREP_PARTITIONS poisoned")
                        .get(&SECTOR_SIZE_2_KIB)
                        .expect("unknown sector size"),
                ),
                porep_id: arbitrary_porep_id,
            },
            not_convertible_to_fr_bytes,
            convertible_to_fr_bytes,
            [0; 32],
            SectorId::from(0),
            [0; 32],
            [0; 32],
            &[],
        );

        if let Err(err) = result {
            let needle = "Invalid all zero commitment";
            let haystack = format!("{}", err);

            assert!(
                haystack.contains(needle),
                format!("\"{}\" did not contain \"{}\"", haystack, needle)
            );
        } else {
            panic!("should have failed comm_r to Fr32 conversion");
        }
    }

    {
        let result = verify_seal::<DefaultOctLCTree>(
            PoRepConfig {
                sector_size: SectorSize(SECTOR_SIZE_2_KIB),
                partitions: PoRepProofPartitions(
                    *POREP_PARTITIONS
                        .read()
                        .expect("POREP_PARTITIONS poisoned")
                        .get(&SECTOR_SIZE_2_KIB)
                        .expect("unknown sector size"),
                ),
                porep_id: arbitrary_porep_id,
            },
            convertible_to_fr_bytes,
            not_convertible_to_fr_bytes,
            [0; 32],
            SectorId::from(0),
            [0; 32],
            [0; 32],
            &[],
        );

        if let Err(err) = result {
            let needle = "Invalid all zero commitment";
            let haystack = format!("{}", err);

            assert!(
                haystack.contains(needle),
                format!("\"{}\" did not contain \"{}\"", haystack, needle)
            );
        } else {
            panic!("should have failed comm_d to Fr32 conversion");
        }
    }
}

#[test]
fn test_random_domain_element() {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    for _ in 0..100 {
        let random_el: DefaultTreeDomain = Fr::random(rng).into();
        let mut randomness = [0u8; 32];
        randomness.copy_from_slice(AsRef::<[u8]>::as_ref(&random_el));
        let back: DefaultTreeDomain =
            as_safe_commitment(&randomness, "test").expect("failed to get domain from randomness");
        assert_eq!(back, random_el);
    }
}
