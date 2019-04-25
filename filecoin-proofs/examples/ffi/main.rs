#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

extern crate ffi_toolkit;
extern crate libc;
extern crate rand;
extern crate tempfile;
#[macro_use(defer)]
extern crate scopeguard;
extern crate sector_base;

include!(concat!(env!("OUT_DIR"), "/libfilecoin_proofs.rs"));

use byteorder::{LittleEndian, WriteBytesExt};
use ffi_toolkit::c_str_to_rust_str;
use ffi_toolkit::free_c_str;
use ffi_toolkit::rust_str_to_c_str;
use filecoin_proofs::error::ExpectWithBacktrace;
use rand::{thread_rng, Rng};
use std::env;
use std::error::Error;
use std::io::Write;
use std::ptr;
use std::slice::from_raw_parts;
use std::sync::atomic::AtomicPtr;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;
use tempfile::TempDir;

///////////////////////////////////////////////////////////////////////////////
// SectorBuilder lifecycle test
///////////////////////////////

fn u64_to_fr_safe(sector_id: u64) -> [u8; 31] {
    let mut byte_vector = vec![];
    byte_vector.write_u64::<LittleEndian>(sector_id).unwrap();
    byte_vector.resize(31, 0);

    let mut byte_array = [0; 31];
    let bytes = &byte_vector[..byte_array.len()]; // panics if not enough data
    byte_array.copy_from_slice(bytes);

    byte_array
}

fn make_piece(num_bytes_in_piece: usize) -> (String, Vec<u8>) {
    let mut rng = thread_rng();
    let bytes = (0..num_bytes_in_piece).map(|_| rng.gen()).collect();
    let key = (0..16)
        .map(|_| (0x20u8 + (rand::random::<f32>() * 96.0) as u8) as char)
        .collect();
    (key, bytes)
}

unsafe fn create_and_add_piece(
    sector_builder: *mut SectorBuilder,
    num_bytes_in_piece: usize,
) -> (Vec<u8>, String, *mut AddPieceResponse) {
    let (piece_key, piece_bytes) = make_piece(num_bytes_in_piece);

    let c_piece_key = rust_str_to_c_str(piece_key.clone());
    defer!(free_c_str(c_piece_key));

    // write piece bytes to a temporary file
    let mut file = NamedTempFile::new().expects("could not create named temp file");
    let p = file.path().to_string_lossy().to_string();
    let _ = file.write_all(&piece_bytes);
    let c_piece_path = rust_str_to_c_str(p);
    defer!(free_c_str(c_piece_path));

    (
        piece_bytes.clone(),
        piece_key.clone(),
        add_piece(
            sector_builder,
            c_piece_key,
            piece_bytes.len() as u64,
            c_piece_path,
        ),
    )
}

unsafe fn create_sector_builder(
    metadata_dir: &TempDir,
    staging_dir: &TempDir,
    sealed_dir: &TempDir,
    prover_id: [u8; 31],
    last_committed_sector_id: u64,
    sector_class: FFISectorClass,
) -> (*mut SectorBuilder, usize) {
    let mut prover_id: [u8; 31] = prover_id;

    let c_metadata_dir = rust_str_to_c_str(metadata_dir.path().to_str().unwrap());
    let c_sealed_dir = rust_str_to_c_str(sealed_dir.path().to_str().unwrap());
    let c_staging_dir = rust_str_to_c_str(staging_dir.path().to_str().unwrap());

    defer!({
        free_c_str(c_metadata_dir);
        free_c_str(c_sealed_dir);
        free_c_str(c_staging_dir);
    });

    let resp = init_sector_builder(
        sector_class,
        last_committed_sector_id,
        c_metadata_dir,
        &mut prover_id,
        c_sealed_dir,
        c_staging_dir,
        2,
    );
    defer!(destroy_init_sector_builder_response(resp));

    if (*resp).status_code != 0 {
        panic!("{}", c_str_to_rust_str((*resp).error_msg))
    }

    (
        (*resp).sector_builder,
        get_max_user_bytes_per_staged_sector(sector_class.sector_size) as usize,
    )
}

struct ConfigurableSizes {
    first_piece_bytes: usize,
    max_bytes: usize,
    second_piece_bytes: usize,
    sector_class: FFISectorClass,
    third_piece_bytes: usize,
}

unsafe fn sector_builder_lifecycle(use_live_store: bool) -> Result<(), Box<Error>> {
    let metadata_dir = tempfile::tempdir().unwrap();
    let staging_dir = tempfile::tempdir().unwrap();
    let sealed_dir = tempfile::tempdir().unwrap();

    let sizes = if use_live_store {
        ConfigurableSizes {
            sector_class: FFISectorClass {
                sector_size: 266338304,
                porep_proof_partitions: 2,
                post_proof_partitions: 1,
            },
            max_bytes: 266338304,
            first_piece_bytes: 26214400,
            second_piece_bytes: 131072000,
            third_piece_bytes: 157286400,
        }
    } else {
        ConfigurableSizes {
            sector_class: FFISectorClass {
                sector_size: 1024,
                porep_proof_partitions: 2,
                post_proof_partitions: 1,
            },
            max_bytes: 1016,
            first_piece_bytes: 100,
            second_piece_bytes: 500,
            third_piece_bytes: 600,
        }
    };

    let (sector_builder_a, max_bytes) = create_sector_builder(
        &metadata_dir,
        &staging_dir,
        &sealed_dir,
        u64_to_fr_safe(0),
        123,
        sizes.sector_class,
    );

    // TODO: Replace the hard-coded byte amounts with values computed
    // from whatever was retrieved from the SectorBuilder.
    if max_bytes != sizes.max_bytes {
        panic!(
            "test assumes the wrong number of bytes (expected: {}, actual: {})",
            sizes.max_bytes, max_bytes
        );
    }

    // verify that we have neither sealed nor staged sectors yet
    {
        let resp = get_sealed_sectors(sector_builder_a);
        defer!(destroy_get_sealed_sectors_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        assert_eq!(0, (*resp).sectors_len);

        let resp = get_staged_sectors(sector_builder_a);
        defer!(destroy_get_staged_sectors_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        assert_eq!(0, (*resp).sectors_len);
    }

    // add first piece, which lazily provisions a new staged sector
    {
        let (_, _, resp) = create_and_add_piece(sector_builder_a, sizes.first_piece_bytes);
        defer!(destroy_add_piece_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        assert_eq!(124, (*resp).sector_id);
    }

    // add second piece, which fits into existing staged sector
    {
        let (_, _, resp) = create_and_add_piece(sector_builder_a, sizes.second_piece_bytes);
        defer!(destroy_add_piece_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        assert_eq!(124, (*resp).sector_id);
    }

    // add third piece, which won't fit into existing staging sector
    {
        let (_, _, resp) = create_and_add_piece(sector_builder_a, sizes.third_piece_bytes);
        defer!(destroy_add_piece_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        // note that the sector id changed here
        assert_eq!(125, (*resp).sector_id);
    }

    // get staged sector metadata and verify that we've now got two staged
    // sectors
    {
        let resp = get_staged_sectors(sector_builder_a);
        defer!(destroy_get_staged_sectors_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        assert_eq!(2, (*resp).sectors_len);
    }

    // drop the first sector builder, relinquishing any locks on persistence
    destroy_sector_builder(sector_builder_a);

    // create a new sector builder using same prover id, which should
    // initialize with metadata persisted by previous sector builder
    let (sector_builder_b, _) = create_sector_builder(
        &metadata_dir,
        &staging_dir,
        &sealed_dir,
        u64_to_fr_safe(0),
        123,
        sizes.sector_class,
    );
    defer!(destroy_sector_builder(sector_builder_b));

    // add fourth piece, where size(piece) == max (will trigger sealing)
    let (bytes_in, piece_key) = {
        let (piece_bytes, piece_key, resp) =
            create_and_add_piece(sector_builder_b, sizes.max_bytes);
        defer!(destroy_add_piece_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        // sector id changed again (piece wouldn't fit)
        assert_eq!(126, (*resp).sector_id);

        (piece_bytes, piece_key)
    };

    // poll for sealed sector metadata through the FFI
    {
        let (result_tx, result_rx) = mpsc::channel();
        let (kill_tx, kill_rx) = mpsc::channel();

        let atomic_ptr = AtomicPtr::new(sector_builder_b);

        let _join_handle = thread::spawn(move || {
            let sector_builder = atomic_ptr.into_inner();

            loop {
                match kill_rx.try_recv() {
                    Ok(_) => return,
                    _ => (),
                };

                let resp = get_seal_status(sector_builder, 126);
                defer!(destroy_get_seal_status_response(resp));

                if (*resp).status_code != 0 {
                    return;
                }

                if (*resp).seal_status_code == FFISealStatus_Sealed {
                    let _ = result_tx.send((*resp).sector_id).unwrap();
                }

                thread::sleep(Duration::from_millis(1000));
            }
        });

        defer!({
            let _ = kill_tx.send(true).unwrap();
        });

        // wait up to 5 minutes for sealing to complete
        let now_sealed_sector_id = if use_live_store {
            result_rx.recv().unwrap()
        } else {
            result_rx.recv_timeout(Duration::from_secs(300)).unwrap()
        };

        assert_eq!(now_sealed_sector_id, 126);
    }

    // get sealed sector and verify the PoRep proof
    {
        let resp = get_seal_status(sector_builder_b, 126);

        {
            let resp2 = verify_seal(
                sizes.sector_class.sector_size,
                sizes.sector_class.porep_proof_partitions,
                &mut (*resp).comm_r,
                &mut (*resp).comm_d,
                &mut (*resp).comm_r_star,
                &mut u64_to_fr_safe(0),
                &mut u64_to_fr_safe(126),
                (*resp).proof_ptr,
                (*resp).proof_len,
            );
            defer!(destroy_verify_seal_response(resp2));

            if (*resp2).status_code != 0 {
                panic!("{}", c_str_to_rust_str((*resp2).error_msg))
            }

            assert!((*resp2).is_valid)
        }

        destroy_get_seal_status_response(resp);
    }

    // get sealed sectors - we should have just one
    {
        let resp = get_sealed_sectors(sector_builder_b);
        defer!(destroy_get_sealed_sectors_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        assert_eq!(1, (*resp).sectors_len);
    }

    // generate and then verify a proof-of-spacetime for the sealed sector
    {
        let resp = get_sealed_sectors(sector_builder_b);
        defer!(destroy_get_sealed_sectors_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        let sealed_sector_metadata: FFISealedSectorMetadata =
            from_raw_parts((*resp).sectors_ptr, (*resp).sectors_len)[0];
        let sealed_sector_replica_commitment: [u8; 32] = sealed_sector_metadata.comm_r;
        // FIXME: for some reason bindgen generates *mut instead of *const.
        let mut challenge_seed: [u8; 32] = [0; 32];

        let resp = generate_post(
            sector_builder_b,
            &sealed_sector_replica_commitment[0],
            32,
            &mut challenge_seed,
        );
        defer!(destroy_generate_post_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        let resp = verify_post(
            sizes.sector_class.sector_size,
            sizes.sector_class.post_proof_partitions,
            &sealed_sector_replica_commitment[0],
            32,
            &mut challenge_seed,
            (*resp).flattened_proofs_ptr,
            (*resp).flattened_proofs_len,
            (*resp).faults_ptr,
            (*resp).faults_len,
        );
        defer!(destroy_verify_post_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        assert!((*resp).is_valid)
    }

    // after sealing, read the bytes (causes unseal) and compare with what we
    // added to the sector
    {
        let c_piece_key = rust_str_to_c_str(piece_key);
        defer!(free_c_str(c_piece_key));

        let resp = read_piece_from_sealed_sector(sector_builder_b, c_piece_key);
        defer!(destroy_read_piece_from_sealed_sector_response(resp));

        if (*resp).status_code != 0 {
            panic!("{}", c_str_to_rust_str((*resp).error_msg))
        }

        let data_ptr = (*resp).data_ptr as *mut u8;
        let data_len = (*resp).data_len;
        let mut bytes_out = Vec::with_capacity(data_len);
        bytes_out.set_len(data_len);
        ptr::copy(data_ptr, bytes_out.as_mut_ptr(), data_len);

        assert_eq!(format!("{:x?}", bytes_in), format!("{:x?}", bytes_out))
    }

    Ok(())
}

fn main() {
    // If TEST_LIVE_SEAL is set, use the Live configuration, and don't unseal
    // — so process running time will closely approximate sealing time.
    let use_live_store = match env::var("TEST_LIVE_SEAL") {
        Ok(_) => true,
        Err(_) => false,
    };

    unsafe { sector_builder_lifecycle(use_live_store).unwrap() };
}
