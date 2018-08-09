use drgporep::{DrgParams, DrgPoRep, SetupParams};
use drgraph::{new_seed, BucketGraph};
use error::Result;
use proof::ProofScheme;

use std::fs::File;
use std::io::{copy, BufReader, BufWriter};
use std::path::PathBuf;

pub static SECTOR_BYTES: usize = 1 << 10; // For initial development, just make this 1Kb.
pub static LAMBDA: usize = 32;

// FIXME: Result will become (CommD, CommR), but for now since we still need to fake values, do that
// in the caller.
pub fn seal(in_path: &PathBuf, out_path: &PathBuf) -> Result<(u64)> {
    let setup_params = SetupParams {
        lambda: LAMBDA,
        drg: DrgParams {
            nodes: SECTOR_BYTES / LAMBDA,
            degree: 5,
            seed: new_seed(),
        },
        sloth_iter: 1,
    };

    let _pub_params = <DrgPoRep<BucketGraph> as ProofScheme>::setup(&setup_params);

    let f_in = File::open(in_path)?;
    let mut reader = BufReader::new(f_in);

    let f_out = File::create(out_path)?;
    let mut buf_writer = BufWriter::new(f_out);

    let bytes_copied = copy(&mut reader, &mut buf_writer)?;

    Ok(bytes_copied)
}
