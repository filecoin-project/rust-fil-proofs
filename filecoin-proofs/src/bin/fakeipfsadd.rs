use blake2b_simd::State as Blake2b;
use clap::{App, Arg};
use std::fs::File;

pub fn main() {
    let matches = App::new("fakeipfsadd")
        .version("0.1")
        .about(
            "
This program is used to simulate the `ipfs add` command while testing. It
accepts a path to a file and writes 32 characters of its hex-encoded BLAKE2b 
checksum to stdout. Note: The real `ipfs add` command computes and emits a CID.
",
        )
        .arg(Arg::with_name("add").index(1).required(true))
        .arg(Arg::with_name("file-path").index(2).required(true))
        .arg(
            Arg::with_name("quieter")
                .short("Q")
                .required(true)
                .help("Simulates the -Q argument to `ipfs add`"),
        )
        .get_matches();

    let src_file_path = matches
        .value_of("file-path")
        .expect("failed to get file path");

    let mut src_file = File::open(&src_file_path)
        .unwrap_or_else(|_| panic!("failed to open file at {}", &src_file_path));

    let mut hasher = Blake2b::new();

    std::io::copy(&mut src_file, &mut hasher).expect("failed to write BLAKE2b bytes to hasher");

    let hex_string: String = hasher.finalize().to_hex()[..32].into();

    println!("{}", hex_string)
}
