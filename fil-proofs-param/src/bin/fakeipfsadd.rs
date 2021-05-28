use std::fs::File;
use std::io;

use blake2b_simd::State as Blake2b;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "fakeipfsadd",
    version = "0.1",
    about = "This program is used to simulate the `ipfs add` command while testing. It accepts a \
        path to a file and writes 32 characters of its hex-encoded BLAKE2b checksum to stdout. \
        Note that the real `ipfs add` command computes and emits a CID."
)]
enum Cli {
    Add {
        #[structopt(help = "Positional argument for the path to the file to add.")]
        file_path: String,
        #[structopt(short = "Q", help = "Simulates the -Q argument to `ipfs add`.")]
        quieter: bool,
    },
}

impl Cli {
    fn file_path(&self) -> &str {
        match self {
            Cli::Add { file_path, .. } => file_path,
        }
    }
}

pub fn main() {
    let cli = Cli::from_args();

    let mut src_file = File::open(cli.file_path())
        .unwrap_or_else(|_| panic!("failed to open file: {}", cli.file_path()));

    let mut hasher = Blake2b::new();
    io::copy(&mut src_file, &mut hasher).expect("failed to write BLAKE2b bytes to hasher");
    let hex_string: String = hasher.finalize().to_hex()[..32].into();
    println!("{}", hex_string)
}
