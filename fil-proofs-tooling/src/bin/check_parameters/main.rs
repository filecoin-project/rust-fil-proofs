use std::path::Path;

use anyhow::Result;
use clap::{Arg, Command};

use storage_proofs_core::parameter_cache::{read_cached_params, Bls12GrothParams};

fn run_map(parameter_file: &Path) -> Result<Bls12GrothParams> {
    read_cached_params(parameter_file)
}

fn main() {
    fil_logger::init();

    let map_cmd = Command::new("map").about("build mapped parameters").arg(
        Arg::new("param")
            .long("parameter-file")
            .help("The parameter file to map")
            .required(true)
            .takes_value(true),
    );

    let matches = Command::new("check_parameters")
        .version("0.1")
        .subcommand(map_cmd)
        .get_matches();

    match matches.subcommand() {
        Some(("map", m)) => {
            let parameter_file_str = m.value_of_t::<String>("param").expect("param failed");
            run_map(Path::new(&parameter_file_str)).expect("run_map failed");
        }
        _ => panic!("Unrecognized subcommand"),
    }
}
