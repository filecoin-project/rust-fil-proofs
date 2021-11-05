use std::path::Path;

use anyhow::Result;
use bellperson::bls::Bls12;
use bellperson::groth16::MappedParameters;
use clap::{value_t, App, Arg, SubCommand};

use storage_proofs_core::parameter_cache::read_cached_params;

fn run_map(parameter_file: &Path) -> Result<MappedParameters<Bls12>> {
    read_cached_params(&parameter_file.to_path_buf())
}

fn main() {
    fil_logger::init();

    let map_cmd = SubCommand::with_name("map")
        .about("build mapped parameters")
        .arg(
            Arg::with_name("param")
                .long("parameter-file")
                .help("The parameter file to map")
                .required(true)
                .takes_value(true),
        );

    let matches = App::new("check_parameters")
        .version("0.1")
        .subcommand(map_cmd)
        .get_matches();

    match matches.subcommand() {
        ("map", Some(m)) => {
            let parameter_file_str = value_t!(m, "param", String).expect("param failed");
            run_map(&Path::new(&parameter_file_str)).expect("run_map failed");
        }
        _ => panic!("Unrecognized subcommand"),
    }
}
