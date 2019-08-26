#[macro_use]
extern crate serde;

use clap::{value_t, App, Arg, SubCommand};

mod hash_fns;
mod zigzag;

fn main() {
    let zigzag_cmd = SubCommand::with_name("zigzag")
                .about("Run zigzag sealing")
                .arg(
                    Arg::with_name("size")
                        .required(true)
                        .long("size")
                        .help("The data size in KB")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("m")
                        .help("The size of m")
                        .long("m")
                        .default_value("5")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("exp")
                        .help("Expansion degree")
                        .long("expansion")
                        .default_value("8")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("challenges")
                        .long("challenges")
                        .help("How many challenges to execute")
                        .default_value("1")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("hasher")
                        .long("hasher")
                        .help("Which hasher should be used. Available: \"pedersen\", \"sha256\", \"blake2s\" (default \"pedersen\")")
                        .default_value("pedersen")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("layers")
                        .long("layers")
                        .help("How many layers to use")
                        .default_value("10")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("no-tmp")
                        .long("no-tmp")
                        .help("Don't use a temp file for random data (write to current directory instead).")
                )
                .arg(
                    Arg::with_name("dump")
                        .long("dump")
                        .help("Dump vanilla proofs to current directory.")
                )
                .arg(
                    Arg::with_name("partitions")
                        .long("partitions")
                        .help("How many circuit partitions to use")
                        .default_value("1")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("groth")
                        .long("groth")
                        .help("Generate and verify a groth circuit proof.")
                )
                .arg(
                    Arg::with_name("bench")
                        .long("bench")
                        .help("Synthesize and report inputs/constraints for a circuit.")
                )
                .arg(
                    Arg::with_name("no-bench")
                        .long("no-bench")
                        .help("Don't synthesize and report inputs/constraints for a circuit.")
                )
                .arg(
                    Arg::with_name("bench-only")
                        .long("bench-only")
                        .help("Don't replicate or perform Groth proving.")
                        .conflicts_with_all(&["no-bench", "groth", "extract"])
                )
                .arg(
                    Arg::with_name("circuit")
                        .long("circuit")
                        .help("Print the constraint system.")
                )
                .arg(
                    Arg::with_name("extract")
                        .long("extract")
                        .help("Extract data after proving and verifying.")
                )
                .arg(
                    Arg::with_name("taper")
                        .long("taper")
                        .help("fraction of challenges by which to taper at each layer")
                        .default_value("0.0")
                )
                .arg(
                    Arg::with_name("taper-layers")
                        .long("taper-layers")
                        .help("number of layers to taper")
                        .takes_value(true)
                );

    let hash_cmd = SubCommand::with_name("hash-constraints")
        .about("Benchmark hash function inside of a circuit");

    let matches = App::new("benchy")
        .version("0.1")
        .subcommand(zigzag_cmd)
        .subcommand(hash_cmd)
        .get_matches();

    match matches.subcommand() {
        ("zigzag", Some(m)) => {
            Ok(())
                .and_then(|_| {
                    let layers = value_t!(m, "layers", usize)?;

                    zigzag::run(zigzag::RunOpts {
                        bench: m.is_present("bench"),
                        bench_only: m.is_present("bench-only"),
                        challenges: value_t!(m, "challenges", usize)?,
                        circuit: m.is_present("circuit"),
                        dump: m.is_present("dump"),
                        exp: value_t!(m, "exp", usize)?,
                        extract: m.is_present("extract"),
                        groth: m.is_present("groth"),
                        hasher: value_t!(m, "hasher", String)?,
                        layers,
                        m: value_t!(m, "m", usize)?,
                        no_bench: m.is_present("no-bench"),
                        no_tmp: m.is_present("no-tmp"),
                        partitions: value_t!(m, "partitions", usize)?,
                        size: value_t!(m, "size", usize)?,
                        taper: value_t!(m, "taper", f64)?,
                        taper_layers: value_t!(m, "taper-layers", usize).unwrap_or(layers),
                    })
                })
                .expect("zigzag failed");
        }
        ("hash-constraints", Some(_m)) => {
            hash_fns::run().expect("hash-constraints failed");
        }
        _ => panic!("carnation"),
    }
}
