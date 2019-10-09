#[macro_use]
extern crate serde;

use clap::{value_t, App, Arg, SubCommand};

mod hash_fns;
mod rational_post;
mod stacked;

fn main() {
    pretty_env_logger::init_timed();

    let stacked_cmd = SubCommand::with_name("stacked")
                .about("Run stacked sealing")
                .arg(
                    Arg::with_name("size")
                        .required(true)
                        .long("size")
                        .help("The data size in KB")
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
                );

    let rational_post_cmd = SubCommand::with_name("rational-post")
        .about("Benchmark Rational PoST")
        .arg(
            Arg::with_name("size")
                .long("size")
                .required(true)
                .help("The data size in KiB")
                .takes_value(true),
        );

    let hash_cmd = SubCommand::with_name("hash-constraints")
        .about("Benchmark hash function inside of a circuit");

    let matches = App::new("benchy")
        .version("0.1")
        .subcommand(stacked_cmd)
        .subcommand(rational_post_cmd)
        .subcommand(hash_cmd)
        .get_matches();

    match matches.subcommand() {
        ("stacked", Some(m)) => {
            Ok(())
                .and_then(|_| {
                    let layers = value_t!(m, "layers", usize)?;
                    stacked::run(stacked::RunOpts {
                        bench: m.is_present("bench"),
                        bench_only: m.is_present("bench-only"),
                        challenges: value_t!(m, "challenges", usize)?,
                        circuit: m.is_present("circuit"),
                        dump: m.is_present("dump"),
                        extract: m.is_present("extract"),
                        groth: m.is_present("groth"),
                        hasher: value_t!(m, "hasher", String)?,
                        layers,
                        no_bench: m.is_present("no-bench"),
                        no_tmp: m.is_present("no-tmp"),
                        partitions: value_t!(m, "partitions", usize)?,
                        size: value_t!(m, "size", usize)?,
                    })
                })
                .expect("stacked failed");
        }
        ("rational-post", Some(m)) => {
            let sector_size_kibs = value_t!(m, "size", usize)
                .expect("could not convert `size` CLI argument to `usize`");
            let sector_size = sector_size_kibs * 1024;
            rational_post::run(sector_size).expect("rational-post failed");
        }
        ("hash-constraints", Some(_m)) => {
            hash_fns::run().expect("hash-constraints failed");
        }
        _ => panic!("carnation"),
    }
}
