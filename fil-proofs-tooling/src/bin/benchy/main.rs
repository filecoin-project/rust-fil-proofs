use std::io::{stdin, stdout};

use anyhow::Result;
use clap::{value_t, App, Arg, SubCommand};

use crate::flarp::FlarpInputs;

mod election_post;
mod flarp;
mod hash_fns;
mod merkleproofs;
mod shared;
mod stacked;

fn main() -> Result<()> {
    fil_logger::init();

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

    let election_post_cmd = SubCommand::with_name("election-post")
        .about("Benchmark Election PoST")
        .arg(
            Arg::with_name("size")
                .long("size")
                .required(true)
                .help("The data size in KiB")
                .takes_value(true),
        );

    let hash_cmd = SubCommand::with_name("hash-constraints")
        .about("Benchmark hash function inside of a circuit");

    let flarp_cmd = SubCommand::with_name("flarp")
        .about("Benchmark flarpy")
        .arg(
            Arg::with_name("config")
                .long("config")
                .takes_value(true)
                .required(false)
                .help("path to config.json"),
        )
        .arg(
            Arg::with_name("skip-seal-proof")
                .long("skip-seal-proof")
                .takes_value(false)
                .help("skip generation (and verification) of seal proof"),
        )
        .arg(
            Arg::with_name("skip-post-proof")
                .long("skip-post-proof")
                .takes_value(false)
                .help("skip generation (and verification) of PoSt proof"),
        )
        .arg(
            Arg::with_name("only-replicate")
                .long("only-replicate")
                .takes_value(false)
                .help("only run replication"),
        )
        .arg(
            Arg::with_name("only-add-piece")
                .long("only-add-piece")
                .takes_value(false)
                .help("only run piece addition"),
        );

    let merkleproof_cmd = SubCommand::with_name("merkleproofs")
        .about("Benchmark merkle proof generation")
        .arg(
            Arg::with_name("size")
                .long("size")
                .required(true)
                .help("The size of the data underlying the tree KiB")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("arity")
                .long("arity")
                .required(false)
                .default_value("2")
                .help("The arity of the merkletree")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("proofs")
                .long("proofs")
                .required(true)
                .help("How many proofs to generate")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("validate")
                .long("validate")
                .required(false)
                .default_value("false")
                .help("Validate proofs if specified")
                .takes_value(false),
        );

    let matches = App::new("benchy")
        .version("0.1")
        .subcommand(stacked_cmd)
        .subcommand(election_post_cmd)
        .subcommand(hash_cmd)
        .subcommand(flarp_cmd)
        .subcommand(merkleproof_cmd)
        .get_matches();

    match matches.subcommand() {
        ("stacked", Some(m)) => {
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
            })?;
        }
        ("election-post", Some(m)) => {
            let sector_size_kibs = value_t!(m, "size", usize)
                .expect("could not convert `size` CLI argument to `usize`");
            let sector_size = sector_size_kibs * 1024;
            election_post::run(sector_size)?;
        }
        ("hash-constraints", Some(_m)) => {
            hash_fns::run()?;
        }
        ("merkleproofs", Some(m)) => {
            let size_kibs = value_t!(m, "size", usize)?;
            let size = size_kibs * 1024;

            let proofs = value_t!(m, "proofs", usize)?;
            let arity = value_t!(m, "arity", usize)?;
            merkleproofs::run(size, proofs, arity, m.is_present("validate"))?;
        }
        ("flarp", Some(m)) => {
            let inputs: FlarpInputs = if m.is_present("config") {
                let file = value_t!(m, "config", String).unwrap();
                serde_json::from_reader(
                    std::fs::File::open(&file)
                        .unwrap_or_else(|_| panic!("invalid file {:?}", file)),
                )
            } else {
                serde_json::from_reader(stdin())
            }
            .expect("failed to deserialize stdin to FlarpInputs");

            let outputs = flarp::run(
                inputs,
                m.is_present("skip-seal-proof"),
                m.is_present("skip-post-proof"),
                m.is_present("only-replicate"),
                m.is_present("only-add-piece"),
            );

            serde_json::to_writer(stdout(), &outputs)
                .expect("failed to write FlarpOutput to stdout")
        }
        _ => panic!("carnation"),
    }

    Ok(())
}
