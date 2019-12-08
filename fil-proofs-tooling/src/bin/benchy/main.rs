use clap::{value_t, App, Arg, SubCommand};

mod election_post;
mod hash_fns;
mod stacked;

fn main() {
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
                    Arg::with_name("window-size")
                        .long("window-size")
                        .help("The window size in bytes")
                        .default_value("4096")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("wrapper-challenges")
                        .long("wrapper-challenges")
                        .help("How many wrapper challenges to execute")
                        .default_value("1")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("window-challenges")
                        .long("window-challenges")
                        .help("How many window challenges to execute")
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

    let matches = App::new("benchy")
        .version("0.1")
        .subcommand(stacked_cmd)
        .subcommand(election_post_cmd)
        .subcommand(hash_cmd)
        .get_matches();

    match matches.subcommand() {
        ("stacked", Some(m)) => {
            Ok(())
                .and_then(|_| {
                    let layers = value_t!(m, "layers", usize)?;
                    let window_size_bytes = value_t!(m, "window-size", usize)
                        .expect("could not convert `window-size` CLI argument to `usize`");
                    let window_size_nodes = window_size_bytes / 32;

                    stacked::run(stacked::RunOpts {
                        bench: m.is_present("bench"),
                        bench_only: m.is_present("bench-only"),
                        window_size_nodes,
                        window_challenges: value_t!(m, "window-challenges", usize)?,
                        wrapper_challenges: value_t!(m, "wrapper-challenges", usize)?,
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
        ("election-post", Some(m)) => {
            let sector_size_kibs = value_t!(m, "size", usize)
                .expect("could not convert `size` CLI argument to `usize`");
            let sector_size = sector_size_kibs * 1024;
            election_post::run(sector_size).expect("election-post failed");
        }
        ("hash-constraints", Some(_m)) => {
            hash_fns::run().expect("hash-constraints failed");
        }
        _ => panic!("carnation"),
    }
}
