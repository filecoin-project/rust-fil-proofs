//requires nightly, or later stable version
//#![warn(clippy::unwrap_used)]

use std::io::{stdin, stdout};
use std::str::FromStr;

use anyhow::Result;
use byte_unit::Byte;
use clap::{Arg, Command};

use storage_proofs_core::api_version::ApiVersion;

use crate::prodbench::ProdbenchInputs;

mod hash_fns;
mod merkleproofs;
mod prodbench;
mod window_post;
mod window_post_fake;
mod winning_post;

fn main() -> Result<()> {
    fil_logger::init();

    let window_post_cmd = Command::new("window-post")
        .about("Benchmark Window PoST")
        .arg(
            Arg::new("preserve-cache")
                .long("preserve-cache")
                .required(false)
                .help("Preserve the directory where cached files are persisted")
                .takes_value(false),
        )
        .arg(
            Arg::new("skip-precommit-phase1")
                .long("skip-precommit-phase1")
                .required(false)
                .help("Skip precommit phase 1")
                .takes_value(false),
        )
        .arg(
            Arg::new("skip-precommit-phase2")
                .long("skip-precommit-phase2")
                .required(false)
                .help("Skip precommit phase 2")
                .takes_value(false),
        )
        .arg(
            Arg::new("skip-commit-phase1")
                .long("skip-commit-phase1")
                .required(false)
                .help("Skip commit phase 1")
                .takes_value(false),
        )
        .arg(
            Arg::new("skip-commit-phase2")
                .long("skip-commit-phase2")
                .required(false)
                .help("Skip commit phase 2")
                .takes_value(false),
        )
        .arg(
            Arg::new("test-resume")
                .long("test-resume")
                .required(false)
                .help("Test replication resume")
                .takes_value(false),
        )
        .arg(
            Arg::new("cache")
                .long("cache")
                .required(false)
                .help("The directory where cached files are persisted")
                .default_value("")
                .takes_value(true),
        )
        .arg(
            Arg::new("size")
                .long("size")
                .required(true)
                .help("The data size (e.g. 2KiB)")
                .takes_value(true),
        )
        .arg(
            Arg::new("api_version")
                .long("api-version")
                .help("The api_version to use (default: 1.1.0)")
                .default_value("1.1.0")
                .takes_value(true),
        );

    let winning_post_cmd = Command::new("winning-post")
        .about("Benchmark Winning PoST")
        .arg(
            Arg::new("size")
                .long("size")
                .required(true)
                .help("The data size (e.g. 2KiB)")
                .takes_value(true),
        )
        .arg(
            Arg::new("fake")
                .long("fake")
                .help("Use fake replica (default: false)")
                .takes_value(false),
        )
        .arg(
            Arg::new("api_version")
                .long("api-version")
                .help("The api_version to use (default: 1.1.0)")
                .default_value("1.1.0")
                .takes_value(true),
        );

    let window_post_fake_cmd = Command::new("window-post-fake")
        .about("Benchmark Window PoST Fake")
        .arg(
            Arg::new("size")
                .long("size")
                .required(true)
                .help("The data size (e.g. 2KiB)")
                .takes_value(true),
        )
        .arg(
            Arg::new("fake")
                .long("fake")
                .help("Use fake replica (default: false)")
                .takes_value(false),
        )
        .arg(
            Arg::new("api_version")
                .long("api-version")
                .help("The api_version to use (default: 1.1.0)")
                .default_value("1.1.0")
                .takes_value(true),
        );

    let hash_cmd =
        Command::new("hash-constraints").about("Benchmark hash function inside of a circuit");

    let prodbench_cmd = Command::new("prodbench")
        .about("Benchmark prodbench")
        .arg(
            Arg::new("config")
                .long("config")
                .takes_value(true)
                .required(false)
                .help("path to config.json"),
        )
        .arg(
            Arg::new("skip-seal-proof")
                .long("skip-seal-proof")
                .takes_value(false)
                .help("skip generation (and verification) of seal proof"),
        )
        .arg(
            Arg::new("skip-post-proof")
                .long("skip-post-proof")
                .takes_value(false)
                .help("skip generation (and verification) of PoSt proof"),
        )
        .arg(
            Arg::new("only-replicate")
                .long("only-replicate")
                .takes_value(false)
                .help("only run replication"),
        )
        .arg(
            Arg::new("only-add-piece")
                .long("only-add-piece")
                .takes_value(false)
                .help("only run piece addition"),
        );

    let merkleproof_cmd = Command::new("merkleproofs")
        .about("Benchmark merkle proof generation")
        .arg(
            Arg::new("size")
                .long("size")
                .required(true)
                .help("The data size (e.g. 2KiB)")
                .takes_value(true),
        )
        .arg(
            Arg::new("proofs")
                .long("proofs")
                .default_value("1024")
                .required(false)
                .help("How many proofs to generate (default is 1024)")
                .takes_value(true),
        )
        .arg(
            Arg::new("validate")
                .long("validate")
                .required(false)
                .default_value("true")
                .help("Validate proofs if specified")
                .takes_value(false),
        );

    let matches = Command::new("benchy")
        .version("0.1")
        .arg_required_else_help(true)
        .subcommand(window_post_cmd)
        .subcommand(window_post_fake_cmd)
        .subcommand(winning_post_cmd)
        .subcommand(hash_cmd)
        .subcommand(prodbench_cmd)
        .subcommand(merkleproof_cmd)
        .get_matches();

    match matches.subcommand() {
        Some(("window-post", m)) => {
            let preserve_cache = m.is_present("preserve-cache");
            // For now these options are combined.
            let skip_precommit_phase1 = m.is_present("skip-precommit-phase1");
            let skip_precommit_phase2 = m.is_present("skip-precommit-phase2");
            let skip_commit_phase1 = m.is_present("skip-commit-phase1");
            let skip_commit_phase2 = m.is_present("skip-commit-phase2");
            let test_resume = m.is_present("test-resume");
            let cache_dir = m.value_of_t::<String>("cache")?;
            let sector_size = Byte::from_str(m.value_of_t::<String>("size")?)?.get_bytes() as usize;
            let api_version = ApiVersion::from_str(&m.value_of_t::<String>("api_version")?)?;
            window_post::run(
                sector_size,
                api_version,
                cache_dir,
                preserve_cache,
                skip_precommit_phase1,
                skip_precommit_phase2,
                skip_commit_phase1,
                skip_commit_phase2,
                test_resume,
            )?;
        }
        Some(("winning-post", m)) => {
            let sector_size = Byte::from_str(m.value_of_t::<String>("size")?)?.get_bytes() as usize;
            let fake_replica = m.is_present("fake");
            let api_version = ApiVersion::from_str(&m.value_of_t::<String>("api_version")?)?;
            winning_post::run(sector_size, fake_replica, api_version)?;
        }
        Some(("window-post-fake", m)) => {
            let sector_size = Byte::from_str(m.value_of_t::<String>("size")?)?.get_bytes() as usize;
            let fake_replica = m.is_present("fake");
            let api_version = ApiVersion::from_str(&m.value_of_t::<String>("api_version")?)?;
            window_post_fake::run(sector_size, fake_replica, api_version)?;
        }
        Some(("hash-constraints", _m)) => {
            hash_fns::run()?;
        }
        Some(("merkleproofs", m)) => {
            let size = Byte::from_str(m.value_of_t::<String>("size")?)?.get_bytes() as usize;

            let proofs = m.value_of_t::<usize>("proofs")?;
            merkleproofs::run(size, proofs, m.is_present("validate"))?;
        }
        Some(("prodbench", m)) => {
            let inputs: ProdbenchInputs = if m.is_present("config") {
                let file = m
                    .value_of_t::<String>("config")
                    .expect("failed to get config");
                serde_json::from_reader(
                    std::fs::File::open(&file)
                        .unwrap_or_else(|_| panic!("invalid file {:?}", file)),
                )
            } else {
                serde_json::from_reader(stdin())
            }
            .expect("failed to deserialize stdin to ProdbenchInputs");

            let outputs = prodbench::run(
                inputs,
                m.is_present("skip-seal-proof"),
                m.is_present("skip-post-proof"),
                m.is_present("only-replicate"),
                m.is_present("only-add-piece"),
            );

            serde_json::to_writer(stdout(), &outputs)
                .expect("failed to write ProdbenchOutput to stdout")
        }
        _ => unreachable!(),
    }

    Ok(())
}
