//requires nightly, or later stable version
//#![warn(clippy::unwrap_used)]

use std::str::FromStr;

use anyhow::Result;
use byte_unit::Byte;
use clap::{builder::PossibleValuesParser, value_parser, Arg, ArgAction, ArgMatches, Command};

use storage_proofs_core::api_version::{ApiFeature, ApiVersion};

mod hash_fns;
mod merkleproofs;
mod porep;
mod window_post;
mod window_post_fake;
mod winning_post;

const API_FEATURES: [&str; 2] = ["synthetic-porep", "non-interactive-porep"];

fn value<'a>(m: &'a ArgMatches, id: &str) -> &'a str {
    m.get_one::<String>(id)
        .expect("required or defaulted argument")
}

fn parse_api_features(m: &ArgMatches) -> Result<Vec<ApiFeature>> {
    match m.get_many::<String>("api_features") {
        Some(api_features) => api_features
            .map(|api_feature| ApiFeature::from_str(api_feature))
            .collect::<Result<_, _>>(),
        None => Ok(Vec::new()),
    }
}

fn main() -> Result<()> {
    fil_logger::init();

    let window_post_cmd = Command::new("window-post")
        .about("Benchmark Window PoST")
        .arg(
            Arg::new("preserve-cache")
                .long("preserve-cache")
                .required(false)
                .help("Preserve the directory where cached files are persisted")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("skip-precommit-phase1")
                .long("skip-precommit-phase1")
                .required(false)
                .help("Skip precommit phase 1")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("skip-precommit-phase2")
                .long("skip-precommit-phase2")
                .required(false)
                .help("Skip precommit phase 2")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("skip-commit-phase1")
                .long("skip-commit-phase1")
                .required(false)
                .help("Skip commit phase 1")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("skip-commit-phase2")
                .long("skip-commit-phase2")
                .required(false)
                .help("Skip commit phase 2")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("test-resume")
                .long("test-resume")
                .required(false)
                .help("Test replication resume")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("cache")
                .long("cache")
                .required(false)
                .help("The directory where cached files are persisted")
                .default_value(""),
        )
        .arg(
            Arg::new("size")
                .long("size")
                .required(true)
                .help("The data size (e.g. 2KiB)"),
        )
        .arg(
            Arg::new("task_numbers")
                .long("task-numbers")
                .required(false)
                .help("The window-post parallels task numbers")
                .value_parser(value_parser!(usize))
                .default_value("1"),
        )
        .arg(
            Arg::new("api_features")
                .long("api-features")
                .value_delimiter(',')
                .value_parser(PossibleValuesParser::new(API_FEATURES))
                .help("The api_features to use, comma separated (e.g. synthetic-porep)"),
        )
        .arg(
            Arg::new("api_version")
                .long("api-version")
                .help("The api_version to use (default: 1.2.0)")
                .default_value("1.2.0"),
        );

    let winning_post_cmd = Command::new("winning-post")
        .about("Benchmark Winning PoST")
        .arg(
            Arg::new("size")
                .long("size")
                .required(true)
                .help("The data size (e.g. 2KiB)"),
        )
        .arg(
            Arg::new("fake")
                .long("fake")
                .help("Use fake replica (default: false)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("api_features")
                .long("api-features")
                .value_delimiter(',')
                .value_parser(PossibleValuesParser::new(API_FEATURES))
                .help("The api_features to use, comma separated (e.g. synthetic-porep)"),
        )
        .arg(
            Arg::new("api_version")
                .long("api-version")
                .help("The api_version to use (default: 1.2.0)")
                .default_value("1.2.0"),
        );

    let window_post_fake_cmd = Command::new("window-post-fake")
        .about("Benchmark Window PoST Fake")
        .arg(
            Arg::new("size")
                .long("size")
                .required(true)
                .help("The data size (e.g. 2KiB)"),
        )
        .arg(
            Arg::new("fake")
                .long("fake")
                .help("Use fake replica (default: false)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("api_features")
                .long("api-features")
                .value_delimiter(',')
                .value_parser(PossibleValuesParser::new(API_FEATURES))
                .help("The api_features to use, comma separated (e.g. synthetic-porep)"),
        )
        .arg(
            Arg::new("api_version")
                .long("api-version")
                .help("The api_version to use (default: 1.2.0)")
                .default_value("1.2.0"),
        );

    let hash_cmd =
        Command::new("hash-constraints").about("Benchmark hash function inside of a circuit");

    let porep_cmd = Command::new("porep")
        .about("Benchmark PoRep")
        .arg(
            Arg::new("preserve-cache")
                .long("preserve-cache")
                .required(false)
                .help("Preserve the directory where cached files are persisted")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("skip-precommit-phase1")
                .long("skip-precommit-phase1")
                .required(false)
                .help("Skip precommit phase 1")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("skip-precommit-phase2")
                .long("skip-precommit-phase2")
                .required(false)
                .help("Skip precommit phase 2")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("skip-commit-phase1")
                .long("skip-commit-phase1")
                .required(false)
                .help("Skip commit phase 1")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("skip-commit-phase2")
                .long("skip-commit-phase2")
                .required(false)
                .help("Skip commit phase 2")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("test-resume")
                .long("test-resume")
                .required(false)
                .help("Test replication resume")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("cache")
                .long("cache")
                .required(false)
                .help("The directory where cached files are persisted")
                .default_value(""),
        )
        .arg(
            Arg::new("size")
                .long("size")
                .required(true)
                .help("The data size (e.g. 2KiB)"),
        )
        .arg(
            Arg::new("task_numbers")
                .long("task-numbers")
                .required(false)
                .help("The window-post parallels task numbers")
                .value_parser(value_parser!(usize))
                .default_value("1"),
        )
        .arg(
            Arg::new("api_features")
                .long("api-features")
                .value_delimiter(',')
                .value_parser(PossibleValuesParser::new(API_FEATURES))
                .help("The api_features to use, comma separated (e.g. synthetic-porep)"),
        )
        .arg(
            Arg::new("api_version")
                .long("api-version")
                .help("The api_version to use (default: 1.2.0)")
                .default_value("1.2.0"),
        );

    let merkleproof_cmd = Command::new("merkleproofs")
        .about("Benchmark merkle proof generation")
        .arg(
            Arg::new("size")
                .long("size")
                .required(true)
                .help("The data size (e.g. 2KiB)"),
        )
        .arg(
            Arg::new("proofs")
                .long("proofs")
                .value_parser(value_parser!(usize))
                .default_value("1024")
                .required(false)
                .help("How many proofs to generate (default is 1024)"),
        )
        .arg(
            Arg::new("validate")
                .long("validate")
                .required(false)
                .default_value("true")
                .help("Validate proofs if specified")
                .action(ArgAction::SetTrue),
        );

    let matches = Command::new("benchy")
        .version("0.1")
        .arg_required_else_help(true)
        .subcommand(window_post_cmd)
        .subcommand(window_post_fake_cmd)
        .subcommand(winning_post_cmd)
        .subcommand(hash_cmd)
        .subcommand(porep_cmd)
        .subcommand(merkleproof_cmd)
        .get_matches();

    match matches.subcommand() {
        Some(("window-post", m)) => {
            let preserve_cache = m.get_flag("preserve-cache");
            // For now these options are combined.
            let skip_precommit_phase1 = m.get_flag("skip-precommit-phase1");
            let skip_precommit_phase2 = m.get_flag("skip-precommit-phase2");
            let skip_commit_phase1 = m.get_flag("skip-commit-phase1");
            let skip_commit_phase2 = m.get_flag("skip-commit-phase2");
            let test_resume = m.get_flag("test-resume");
            let cache_dir = value(m, "cache").to_owned();
            let sector_size = Byte::from_str(value(m, "size"))?.get_bytes() as usize;
            let api_version = ApiVersion::from_str(value(m, "api_version"))?;
            let api_features = parse_api_features(m)?;
            let task_numbers = *m
                .get_one::<usize>("task_numbers")
                .expect("defaulted argument");

            if task_numbers == 1 {
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
                    api_features,
                )?;
            } else {
                let cache_dir: Vec<&str> = cache_dir.split(',').collect();
                if cache_dir.len() != task_numbers {
                    panic!("cache_dir.len() != task_numbers");
                }
                let mut children = Vec::new();
                for dir in cache_dir.iter().take(task_numbers) {
                    let task_dir = String::from(*dir);
                    let api_features_clone = api_features.clone();
                    let t = std::thread::spawn(move || {
                        window_post::run(
                            sector_size,
                            api_version,
                            task_dir,
                            preserve_cache,
                            skip_precommit_phase1,
                            skip_precommit_phase2,
                            skip_commit_phase1,
                            skip_commit_phase2,
                            test_resume,
                            api_features_clone,
                        )
                        .expect("window_post run error");
                    });
                    children.push(t);
                }

                for child in children {
                    child.join().expect("oops! the child thread panicked");
                }
            }
        }
        Some(("winning-post", m)) => {
            let sector_size = Byte::from_str(value(m, "size"))?.get_bytes() as usize;
            let fake_replica = m.get_flag("fake");
            let api_version = ApiVersion::from_str(value(m, "api_version"))?;
            let api_features = parse_api_features(m)?;
            winning_post::run(sector_size, fake_replica, api_version, api_features)?;
        }
        Some(("window-post-fake", m)) => {
            let sector_size = Byte::from_str(value(m, "size"))?.get_bytes() as usize;
            let fake_replica = m.get_flag("fake");
            let api_version = ApiVersion::from_str(value(m, "api_version"))?;
            let api_features = parse_api_features(m)?;
            window_post_fake::run(sector_size, fake_replica, api_version, api_features)?;
        }
        Some(("hash-constraints", _m)) => {
            hash_fns::run()?;
        }
        Some(("merkleproofs", m)) => {
            let size = Byte::from_str(value(m, "size"))?.get_bytes() as usize;

            let proofs = *m.get_one::<usize>("proofs").expect("defaulted argument");
            merkleproofs::run(size, proofs, m.get_flag("validate"))?;
        }
        Some(("porep", m)) => {
            let preserve_cache = m.get_flag("preserve-cache");
            // For now these options are combined.
            let skip_precommit_phase1 = m.get_flag("skip-precommit-phase1");
            let skip_precommit_phase2 = m.get_flag("skip-precommit-phase2");
            let skip_commit_phase1 = m.get_flag("skip-commit-phase1");
            let skip_commit_phase2 = m.get_flag("skip-commit-phase2");
            let test_resume = m.get_flag("test-resume");
            let cache_dir = value(m, "cache").to_owned();
            let sector_size = Byte::from_str(value(m, "size"))?.get_bytes() as usize;
            let api_version = ApiVersion::from_str(value(m, "api_version"))?;
            let api_features = parse_api_features(m)?;

            porep::run(
                sector_size,
                api_version,
                api_features,
                cache_dir,
                preserve_cache,
                skip_precommit_phase1,
                skip_precommit_phase2,
                skip_commit_phase1,
                skip_commit_phase2,
                test_resume,
            )?;
        }
        _ => unreachable!(),
    }

    Ok(())
}
