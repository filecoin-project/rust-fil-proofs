use std::io;
use std::io::prelude::*;
use std::iter::FromIterator;
use std::path::PathBuf;
use std::process::exit;

use clap::{values_t, App, Arg, ArgMatches};
use failure::err_msg;

use filecoin_proofs::param::*;
use itertools::Itertools;
use std::collections::HashSet;
use storage_proofs::parameter_cache::{GROTH_PARAMETER_EXT, PARAMETER_CACHE_DIR};

pub fn main() {
    let matches = App::new("paramfetch")
        .version("1.1")
        .about(
            &format!(
                "
Set $FILECOIN_PARAMETER_CACHE to specify parameter file directory.
Defaults to '{}'

Use -g,--gateway to specify ipfs gateway.
Defaults to 'https://ipfs.io'
",
                PARAMETER_CACHE_DIR
            )[..],
        )
        .arg(
            Arg::with_name("json")
                .value_name("JSON")
                .takes_value(true)
                .short("j")
                .long("json")
                .help("Use specific json file"),
        )
        .arg(
            Arg::with_name("gateway")
                .value_name("URL")
                .takes_value(true)
                .short("g")
                .long("gateway")
                .help("Use specific ipfs gateway"),
        )
        .arg(
            Arg::with_name("retry")
                .short("r")
                .long("retry")
                .help("Prompt to retry on failure"),
        )
        .arg(
            Arg::with_name("all")
                .short("a")
                .long("all")
                .conflicts_with("params-for-sector-sizes")
                .help("Download all available parameter files"),
        )
        .arg(
            Arg::with_name("params-for-sector-sizes")
                .short("z")
                .long("params-for-sector-sizes")
                .conflicts_with("all")
                .require_delimiter(true)
                .value_delimiter(",")
                .multiple(true)
                .help("A comma-separated list of sector sizes, in bytes, for which Groth parameters will be downloaded"),
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .help("Print diagnostic information to stdout"),
        )
        .get_matches();

    match fetch(&matches) {
        Ok(_) => println!("done"),
        Err(err) => {
            println!("fatal error: {}", err);
            exit(1);
        }
    }
}

fn fetch(matches: &ArgMatches) -> Result<()> {
    let json_path = PathBuf::from(matches.value_of("json").unwrap_or("./parameters.json"));
    let retry = matches.is_present("retry");
    let gateway = matches.value_of("gateway").unwrap_or("https://ipfs.io");

    if !json_path.exists() {
        return Err(err_msg(format!(
            "json file '{}' does not exist",
            &json_path.to_str().unwrap_or("")
        )));
    }

    let parameter_map = get_parameter_map(&json_path)?;
    let all_parameter_ids = get_mapped_parameter_ids(&parameter_map)?;

    println!("checking {} parameter files...", all_parameter_ids.len());
    println!();

    let mut parameter_ids = all_parameter_ids;

    if matches.is_present("params-for-sector-sizes") {
        let whitelisted_sector_sizes: Vec<u64> =
            values_t!(matches.values_of("params-for-sector-sizes"), u64)?;

        let whitelisted_sector_sizes: HashSet<u64> =
            HashSet::from_iter(whitelisted_sector_sizes.iter().cloned());

        parameter_ids = parameter_ids
            .into_iter()
            .filter(|id| {
                !has_extension(id, GROTH_PARAMETER_EXT) || {
                    parameter_map
                        .get(id)
                        .and_then(|p| p.sector_size)
                        .map(|n| whitelisted_sector_sizes.contains(&n))
                        .unwrap_or(false)
                }
            })
            .collect_vec();
    }

    parameter_ids = get_pending_parameter_ids(&parameter_map, parameter_ids)?;

    if !matches.is_present("params-for-sector-sizes")
        && !matches.is_present("all")
        && !parameter_ids.is_empty()
    {
        parameter_ids = choose_from(parameter_ids)?;
        println!();
    }

    loop {
        println!("{} parameter files to fetch...", parameter_ids.len());
        println!();

        for parameter_id in &parameter_ids {
            println!("fetching: {}", parameter_id);
            print!("downloading parameter file... ");
            io::stdout().flush().unwrap();

            match spawn_fetch_parameter_file(
                matches.is_present("verbose"),
                &parameter_map,
                &parameter_id,
                &gateway,
            ) {
                Ok(_) => println!("ok\n"),
                Err(err) => println!("error: {}\n", err),
            }
        }

        parameter_ids = get_pending_parameter_ids(&parameter_map, parameter_ids)?;

        if parameter_ids.is_empty() {
            break;
        } else {
            println!(
                "{} parameter files failed to be fetched:",
                parameter_ids.len()
            );

            for parameter_id in &parameter_ids {
                println!("{}", parameter_id);
            }

            println!();

            if !retry || !choose("try again?") {
                return Err(err_msg("some parameter files failed to be fetched. try again, or run paramcache to generate locally"));
            }
        }
    }

    Ok(())
}

fn get_pending_parameter_ids(
    parameter_map: &ParameterMap,
    parameter_ids: Vec<String>,
) -> Result<Vec<String>> {
    Ok(parameter_ids
        .into_iter()
        .filter(|parameter_id| {
            println!("checking: {}", parameter_id);
            print!("does parameter file exist... ");

            if get_parameter_file_path(parameter_id).exists() {
                println!("yes");
                print!("is parameter file valid... ");
                io::stdout().flush().unwrap();

                match validate_parameter_file(&parameter_map, &parameter_id) {
                    Ok(true) => {
                        println!("yes\n");
                        false
                    }
                    Ok(false) => {
                        println!("no\n");
                        invalidate_parameter_file(&parameter_id).unwrap();
                        true
                    }
                    Err(err) => {
                        println!("error: {}\n", err);
                        true
                    }
                }
            } else {
                println!("no\n");
                true
            }
        })
        .collect())
}
