use clap::{App, Arg, ArgMatches};
use filecoin_proofs::param::*;
use std::path::PathBuf;
use std::process::exit;
use storage_proofs::parameter_cache::PARAMETER_CACHE_DIR;

pub fn main() {
    let matches = App::new("paramfetch")
        .version("1.0")
        .about(
            &format!(
                "
Set $FILECOIN_PARAMETER_CACHE to specify parameter directory.
Defaults to '{}'
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
            Arg::with_name("all")
                .short("a")
                .long("all")
                .help("Download all available parameters"),
        )
        .get_matches();

    match fetch(&matches) {
        Ok(_) => println!("success"),
        Err(err) => {
            println!("fatal error: {}", err);
            exit(1);
        }
    }
}

fn fetch(matches: &ArgMatches) -> Result<()> {
    let json = PathBuf::from(matches.value_of("json").unwrap_or("./parameters.json"));
    let parameter_map = get_parameter_map(&json)?;

    let parameter_ids = if matches.is_present("all") {
        get_mapped_parameter_ids(&parameter_map)?
    } else {
        choose_from(get_mapped_parameter_ids(&parameter_map)?)?
    };

    if !parameter_ids.is_empty() {
        println!("fetching parameters");

        for parameter_id in parameter_ids {
            println!("fetching {}", parameter_id);

            if get_parameter_file_path(&parameter_id).exists() {
                println!("ok (already exists)");
            } else {
                match fetch_parameter_file(&parameter_map, &parameter_id) {
                    Ok(_) => println!("ok"),
                    Err(err) => println!("error: {}", err),
                }
            }
        }
    } else {
        println!("no parameters to fetch");
    }

    let parameter_ids = get_mapped_parameter_ids(&parameter_map)?;

    if !parameter_ids.is_empty() {
        println!("validating parameters");

        let mut all_valid = true;

        for parameter_id in get_mapped_parameter_ids(&parameter_map)? {
            println!("validating {}", parameter_id);

            match validate_parameter_file(&parameter_map, &parameter_id) {
                Ok(true) => println!("ok"),
                Ok(false) => {
                    println!("error: invalid parameter file");
                    invalidate_parameter_file(&parameter_id)?;
                    all_valid = false;
                }
                Err(err) => {
                    println!("error: {}", err);
                    all_valid = false;
                }
            }
        }

        if !all_valid {
            println!("some parameter files were invalid, you may need to run paramfetch again");
        }
    } else {
        println!("no parameters to validate");
    }

    Ok(())
}
