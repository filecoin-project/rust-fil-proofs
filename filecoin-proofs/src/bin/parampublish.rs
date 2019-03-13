use clap::{App, Arg, ArgMatches};
use filecoin_proofs::param::*;
use std::collections::HashMap;
use std::io;
use std::io::prelude::*;
use std::path::PathBuf;
use std::process::exit;
use storage_proofs::parameter_cache::PARAMETER_CACHE_DIR;

pub fn main() {
    let matches = App::new("parampublish")
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
                .help("Publish all local parameters"),
        )
        .get_matches();

    match publish(&matches) {
        Ok(_) => println!("done"),
        Err(err) => {
            println!("fatal error: {}", err);
            exit(1);
        }
    }
}

fn publish(matches: &ArgMatches) -> Result<()> {
    let mut parameter_ids = get_local_parameter_ids()?;

    if !matches.is_present("all") {
        parameter_ids = choose_from(parameter_ids)?;
        println!();
    };

    let json = PathBuf::from(matches.value_of("json").unwrap_or("./parameters.json"));
    let mut parameter_map: ParameterMap = HashMap::new();

    if !parameter_ids.is_empty() {
        println!("publishing {} parameters...", parameter_ids.len());
        println!();

        for parameter_id in parameter_ids {
            println!("publishing: {}", parameter_id);
            print!("publishing to ipfs... ");
            io::stdout().flush().unwrap();

            match publish_parameter_file(&parameter_id) {
                Ok(cid) => {
                    println!("ok");
                    print!("generating digest... ");
                    io::stdout().flush().unwrap();

                    let digest = get_parameter_digest(&parameter_id)?;
                    let data = ParameterData { cid, digest };

                    parameter_map.insert(parameter_id, data);

                    println!("ok");
                }
                Err(err) => println!("error: {}", err),
            }

            println!();
        }

        save_parameter_map(&parameter_map, &json)?;
    } else {
        println!("no parameters to publish");
    }

    Ok(())
}
