use clap::{App, AppSettings, Arg, SubCommand};

use filecoin_proofs::param::*;
use std::path::PathBuf;
use storage_proofs::parameter_cache::PARAMETER_CACHE_DIR;

pub fn main() {
    let matches = App::new("paramfetch")
        .setting(AppSettings::ArgRequiredElseHelp)
        .version("1.0")
        .about("")
        .about(
            &format!(
                "
Set $FILECOIN_PARAMETER_CACHE to specify parameter directory. Defaults to '{}'
",
                PARAMETER_CACHE_DIR
            )[..],
        )
        .arg(
            Arg::with_name("json")
                .global(true)
                .value_name("JSON")
                .takes_value(true)
                .short("j")
                .long("json")
                .help("Use specific json file"),
        )
        .subcommand(
            SubCommand::with_name("fetch")
                .arg(
                    Arg::with_name("all")
                        .short("a")
                        .long("all")
                        .help("Download all available parameters"),
                )
                .about("Download parameters through IPFS"),
        )
        .subcommand(
            SubCommand::with_name("check").about("Check which mapped parameters have been fetched"),
        )
        .get_matches();

    let json = PathBuf::from(matches.value_of("json").unwrap_or("./parameters.json"));
    let parameter_map = load_parameter_map(&json).expect(ERROR_PARAMETERS_MAPPED);

    if let Some(matches) = matches.subcommand_matches("fetch") {
        let parameters = if matches.is_present("all") {
            get_mapped_parameters(&parameter_map)
        } else {
            choose_mapped_parameters(&parameter_map)
        }
        .expect(ERROR_PARAMETERS_MAPPED);

        if parameters.len() > 0 {
            println!("fetching parameters");

            for parameter in parameters.iter() {
                println!("fetching '{}'...", parameter);

                match fetch_parameter_file(&parameter_map, parameter.to_string()) {
                    Ok(_) => {
                        println!("checking digest...");
                        let digest =
                            get_parameter_digest(parameter.to_string()).expect(ERROR_DIGEST);

                        if digest != parameter_map.get(parameter).unwrap().digest {
                            println!("failed integrity check. you should remove this parameter and try again");
                        } else {
                            println!("ok");
                        }
                    }
                    Err(_) => println!("error"),
                }
            }
        } else {
            println!("nothing to fetch");
        }
    }

    if let Some(_) = matches.subcommand_matches("check") {
        let mapped_parameters =
            get_mapped_parameters(&parameter_map).expect(ERROR_PARAMETERS_MAPPED);
        let local_parameters = get_local_parameters().expect(ERROR_PARAMETERS_LOCAL);

        mapped_parameters.iter().for_each(|p| {
            let local = local_parameters.contains(p);
            let check = if local { "☑" } else { "☐" };

            println!("{} {}", check, p);
        });
    }
}
