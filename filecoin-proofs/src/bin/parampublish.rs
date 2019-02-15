use clap::{App, AppSettings, Arg, SubCommand};
use std::collections::HashMap;
use std::path::PathBuf;

use filecoin_proofs::param::*;
use storage_proofs::parameter_cache::PARAMETER_CACHE_DIR;

pub fn main() {
    let matches = App::new("parampublish")
        .setting(AppSettings::ArgRequiredElseHelp)
        .version("1.0")
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
            SubCommand::with_name("publish")
                .arg(
                    Arg::with_name("all")
                        .short("a")
                        .long("all")
                        .help("Publish all local parameters"),
                )
                .about("Publish local parameters through IPFS"),
        )
        .subcommand(
            SubCommand::with_name("check")
                .about("Check which local parameters have been published"),
        )
        .get_matches();

    let json = PathBuf::from(matches.value_of("json").unwrap_or("./parameters.json"));
    let parameter_map = load_parameter_map(&json).expect(ERROR_PARAMETERS_MAPPED);

    if let Some(matches) = matches.subcommand_matches("publish") {
        let mut new_parameter_map: ParameterMap = HashMap::new();
        let parameters = if matches.is_present("all") {
            get_local_parameters()
        } else {
            choose_local_parameters()
        }
        .expect(ERROR_PARAMETERS_LOCAL);

        if parameters.len() > 0 {
            println!("publishing parameters");

            for parameter in parameters.iter() {
                println!("publishing '{}'...", parameter);

                match publish_parameter_file(parameter.to_string()) {
                    Ok(cid) => {
                        println!("generating sha256...");
                        let sha256 =
                            get_parameter_sha256(parameter.to_string()).expect(ERROR_SHA256);
                        let data = ParameterData {
                            cid: cid,
                            sha256: sha256,
                        };

                        println!("ok.");
                        new_parameter_map.insert(parameter.to_string(), data);
                    }
                    Err(err) => println!("err: {}", err),
                }
            }

            save_parameter_map(&new_parameter_map, &json).expect(ERROR_PARAMETER_MAP_SAVE);
        } else {
            println!("nothing to publish");
        }
    }

    if let Some(_) = matches.subcommand_matches("check") {
        let mapped_parameters =
            get_mapped_parameters(&parameter_map).expect(ERROR_PARAMETERS_MAPPED);
        let local_parameters = get_local_parameters().expect(ERROR_PARAMETERS_LOCAL);

        local_parameters.iter().for_each(|p| {
            let mapped = mapped_parameters.contains(p);
            let check = if mapped { "☑" } else { "☐" };

            println!("{} {}", check, p);
        });
    }
}
