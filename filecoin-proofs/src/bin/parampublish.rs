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
    let parameter_map = get_parameter_map(&json).expect(ERROR_PARAMETERS_MAPPED);

    if let Some(matches) = matches.subcommand_matches("publish") {
        let mut new_parameter_map: ParameterMap = HashMap::new();
        let parameter_ids = if matches.is_present("all") {
            get_local_parameter_ids()
        } else {
            choose_local_parameter_ids()
        }
        .expect(ERROR_PARAMETERS_LOCAL);

        if !parameter_ids.is_empty() {
            println!("publishing parameters");

            for parameter_id in parameter_ids.into_iter() {
                println!("publishing '{}'...", parameter_id);

                match publish_parameter_file(&parameter_id) {
                    Ok(cid) => {
                        println!("generating digest...");
                        let digest = get_parameter_digest(&parameter_id).expect(ERROR_DIGEST);
                        let data = ParameterData { cid, digest };

                        println!("ok.");
                        new_parameter_map.insert(parameter_id, data);
                    }
                    Err(err) => println!("err: {}", err),
                }
            }

            save_parameter_map(&new_parameter_map, &json).expect(ERROR_PARAMETER_MAP_SAVE);
        } else {
            println!("nothing to publish");
        }
    }

    if matches.subcommand_matches("check").is_some() {
        let mapped_parameters =
            get_mapped_parameter_ids(&parameter_map).expect(ERROR_PARAMETERS_MAPPED);
        let local_parameters = get_local_parameter_ids().expect(ERROR_PARAMETERS_LOCAL);

        local_parameters.iter().for_each(|p| {
            let mapped = mapped_parameters.contains(p);
            let check = if mapped { "☑" } else { "☐" };

            println!("{} {}", check, p);
        });
    }
}
