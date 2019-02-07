use clap::{App, AppSettings, Arg, SubCommand};
use std::collections::HashMap;

use filecoin_proofs::param::*;

pub fn main() {
    let matches = App::new("parampublish")
        .setting(AppSettings::ArgRequiredElseHelp)
        .version("1.0")
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

    if let Some(matches) = matches.subcommand_matches("publish") {
        let mut map = HashMap::new();
        let parameters = if matches.is_present("all") {
            get_local_parameters()
        } else {
            choose_local_parameters()
        }
        .expect(ERROR_PARAMETERS_LOCAL);

        if parameters.len() > 0 {
            println!("publishing parameters:");

            parameters.iter().for_each(|p| {
                print!("{}... ", p);

                match publish_parameter_file(p.to_string()) {
                    Ok(cid) => {
                        map.insert(p.to_string(), cid);
                        println!("ok");
                    }
                    Err(_) => println!("error"),
                }
            });

            save_parameter_map(map).expect(ERROR_PARAMETER_MAP_SAVE);
        } else {
            println!("nothing to publish");
        }
    }

    if let Some(_) = matches.subcommand_matches("check") {
        let mapped_parameters = get_mapped_parameters().expect(ERROR_PARAMETERS_MAPPED);
        let local_parameters = get_local_parameters().expect(ERROR_PARAMETERS_LOCAL);

        local_parameters.iter().for_each(|p| {
            let mapped = mapped_parameters.contains(p);
            let check = if mapped { "☑" } else { "☐" };

            println!("{} {}", check, p);
        });
    }
}
