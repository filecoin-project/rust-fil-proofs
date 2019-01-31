use failure::{err_msg, Error};
use regex::Regex;
use std::collections::HashMap;
use std::env;
use std::fs::{read_dir, File};
use std::io::{stdin, stdout, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::process::Command;

pub type Result<T> = ::std::result::Result<T, Error>;

trait PathBufStrings {
    fn file_name(&self) -> String;
    fn to_string(&self) -> String;
}

impl PathBufStrings for PathBuf {
    fn file_name(&self) -> String {
        self.as_path().file_name().unwrap().to_str().unwrap().into()
    }

    fn to_string(&self) -> String {
        self.as_path().to_str().unwrap().into()
    }
}

pub fn load_parameter_map() -> Result<HashMap<String, String>> {
    let path = PathBuf::from("./parammap.json");

    if path.exists() {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let map = serde_json::from_reader(reader)?;

        Ok(map)
    } else {
        Ok(HashMap::new())
    }
}

pub fn save_parameter_map(map: HashMap<String, String>) -> Result<()> {
    let file = File::create("./parammap.json")?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &map)?;

    Ok(())
}

pub fn get_parameter_files() -> Result<Vec<PathBuf>> {
    let files: Vec<_> = read_dir("/tmp/filecoin-proof-parameters")?
        .into_iter()
        .map(|f| f.unwrap().path())
        .filter(|p| p.is_file())
        .collect();

    Ok(files)
}

pub fn publish_parameter_file(path: &PathBuf) -> Result<String> {
    let output = Command::new("ipfs")
        .arg("add")
        .arg(path.to_string())
        .output()
        .expect("failed to run ipfs command");

    if !output.status.success() {
        Err(err_msg("failed to publish"))
    } else {
        let pattern = Regex::new("added ([^ ]+) ")?;
        let string = String::from_utf8(output.stdout)?;
        let captures = pattern
            .captures(string.as_str())
            .expect("failed to capture ipfs output");
        let cid = captures.get(1).expect("failed to parse ipfs output");

        Ok(cid.as_str().to_string())
    }
}

pub fn choose(message: String) -> bool {
    loop {
        print!("{} [y/n]: ", message);
        let _ = stdout().flush();
        let mut s = String::new();
        stdin().read_line(&mut s).expect("invalid string");

        match s.trim().to_uppercase().as_str() {
            "Y" => return true,
            "N" => return false,
            _ => {}
        }
    }
}

pub fn choose_parameter_files() -> Result<Vec<PathBuf>> {
    let files = get_parameter_files()?
        .into_iter()
        .filter(|p| choose(p.file_name()))
        .collect();

    Ok(files)
}

pub fn command_list() {
    let files: Vec<PathBuf> = get_parameter_files().expect("error finding files");
    println!(
        "{}",
        files
            .into_iter()
            .map(|f| f.file_name())
            .collect::<Vec<String>>()
            .join("\n")
    );
}

pub fn command_map() {
    let map = load_parameter_map().expect("error loading parameter map");
    map.into_iter().for_each(|(k, v)| println!("{}: {}", k, v));
}

pub fn command_publish() {
    let mut map = load_parameter_map().expect("error loading parameter map");
    let files: Vec<PathBuf> = choose_parameter_files().expect("error choosing files");

    if files.len() > 0 {
        println!("publishing:");

        files.into_iter().for_each(|f| {
            print!("{}... ", &f.file_name());

            match publish_parameter_file(&f) {
                Ok(cid) => {
                    map.insert(f.file_name(), cid);
                    println!("ok");
                }
                Err(_) => println!("error"),
            }
        });

        save_parameter_map(map).expect("error saving parameter map");
    } else {
        println!("nothing to publish");
    }
}

pub fn command_help() {
    println!(
        "USAGE
  parampublish <command>

SUBCOMMANDS
  list      show all available parameter files
  map       show existing mapping of parameter file <-> ipfs cid
  publish   choose and publish parameter files"
    );
}

pub fn command_invalid(command: &str) {
    println!(
        "parampublish: '{}' is not a valid parampublish command",
        command
    );
}

pub fn main() {
    let args = env::args().collect::<Vec<String>>();

    match args.len() {
        1 => command_help(),
        _ => match &args[1][..] {
            "list" => command_list(),
            "map" => command_map(),
            "publish" => command_publish(),
            "help" => command_help(),
            c => command_invalid(c),
        },
    }
}
