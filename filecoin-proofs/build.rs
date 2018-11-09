extern crate bindgen;
extern crate cbindgen;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    let cfg = cbindgen::Config::from_root_or_default(std::path::Path::new(&crate_dir));

    let c = cbindgen::Builder::new()
        .with_config(cfg)
        .with_crate(crate_dir)
        .with_header(format!("/* libproofs Header Version {} */", VERSION))
        .with_language(cbindgen::Language::C)
        .generate();

    // This is needed to ensure we don't panic if there are errors in the crates code
    // but rather just tell the rest of the system we can't proceed.
    match c {
        Ok(res) => {
            res.write_to_file("libfilecoin_proofs.h");
        }
        Err(err) => {
            eprintln!("unable to generate bindings: {:?}", err);
            std::process::exit(1);
        }
    }

    let b = bindgen::builder()
        .header("libfilecoin_proofs.h")
        // Here, we tell Rust to link libfilecoin_proofs so that auto-generated
        // symbols are linked to symbols in the compiled dylib. For reasons
        // unbeknown to me, the link attribute needs to precede an extern block.
        .raw_line("#[link(name = \"filecoin_proofs\")]\nextern \"C\" {}")
        .generate();

    match b {
        Ok(res) => {
            res.write_to_file("examples/ffi/libfilecoin_proofs.rs")
                .expect("could not write file");
        }
        Err(err) => {
            eprintln!("unable to generate bindings: {:?}", err);
            std::process::exit(1);
        }
    }
}
