use std::process::exit;
use std::str::FromStr;

use dialoguer::{theme::ColorfulTheme, MultiSelect};
use filecoin_hashers::Hasher;
use filecoin_proofs::{
    constants::{DefaultPieceHasher, DefaultTreeHasher, PUBLISHED_SECTOR_SIZES},
    types::{PoRepConfig, PoStConfig, SectorSize},
    with_shape, PoStType,
};
use generic_array::typenum::{U0, U2, U8};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::pasta::{Fp, Fq};
use humansize::{file_size_opts, FileSize};
use indicatif::ProgressBar;
use log::{error, info, warn};
use storage_proofs_core::{
    api_version::ApiVersion,
    halo2::{Halo2Field, Halo2Keypair},
    merkle::MerkleTreeTrait,
    util::NODE_SIZE,
};
use storage_proofs_porep::stacked::halo2::{
    constants::{
        SECTOR_NODES_16_KIB, SECTOR_NODES_16_MIB, SECTOR_NODES_1_GIB, SECTOR_NODES_2_KIB,
        SECTOR_NODES_32_GIB, SECTOR_NODES_32_KIB, SECTOR_NODES_4_KIB, SECTOR_NODES_512_MIB,
        SECTOR_NODES_64_GIB, SECTOR_NODES_8_MIB,
    },
    SdrPorepCircuit,
};
use storage_proofs_post::halo2::{PostCircuit, WindowPostCircuit, WinningPostCircuit};
use storage_proofs_update::halo2::EmptySectorUpdateCircuit;
use structopt::StructOpt;

fn cache_halo2_porep_params<Tree>(porep_config: PoRepConfig)
where
    Tree: 'static + MerkleTreeTrait,
    DefaultPieceHasher<Tree::Field>: Hasher<Field = Tree::Field>,
    DefaultTreeHasher<Tree::Field>: Hasher<Field = Tree::Field>,
    <Tree as MerkleTreeTrait>::Field: FieldExt,
    <Tree as MerkleTreeTrait>::Field: Halo2Field,
{
    info!("generating PoRep halo2 params");

    let sector_size = u64::from(SectorSize::from(porep_config)) as usize;
    let leaf_count = sector_size / NODE_SIZE;
    match leaf_count {
        // base shape
        SECTOR_NODES_2_KIB => {
            let circ =
                SdrPorepCircuit::<Tree::Field, U8, U0, U0, SECTOR_NODES_2_KIB>::blank_circuit();
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // base shape
        SECTOR_NODES_8_MIB => {
            let circ =
                SdrPorepCircuit::<Tree::Field, U8, U0, U0, SECTOR_NODES_8_MIB>::blank_circuit();
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // base shape
        SECTOR_NODES_512_MIB => {
            let circ =
                SdrPorepCircuit::<Tree::Field, U8, U0, U0, SECTOR_NODES_512_MIB>::blank_circuit();
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // sub2 shape
        SECTOR_NODES_4_KIB => {
            let circ =
                SdrPorepCircuit::<Tree::Field, U8, U2, U0, SECTOR_NODES_4_KIB>::blank_circuit();
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // sub2 shape
        SECTOR_NODES_16_MIB => {
            let circ =
                SdrPorepCircuit::<Tree::Field, U8, U2, U0, SECTOR_NODES_16_MIB>::blank_circuit();
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // sub2 shape
        SECTOR_NODES_1_GIB => {
            let circ =
                SdrPorepCircuit::<Tree::Field, U8, U2, U0, SECTOR_NODES_1_GIB>::blank_circuit();
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // sub8 shape
        SECTOR_NODES_16_KIB => {
            let circ =
                SdrPorepCircuit::<Tree::Field, U8, U8, U0, SECTOR_NODES_16_KIB>::blank_circuit();
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // sub8 shape
        SECTOR_NODES_32_GIB => {
            let circ =
                SdrPorepCircuit::<Tree::Field, U8, U8, U0, SECTOR_NODES_32_GIB>::blank_circuit();
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // top2 shape
        SECTOR_NODES_32_KIB => {
            let circ =
                SdrPorepCircuit::<Tree::Field, U8, U8, U2, SECTOR_NODES_32_KIB>::blank_circuit();
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // top2 shape
        SECTOR_NODES_64_GIB => {
            let circ =
                SdrPorepCircuit::<Tree::Field, U8, U8, U2, SECTOR_NODES_64_GIB>::blank_circuit();
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        _ => panic!("Unsupported sector size!"),
    }
}

fn cache_halo2_winning_post_params<Tree>(post_config: PoStConfig)
where
    Tree: 'static + MerkleTreeTrait,
    DefaultPieceHasher<Tree::Field>: Hasher<Field = Tree::Field>,
    DefaultTreeHasher<Tree::Field>: Hasher<Field = Tree::Field>,
    <Tree as MerkleTreeTrait>::Field: FieldExt,
    <Tree as MerkleTreeTrait>::Field: Halo2Field,
{
    info!("generating Winning PoSt halo2 params");

    let sector_size = u64::from(SectorSize::from(post_config)) as usize;
    let leaf_count = sector_size / 32;
    match leaf_count {
        // base shape
        SECTOR_NODES_2_KIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                Tree::Field,
                U8,
                U0,
                U0,
                SECTOR_NODES_2_KIB,
            >::blank_circuit());
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // base shape
        SECTOR_NODES_8_MIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                Tree::Field,
                U8,
                U0,
                U0,
                SECTOR_NODES_8_MIB,
            >::blank_circuit());
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // base shape
        SECTOR_NODES_512_MIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                Tree::Field,
                U8,
                U0,
                U0,
                SECTOR_NODES_512_MIB,
            >::blank_circuit());
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // sub2 shape
        SECTOR_NODES_4_KIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                Tree::Field,
                U8,
                U2,
                U0,
                SECTOR_NODES_4_KIB,
            >::blank_circuit());
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // sub2 shape
        SECTOR_NODES_16_MIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                Tree::Field,
                U8,
                U2,
                U0,
                SECTOR_NODES_16_MIB,
            >::blank_circuit());
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // sub2 shape
        SECTOR_NODES_1_GIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                Tree::Field,
                U8,
                U2,
                U0,
                SECTOR_NODES_1_GIB,
            >::blank_circuit());
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // sub8 shape
        SECTOR_NODES_16_KIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                Tree::Field,
                U8,
                U8,
                U0,
                SECTOR_NODES_16_KIB,
            >::blank_circuit());
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // sub8 shape
        SECTOR_NODES_32_GIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                Tree::Field,
                U8,
                U8,
                U0,
                SECTOR_NODES_32_GIB,
            >::blank_circuit());
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // top2 shape
        SECTOR_NODES_32_KIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                Tree::Field,
                U8,
                U8,
                U2,
                SECTOR_NODES_32_KIB,
            >::blank_circuit());
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // top2 shape
        SECTOR_NODES_64_GIB => {
            let circ = PostCircuit::from(WinningPostCircuit::<
                Tree::Field,
                U8,
                U8,
                U2,
                SECTOR_NODES_64_GIB,
            >::blank_circuit());
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        _ => panic!("Unsupported sector size!"),
    }
}

fn cache_halo2_window_post_params<Tree>(post_config: PoStConfig)
where
    Tree: 'static + MerkleTreeTrait,
    DefaultPieceHasher<Tree::Field>: Hasher<Field = Tree::Field>,
    DefaultTreeHasher<Tree::Field>: Hasher<Field = Tree::Field>,
    <Tree as MerkleTreeTrait>::Field: FieldExt,
    <Tree as MerkleTreeTrait>::Field: Halo2Field,
{
    info!("generating Window PoSt halo2 params");

    let sector_size = u64::from(SectorSize::from(post_config)) as usize;
    let leaf_count = sector_size / 32;
    match leaf_count {
        // base shape
        SECTOR_NODES_2_KIB => {
            let circ = PostCircuit::from(WindowPostCircuit::<
                Tree::Field,
                U8,
                U0,
                U0,
                SECTOR_NODES_2_KIB,
            >::blank_circuit());
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // base shape
        SECTOR_NODES_8_MIB => {
            let circ = PostCircuit::from(WindowPostCircuit::<
                Tree::Field,
                U8,
                U0,
                U0,
                SECTOR_NODES_8_MIB,
            >::blank_circuit());
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // base shape
        SECTOR_NODES_512_MIB => {
            let circ = PostCircuit::from(WindowPostCircuit::<
                Tree::Field,
                U8,
                U0,
                U0,
                SECTOR_NODES_512_MIB,
            >::blank_circuit());
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // sub2 shape
        SECTOR_NODES_4_KIB => {
            let circ = PostCircuit::from(WindowPostCircuit::<
                Tree::Field,
                U8,
                U2,
                U0,
                SECTOR_NODES_4_KIB,
            >::blank_circuit());
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // sub2 shape
        SECTOR_NODES_16_MIB => {
            let circ = PostCircuit::from(WindowPostCircuit::<
                Tree::Field,
                U8,
                U2,
                U0,
                SECTOR_NODES_16_MIB,
            >::blank_circuit());
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // sub2 shape
        SECTOR_NODES_1_GIB => {
            let circ = PostCircuit::from(WindowPostCircuit::<
                Tree::Field,
                U8,
                U2,
                U0,
                SECTOR_NODES_1_GIB,
            >::blank_circuit());
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // sub8 shape
        SECTOR_NODES_16_KIB => {
            let circ = PostCircuit::from(WindowPostCircuit::<
                Tree::Field,
                U8,
                U8,
                U0,
                SECTOR_NODES_16_KIB,
            >::blank_circuit());
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // sub8 shape
        SECTOR_NODES_32_GIB => {
            let circ = PostCircuit::from(WindowPostCircuit::<
                Tree::Field,
                U8,
                U8,
                U0,
                SECTOR_NODES_32_GIB,
            >::blank_circuit());
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // top2 shape
        SECTOR_NODES_32_KIB => {
            let circ = PostCircuit::from(WindowPostCircuit::<
                Tree::Field,
                U8,
                U8,
                U2,
                SECTOR_NODES_32_KIB,
            >::blank_circuit());
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // top2 shape
        SECTOR_NODES_64_GIB => {
            let circ = PostCircuit::from(WindowPostCircuit::<
                Tree::Field,
                U8,
                U8,
                U2,
                SECTOR_NODES_64_GIB,
            >::blank_circuit());
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        _ => panic!("Unsupported sector size!"),
    }
}

fn cache_halo2_empty_sector_update_params<Tree>(porep_config: PoRepConfig)
where
    Tree: 'static + MerkleTreeTrait,
    DefaultPieceHasher<Tree::Field>: Hasher<Field = Tree::Field>,
    DefaultTreeHasher<Tree::Field>: Hasher<Field = Tree::Field>,
    <Tree as MerkleTreeTrait>::Field: FieldExt,
    <Tree as MerkleTreeTrait>::Field: Halo2Field,
{
    info!("generating Empty Sector Update halo2 params");

    let sector_size = u64::from(SectorSize::from(porep_config)) as usize;
    let leaf_count = sector_size / 32;
    match leaf_count {
        // base shape
        SECTOR_NODES_2_KIB => {
            let circ =
                EmptySectorUpdateCircuit::<Tree::Field, U8, U0, U0, SECTOR_NODES_2_KIB>::blank_circuit();
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // base shape
        SECTOR_NODES_8_MIB => {
            let circ =
                EmptySectorUpdateCircuit::<Tree::Field, U8, U0, U0, SECTOR_NODES_8_MIB>::blank_circuit();
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // base shape
        SECTOR_NODES_512_MIB => {
            let circ =
                EmptySectorUpdateCircuit::<Tree::Field, U8, U0, U0, SECTOR_NODES_512_MIB>::blank_circuit();
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // sub2 shape
        SECTOR_NODES_4_KIB => {
            let circ =
                EmptySectorUpdateCircuit::<Tree::Field, U8, U2, U0, SECTOR_NODES_4_KIB>::blank_circuit();
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // sub2 shape
        SECTOR_NODES_16_MIB => {
            let circ =
                EmptySectorUpdateCircuit::<Tree::Field, U8, U2, U0, SECTOR_NODES_16_MIB>::blank_circuit();
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // sub2 shape
        SECTOR_NODES_1_GIB => {
            let circ =
                EmptySectorUpdateCircuit::<Tree::Field, U8, U2, U0, SECTOR_NODES_1_GIB>::blank_circuit();
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // sub8 shape
        SECTOR_NODES_16_KIB => {
            let circ =
                EmptySectorUpdateCircuit::<Tree::Field, U8, U8, U0, SECTOR_NODES_16_KIB>::blank_circuit();
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // sub8 shape
        SECTOR_NODES_32_GIB => {
            let circ =
                EmptySectorUpdateCircuit::<Tree::Field, U8, U8, U0, SECTOR_NODES_32_GIB>::blank_circuit();
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // top2 shape
        SECTOR_NODES_32_KIB => {
            let circ =
                EmptySectorUpdateCircuit::<Tree::Field, U8, U8, U2, SECTOR_NODES_32_KIB>::blank_circuit();
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        // top2 shape
        SECTOR_NODES_64_GIB => {
            let circ =
                EmptySectorUpdateCircuit::<Tree::Field, U8, U8, U2, SECTOR_NODES_64_GIB>::blank_circuit();
            let _keypair = Halo2Keypair::<<Tree::Field as Halo2Field>::Affine, _>::create(&circ)
                .expect("failed to create halo2 keypair");
        }
        _ => panic!("Unsupported sector size!"),
    }
}

#[derive(Debug, StructOpt)]
#[structopt(
    name = "halo2paramcache",
    about = "generates and caches SDR PoRep, Winning-PoSt, Window-PoSt, and EmptySectorUpdate halo2 params"
)]
struct Opt {
    #[structopt(long, group = "onlyonecache", help = "Only cache PoSt halo2 params.")]
    only_post: bool,
    #[structopt(
        long,
        group = "onlyonecache",
        help = "Only cache EmptySectorUpdate halo2 params."
    )]
    only_sector_update: bool,
    #[structopt(
        short = "z",
        long,
        use_delimiter = true,
        help = "A comma-separated list of sector sizes (in number of bytes)."
    )]
    sector_sizes: Vec<u64>,
    #[structopt(
        long = "api-version",
        value_name = "SEMANTIC VERSION",
        default_value = "1.1.0",
        help = "Use a specific rust-fil-proofs API version."
    )]
    api_version: String,
}

fn generate_halo2_porep_params(sector_size: u64, api_version: ApiVersion) {
    with_shape!(
        sector_size,
        Fp,
        cache_halo2_porep_params,
        PoRepConfig::new_halo2(SectorSize(sector_size), [0; 32], api_version)
    );

    with_shape!(
        sector_size,
        Fq,
        cache_halo2_porep_params,
        PoRepConfig::new_halo2(SectorSize(sector_size), [0; 32], api_version)
    );
}

fn generate_halo2_post_params(sector_size: u64, api_version: ApiVersion) {
    with_shape!(
        sector_size,
        Fp,
        cache_halo2_winning_post_params,
        PoStConfig::new_halo2(
            SectorSize(sector_size),
            PoStType::Winning,
            true,
            api_version
        )
    );
    with_shape!(
        sector_size,
        Fq,
        cache_halo2_winning_post_params,
        PoStConfig::new_halo2(
            SectorSize(sector_size),
            PoStType::Winning,
            true,
            api_version
        )
    );

    with_shape!(
        sector_size,
        Fp,
        cache_halo2_window_post_params,
        PoStConfig::new_halo2(SectorSize(sector_size), PoStType::Window, true, api_version)
    );
    with_shape!(
        sector_size,
        Fq,
        cache_halo2_window_post_params,
        PoStConfig::new_halo2(SectorSize(sector_size), PoStType::Window, true, api_version)
    );
}

fn generate_halo2_empty_sector_update_params(sector_size: u64, api_version: ApiVersion) {
    with_shape!(
        sector_size,
        Fp,
        cache_halo2_empty_sector_update_params,
        PoRepConfig::new_halo2(SectorSize(sector_size), [0; 32], api_version)
    );

    with_shape!(
        sector_size,
        Fq,
        cache_halo2_empty_sector_update_params,
        PoRepConfig::new_halo2(SectorSize(sector_size), [0; 32], api_version)
    );
}

pub fn main() {
    fil_logger::init();

    let mut opts = Opt::from_args();

    // If no sector-sizes were given provided via. the CLI, display an interactive menu. Otherwise,
    // filter out invalid CLI sector-size arguments.
    if opts.sector_sizes.is_empty() {
        let sector_size_strings: Vec<String> = PUBLISHED_SECTOR_SIZES
            .iter()
            .map(|sector_size| {
                let human_size = sector_size
                    .file_size(file_size_opts::BINARY)
                    .expect("failed to format sector size");
                // Right align numbers for easier reading.
                format!("{: >7}", human_size)
            })
            .collect();

        opts.sector_sizes = MultiSelect::with_theme(&ColorfulTheme::default())
            .with_prompt(
                "Select the sizes that should be generated if not already cached [use space key to \
                select, press return to finish]",
            )
            .items(&sector_size_strings)
            .interact()
            .expect("interaction failed")
            .into_iter()
            .map(|i| PUBLISHED_SECTOR_SIZES[i])
            .collect();
    } else {
        opts.sector_sizes.retain(|size| {
            if PUBLISHED_SECTOR_SIZES.contains(size) {
                true
            } else {
                let human_size = size
                    .file_size(file_size_opts::BINARY)
                    .expect("failed to humansize sector size argument");
                warn!("ignoring invalid sector size argument: {}", human_size);
                false
            }
        });
    }

    if opts.sector_sizes.is_empty() {
        error!("no valid sector sizes given, aborting");
        exit(1);
    }

    let api_version = ApiVersion::from_str(&opts.api_version)
        .expect("Cannot parse API version from semver string (e.g. 1.1.0)");

    for sector_size in opts.sector_sizes {
        let human_size = sector_size
            .file_size(file_size_opts::BINARY)
            .expect("failed to format sector size");
        let message = format!("Generating sector size: {}", human_size);
        info!("{}", &message);

        let spinner = ProgressBar::new_spinner();
        spinner.set_message(message);
        spinner.enable_steady_tick(100);

        if opts.only_sector_update {
            generate_halo2_empty_sector_update_params(sector_size, api_version);
        } else {
            generate_halo2_post_params(sector_size, api_version);

            if !opts.only_post {
                generate_halo2_porep_params(sector_size, api_version);
                generate_halo2_empty_sector_update_params(sector_size, api_version);
            }
        }

        spinner.finish_with_message(format!("✔ Generated sector size: {}", human_size));
    }
}
