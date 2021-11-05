use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use bincode::deserialize;
use std::str::FromStr;
use filecoin_hashers::{HashFunction, Hasher};

use bellperson::bls::Fr;
use fil_proofs_tooling::measure;
use fil_proofs_tooling::shared::{PROVER_ID, RANDOMNESS};
use filecoin_proofs::constants::{
    WINDOW_POST_CHALLENGE_COUNT, WINDOW_POST_SECTOR_COUNT,
};
use filecoin_proofs::types::{
    PoStConfig, SectorSize, ChallengeSeed,
};
use storage_proofs_core::api_version::ApiVersion;
use filecoin_proofs::{
	generate_window_post, with_shape, PoStType, PrivateReplicaInfo, commitment_from_fr,
	PublicReplicaInfo, aggregate_window_post_proofs, verify_aggregate_window_post_proofs,
    get_window_post_inputs,
};
use storage_proofs_core::merkle::MerkleTreeTrait;
use storage_proofs_core::sector::SectorId;
use storage_proofs_core::cache_key::CacheKey;

// const FAKE_RANDOMNESS: [u8; 32] = [10; 32];

#[allow(clippy::too_many_arguments)]
fn run_agg_proofs<Tree: 'static + MerkleTreeTrait>(
	root_dir: PathBuf,
	sector_size: u64,
	num_agg: u64,
) -> anyhow::Result<()>{
	let mut pub_replica_infos: Vec<BTreeMap<SectorId, PublicReplicaInfo>> = Vec::new();
	let mut randomnesses: Vec<ChallengeSeed> = Vec::new();
	let mut proofs: Vec<Vec<u8>> = Vec::new();

	let api_version = ApiVersion::from_str("1.0.0")?;
	let post_config = PoStConfig {
            sector_size: SectorSize(sector_size),
            challenge_count: WINDOW_POST_CHALLENGE_COUNT,
            sector_count: *WINDOW_POST_SECTOR_COUNT
                .read()
                .expect("WINDOW_POST_SECTOR_COUNT poisoned")
                .get(&sector_size)
                .expect("unknown sector size"),
            typ: PoStType::Window,
            priority: true,
            api_version,
        };

    let start_time = Instant::now();
	for index in 0..num_agg {

        let mut pub_replica_info: BTreeMap<SectorId, PublicReplicaInfo> = BTreeMap::new();
        let mut priv_replica_info: BTreeMap<SectorId, PrivateReplicaInfo<Tree>> = BTreeMap::new();

        for k in 0..2{
            let sector_id = (index * 2 + k) % 2048;
            let cache_dir = root_dir.join(format!("cache-{}",sector_id));
            let (comm_c, comm_r_last) = {
                let p_aux_path = cache_dir.join(CacheKey::PAux.to_string());
                let p_aux_bytes = fs::read(&p_aux_path)?;

                deserialize(&p_aux_bytes)
            }?;
            let commr: <Tree::Hasher as Hasher>::Domain =
                <Tree::Hasher as Hasher>::Function::hash2(&comm_c, &comm_r_last);
            let comm_r = commitment_from_fr(commr.into());

            let sector_id = SectorId::from(sector_id);
            let sealed_file_path = cache_dir.join("sealed-file");

            let pub_replica = PublicReplicaInfo::new(comm_r).expect("failed to create public replica info");

            let priv_replica = PrivateReplicaInfo::<Tree>::new(sealed_file_path, comm_r, cache_dir.clone())
                .expect("failed to create private replica info");

            pub_replica_info.insert(sector_id, pub_replica);
            priv_replica_info.insert(sector_id, priv_replica);
        }

        pub_replica_infos.push(pub_replica_info);

        // if index == 0 {
        //     randomnesses.push(FAKE_RANDOMNESS);
        // } else {
        randomnesses.push(RANDOMNESS);
        // }
        
        let gen_window_post_measurement = measure(|| {
            generate_window_post::<Tree>(&post_config, &RANDOMNESS, &priv_replica_info, PROVER_ID)
        })
        .expect("failed to generate window post");

        let proof = gen_window_post_measurement.return_value;

        proofs.push(proof);
	}
	let generate_window_post_time = start_time.elapsed().as_millis();

    use rayon::prelude::*;
    let commit_inputs: Vec<Vec<Fr>> = pub_replica_infos
        .par_iter()
        .zip(randomnesses.par_iter())
        .map(|(replica, randomness)| get_window_post_inputs::<Tree>(&post_config, replica, randomness, PROVER_ID))
        .try_reduce(Vec::new, |mut acc, current| {
                acc.extend(current);
                Ok(acc)
            })?;
    for commit_input in commit_inputs.iter(){
        println!("\n commit inputs : {:?}", commit_input);
    }

	let start_time = Instant::now();
    let aggregate_proof = &aggregate_window_post_proofs::<Tree>(&post_config, randomnesses.as_slice(), proofs.as_slice(), 2)?;
    let aggregate_window_post_proofs_cold_time = start_time.elapsed().as_millis();

    let start_time = Instant::now();
    let ok = verify_aggregate_window_post_proofs::<Tree>(&post_config, PROVER_ID, aggregate_proof.to_vec(), randomnesses.as_slice(), pub_replica_infos.as_slice())?;
    let verify_aggregate_proofs_cold_time = start_time.elapsed().as_millis();

    if ok {
        println!("aggregate proofs(cold) is true");
    } else {
        println!("aggregate proofs(cold) is false");
    }

    let start_time = Instant::now();
    let aggregate_proof = &aggregate_window_post_proofs::<Tree>(&post_config, randomnesses.as_slice(), proofs.as_slice(), 2)?;
    let aggregate_window_post_proofs_hot_time = start_time.elapsed().as_millis();

    let start_time = Instant::now();
    let ok = verify_aggregate_window_post_proofs::<Tree>(&post_config, PROVER_ID, aggregate_proof.to_vec(), randomnesses.as_slice(), pub_replica_infos.as_slice())?;
    let verify_aggregate_proofs_hot_time = start_time.elapsed().as_millis();
    
    if ok {
        println!("aggregate proofs(hot) is true");
    } else {
        println!("aggregate proofs(hot) is false");
    }

    println!("#################################################");
    println!("generate {} window-post using {}", num_agg, generate_window_post_time);
    println!("aggregate {} window-post proofs (cold) using {}", num_agg, aggregate_window_post_proofs_cold_time);
    println!("aggregate {} window-post proofs (hot) using {}", num_agg, aggregate_window_post_proofs_hot_time);
    println!("verify_aggregate {} window-post proofs (cold) using {}", num_agg, verify_aggregate_proofs_cold_time);
    println!("verify_aggregate {} window-post proofs (hot) using {}", num_agg, verify_aggregate_proofs_hot_time);
    println!("aggregate proofs size is {}", aggregate_proof.len());
    println!("#################################################");

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn run(
	root_dir: String,
	sector_size: usize,
	num_agg: usize,
) -> anyhow::Result<()>{
	let root = PathBuf::from(root_dir);
    with_shape!(
        sector_size as u64,
        run_agg_proofs,
        root,
        sector_size as u64,
        num_agg as u64,
    )
}