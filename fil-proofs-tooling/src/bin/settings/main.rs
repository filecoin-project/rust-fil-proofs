use anyhow::Result;

use storage_proofs::settings::{Settings, SETTINGS};

fn main() -> Result<()> {
    let Settings {
        parameter_cache,
        maximize_caching,
        parent_cache,
        sdr_parents_cache_size,
        use_gpu_column_builder,
        max_gpu_column_batch_size,
        column_write_batch_size,
        use_gpu_tree_builder,
        max_gpu_tree_batch_size,
        rows_to_discard,
        window_post_synthesis_num_cpus,
        pedersen_hash_exp_window_size,
        use_fil_blst,
    } = &*SETTINGS.lock().unwrap();

    println!("parameter_cache: {}", parameter_cache);
    println!("maximize_caching: {}", maximize_caching);
    println!("parent_cache: {}", parent_cache);
    println!("sdr_parents_cache_size: {}", sdr_parents_cache_size);

    println!("use_gpu_column_builder: {}", use_gpu_column_builder);
    println!("max_gpu_column_batch_size: {}", max_gpu_column_batch_size);
    println!("column_write_batch_size: {}", column_write_batch_size);

    println!("use_gpu_tree_builder: {}", use_gpu_tree_builder);
    println!("max_gpu_tree_batch_size: {}", max_gpu_tree_batch_size);

    println!("rows_to_discard: {}", rows_to_discard);
    println!(
        "window_post_synthesis_num_cpus: {}",
        window_post_synthesis_num_cpus
    );
    println!(
        "pedersen_hash_exp_window_size: {}",
        pedersen_hash_exp_window_size
    );

    println!("use_fil_blst: {}", use_fil_blst);

    Ok(())
}
