use anyhow::Result;

use storage_proofs::settings;

fn main() -> Result<()> {
    println!(
        "parameter_cache: {}",
        settings::SETTINGS.lock().unwrap().parameter_cache
    );
    println!(
        "maximize_caching: {}",
        settings::SETTINGS.lock().unwrap().maximize_caching
    );
    println!(
        "parent_cache: {}",
        settings::SETTINGS.lock().unwrap().parent_cache
    );
    println!(
        "sdr_parents_cache_size: {}",
        settings::SETTINGS.lock().unwrap().sdr_parents_cache_size
    );

    println!(
        "use_gpu_column_builder: {}",
        settings::SETTINGS.lock().unwrap().use_gpu_column_builder
    );
    println!(
        "max_gpu_column_batch_size: {}",
        settings::SETTINGS.lock().unwrap().max_gpu_column_batch_size
    );
    println!(
        "column_write_batch_size: {}",
        settings::SETTINGS.lock().unwrap().column_write_batch_size
    );

    println!(
        "use_gpu_tree_builder: {}",
        settings::SETTINGS.lock().unwrap().use_gpu_tree_builder
    );
    println!(
        "max_gpu_tree_batch_size: {}",
        settings::SETTINGS.lock().unwrap().max_gpu_tree_batch_size
    );

    println!(
        "rows_to_discard: {}",
        settings::SETTINGS.lock().unwrap().rows_to_discard
    );
    println!(
        "window_post_synthesis_num_cpus: {}",
        settings::SETTINGS
            .lock()
            .unwrap()
            .window_post_synthesis_num_cpus
    );
    println!(
        "pedersen_hash_exp_window_size: {}",
        settings::SETTINGS
            .lock()
            .unwrap()
            .pedersen_hash_exp_window_size
    );

    Ok(())
}
