use std::collections::btree_map::BTreeMap;

use failure::Error as FailureError;

use crate::paramfetch::support::session::ParamFetchSessionBuilder;
use crate::support::tmp_manifest;
use blake2b_simd::State as Blake2b;
use filecoin_proofs::param::ParameterData;
use rand::Rng;

/// Produce a random sequence of bytes and first 32 characters of hex encoded
/// BLAKE2b checksum. This helper function must be kept up-to-date with the
/// parampublish implementation.
fn rand_bytes_with_blake2b() -> Result<(Vec<u8>, String), FailureError> {
    let bytes = rand::thread_rng().gen::<[u8; 32]>();

    let mut hasher = Blake2b::new();

    let mut as_slice = &bytes[..];

    std::io::copy(&mut as_slice, &mut hasher)?;

    Ok((
        bytes.iter().cloned().collect(),
        hasher.finalize().to_hex()[..32].into(),
    ))
}

#[test]
fn nothing_to_fetch_if_cache_fully_hydrated() {
    Ok::<(), FailureError>(())
        .and_then(|_| {
            let mut manifest: BTreeMap<String, ParameterData> = BTreeMap::new();

            let (aaa_bytes, aaa_checksum) = rand_bytes_with_blake2b()?;
            let mut aaa_bytes: &[u8] = &aaa_bytes;

            // manifest entry checksum matches the BLAKE2b we compute locally
            manifest.insert(
                "aaa.vk".to_string(),
                ParameterData {
                    cid: "".to_string(),
                    digest: aaa_checksum.clone(),
                    sector_size: 1234,
                },
            );

            let mut session = ParamFetchSessionBuilder::new(tmp_manifest(Some(manifest))?)
                .with_session_timeout_ms(1000)
                .with_file_and_bytes("aaa.vk", &mut aaa_bytes)
                .build();

            session.exp_string("checking: aaa.vk")?;
            session.exp_string("0 files to fetch")?;
            session.exp_string("done")?;

            Ok(())
        })
        .expect("paramfetch test failed");
}

#[test]
fn prompts_to_download_if_file_in_manifest_is_missing() {
    Ok::<(), FailureError>(())
        .and_then(|_| {
            let mut manifest: BTreeMap<String, ParameterData> = BTreeMap::new();

            manifest.insert(
                "aaa.vk".to_string(),
                ParameterData {
                    cid: "".to_string(),
                    digest: "".to_string(),
                    sector_size: 1234,
                },
            );

            let mut session = ParamFetchSessionBuilder::new(tmp_manifest(Some(manifest))?)
                .with_session_timeout_ms(1000)
                .build();

            session.exp_string("checking: aaa.vk")?;
            session.exp_string("does file exist... no")?;
            session.exp_string("[y/n] (sector size: 1234B) aaa.vk: ")?;

            Ok(())
        })
        .expect("paramfetch test failed");
}

#[test]
fn prompts_to_download_if_file_checksum_does_not_match_manifest() {
    Ok::<(), FailureError>(())
        .and_then(|_| {
            let mut manifest: BTreeMap<String, ParameterData> = BTreeMap::new();

            let (aaa_bytes, _) = rand_bytes_with_blake2b()?;
            let mut aaa_bytes: &[u8] = &aaa_bytes;

            manifest.insert(
                "aaa.vk".to_string(),
                ParameterData {
                    cid: "".to_string(),
                    digest: "obviouslywrong".to_string(),
                    sector_size: 5555,
                },
            );

            // create a manifest
            let manifest_pbuf = tmp_manifest(Some(manifest))?;

            // start a session
            let mut session = ParamFetchSessionBuilder::new(manifest_pbuf)
                .with_session_timeout_ms(1000)
                .with_file_and_bytes("aaa.vk", &mut aaa_bytes)
                .build();

            session.exp_string("checking: aaa.vk")?;
            session.exp_string("does file exist... yes")?;
            session.exp_string("is file valid... no")?;
            session.exp_string("[y/n] (sector size: 5555B) aaa.vk: ")?;

            Ok(())
        })
        .expect("paramfetch test failed");
}

#[test]
fn fetches_vk_even_if_sector_size_does_not_match() {
    Ok::<(), FailureError>(())
        .and_then(|_| {
            let mut manifest: BTreeMap<String, ParameterData> = BTreeMap::new();

            manifest.insert(
                "aaa.params".to_string(),
                ParameterData {
                    cid: "".to_string(),
                    digest: "".to_string(),
                    sector_size: 1234,
                },
            );

            manifest.insert(
                "aaa.vk".to_string(),
                ParameterData {
                    cid: "".to_string(),
                    digest: "".to_string(),
                    sector_size: 1234,
                },
            );

            let mut session = ParamFetchSessionBuilder::new(tmp_manifest(Some(manifest))?)
                .with_session_timeout_ms(1000)
                .whitelisted_sector_sizes(vec!["6666".to_string(), "4444".to_string()])
                .build();

            session.exp_string("2 files in manifest")?;
            session.exp_string("1 files to check for (re)download")?;
            session.exp_string("checking: aaa.vk")?;
            session.exp_string("does file exist... no")?;

            Ok(())
        })
        .expect("paramfetch test failed");
}
