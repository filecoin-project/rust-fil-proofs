use crate::api::sector_builder::state::*;
use crate::api::sector_builder::WrappedKeyValueStore;
use crate::error::Result;
use std::sync::Arc;

pub fn load_snapshot(
    kv_store: &Arc<WrappedKeyValueStore>,
    prover_id: &[u8; 31],
) -> Result<Option<StateSnapshot>> {
    let result: Option<Vec<u8>> = kv_store.inner.get(prover_id)?;

    if let Some(val) = result {
        return serde_cbor::from_slice(&val[..])
            .map_err(failure::Error::from)
            .map(Option::Some);
    }

    Ok(None)
}

pub fn persist_snapshot(
    kv_store: &Arc<WrappedKeyValueStore>,
    snapshot: &StateSnapshot,
) -> Result<()> {
    let serialized = serde_cbor::to_vec(snapshot)?;
    kv_store.inner.put(&snapshot.prover_id[..], &serialized)?;
    Ok(())
}

pub fn make_snapshot(
    prover_id: &[u8; 31],
    staged_state: &StagedState,
    sealed_state: &SealedState,
) -> StateSnapshot {
    StateSnapshot {
        prover_id: *prover_id,
        staged: StagedState {
            sector_id_nonce: staged_state.sector_id_nonce,
            sectors: staged_state.sectors.clone(),
        },
        sealed: SealedState {
            sectors: sealed_state.sectors.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use crate::api::sector_builder::helpers::snapshots::*;
    use crate::api::sector_builder::kv_store::fs::FileSystemKvs;
    use crate::api::sector_builder::metadata::StagedSectorMetadata;
    use crate::api::sector_builder::state::SealedState;
    use crate::api::sector_builder::state::StagedState;
    use crate::api::sector_builder::SectorId;
    use crate::api::sector_builder::WrappedKeyValueStore;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::Mutex;

    #[test]
    fn test_alpha() {
        let metadata_dir = tempfile::tempdir().unwrap();

        let kv_store = Arc::new(WrappedKeyValueStore {
            inner: Box::new(FileSystemKvs::initialize(metadata_dir).unwrap()),
        });

        let prover_id = [0; 31];

        let (staged_state, sealed_state) = {
            let mut m: HashMap<SectorId, StagedSectorMetadata> = HashMap::new();

            m.insert(123, Default::default());

            let staged_state = Mutex::new(StagedState {
                sector_id_nonce: 100,
                sectors: m,
            });

            let sealed_state: Mutex<SealedState> = Default::default();

            (staged_state, sealed_state)
        };

        let to_persist = make_snapshot(
            &prover_id,
            &staged_state.lock().unwrap(),
            &sealed_state.lock().unwrap(),
        );

        let _ = persist_snapshot(&kv_store, &to_persist).unwrap();

        let loaded = load_snapshot(&kv_store, &prover_id).unwrap().unwrap();

        assert_eq!(to_persist, loaded);
    }
}
