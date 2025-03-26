use std::sync::{Arc, Mutex, OnceLock};

use ethportal_api::{types::network::Subnetwork, HistoryContentKey};
use tracing::warn;

use crate::{
    error::ContentStoreError,
    versioned::{ContentType, EphemeralV1Store, EphemeralV1StoreConfig, VersionedContentStore},
    PortalStorageConfig,
};

// Global store with thread-safe initialization
static SHARED_STORE: OnceLock<Mutex<Option<Arc<EphemeralV1Store<HistoryContentKey>>>>> =
    OnceLock::new();

/// Get a shared instance of the EphemeralV1Store that can handle both Beacon and History networks.
pub fn get_shared_ephemeral_store(
    config: &PortalStorageConfig,
    start_background_task: bool,
) -> Arc<EphemeralV1Store<HistoryContentKey>> {
    // Initialize the global mutex if not already done
    let store_mutex = SHARED_STORE.get_or_init(|| Mutex::new(None));

    // Lock the mutex and check if we need to create the store
    let mut store_guard = store_mutex.lock().unwrap();
    if store_guard.is_none() {
        *store_guard = Some(Arc::new(
            create_shared_ephemeral_store(config, start_background_task)
                .expect("Failed to create shared ephemeral store"),
        ));
    }

    // Clone the Arc before releasing the lock
    store_guard.as_ref().unwrap().clone()
}

// Helper function to create a new shared EphemeralV1Store
fn create_shared_ephemeral_store(
    config: &PortalStorageConfig,
    start_background_task: bool,
) -> Result<EphemeralV1Store<HistoryContentKey>, ContentStoreError> {
    let ephemeral_config = EphemeralV1StoreConfig {
        content_type: ContentType::HistoryEphemeral,
        subnetwork: Subnetwork::History,
        node_data_dir: config.node_data_dir.clone(),
        sql_connection_pool: config.sql_connection_pool.clone(),
    };

    let mut store = EphemeralV1Store::create(ContentType::HistoryEphemeral, ephemeral_config)?;

    // Start the background purging task only if explicitly requested
    if start_background_task {
        if let Err(e) = store.start_background_purge_task() {
            warn!(
                "Failed to start background purge task for shared ephemeral storage: {}",
                e
            );
        }
    }

    Ok(store)
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;
    use crate::test_utils::create_test_portal_storage_config_with_capacity;

    #[test]
    fn test_shared_store_singleton_behavior() {
        // Create a test config
        let (temp_dir, config) = create_test_portal_storage_config_with_capacity(10).unwrap();

        // Get the store instance
        let first_instance = get_shared_ephemeral_store(&config, false);

        // Get the store again, should be the same instance
        let second_instance = get_shared_ephemeral_store(&config, false);

        // Ensure we have the same instance (Arc pointers to the same allocation)
        assert!(Arc::ptr_eq(&first_instance, &second_instance));

        // Clean up
        drop(first_instance);
        drop(second_instance);
        drop(temp_dir);

        // Reset the static for other tests
        // This is a bit hacky but necessary for tests that use the same static
        let store_mutex = SHARED_STORE.get().unwrap();
        *store_mutex.lock().unwrap() = None;
    }

    #[test]
    fn test_shared_store_thread_safety() {
        // Create a test config
        let (temp_dir, config) = create_test_portal_storage_config_with_capacity(10).unwrap();

        // Get the store from the main thread
        let main_instance = get_shared_ephemeral_store(&config, false);

        // Spawn threads that will try to get the store
        let mut handles = vec![];
        for _ in 0..5 {
            let config_clone = config.clone();
            let handle = thread::spawn(move || get_shared_ephemeral_store(&config_clone, false));
            handles.push(handle);
        }

        // Collect results from threads
        for handle in handles {
            let thread_instance = handle.join().unwrap();
            // Ensure all instances are the same
            assert!(Arc::ptr_eq(&main_instance, &thread_instance));
        }

        // Clean up
        drop(main_instance);
        drop(temp_dir);

        // Reset the static for other tests
        let store_mutex = SHARED_STORE.get().unwrap();
        *store_mutex.lock().unwrap() = None;
    }
}
