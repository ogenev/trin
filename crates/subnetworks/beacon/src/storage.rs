use std::{path::PathBuf, time::Duration};

use alloy::primitives::B256;
use ethportal_api::{
    consensus::fork::ForkName,
    types::{
        content_value::beacon::{
            ForkVersionedHistoricalSummariesWithProof, ForkVersionedLightClientBootstrap,
            ForkVersionedLightClientFinalityUpdate, ForkVersionedLightClientOptimisticUpdate,
            ForkVersionedLightClientUpdate, LightClientUpdatesByRange,
        },
        distance::Distance,
        network::Subnetwork,
        portal::PaginateLocalContentInfo,
    },
    BeaconContentKey, OverlayContentKey, RawContentValue,
};
use light_client::consensus::rpc::portal_rpc::expected_current_slot;
use r2d2::Pool;
use r2d2_sqlite::{rusqlite, SqliteConnectionManager};
use rusqlite::{params, OptionalExtension};
use ssz::{Decode, Encode};
use ssz_types::{typenum::U128, VariableList};
use tracing::{debug, error, info};
use tree_hash::TreeHash;
use trin_metrics::storage::StorageMetricsReporter;
use trin_storage::{
    error::ContentStoreError,
    sql::{
        HISTORICAL_SUMMARIES_EPOCH_LOOKUP_QUERY, HISTORICAL_SUMMARIES_LOOKUP_QUERY,
        INSERT_BOOTSTRAP_QUERY, INSERT_LC_UPDATE_QUERY,
        INSERT_OR_REPLACE_HISTORICAL_SUMMARIES_QUERY, LC_BOOTSTRAP_LATEST_BLOCK_ROOT_QUERY,
        LC_BOOTSTRAP_LOOKUP_QUERY, LC_BOOTSTRAP_PRUNE_QUERY, LC_BOOTSTRAP_ROOT_LOOKUP_QUERY,
        LC_UPDATE_LOOKUP_QUERY, LC_UPDATE_PERIOD_LOOKUP_QUERY, TOTAL_DATA_SIZE_QUERY_BEACON,
    },
    utils::get_total_size_of_directory_in_bytes,
    ContentStore, DataSize, PortalStorageConfig, ShouldWeStoreContent,
};
use trin_validation::chain_head::ChainHead;

/// Store ephemeral light client data in memory
#[derive(Debug)]
pub struct BeaconStorageCache {
    optimistic_update: Option<ForkVersionedLightClientOptimisticUpdate>,
    finality_update: Option<ForkVersionedLightClientFinalityUpdate>,
}

impl Default for BeaconStorageCache {
    fn default() -> Self {
        Self::new()
    }
}

impl BeaconStorageCache {
    pub fn new() -> Self {
        Self {
            optimistic_update: None,
            finality_update: None,
        }
    }

    /// Returns the optimistic update if it exists and matches the given signature slot.
    pub fn get_optimistic_update(
        &self,
        signature_slot: u64,
    ) -> Option<ForkVersionedLightClientOptimisticUpdate> {
        if let Some(optimistic_update) = &self.optimistic_update {
            if optimistic_update.update.signature_slot() >= &signature_slot {
                return Some(optimistic_update.clone());
            }
        }

        None
    }

    /// Returns the finality update if it exists and matches the given finalized slot.
    pub fn get_finality_update(
        &self,
        finalized_slot: u64,
    ) -> Option<ForkVersionedLightClientFinalityUpdate> {
        if let Some(finality_update) = &self.finality_update {
            // Returns the current finality update if it's finality slot is bigger or equal to the
            // requested slot.
            if finality_update
                .update
                .finalized_header_electra()
                .ok()?
                .beacon
                .slot
                >= finalized_slot
            {
                return Some(finality_update.clone());
            }
        }

        None
    }

    /// Sets the light client optimistic update
    pub fn set_optimistic_update(
        &mut self,
        optimistic_update: ForkVersionedLightClientOptimisticUpdate,
    ) {
        self.optimistic_update = Some(optimistic_update);
    }

    /// Sets the light client finality update
    pub fn set_finality_update(&mut self, finality_update: ForkVersionedLightClientFinalityUpdate) {
        self.finality_update = Some(finality_update);
    }
}

/// Storage layer for the state network. Encapsulates beacon network specific data and logic.
pub struct BeaconStorage {
    node_data_dir: PathBuf,
    sql_connection_pool: Pool<SqliteConnectionManager>,
    metrics: StorageMetricsReporter,
    cache: BeaconStorageCache,
    chain_head: ChainHead,
}

impl ContentStore for BeaconStorage {
    type Key = BeaconContentKey;

    fn get(&self, key: &BeaconContentKey) -> Result<Option<RawContentValue>, ContentStoreError> {
        match key {
            BeaconContentKey::LightClientBootstrap(content_key) => self
                .lookup_lc_bootstrap_value(&content_key.block_hash)
                .map(|value| value.map(RawContentValue::from))
                .map_err(|err| {
                    ContentStoreError::Database(format!(
                        "Error looking up LightClientBootstrap content value: {err:?}"
                    ))
                }),
            BeaconContentKey::LightClientUpdatesByRange(content_key) => {
                let periods =
                    content_key.start_period..(content_key.start_period + content_key.count);

                let mut content: Vec<ForkVersionedLightClientUpdate> = Vec::new();

                for period in periods {
                    let result = self.lookup_lc_update_value(period).map_err(|err| {
                        ContentStoreError::Database(format!(
                            "Error looking up LightClientUpdate content value: {err:?}"
                        ))
                    })?;

                    match result {
                        Some(result) => content.push(
                            ForkVersionedLightClientUpdate::from_ssz_bytes(result.as_slice())
                                .map_err(|err| {
                                    ContentStoreError::Database(format!(
                                        "Error ssz decode ForkVersionedLightClientUpdate value: {err:?}"
                                    ))
                                })?,
                        ),
                        None => return Ok(None),
                    }
                }

                let result = VariableList::<ForkVersionedLightClientUpdate, U128>::new(content)
                    .map_err(|err| ContentStoreError::Database(
                        format!(
                            "Error building VariableList from ForkVersionedLightClientUpdate data: {err:?}"
                        ),
                    ))?;

                Ok(Some(result.as_ssz_bytes().into()))
            }
            BeaconContentKey::LightClientFinalityUpdate(content_key) => {
                match self.cache.get_finality_update(content_key.finalized_slot) {
                    Some(finality_update) => Ok(Some(finality_update.as_ssz_bytes().into())),
                    None => Ok(None),
                }
            }
            BeaconContentKey::LightClientOptimisticUpdate(content_key) => {
                match self.cache.get_optimistic_update(content_key.signature_slot) {
                    Some(optimistic_update) => Ok(Some(optimistic_update.as_ssz_bytes().into())),
                    None => Ok(None),
                }
            }
            BeaconContentKey::HistoricalSummariesWithProof(content_key) => {
                let epoch = content_key.epoch;
                self.lookup_historical_summaries_value(epoch)
            }
        }
    }

    fn put<V: AsRef<[u8]>>(
        &mut self,
        key: BeaconContentKey,
        value: V,
    ) -> Result<Vec<(BeaconContentKey, RawContentValue)>, ContentStoreError> {
        // in the beacon network we don't return any dropped content for propagation
        self.store(&key, &value.as_ref().to_vec()).and(Ok(vec![]))
    }

    /// The "radius" concept is not applicable for Beacon network
    fn should_we_store(
        &self,
        key: &BeaconContentKey,
    ) -> Result<ShouldWeStoreContent, ContentStoreError> {
        match key {
            BeaconContentKey::LightClientBootstrap(content_key) => {
                let is_key_available = self
                    .lookup_lc_bootstrap_block_root(&content_key.block_hash)
                    .map_err(|err| {
                        ContentStoreError::Database(format!(
                            "Error looking up light client bootstrap block root: {err:?}"
                        ))
                    })?
                    .is_some();
                if is_key_available {
                    return Ok(ShouldWeStoreContent::AlreadyStored);
                }
                Ok(ShouldWeStoreContent::Store)
            }
            BeaconContentKey::LightClientUpdatesByRange(content_key) => {
                // Check if any of the periods are available, return AlreadyStored if so otherwise
                // Store
                let periods =
                    content_key.start_period..(content_key.start_period + content_key.count);

                for period in periods {
                    let is_period_available = self
                        .lookup_lc_update_period(period)
                        .map_err(|err| {
                            ContentStoreError::Database(format!(
                                "Error looking up light client update period: {err:?}"
                            ))
                        })?
                        .is_some();
                    if is_period_available {
                        return Ok(ShouldWeStoreContent::AlreadyStored);
                    }
                }
                Ok(ShouldWeStoreContent::Store)
            }
            BeaconContentKey::LightClientFinalityUpdate(content_key) => {
                match self.cache.get_finality_update(content_key.finalized_slot) {
                    Some(_) => Ok(ShouldWeStoreContent::AlreadyStored),
                    None => Ok(ShouldWeStoreContent::Store),
                }
            }
            BeaconContentKey::LightClientOptimisticUpdate(content_key) => {
                match self.cache.get_optimistic_update(content_key.signature_slot) {
                    Some(content) => {
                        if content.update.signature_slot() >= &content_key.signature_slot {
                            Ok(ShouldWeStoreContent::AlreadyStored)
                        } else {
                            Ok(ShouldWeStoreContent::Store)
                        }
                    }
                    None => Ok(ShouldWeStoreContent::Store),
                }
            }
            BeaconContentKey::HistoricalSummariesWithProof(content_key) => {
                let epoch = content_key.epoch;
                let is_epoch_available = self
                    .lookup_historical_summaries_epoch(epoch)
                    .map_err(|err| {
                        ContentStoreError::Database(format!(
                            "Error looking up historical summaries epoch: {err:?}"
                        ))
                    })?
                    .is_some();
                if is_epoch_available {
                    Ok(ShouldWeStoreContent::AlreadyStored)
                } else {
                    Ok(ShouldWeStoreContent::Store)
                }
            }
        }
    }

    /// The "radius" concept is not applicable for Beacon network, this is why we always return the
    /// max radius.
    fn radius(&self) -> Distance {
        Distance::MAX
    }
}

impl BeaconStorage {
    pub fn new(
        config: PortalStorageConfig,
        chain_head: ChainHead,
    ) -> Result<Self, ContentStoreError> {
        let storage = Self {
            node_data_dir: config.node_data_dir,
            sql_connection_pool: config.sql_connection_pool,
            metrics: StorageMetricsReporter::new(Subnetwork::Beacon),
            cache: BeaconStorageCache::new(),
            chain_head,
        };

        // Report current total storage usage.
        let total_storage_usage = storage.get_total_storage_usage_in_bytes_on_disk()?;
        storage
            .metrics
            .report_total_storage_usage_bytes(total_storage_usage as f64);

        // Report total storage used by network content.
        let network_content_storage_usage =
            storage.get_total_storage_usage_in_bytes_from_network()?;
        storage
            .metrics
            .report_content_data_storage_bytes(network_content_storage_usage as f64);

        // Update historical summaries to the latest stored version
        if let Some(historical_summaries_bytes) = storage.lookup_historical_summaries_value(0)? {
            let fork_versioned_historical_summaries =
                ForkVersionedHistoricalSummariesWithProof::from_ssz_bytes(
                    &historical_summaries_bytes,
                )
                .map_err(|err| ContentStoreError::InvalidData {
                    message: format!(
                        "Error decoding ForkVersionedHistoricalSummariesWithProof: {err:?}"
                    ),
                })?;
            storage.chain_head.update_historical_summaries(
                fork_versioned_historical_summaries
                    .historical_summaries_with_proof
                    .historical_summaries,
            );
        }

        Ok(storage)
    }

    /// Spawn a task to prune old  beacon data from the database on every new run and once a day
    pub fn spawn_pruning_task(&self) {
        let sql_connection_pool = self.sql_connection_pool.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60 * 60 * 24)); // once a day
            loop {
                interval.tick().await;
                if let Err(e) = prune_old_bootstrap_data(&sql_connection_pool) {
                    error!("Failed pruning old bootstrap data: {:?}", e);
                }
            }
        });
    }

    fn db_insert_lc_bootstrap(
        &self,
        block_root: &[u8; 32],
        value: &Vec<u8>,
        slot: u64,
    ) -> Result<usize, ContentStoreError> {
        let conn = self.sql_connection_pool.get()?;
        Ok(conn.execute(
            INSERT_BOOTSTRAP_QUERY,
            params![block_root, value, slot, 32 + value.len() + 8],
        )?)
    }

    fn db_insert_lc_update(&self, period: &u64, value: &Vec<u8>) -> Result<(), ContentStoreError> {
        let conn = self.sql_connection_pool.get()?;
        let value_size = value.len();

        match conn.execute(
            INSERT_LC_UPDATE_QUERY,
            params![period, value, 0, value_size],
        ) {
            Ok(_) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    /// Insert or replace historical summaries with proof into the database
    fn db_insert_or_replace_historical_summaries_with_proof(
        &self,
        epoch: &u64,
        value: &Vec<u8>,
    ) -> Result<(), ContentStoreError> {
        let conn = self.sql_connection_pool.get()?;
        let value_size = value.len();

        match conn.execute(
            INSERT_OR_REPLACE_HISTORICAL_SUMMARIES_QUERY,
            params![1, epoch, value, value_size],
        ) {
            Ok(_) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    pub fn store(
        &mut self,
        key: &BeaconContentKey,
        value: &Vec<u8>,
    ) -> Result<(), ContentStoreError> {
        let content_id = key.content_id();

        match key {
            BeaconContentKey::LightClientBootstrap(_) => {
                let bootstrap =
                    ForkVersionedLightClientBootstrap::from_ssz_bytes(value).map_err(|err| {
                        ContentStoreError::InvalidData {
                            message: format!(
                                "Error decoding ForkVersionedLightClientBootstrap value: {err:?}"
                            ),
                        }
                    })?;

                let (slot, block_root) = match bootstrap.fork_name {
                    ForkName::Bellatrix => {
                        let bootstrap_header = bootstrap.bootstrap.header_bellatrix().map_err(|err| {
                            ContentStoreError::InvalidData {
                                message: format!(
                                    "Error getting header from bellatrix ForkVersionedLightClientBootstrap value: {err:?}"
                                ),
                            }
                        })?;

                        (
                            bootstrap_header.beacon.slot,
                            bootstrap_header.beacon.tree_hash_root(),
                        )
                    }
                    ForkName::Capella => {
                        let bootstrap_header = bootstrap.bootstrap.header_capella().map_err(|err| {
                            ContentStoreError::InvalidData {
                                message: format!(
                                    "Error getting header from capella ForkVersionedLightClientBootstrap value: {err:?}"
                                ),
                            }
                        })?;

                        (
                            bootstrap_header.beacon.slot,
                            bootstrap_header.beacon.tree_hash_root(),
                        )
                    }
                    ForkName::Deneb => {
                        let bootstrap_header = bootstrap.bootstrap.header_deneb().map_err(|err| {
                            ContentStoreError::InvalidData {
                                message: format!(
                                    "Error getting header from deneb ForkVersionedLightClientBootstrap value: {err:?}"
                                ),
                            }
                        })?;

                        (
                            bootstrap_header.beacon.slot,
                            bootstrap_header.beacon.tree_hash_root(),
                        )
                    }
                    ForkName::Electra => {
                        let bootstrap_header = bootstrap.bootstrap.header_electra().map_err(|err| {
                            ContentStoreError::InvalidData {
                                message: format!(
                                    "Error getting header from electra ForkVersionedLightClientBootstrap value: {err:?}"
                                ),
                            }
                        })?;

                        (
                            bootstrap_header.beacon.slot,
                            bootstrap_header.beacon.tree_hash_root(),
                        )
                    }
                };

                if let Err(err) = self.db_insert_lc_bootstrap(&block_root, value, slot) {
                    debug!(block_root = %block_root, "Error writing light client bootstrap to lc_bootstrap db table: {err:?}");
                    return Err(err);
                } else {
                    self.metrics.increase_entry_count();
                }
            }
            BeaconContentKey::LightClientUpdatesByRange(update) => {
                // Build a range of values starting with update.start_period and len
                // update.count
                let periods = update.start_period..(update.start_period + update.count);
                let update_values =
                    LightClientUpdatesByRange::from_ssz_bytes(value).map_err(|err| {
                        ContentStoreError::InvalidData {
                            message: format!(
                                "Error decoding LightClientUpdatesByRange value: {err:?}"
                            ),
                        }
                    })?;

                for (period, value) in periods.zip(update_values.as_ref()) {
                    if let Err(err) = self.db_insert_lc_update(&period, &value.encode()) {
                        debug!("Error writing light client update by range content ID {content_id:?} to beacon network db: {err:?}");
                    } else {
                        self.metrics.increase_entry_count();
                    }
                }
            }
            BeaconContentKey::LightClientFinalityUpdate(_) => {
                let fork_versioned_update = ForkVersionedLightClientFinalityUpdate::from_ssz_bytes(
                    value,
                )
                .map_err(|err| ContentStoreError::InvalidData {
                    message: format!(
                        "Error decoding ForkVersionedLightClientFinalityUpdate value: {err:?}"
                    ),
                })?;
                self.chain_head
                    .process_finality_update(fork_versioned_update.update.clone());
                self.cache.set_finality_update(fork_versioned_update);
            }
            BeaconContentKey::LightClientOptimisticUpdate(_) => {
                let fork_versioned_update =
                    ForkVersionedLightClientOptimisticUpdate::from_ssz_bytes(value).map_err(
                        |err| ContentStoreError::InvalidData {
                            message: format!("Error decoding ForkVersionedLightClientOptimistipdate value: {err:?}"),
                        },
                    )?;
                self.chain_head
                    .process_optimistic_update(fork_versioned_update.update.clone());
                self.cache.set_optimistic_update(fork_versioned_update);
            }
            BeaconContentKey::HistoricalSummariesWithProof(historical_summaries_key) => {
                let fork_versioned_historical_summaries =
                    ForkVersionedHistoricalSummariesWithProof::from_ssz_bytes(value).map_err(
                        |err| ContentStoreError::InvalidData {
                            message:  format!("Error decoding ForkVersionedHistoricalSummariesWithProof value: {err:?}"),
                        },
                    )?;
                self.chain_head.update_historical_summaries(
                    fork_versioned_historical_summaries
                        .historical_summaries_with_proof
                        .historical_summaries,
                );
                if let Err(err) = self.db_insert_or_replace_historical_summaries_with_proof(
                    &historical_summaries_key.epoch,
                    value,
                ) {
                    debug!("Error writing historical summaries with proof to beacon network db: {err:?}");
                    return Err(err);
                } else {
                    self.metrics.increase_entry_count();
                }
            }
        }

        let total_bytes_on_disk = self.get_total_storage_usage_in_bytes_on_disk()?;
        self.metrics
            .report_total_storage_usage_bytes(total_bytes_on_disk as f64);

        Ok(())
    }

    pub fn paginate(
        &self,
        _offset: &u64,
        _limit: &u64,
    ) -> Result<PaginateLocalContentInfo<BeaconContentKey>, ContentStoreError> {
        Err(ContentStoreError::Database(
            "Paginate not implemented for Beacon storage".to_string(),
        ))
    }

    /// Public method for determining how much actual disk space is being used to store this node's
    /// Portal Network data. Intended for analysis purposes. PortalStorage's capacity
    /// decision-making is not based off of this method.
    pub fn get_total_storage_usage_in_bytes_on_disk(&self) -> Result<u64, ContentStoreError> {
        let storage_usage = get_total_size_of_directory_in_bytes(&self.node_data_dir)?;
        Ok(storage_usage)
    }

    /// Internal method for measuring the total amount of requestable data that the node is storing.
    fn get_total_storage_usage_in_bytes_from_network(&self) -> Result<u64, ContentStoreError> {
        let conn = self.sql_connection_pool.get()?;

        let mut content_data_stmt = conn.prepare(TOTAL_DATA_SIZE_QUERY_BEACON)?;
        let content_data_result = content_data_stmt.query_map([], |row| {
            Ok(DataSize {
                num_bytes: row.get(0)?,
            })
        });
        let content_data_sum = match content_data_result?.next() {
            Some(total) => total,
            None => {
                let err = "Unable to compute sum over content item sizes".to_string();
                return Err(ContentStoreError::Database(err));
            }
        }?
        .num_bytes;

        self.metrics
            .report_content_data_storage_bytes(content_data_sum);

        Ok(content_data_sum as u64)
    }

    /// Public method for looking up the latest block root in the light client bootstrap table
    pub fn lookup_latest_block_root(&self) -> anyhow::Result<Option<B256>> {
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(LC_BOOTSTRAP_LATEST_BLOCK_ROOT_QUERY)?;
        let result: Result<Vec<Vec<u8>>, ContentStoreError> = query
            .query_map([], |row| {
                let row: Vec<u8> = row.get(0)?;
                Ok(row)
            })?
            .map(|row| row.map_err(ContentStoreError::Rusqlite))
            .collect();

        match result?.first() {
            Some(val) => Ok(Some(B256::try_from(val.as_slice())?)),
            None => Ok(None),
        }
    }

    /// Public method for looking up a light client bootstrap by block root
    pub fn lookup_lc_bootstrap_block_root(
        &self,
        block_root: &[u8; 32],
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(LC_BOOTSTRAP_ROOT_LOOKUP_QUERY)?;
        let result: Result<Vec<Vec<u8>>, ContentStoreError> = query
            .query_map([block_root], |row| {
                let row: Vec<u8> = row.get(0)?;
                Ok(row)
            })?
            .map(|row| row.map_err(ContentStoreError::Rusqlite))
            .collect();

        match result?.first() {
            Some(val) => Ok(Some(val.to_vec())),
            None => Ok(None),
        }
    }

    /// Public method for looking up a light client update by period number
    pub fn lookup_lc_update_period(&self, period: u64) -> anyhow::Result<Option<u64>> {
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(LC_UPDATE_PERIOD_LOOKUP_QUERY)?;

        let rows: Result<Vec<u64>, rusqlite::Error> = query
            .query_map([period], |row| {
                let row: u64 = row.get(0)?;
                Ok(row)
            })?
            .collect();

        match rows?.first() {
            Some(val) => Ok(Some(*val)),
            None => Ok(None),
        }
    }

    /// Public method for looking up a historical summaries epoch by epoch number
    pub fn lookup_historical_summaries_epoch(&self, epoch: u64) -> anyhow::Result<Option<u64>> {
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(HISTORICAL_SUMMARIES_EPOCH_LOOKUP_QUERY)?;

        let rows: Result<Vec<u64>, rusqlite::Error> = query
            .query_map([epoch], |row| {
                let row: u64 = row.get(0)?;
                Ok(row)
            })?
            .collect();

        match rows?.first() {
            Some(val) => Ok(Some(*val)),
            None => Ok(None),
        }
    }

    /// Public method for looking up a light client bootstrap value by block root
    pub fn lookup_lc_bootstrap_value(
        &self,
        block_root: &[u8; 32],
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(LC_BOOTSTRAP_LOOKUP_QUERY)?;
        let result: Result<Vec<Vec<u8>>, ContentStoreError> = query
            .query_map([block_root], |row| {
                let row: Vec<u8> = row.get(0)?;
                Ok(row)
            })?
            .map(|row| row.map_err(ContentStoreError::Rusqlite))
            .collect();

        Ok(result?.first().map(|val| val.to_vec()))
    }

    /// Public method for looking up a  light client update value by period number
    pub fn lookup_lc_update_value(&self, period: u64) -> anyhow::Result<Option<Vec<u8>>> {
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(LC_UPDATE_LOOKUP_QUERY)?;

        let rows: Result<Vec<Vec<u8>>, rusqlite::Error> = query
            .query_map([period], |row| {
                let row: Vec<u8> = row.get(0)?;
                Ok(row)
            })?
            .collect();

        match rows?.first() {
            Some(val) => Ok(Some(val.to_vec())),
            None => Ok(None),
        }
    }

    /// Public method for looking up a historical summaries with proof value by epoch number
    pub fn lookup_historical_summaries_value(
        &self,
        epoch: u64,
    ) -> Result<Option<RawContentValue>, ContentStoreError> {
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(HISTORICAL_SUMMARIES_LOOKUP_QUERY)?;

        Ok(query
            .query_row([epoch], |row| {
                let row: Vec<u8> = row.get(0)?;
                Ok(RawContentValue::from(row))
            })
            .optional()?)
    }
    /// Get a summary of the current state of storage
    pub fn get_summary_info(&self) -> String {
        self.metrics.get_summary()
    }
}

/// Prune old bootstrap data from the database
fn prune_old_bootstrap_data(
    sql_connection_pool: &Pool<SqliteConnectionManager>,
) -> Result<(), ContentStoreError> {
    let conn = sql_connection_pool.get()?;
    let expected_current_slot = expected_current_slot();
    // One slot is 12 sec, and we want the threshold to be 4 months before the current slot
    let slot_threshold = expected_current_slot - (4 * 30 * 24 * 60 * 60 / 12);
    info!(
        slot_threshold = slot_threshold,
        "Pruning light client bootstrap data  outside of the weak subjectivity period..."
    );

    match conn.execute(LC_BOOTSTRAP_PRUNE_QUERY, params![slot_threshold]) {
        Ok(_) => {
            info!("Pruning light client bootstrap data completed successfully");
            Ok(())
        }
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use ethportal_api::{
        types::content_key::beacon::{
            HistoricalSummariesWithProofKey, LightClientFinalityUpdateKey,
            LightClientOptimisticUpdateKey,
        },
        BeaconContentValue, ContentValue, LightClientBootstrapKey, LightClientUpdatesByRangeKey,
    };
    use tree_hash::TreeHash;
    use trin_storage::test_utils::create_test_portal_storage_config_with_capacity;
    use trin_utils::{submodules::read_yaml_portal_spec_tests_file, testing::ContentItem};

    use super::*;
    use crate::test_utils;

    #[test]
    fn test_beacon_storage_get_put_bootstrap() {
        let (_temp_dir, config) = create_test_portal_storage_config_with_capacity(10).unwrap();
        let mut storage = BeaconStorage::new(config, ChainHead::new_pectra_defaults()).unwrap();
        let value = test_utils::get_light_client_bootstrap(0);
        let block_root = value
            .bootstrap
            .header_deneb()
            .unwrap()
            .beacon
            .tree_hash_root();
        let key = BeaconContentKey::LightClientBootstrap(LightClientBootstrapKey {
            block_hash: block_root.0,
        });
        storage.put(key.clone(), value.as_ssz_bytes()).unwrap();
        let result = storage.get(&key).unwrap().unwrap();
        assert_eq!(result, value.as_ssz_bytes());
    }

    #[test]
    fn test_beacon_storage_get_put_updates_by_range() {
        let (_temp_dir, config) = create_test_portal_storage_config_with_capacity(10).unwrap();
        let mut storage = BeaconStorage::new(config, ChainHead::new_pectra_defaults()).unwrap();
        let key = BeaconContentKey::LightClientUpdatesByRange(LightClientUpdatesByRangeKey {
            start_period: 1,
            count: 2,
        });
        let lc_update_0 = test_utils::get_light_client_update(0);
        let lc_update_1 = test_utils::get_light_client_update(1);
        let value = VariableList::<ForkVersionedLightClientUpdate, U128>::new(vec![
            lc_update_0.clone(),
            lc_update_1.clone(),
        ])
        .unwrap();
        storage.put(key.clone(), value.as_ssz_bytes()).unwrap();
        let result = storage.get(&key).unwrap().unwrap();

        assert_eq!(result, value.as_ssz_bytes());

        // Test getting the first individual updates
        let key_0 = BeaconContentKey::LightClientUpdatesByRange(LightClientUpdatesByRangeKey {
            start_period: 1,
            count: 1,
        });
        let expected_value_0 =
            VariableList::<ForkVersionedLightClientUpdate, U128>::new(vec![lc_update_0.clone()])
                .unwrap();
        let result_0 = storage.get(&key_0).unwrap().unwrap();
        assert_eq!(result_0, expected_value_0.as_ssz_bytes());

        // Test getting the second individual updates. The start period must be 2,
        let key_1 = BeaconContentKey::LightClientUpdatesByRange(LightClientUpdatesByRangeKey {
            start_period: 2,
            count: 1,
        });
        let expected_value_1 =
            VariableList::<ForkVersionedLightClientUpdate, U128>::new(vec![lc_update_1]).unwrap();
        let result_1 = storage.get(&key_1).unwrap().unwrap();
        assert_eq!(result_1, expected_value_1.as_ssz_bytes());
    }

    #[test]
    #[ignore = "Missing Pectra test vectors"]
    fn test_beacon_storage_get_put_finality_update() {
        let (_temp_dir, config) = create_test_portal_storage_config_with_capacity(10).unwrap();
        let mut storage = BeaconStorage::new(config, ChainHead::new_pectra_defaults()).unwrap();
        let value = test_utils::get_light_client_finality_update(0);
        let finalized_slot = value.update.finalized_header_deneb().unwrap().beacon.slot;
        let key = BeaconContentKey::LightClientFinalityUpdate(LightClientFinalityUpdateKey {
            finalized_slot,
        });
        storage.put(key.clone(), value.as_ssz_bytes()).unwrap();
        let result = storage.get(&key).unwrap().unwrap();
        assert_eq!(result, value.as_ssz_bytes());

        // Test is_key_within_radius_and_unavailable for the same finalized slot
        let should_store_content = storage.should_we_store(&key).unwrap();
        assert_eq!(should_store_content, ShouldWeStoreContent::AlreadyStored);

        // Test is_key_within_radius_and_unavailable for older finalized slot
        let key = BeaconContentKey::LightClientFinalityUpdate(LightClientFinalityUpdateKey {
            finalized_slot: finalized_slot - 1,
        });
        let should_store_content = storage.should_we_store(&key).unwrap();
        assert_eq!(should_store_content, ShouldWeStoreContent::AlreadyStored);

        // Test is_key_within_radius_and_unavailable for newer finalized slot
        let key = BeaconContentKey::LightClientFinalityUpdate(LightClientFinalityUpdateKey {
            finalized_slot: finalized_slot + 1,
        });
        let should_store_content = storage.should_we_store(&key).unwrap();
        assert_eq!(should_store_content, ShouldWeStoreContent::Store);

        // Test getting the latest finality update
        let key = BeaconContentKey::LightClientFinalityUpdate(LightClientFinalityUpdateKey {
            finalized_slot: 0,
        });
        let result = storage.get(&key).unwrap().unwrap();
        assert_eq!(result, value.as_ssz_bytes());
    }

    #[test]
    fn test_beacon_storage_get_put_optimistic_update() {
        let (_temp_dir, config) = create_test_portal_storage_config_with_capacity(10).unwrap();
        let mut storage = BeaconStorage::new(config, ChainHead::new_pectra_defaults()).unwrap();
        let value = test_utils::get_light_client_optimistic_update(0);
        let signature_slot = *value.update.signature_slot();
        let key = BeaconContentKey::LightClientOptimisticUpdate(LightClientOptimisticUpdateKey {
            signature_slot,
        });
        storage.put(key.clone(), value.as_ssz_bytes()).unwrap();
        let result = storage.get(&key).unwrap().unwrap();
        assert_eq!(result, value.as_ssz_bytes());

        // Test is_key_within_radius_and_unavailable for the same signature slot
        let should_store_content = storage.should_we_store(&key).unwrap();
        assert_eq!(should_store_content, ShouldWeStoreContent::AlreadyStored);

        // Test is_key_within_radius_and_unavailable for older signature slot
        let key = BeaconContentKey::LightClientOptimisticUpdate(LightClientOptimisticUpdateKey {
            signature_slot: signature_slot - 1,
        });
        let should_store_content = storage.should_we_store(&key).unwrap();
        assert_eq!(should_store_content, ShouldWeStoreContent::AlreadyStored);

        // Test is_key_within_radius_and_unavailable for newer signature slot
        let key = BeaconContentKey::LightClientOptimisticUpdate(LightClientOptimisticUpdateKey {
            signature_slot: signature_slot + 1,
        });
        let should_store_content = storage.should_we_store(&key).unwrap();
        assert_eq!(should_store_content, ShouldWeStoreContent::Store);

        // Test getting unavailable optimistic update
        let key = BeaconContentKey::LightClientOptimisticUpdate(LightClientOptimisticUpdateKey {
            signature_slot: signature_slot + 1,
        });
        let result = storage.get(&key).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_beacon_storage_get_put_historical_summaries() {
        let (_temp_dir, config) = create_test_portal_storage_config_with_capacity(10).unwrap();
        let mut storage = BeaconStorage::new(config, ChainHead::new_pectra_defaults()).unwrap();

        let test_data: ContentItem<BeaconContentKey> = read_yaml_portal_spec_tests_file(
            "tests/mainnet/beacon_chain/historical_summaries_with_proof/electra/historical_summaries_with_proof.yaml",
        ).unwrap();

        let key = test_data.content_key.clone();
        let value = test_data.content_value().unwrap();

        let BeaconContentValue::HistoricalSummariesWithProof(
            fork_versioned_historical_summaries_with_proof,
        ) = &value
        else {
            panic!("Expected HistoricalSummariesWithProof content value");
        };
        let epoch = fork_versioned_historical_summaries_with_proof
            .historical_summaries_with_proof
            .epoch;

        storage.put(key.clone(), value.encode()).unwrap();
        let result = storage.get(&key).unwrap().unwrap();
        assert_eq!(result, value.encode());

        // Test is_key_within_radius_and_unavailable for the same epoch
        let should_store_content = storage.should_we_store(&key).unwrap();
        assert_eq!(should_store_content, ShouldWeStoreContent::AlreadyStored);

        // Test is_key_within_radius_and_unavailable for older epoch
        let key = BeaconContentKey::HistoricalSummariesWithProof(HistoricalSummariesWithProofKey {
            epoch: epoch - 1,
        });
        let should_store_content = storage.should_we_store(&key).unwrap();
        assert_eq!(should_store_content, ShouldWeStoreContent::AlreadyStored);

        // Test is_key_within_radius_and_unavailable for newer epoch
        let key = BeaconContentKey::HistoricalSummariesWithProof(HistoricalSummariesWithProofKey {
            epoch: epoch + 1,
        });
        let should_store_content = storage.should_we_store(&key).unwrap();
        assert_eq!(should_store_content, ShouldWeStoreContent::Store);

        // Test getting unavailable historical summaries with proof
        let key = BeaconContentKey::HistoricalSummariesWithProof(HistoricalSummariesWithProofKey {
            epoch: epoch + 1,
        });
        let result = storage.get(&key).unwrap();
        assert_eq!(result, None);

        // Test getting the latest historical summaries with proof
        let key = BeaconContentKey::HistoricalSummariesWithProof(HistoricalSummariesWithProofKey {
            epoch: 0,
        });
        let result = storage.get(&key).unwrap().unwrap();
        assert_eq!(result, value.encode());
    }

    #[test]
    fn test_beacon_storage_prune_old_bootstrap_data() {
        let (_temp_dir, config) = create_test_portal_storage_config_with_capacity(10).unwrap();
        let mut storage = BeaconStorage::new(config, ChainHead::new_pectra_defaults()).unwrap();
        let mut value = test_utils::get_light_client_bootstrap(0);
        // Set the bootstrap slot to outdated value
        let current_slot = expected_current_slot();
        let outdated_slot = current_slot - (4 * 30 * 24 * 60 * 60 / 12) - 1;
        value.bootstrap.header_deneb_mut().unwrap().beacon.slot = outdated_slot;
        let block_root = value
            .bootstrap
            .header_deneb()
            .unwrap()
            .beacon
            .tree_hash_root();
        let key = BeaconContentKey::LightClientBootstrap(LightClientBootstrapKey {
            block_hash: block_root.0,
        });
        // Ensure the bootstrap is saved into db
        storage.put(key.clone(), value.as_ssz_bytes()).unwrap();
        let result = storage.get(&key).unwrap().unwrap();
        assert_eq!(result, value.as_ssz_bytes());
        // Prune the old bootstrap data
        let result = prune_old_bootstrap_data(&storage.sql_connection_pool);
        assert!(result.is_ok());
        // Check if the data was pruned
        let result = storage.get(&key).unwrap();
        assert_eq!(result, None);
    }
}
