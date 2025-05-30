use std::{collections::HashMap, time::Duration};

use alloy::primitives::B256;
use anyhow::anyhow;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_u64;

use crate::config::networks;

/// The location where the list of checkpoint services are stored.
pub const CHECKPOINT_SYNC_SERVICES_LIST: &str = "https://raw.githubusercontent.com/ethpandaops/checkpoint-sync-health-checks/master/_data/endpoints.yaml";

const REQUEST_TIMEOUT_SEC: u64 = 5;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawSlotResponse {
    pub data: RawSlotResponseData,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawSlotResponseData {
    pub slots: Vec<Slot>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Slot {
    #[serde(deserialize_with = "as_u64")]
    pub slot: u64,
    pub block_root: Option<B256>,
    pub state_root: Option<B256>,
    #[serde(deserialize_with = "as_u64")]
    pub epoch: u64,
    pub time: StartEndTime,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartEndTime {
    /// An ISO 8601 formatted UTC timestamp.
    pub start_time: String,
    /// An ISO 8601 formatted UTC timestamp.
    pub end_time: String,
}

/// A health check for the checkpoint sync service.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Health {
    /// If the node is healthy.
    pub result: bool,
    /// An [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601) UTC timestamp.
    pub date: String,
}

/// A checkpoint fallback service.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointFallbackService {
    /// The endpoint for the checkpoint sync service.
    pub endpoint: String,
    /// The checkpoint sync service name.
    pub name: String,
    /// The service state.
    pub state: bool,
    /// If the service is verified.
    pub verification: bool,
    /// Contact information for the service maintainers.
    pub contacts: Option<serde_yaml::Value>,
    /// Service Notes
    pub notes: Option<serde_yaml::Value>,
    /// The service health check.
    pub health: Vec<Health>,
}

/// The CheckpointFallback manages checkpoint fallback services.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointFallback {
    /// Services Map
    pub services: HashMap<networks::Network, Vec<CheckpointFallbackService>>,
    /// A list of supported networks to build.
    /// Default: [mainnet]
    pub networks: Vec<networks::Network>,
}

impl CheckpointFallback {
    /// Constructs a new checkpoint fallback service.
    pub fn new() -> Self {
        Self {
            services: Default::default(),
            networks: [networks::Network::Mainnet].to_vec(),
        }
    }

    /// Build the checkpoint fallback service from the community-maintained list by [ethPandaOps](https://github.com/ethpandaops).
    ///
    /// The list is defined in [ethPandaOps/checkpoint-fallback-service](https://github.com/ethpandaops/checkpoint-sync-health-checks/blob/master/_data/endpoints.yaml).
    pub async fn build(mut self) -> anyhow::Result<Self> {
        // Fetch the services
        let res = Self::send_request(CHECKPOINT_SYNC_SERVICES_LIST).await?;
        let yaml = res.text().await?;

        // Parse the yaml content results.
        let list: serde_yaml::Value = serde_yaml::from_str(&yaml)?;

        // Construct the services mapping from network <> list of services
        let mut services = HashMap::new();
        for network in &self.networks {
            // Try to parse list of checkpoint fallback services
            let service_list = list
                .get(network.to_string().to_lowercase())
                .ok_or_else(|| {
                    anyhow!(format!("missing {network} fallback checkpoint services"))
                })?;
            let parsed: Vec<CheckpointFallbackService> =
                serde_yaml::from_value(service_list.clone())?;
            services.insert(*network, parsed);
        }
        self.services = services;

        Ok(self)
    }

    /// Fetch the latest checkpoint from the checkpoint fallback service.
    pub async fn fetch_latest_checkpoint(
        &self,
        network: &networks::Network,
    ) -> anyhow::Result<B256> {
        let services = &self.get_healthy_fallback_services(network);
        Self::fetch_latest_checkpoint_from_services(&services[..]).await
    }

    async fn query_service(endpoint: &str) -> Option<RawSlotResponse> {
        let constructed_url = Self::construct_url(endpoint);
        let res = Self::send_request(&constructed_url).await.ok()?;
        let raw = res.json().await.ok()?;
        Some(raw)
    }

    /// Fetch the latest checkpoint from a list of checkpoint fallback services.
    pub async fn fetch_latest_checkpoint_from_services(
        services: &[CheckpointFallbackService],
    ) -> anyhow::Result<B256> {
        // Iterate over all mainnet checkpoint sync services and get the latest checkpoint slot for
        // each.
        let tasks: Vec<_> = services
            .iter()
            .map(|service| async move {
                let service = service.clone();
                match Self::query_service(&service.endpoint).await {
                    Some(raw) => {
                        if raw.data.slots.is_empty() {
                            return Err(anyhow!("no slots"));
                        }

                        let slot = raw
                            .data
                            .slots
                            .iter()
                            .find(|s| s.block_root.is_some())
                            .ok_or(anyhow!("no valid slots"))?;

                        Ok(slot.clone())
                    }
                    None => Err(anyhow!("failed to query service")),
                }
            })
            .collect();

        let slots = futures::future::join_all(tasks)
            .await
            .iter()
            .filter_map(|slot| match &slot {
                Ok(s) => Some(s.clone()),
                _ => None,
            })
            .filter(|s| s.block_root.is_some())
            .collect::<Vec<_>>();

        // Get the max epoch
        let max_epoch_slot = slots
            .iter()
            .max_by_key(|x| x.epoch)
            .ok_or(anyhow!("Failed to find max epoch from checkpoint slots"))?;
        let max_epoch = max_epoch_slot.epoch;

        // Filter out all the slots that are not the max epoch.
        let slots = slots
            .into_iter()
            .filter(|x| x.epoch == max_epoch)
            .collect::<Vec<_>>();

        // Return the most commonly verified checkpoint.
        let checkpoints = slots
            .iter()
            .filter_map(|x| x.block_root)
            .collect::<Vec<_>>();
        let mut m: HashMap<B256, usize> = HashMap::new();
        for c in checkpoints {
            *m.entry(c).or_default() += 1;
        }
        let most_common = m.into_iter().max_by_key(|(_, v)| *v).map(|(k, _)| k);

        // Return the most commonly verified checkpoint for the latest epoch.
        most_common.ok_or_else(|| anyhow!("No checkpoint found"))
    }

    /// Associated function to fetch the latest checkpoint from a specific checkpoint sync fallback
    /// service api url.
    pub async fn fetch_checkpoint_from_api(url: &str) -> anyhow::Result<B256> {
        // Fetch the url
        let constructed_url = Self::construct_url(url);
        let res = Self::send_request(&constructed_url).await?;
        let raw: RawSlotResponse = res.json().await?;
        let slot = raw.data.slots[0].clone();
        slot.block_root
            .ok_or_else(|| anyhow!("Checkpoint not in returned slot"))
    }

    /// Constructs the checkpoint fallback service url for fetching a slot.
    ///
    /// This is an associated function and can be used like so:
    ///
    /// ```rust
    /// use light_client::config::CheckpointFallback;
    ///
    /// let url = CheckpointFallback::construct_url("https://sync-mainnet.beaconcha.in");
    /// assert_eq!(
    ///     "https://sync-mainnet.beaconcha.in/checkpointz/v1/beacon/slots",
    ///     url
    /// );
    /// ```
    pub fn construct_url(endpoint: &str) -> String {
        // some endpoints have trailing slashes
        let endpoint = endpoint.trim_end_matches('/');
        format!("{endpoint}/checkpointz/v1/beacon/slots")
    }

    /// Returns a list of all checkpoint fallback endpoints.
    ///
    /// ### Warning
    ///
    /// These services are not healthchecked **nor** trustworthy and may act with malice by
    /// returning invalid checkpoints.
    #[allow(unused)]
    pub fn get_all_fallback_endpoints(&self, network: &networks::Network) -> Vec<String> {
        self.services[network]
            .iter()
            .map(|service| service.endpoint.clone())
            .collect()
    }

    /// Returns a list of healthchecked checkpoint fallback endpoints.
    ///
    /// ### Warning
    ///
    /// These services are not trustworthy and may act with malice by returning invalid checkpoints.
    #[allow(unused)]
    pub fn get_healthy_fallback_endpoints(&self, network: &networks::Network) -> Vec<String> {
        self.services[network]
            .iter()
            .filter(|service| service.state)
            .map(|service| service.endpoint.clone())
            .collect()
    }

    /// Returns a list of healthchecked checkpoint fallback services.
    ///
    /// ### Warning
    ///
    /// These services are not trustworthy and may act with malice by returning invalid checkpoints.
    #[allow(unused)]
    pub fn get_healthy_fallback_services(
        &self,
        network: &networks::Network,
    ) -> Vec<CheckpointFallbackService> {
        self.services[network]
            .iter()
            .filter(|service| service.state)
            .cloned()
            .collect::<Vec<CheckpointFallbackService>>()
    }

    /// Returns the raw checkpoint fallback service objects for a given network.
    #[allow(unused)]
    pub fn get_fallback_services(
        &self,
        network: &networks::Network,
    ) -> &Vec<CheckpointFallbackService> {
        self.services[network].as_ref()
    }

    async fn send_request(url: &str) -> anyhow::Result<Response> {
        let client = reqwest::Client::new();
        Ok(client
            .get(url)
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SEC))
            .send()
            .await?)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{config, config::networks};

    #[tokio::test]
    async fn test_checkpoint_fallback() {
        let cf = config::checkpoints::CheckpointFallback::new();

        assert_eq!(cf.services.get(&networks::Network::Mainnet), None);
        assert_eq!(cf.networks, [networks::Network::Mainnet].to_vec());
    }

    #[tokio::test]
    async fn test_construct_checkpoints() {
        let cf = config::checkpoints::CheckpointFallback::new()
            .build()
            .await
            .unwrap();

        assert!(cf.services[&networks::Network::Mainnet].len() > 1);
    }

    #[tokio::test]
    async fn test_fetch_latest_checkpoints() {
        let cf = config::checkpoints::CheckpointFallback::new()
            .build()
            .await
            .unwrap();
        let checkpoint = cf
            .fetch_latest_checkpoint(&networks::Network::Mainnet)
            .await
            .unwrap();
        assert_ne!(checkpoint, B256::ZERO);
    }

    #[tokio::test]
    async fn test_get_all_fallback_endpoints() {
        let cf = config::checkpoints::CheckpointFallback::new()
            .build()
            .await
            .unwrap();
        let urls = cf.get_all_fallback_endpoints(&networks::Network::Mainnet);
        assert!(!urls.is_empty());
    }

    #[tokio::test]
    async fn test_get_healthy_fallback_endpoints() {
        let cf = config::checkpoints::CheckpointFallback::new()
            .build()
            .await
            .unwrap();
        let urls = cf.get_healthy_fallback_endpoints(&networks::Network::Mainnet);
        assert!(!urls.is_empty());
    }
}
