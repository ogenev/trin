use ethportal_api::HistoryContentValue;
use ethportal_api::HistoryNetworkApiClient;
use ethportal_api::{BlockHeaderKey, HistoryContentKey};
use serde_json::json;

use crate::jsonrpc::HISTORY_CONTENT_VALUE;
use crate::{Peertest, PeertestConfig};

pub async fn test_paginate_local_storage(peertest_config: PeertestConfig, _peertest: &Peertest) {
    let ipc_client = reth_ipc::client::IpcClientBuilder::default()
        .build(&peertest_config.target_ipc_path)
        .await
        .unwrap();
    // Test paginate with empty storage
    let result = ipc_client.paginate_local_content_keys(0, 1).await.unwrap();
    assert_eq!(result.total_entries, 0);
    assert_eq!(result.content_keys.len(), 0);

    let mut content_keys: Vec<String> = (0..20_u8)
        .map(|_| {
            serde_json::to_string(&HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey {
                block_hash: rand::random(),
            }))
            .unwrap()
        })
        .collect();

    for content_key in content_keys.clone().into_iter() {
        // Store content to offer in the testnode db
        let dummy_content_value: HistoryContentValue =
            serde_json::from_value(json!(HISTORY_CONTENT_VALUE)).unwrap();
        let store_result = ipc_client
            .store(
                serde_json::from_str(&content_key).unwrap(),
                dummy_content_value,
            )
            .await
            .unwrap();
        assert!(store_result);
    }
    // Sort content keys to use for testing
    content_keys.sort();

    // Test paginate
    let result = ipc_client.paginate_local_content_keys(0, 1).await.unwrap();
    assert_eq!(result.total_entries, 20);

    let paginated_content_keys: Vec<String> = result
        .content_keys
        .iter()
        .map(|v| serde_json::to_string(v).unwrap())
        .collect();
    assert_eq!(paginated_content_keys, &content_keys[0..1]);

    // Test paginate with different offset & limit
    let result = ipc_client.paginate_local_content_keys(5, 10).await.unwrap();
    assert_eq!(result.total_entries, 20);
    let paginated_content_keys: Vec<String> = result
        .content_keys
        .iter()
        .map(|v| serde_json::to_string(v).unwrap())
        .collect();
    assert_eq!(paginated_content_keys, &content_keys[5..15]);

    // Test paginate with out of bounds limit
    let result = ipc_client
        .paginate_local_content_keys(19, 20)
        .await
        .unwrap();

    assert_eq!(result.total_entries, 20);
    let paginated_content_keys: Vec<String> = result
        .content_keys
        .iter()
        .map(|v| serde_json::to_string(v).unwrap())
        .collect();
    assert_eq!(paginated_content_keys, &content_keys[19..]);

    // Test paginate with out of bounds offset
    let result = ipc_client
        .paginate_local_content_keys(21, 10)
        .await
        .unwrap();
    assert_eq!(result.total_entries, 20);
    assert!(result
        .content_keys
        .iter()
        .map(|v| serde_json::to_string(v).unwrap())
        .next()
        .is_none());
}
