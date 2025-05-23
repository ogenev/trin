use std::{fmt, hash::Hash};

use alloy::primitives::B256;
use bytes::{BufMut, BytesMut};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};

use crate::{
    types::{content_key::overlay::OverlayContentKey, state_trie::nibbles::Nibbles},
    utils::bytes::hex_encode_compact,
    ContentKeyError, RawContentKey,
};

// Prefixes for the different types of state content keys:
// https://github.com/ethereum/portal-network-specs/blob/638aca50c913a749d0d762264d9a4ac72f1a9966/state-network.md
pub const STATE_ACCOUNT_TRIE_NODE_KEY_PREFIX: u8 = 0x20;
pub const STATE_STORAGE_TRIE_NODE_KEY_PREFIX: u8 = 0x21;
pub const STATE_CONTRACT_BYTECODE_KEY_PREFIX: u8 = 0x22;

/// A content key in the state overlay network.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateContentKey {
    /// A trie node from the state trie.
    AccountTrieNode(AccountTrieNodeKey),
    /// A trie node from some account's contract storage.
    ContractStorageTrieNode(ContractStorageTrieNodeKey),
    /// An account's contract bytecode.
    ContractBytecode(ContractBytecodeKey),
}

impl Hash for StateContentKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&self.to_bytes());
    }
}

/// A key for a trie node from the state trie.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct AccountTrieNodeKey {
    /// Trie path of the node.
    pub path: Nibbles,
    /// Hash of the node.
    pub node_hash: B256,
}

/// A key for a trie node from some account's contract storage.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct ContractStorageTrieNodeKey {
    /// Address hash of the account.
    pub address_hash: B256,
    /// Trie path of the node.
    pub path: Nibbles,
    /// Hash of the node.
    pub node_hash: B256,
}

/// A key for an account's contract bytecode.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct ContractBytecodeKey {
    /// Address hash of the account.
    pub address_hash: B256,
    /// Hash of the bytecode.
    pub code_hash: B256,
}

impl OverlayContentKey for StateContentKey {
    fn to_bytes(&self) -> RawContentKey {
        let mut bytes;

        match self {
            Self::AccountTrieNode(key) => {
                bytes = BytesMut::with_capacity(1 + key.ssz_bytes_len());
                bytes.put_u8(STATE_ACCOUNT_TRIE_NODE_KEY_PREFIX);
                bytes.put_slice(&key.as_ssz_bytes());
            }
            Self::ContractStorageTrieNode(key) => {
                bytes = BytesMut::with_capacity(1 + key.ssz_bytes_len());
                bytes.put_u8(STATE_STORAGE_TRIE_NODE_KEY_PREFIX);
                bytes.put_slice(&key.as_ssz_bytes());
            }
            Self::ContractBytecode(key) => {
                bytes = BytesMut::with_capacity(1 + key.ssz_bytes_len());
                bytes.put_u8(STATE_CONTRACT_BYTECODE_KEY_PREFIX);
                bytes.put_slice(&key.as_ssz_bytes());
            }
        }

        RawContentKey::from(bytes.freeze())
    }

    fn try_from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, ContentKeyError> {
        let bytes = bytes.as_ref();
        let Some((&selector, key)) = bytes.split_first() else {
            return Err(ContentKeyError::from_decode_error(
                DecodeError::InvalidLengthPrefix {
                    len: bytes.len(),
                    expected: 1,
                },
                bytes,
            ));
        };
        match selector {
            STATE_ACCOUNT_TRIE_NODE_KEY_PREFIX => AccountTrieNodeKey::from_ssz_bytes(key)
                .map(Self::AccountTrieNode)
                .map_err(|e| ContentKeyError::from_decode_error(e, bytes)),
            STATE_STORAGE_TRIE_NODE_KEY_PREFIX => ContractStorageTrieNodeKey::from_ssz_bytes(key)
                .map(Self::ContractStorageTrieNode)
                .map_err(|e| ContentKeyError::from_decode_error(e, bytes)),
            STATE_CONTRACT_BYTECODE_KEY_PREFIX => ContractBytecodeKey::from_ssz_bytes(key)
                .map(Self::ContractBytecode)
                .map_err(|e| ContentKeyError::from_decode_error(e, bytes)),
            _ => Err(ContentKeyError::from_decode_error(
                DecodeError::UnionSelectorInvalid(selector),
                bytes,
            )),
        }
    }
}

impl Serialize for StateContentKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for StateContentKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = RawContentKey::deserialize(deserializer)?;
        Self::try_from_bytes(bytes).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for StateContentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::AccountTrieNode(key) => format!(
                "AccountTrieNode {{ path: {}, node_hash: {} }}",
                &key.path,
                hex_encode_compact(key.node_hash)
            ),
            Self::ContractStorageTrieNode(key) => {
                format!(
                    "ContractStorageTrieNode {{ address_hash: {}, path: {}, node_hash: {} }}",
                    hex_encode_compact(key.address_hash),
                    &key.path,
                    hex_encode_compact(key.node_hash)
                )
            }
            Self::ContractBytecode(key) => {
                format!(
                    "ContractBytecode {{ address_hash: {}, code_hash: {} }}",
                    hex_encode_compact(key.address_hash),
                    hex_encode_compact(key.code_hash)
                )
            }
        };

        write!(f, "{s}")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use std::{path::PathBuf, str::FromStr};

    use alloy::primitives::{bytes, keccak256, Address};
    use anyhow::Result;
    use rstest::rstest;
    use serde_yaml::Value;

    use super::*;
    use crate::{test_utils::read_yaml_portal_spec_tests_file, utils::bytes::hex_decode};

    const TEST_DATA_DIRECTORY: &str = "tests/mainnet/state/serialization";

    #[test]
    fn account_trie_node_key() -> Result<()> {
        let yaml = read_yaml_file("account_trie_node_key.yaml")?;
        let yaml = yaml.as_mapping().unwrap();

        let expected_content_key = StateContentKey::AccountTrieNode(AccountTrieNodeKey {
            path: yaml_as_nibbles(&yaml["path"]),
            node_hash: yaml_as_b256(&yaml["node_hash"]),
        });

        assert_content_key(&yaml["content_key"], expected_content_key)
    }

    #[test]
    fn contract_storage_trie_node_key() -> Result<()> {
        let yaml = read_yaml_file("contract_storage_trie_node_key.yaml")?;
        let yaml = yaml.as_mapping().unwrap();

        let expected_content_key =
            StateContentKey::ContractStorageTrieNode(ContractStorageTrieNodeKey {
                address_hash: keccak256(yaml_as_address(&yaml["address"])),
                path: yaml_as_nibbles(&yaml["path"]),
                node_hash: yaml_as_b256(&yaml["node_hash"]),
            });

        assert_content_key(&yaml["content_key"], expected_content_key)
    }

    #[test]
    fn contract_bytecode_key() -> Result<()> {
        let yaml = read_yaml_file("contract_bytecode_key.yaml")?;
        let yaml = yaml.as_mapping().unwrap();

        let expected_content_key = StateContentKey::ContractBytecode(ContractBytecodeKey {
            address_hash: keccak256(yaml_as_address(&yaml["address"])),
            code_hash: yaml_as_b256(&yaml["code_hash"]),
        });

        assert_content_key(&yaml["content_key"], expected_content_key)
    }

    #[test]
    fn decode_empty_key_should_fail() {
        assert_eq!(
            StateContentKey::try_from_bytes([]).unwrap_err().to_string(),
            "Unable to decode key SSZ bytes 0x due to InvalidLengthPrefix { len: 0, expected: 1 }",
        );
    }

    #[test]
    fn decode_key_with_invalid_selector_should_fail() {
        let invalid_selector_content_key = bytes!(
            "0024000000c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4700005000000"
        );
        assert_eq!(
            StateContentKey::try_from_bytes(&invalid_selector_content_key)
                .unwrap_err()
                .to_string(),
            format!("Unable to decode key SSZ bytes {invalid_selector_content_key} due to UnionSelectorInvalid(0)"),
        );
    }

    #[rstest]
    #[case::account_trie_node_key("account_trie_node_key.yaml")]
    #[case::contract_storage_trie_node_key("contract_storage_trie_node_key.yaml")]
    #[case::contract_bytecode_key("contract_bytecode_key.yaml")]
    fn encode_decode(#[case] filename: &str) -> Result<()> {
        let yaml = read_yaml_file(filename)?;
        let yaml = yaml.as_mapping().unwrap();

        let content_key_bytes = RawContentKey::from_str(yaml["content_key"].as_str().unwrap())?;
        let content_key = StateContentKey::try_from_bytes(&content_key_bytes)?;

        assert_eq!(content_key.to_bytes(), content_key_bytes);
        Ok(())
    }

    #[rstest]
    #[case::account_trie_node_key("account_trie_node_key.yaml")]
    #[case::contract_storage_trie_node_key("contract_storage_trie_node_key.yaml")]
    #[case::contract_bytecode_key("contract_bytecode_key.yaml")]
    fn serde(#[case] filename: &str) -> Result<()> {
        let yaml = read_yaml_file(filename)?;
        let yaml = yaml.as_mapping().unwrap();

        let content_key = StateContentKey::deserialize(&yaml["content_key"])?;

        assert_eq!(
            serde_yaml::to_value(content_key).unwrap(),
            yaml["content_key"]
        );

        Ok(())
    }

    #[rstest]
    #[case::account_trie_node_key("account_trie_node_key.yaml")]
    #[case::contract_storage_trie_node_key("contract_storage_trie_node_key.yaml")]
    #[case::contract_bytecode_key("contract_bytecode_key.yaml")]
    fn content_id(#[case] filename: &str) -> Result<()> {
        let yaml = read_yaml_file(filename)?;
        let yaml = yaml.as_mapping().unwrap();

        let content_key_bytes = hex_decode(yaml["content_key"].as_str().unwrap())?;
        let content_key = StateContentKey::try_from_bytes(&content_key_bytes)?;
        let expected_content_id = yaml_as_b256(&yaml["content_id"]);

        assert_eq!(B256::from(content_key.content_id()), expected_content_id);
        Ok(())
    }

    fn read_yaml_file(filename: &str) -> anyhow::Result<Value> {
        read_yaml_portal_spec_tests_file(PathBuf::from(TEST_DATA_DIRECTORY).join(filename))
    }

    fn yaml_as_address(value: &Value) -> Address {
        Address::from_str(value.as_str().unwrap()).unwrap()
    }

    fn yaml_as_b256(value: &Value) -> B256 {
        B256::from_str(value.as_str().unwrap()).unwrap()
    }

    fn yaml_as_hex(value: &Value) -> Vec<u8> {
        hex_decode(value.as_str().unwrap()).unwrap()
    }

    fn yaml_as_nibbles(value: &Value) -> Nibbles {
        let nibbles: Vec<u8> = value
            .as_sequence()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect();
        Nibbles::try_from_unpacked_nibbles(&nibbles).unwrap()
    }

    fn assert_content_key(value: &Value, expected_content_key: StateContentKey) -> Result<()> {
        assert_eq!(
            StateContentKey::try_from_bytes(yaml_as_hex(value))?,
            expected_content_key,
            "decoding from bytes {value:?} didn't match expected key {expected_content_key:?}"
        );

        assert_eq!(
            StateContentKey::deserialize(value)?,
            expected_content_key,
            "deserialization from string {value:?} didn't match expected key {expected_content_key:?}");

        Ok(())
    }
}
