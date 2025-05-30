//! The format for storing full flat state snapshots.
//!
//! Filename:
//!
//! ```text
//! <network-name>-<block-number>-<short-state-root>.e2ss
//! ```
//!
//! Type definitions:
//!
//! ```text
//! e2ss := Version | CompressedHeader | account*
//! account :=  CompressedAccount | CompressedStorage*
//!
//! Version             = { type: 0x6532, data: nil }
//! CompressedHeader    = { type: 0x0300,   data: snappyFramed(rlp(header)) }
//! CompressedAccount   = { type: 0x0800,   data: snappyFramed(rlp(Account)) }
//! CompressedStorage   = { type: 0x0900,   data: snappyFramed(rlp(Vec<StorageItem>)) }
//!
//! Account             = { address_hash, AccountState, raw_bytecode, storage_entry_count }
//! AccountState        = { nonce, balance, storage_root, code_hash }
//! StorageItem         = { storage_index_hash, value }
//! ```
//!
//! CompressedStorage can have a max of 10 million storage items, records must be filled before
//! creating a new one, and must be sorted by storage_index_hash across all entries.

use std::{
    fs::{self, File},
    io::{ErrorKind, Read, Write},
    ops::Deref,
    path::{Path, PathBuf},
};

use alloy::{
    consensus::Header,
    primitives::{hex, B256, U256},
    rlp::{Decodable, RlpDecodable, RlpEncodable},
};
use anyhow::{bail, ensure};
use ethportal_api::types::state_trie::account_state::AccountState;

use crate::{
    e2store::{
        stream::{E2StoreStreamReader, E2StoreStreamWriter},
        types::{Entry, VersionEntry},
    },
    entry_types,
    types::HeaderEntry,
    utils::underlying_io_error_kind,
};

pub const MAX_STORAGE_ITEMS: usize = 10_000_000;

/// The `E2SS` streaming writer.
///
/// Unlike [crate::era::Era] and [crate::era1::Era1], the `E2SS` files are too big to be held in
/// memory.
pub struct E2SSWriter {
    pub version: VersionEntry,
    pub header: HeaderEntry,

    writer: E2StoreStreamWriter<File>,
    pending_storage_entries: u32,
    path: PathBuf,
}

impl E2SSWriter {
    pub fn create(path: &Path, header: Header) -> anyhow::Result<Self> {
        fs::create_dir_all(path)?;
        ensure!(path.is_dir(), "e2ss path is not a directory: {:?}", path);
        let path = path.join(format!(
            "mainnet-{:010}-{}.e2ss",
            header.number,
            hex::encode(&header.state_root.as_slice()[..4])
        ));
        ensure!(!path.exists(), "e2ss file already exists: {:?}", path);
        let mut writer = E2StoreStreamWriter::create(&path)?;

        let version = VersionEntry::default();
        writer.append_entry(&Entry::from(&version))?;

        let header = HeaderEntry { header };
        writer.append_entry(&Entry::try_from(&header)?)?;

        Ok(Self {
            version,
            header,
            writer,
            pending_storage_entries: 0,
            path,
        })
    }

    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    pub fn append_entry(&mut self, entry: &AccountOrStorageEntry) -> anyhow::Result<usize> {
        let size = match entry {
            AccountOrStorageEntry::Account(account) => {
                ensure!(
                    self.pending_storage_entries == 0,
                    "Invalid append entry state: expected a storage entry, got an account entry. Still have {} storage entries left to append", self.pending_storage_entries                
                );

                self.pending_storage_entries = account.storage_count;
                let entry: Entry = account.clone().try_into()?;
                self.writer.append_entry(&entry)?;
                entry.value.len()
            }
            AccountOrStorageEntry::Storage(storage) => {
                match self.pending_storage_entries {
                    0 => bail!("Invalid append entry state: expected an account entry, got a storage entry. No storage entries left to append for the account"),
                    1 => ensure!(
                        storage.len() <= MAX_STORAGE_ITEMS,
                        "Storage entry can't have more than 10 million items",
                    ),
                    _ => ensure!(
                        storage.len() == MAX_STORAGE_ITEMS,
                        "Only last storage entry can have less than 10 million items",
                    ),
                }

                self.pending_storage_entries -= 1;
                let entry: Entry = storage.clone().try_into()?;
                self.writer.append_entry(&entry)?;
                entry.value.len()
            }
        };
        Ok(size)
    }

    pub fn flush(&mut self) -> anyhow::Result<()> {
        self.writer.flush()
    }
}

/// The `E2SS` streaming reader.
///
/// Unlike [crate::era::Era] and [crate::era1::Era1], the `E2SS` files are too big to be held in
/// memory.
pub struct E2SSReader {
    pub version: VersionEntry,
    pub header: HeaderEntry,

    reader: E2StoreStreamReader<File>,
    pending_storage_entries: u32,
    path: PathBuf,
}

impl E2SSReader {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let mut reader = E2StoreStreamReader::open(path)?;

        let version = VersionEntry::try_from(&reader.next_entry()?)?;
        let header = HeaderEntry::try_from(&reader.next_entry()?)?;

        Ok(Self {
            version,
            header,
            reader,
            pending_storage_entries: 0,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        self.path.as_path()
    }
}

impl Iterator for E2SSReader {
    type Item = AccountOrStorageEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pending_storage_entries > 0 {
            self.pending_storage_entries -= 1;

            let raw_storage_entry = match self.reader.next_entry() {
                Ok(raw_storage_entry) => raw_storage_entry,
                Err(err) => panic!("Failed to read next storage entry: {:?}", err),
            };

            let storage_entry = match StorageEntry::try_from(&raw_storage_entry) {
                Ok(storage_entry) => storage_entry,
                Err(err) => panic!("Failed to decode next storage entry: {:?}", err),
            };
            return Some(AccountOrStorageEntry::Storage(storage_entry));
        }

        let raw_account_entry = match self.reader.next_entry() {
            Ok(raw_account_entry) => raw_account_entry,
            Err(err) => match err {
                // If we read to the end of the error file we should get this
                err if underlying_io_error_kind(&err).is_some()
                    && underlying_io_error_kind(&err)
                        .expect("We already checked there is some")
                        == ErrorKind::UnexpectedEof =>
                {
                    return None
                }
                err => panic!("Failed reading next account entry: {:?}", err),
            },
        };

        let account_entry = match AccountEntry::try_from(&raw_account_entry) {
            Ok(account_entry) => account_entry,
            Err(err) => panic!("Failed decoding next account entry: {:?}", err),
        };
        self.pending_storage_entries = account_entry.storage_count;
        Some(AccountOrStorageEntry::Account(account_entry))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum AccountOrStorageEntry {
    Account(AccountEntry),
    Storage(StorageEntry),
}

#[derive(Clone, Eq, PartialEq, Debug, RlpEncodable, RlpDecodable)]
pub struct AccountEntry {
    pub address_hash: B256,
    pub account_state: AccountState,
    pub bytecode: Vec<u8>,
    pub storage_count: u32,
}

impl TryFrom<&Entry> for AccountEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == entry_types::COMPRESSED_ACCOUNT,
            "invalid account entry: incorrect account type"
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid account entry: incorrect account reserved bytes"
        );
        let mut decoder = snap::read::FrameDecoder::new(&entry.value[..]);
        let mut buf: Vec<u8> = vec![];
        decoder.read_to_end(&mut buf)?;
        let account = Decodable::decode(&mut buf.as_slice())?;
        Ok(account)
    }
}

impl TryFrom<AccountEntry> for Entry {
    type Error = anyhow::Error;

    fn try_from(value: AccountEntry) -> Result<Self, Self::Error> {
        let rlp_encoded = alloy::rlp::encode(value);
        let mut encoder = snap::write::FrameEncoder::new(vec![]);
        let bytes_written = encoder.write(&rlp_encoded)?;
        ensure!(
            bytes_written == rlp_encoded.len(),
            "FrameEncoder should write whole rlp encoding"
        );
        let encoded = encoder.into_inner()?;
        Ok(Entry::new(entry_types::COMPRESSED_ACCOUNT, encoded))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct StorageEntry(pub Vec<StorageItem>);

impl Deref for StorageEntry {
    type Target = Vec<StorageItem>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Eq, PartialEq, Debug, RlpEncodable, RlpDecodable)]
pub struct StorageItem {
    pub storage_index_hash: B256,
    pub value: U256,
}

impl TryFrom<&Entry> for StorageEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == entry_types::COMPRESSED_STORAGE,
            "invalid storage entry: incorrect storage type"
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid storage entry: incorrect storage reserved bytes"
        );
        let mut decoder = snap::read::FrameDecoder::new(&entry.value[..]);
        let mut buf: Vec<u8> = vec![];
        decoder.read_to_end(&mut buf)?;
        let storage = Decodable::decode(&mut buf.as_slice())?;
        Ok(Self(storage))
    }
}

impl TryFrom<StorageEntry> for Entry {
    type Error = anyhow::Error;

    fn try_from(value: StorageEntry) -> Result<Self, Self::Error> {
        let rlp_encoded = alloy::rlp::encode(value.0);
        let mut encoder = snap::write::FrameEncoder::new(vec![]);
        let bytes_written = encoder.write(&rlp_encoded)?;
        ensure!(
            bytes_written == rlp_encoded.len(),
            "FrameEncoder should write whole rlp encoding"
        );
        let encoded = encoder.into_inner()?;
        Ok(Entry::new(entry_types::COMPRESSED_STORAGE, encoded))
    }
}

#[cfg(test)]
mod tests {
    use trin_utils::dir::create_temp_test_dir;

    use super::*;
    use crate::e2store::types::VersionEntry;

    #[test]
    fn test_e2ss_stream_write_and_read() -> anyhow::Result<()> {
        // setup
        let tmp_dir = create_temp_test_dir()?;

        // create fake execution block header
        let header = Header {
            number: 5_000_000,
            ..Default::default()
        };

        // create a new e2store file and write some data to it
        let mut e2ss_writer = E2SSWriter::create(tmp_dir.path(), header.clone())?;

        let e2ss_path = tmp_dir.path().join(format!(
            "mainnet-{:010}-{}.e2ss",
            header.number,
            hex::encode(&header.state_root.as_slice()[..4])
        ));
        assert_eq!(e2ss_writer.path(), e2ss_path);

        let account = AccountOrStorageEntry::Account(AccountEntry {
            address_hash: B256::default(),
            account_state: AccountState::default(),
            bytecode: vec![],
            storage_count: 1,
        });

        assert_eq!(e2ss_writer.pending_storage_entries, 0);
        let size = e2ss_writer.append_entry(&account)?;
        assert_eq!(size, 101);
        assert_eq!(e2ss_writer.pending_storage_entries, 1);

        let storage = AccountOrStorageEntry::Storage(StorageEntry(vec![StorageItem {
            storage_index_hash: B256::default(),
            value: U256::default(),
        }]));

        let size = e2ss_writer.append_entry(&storage)?;
        assert_eq!(size, 29);
        assert_eq!(e2ss_writer.pending_storage_entries, 0);
        e2ss_writer.flush()?;
        drop(e2ss_writer);

        // read results and see if they match
        let mut e2ss_reader = E2SSReader::open(&e2ss_path)?;
        assert_eq!(e2ss_reader.path(), &e2ss_path);

        let default_version_entry = VersionEntry::default();
        assert_eq!(e2ss_reader.version, default_version_entry);
        assert_eq!(e2ss_reader.header, HeaderEntry { header });
        assert_eq!(e2ss_reader.pending_storage_entries, 0);
        let read_account_tuple = e2ss_reader.next().unwrap();
        assert_eq!(account, read_account_tuple);
        assert_eq!(e2ss_reader.pending_storage_entries, 1);

        let read_storage_tuple = e2ss_reader.next().unwrap();
        assert_eq!(storage, read_storage_tuple);
        assert_eq!(e2ss_reader.pending_storage_entries, 0);

        // cleanup
        tmp_dir.close()?;
        Ok(())
    }
}
