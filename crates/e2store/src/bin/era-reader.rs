use std::{
    fs,
    path::{Path, PathBuf},
};

use alloy::{
    consensus::{
        proofs::{calculate_transaction_root, calculate_withdrawals_root},
        Header, TxEnvelope,
    },
    eips::eip4895::Withdrawal,
    primitives::{b256, Bloom, B256, B64, U256},
};
use alloy_rlp::Decodable;
use anyhow::{anyhow, bail, Context};
use clap::Parser;
use e2store::era::Era;
use ethportal_api::{
    consensus::{
        beacon_block::{BeaconBlock, SignedBeaconBlock},
        body::Transactions,
        execution_payload::ExecutionPayloadDeneb,
    },
    types::execution::header_with_proof::{
        build_historical_summaries_proof, BlockHeaderProof, HeaderWithProof,
    },
    ContentValue, HistoryContentKey, HistoryContentValue, OverlayContentKey,
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use ssz::Encode;

#[derive(Debug, Parser)]
#[command(
    name = "Era Reader",
    about = "Reads Era files from a folder and provides information about them."
)]
struct Config {
    #[arg(help = "The path to the folder containing Era files.")]
    folder_path: PathBuf,

    #[arg(short, long, help = "List only file names without processing content.")]
    list_only: bool,

    #[arg(
        short,
        long,
        help = "Show detailed information about blocks in the Era files."
    )]
    detailed: bool,

    #[arg(
        short,
        long,
        help = "Save BeaconState as SSZ bytes to a file with the same name but .ssz extension"
    )]
    save_state: bool,

    #[arg(
        short = 'b',
        long,
        help = "Save the last two beacon blocks as SSZ files"
    )]
    save_blocks: bool,

    #[arg(
        short = 'k',
        long,
        help = "Create history content key and value from HeaderWithProof and save as hex in YAML"
    )]
    save_content_key_value: bool,
}

/// Structure for storing content key-value pair
#[derive(Serialize, Deserialize)]
struct ContentKeyValue {
    content_key: String,
    content_value: String,
}

fn main() -> anyhow::Result<()> {
    let config = Config::parse();

    // Check if the folder exists
    if !config.folder_path.exists() {
        bail!("Folder does not exist: {}", config.folder_path.display());
    }

    if !config.folder_path.is_dir() {
        bail!("Path is not a directory: {}", config.folder_path.display());
    }

    // Find all files with .era extension
    let era_files = find_era_files(&config.folder_path)?;

    println!("Found {} Era files:", era_files.len());

    if era_files.is_empty() {
        println!(
            "No Era files found in folder: {}",
            config.folder_path.display()
        );
        return Ok(());
    }

    // If list_only flag is set, just list the file names
    if config.list_only {
        for file_path in era_files {
            println!("  {}", file_path.display());
        }
        return Ok(());
    }

    // Process each Era file
    for file_path in era_files {
        process_era_file(
            &file_path,
            config.detailed,
            config.save_state,
            config.save_blocks,
            config.save_content_key_value,
        )?;
    }

    Ok(())
}

/// Find all files with .era extension in the specified directory
fn find_era_files(dir_path: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut era_files = Vec::new();

    for entry in fs::read_dir(dir_path)
        .with_context(|| format!("Failed to read directory: {}", dir_path.display()))?
    {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            if let Some(extension) = path.extension() {
                if extension == "era" {
                    era_files.push(path);
                }
            }
        }
    }

    era_files.sort();
    Ok(era_files)
}

/// Process an Era file and display its information
fn process_era_file(
    file_path: &Path,
    detailed: bool,
    save_state: bool,
    save_blocks: bool,
    save_content_key_value: bool,
) -> anyhow::Result<()> {
    println!("\nProcessing file: {}", file_path.display());

    // Read the Era file
    let era = Era::read_from_file(file_path.to_str().unwrap())
        .with_context(|| format!("Failed to read Era file: {}", file_path.display()))?;

    // Print basic information
    println!("  Version: {:?}", era.version);
    println!("  Block count: {}", era.blocks.len());

    if era.blocks.is_empty() {
        println!("  No blocks in this Era file");
        return Ok(());
    }

    // Print information about first and last blocks
    let first_block = &era.blocks.first().unwrap().block;
    let last_block = &era.blocks.last().unwrap().block;

    println!(
        "  First block slot: {}",
        first_block.message_deneb().unwrap().slot
    );
    println!(
        "  Last block slot: {}",
        last_block.message_deneb().unwrap().slot
    );

    let first_exec_block = first_block.execution_block_number();
    let last_exec_block = last_block.execution_block_number();
    println!(
        "  Execution block range: {} to {}",
        first_exec_block, last_exec_block
    );

    // If detailed flag is set, print information about all blocks
    if detailed {
        println!("\n  Block details:");
        for (i, compressed_block) in era.blocks.iter().enumerate() {
            let block = &compressed_block.block;
            print!(
                "    Block {}: Slot {}",
                i,
                block.message_deneb().unwrap().slot
            );

            let exec_block = get_execution_block_number(block);
            println!(" (Execution block: {})", exec_block);
        }
    }

    // Save BeaconState as SSZ bytes if requested
    if save_state {
        // Get the BeaconState from the era
        let beacon_state = &era.era_state.state;
        let state_slot = beacon_state.slot();

        // Create output file path with descriptive name including slot number
        let mut ssz_file_path = file_path.to_path_buf();
        ssz_file_path.set_file_name(format!("state_slot_{}.ssz", state_slot));

        // Encode the BeaconState to SSZ bytes
        let ssz_bytes = beacon_state.as_ssz_bytes();

        // Write to file
        fs::write(&ssz_file_path, &ssz_bytes)
            .with_context(|| format!("Failed to write SSZ file: {}", ssz_file_path.display()))?;

        println!("  Saved BeaconState as SSZ to: {}", ssz_file_path.display());
        println!("  Beacon state slot: {}", state_slot);
        println!("  SSZ file size: {} bytes", ssz_bytes.len());
    }

    // Save the last two beacon blocks as SSZ files if requested
    if save_blocks && era.blocks.len() >= 2 {
        let blocks_len = era.blocks.len();

        // Extract the last two blocks
        let last_block = era.blocks[blocks_len - 1].block.message_deneb().unwrap();
        let second_last_block = era.blocks[blocks_len - 2].block.message_deneb().unwrap();

        // Save the last block
        let last_block_slot = last_block.slot;
        let mut last_block_path = file_path.to_path_buf();
        last_block_path.set_file_name(format!("block_slot_{}.ssz", last_block_slot));

        let last_block_ssz = last_block.as_ssz_bytes();
        fs::write(&last_block_path, &last_block_ssz).with_context(|| {
            format!(
                "Failed to write last block SSZ file: {}",
                last_block_path.display()
            )
        })?;

        println!(
            "  Saved last block (slot {}) as SSZ to: {}",
            last_block_slot,
            last_block_path.display()
        );
        println!("  Last block SSZ file size: {} bytes", last_block_ssz.len());

        // Save the second last block
        let second_last_slot = second_last_block.slot;
        let mut second_last_path = file_path.to_path_buf();
        second_last_path.set_file_name(format!("block_slot_{}.ssz", second_last_slot));

        let second_last_ssz = second_last_block.as_ssz_bytes();
        fs::write(&second_last_path, &second_last_ssz).with_context(|| {
            format!(
                "Failed to write second last block SSZ file: {}",
                second_last_path.display()
            )
        })?;

        println!(
            "  Saved second last block (slot {}) as SSZ to: {}",
            second_last_slot,
            second_last_path.display()
        );
        println!(
            "  Second last block SSZ file size: {} bytes",
            second_last_ssz.len()
        );
    } else if save_blocks {
        println!(
            "  Not enough blocks to save the last two (found only {} blocks)",
            era.blocks.len()
        );
    }

    // Extract and create content key-value pairs
    if save_content_key_value {
        println!("\n  Creating content key-value pairs:");

        // Process the last block to create content key-value
        if let Some(last_compressed_block) = era.blocks.last() {
            let signed_block = &last_compressed_block.block;

            // Unwrap the Deneb variant of the beacon block
            let block_deneb = match signed_block.message_deneb() {
                Ok(deneb) => deneb,
                Err(_) => {
                    println!("  Block is not in Deneb format, skipping");
                    return Err(anyhow!("Block is not in Deneb format"));
                }
            };

            // Get the beacon state
            let beacon_state = &era.era_state.state;

            // Convert BeaconBlockDeneb to BeaconBlock
            let beacon_block = BeaconBlock::Deneb(block_deneb.clone());

            let execution_payload = block_deneb.body.execution_payload.clone();
            let block_number = execution_payload.block_number;

            // Create a Header from the ExecutionPayload
            let transactions = decode_transactions(&execution_payload.transactions)?;
            let withdrawals: Vec<Withdrawal> = execution_payload
                .withdrawals
                .iter()
                .map(Withdrawal::from)
                .collect();

            let header = pre_pectra_execution_payload_to_header(
                execution_payload.clone(),
                &transactions,
                &withdrawals,
            )?;

            // Build proper historical summaries proof using the beacon block and state
            println!("  Building historical summaries proof...");
            let proof =
                build_historical_summaries_proof(block_deneb.slot, beacon_state, &beacon_block);

            let header_with_proof = HeaderWithProof {
                header,
                proof: BlockHeaderProof::HistoricalSummaries(proof),
            };

            // Create history content key and value
            let history_content_key =
                HistoryContentKey::new_block_header_by_hash(header_with_proof.header.hash_slow());
            let content_key_hex = history_content_key.to_hex();
            let history_content_value =
                HistoryContentValue::BlockHeaderWithProof(header_with_proof);
            let content_value_hex = history_content_value.to_hex();

            // Create YAML file with hex-encoded key and value
            let content_key_value = ContentKeyValue {
                content_key: content_key_hex.clone(),
                content_value: content_value_hex,
            };

            let mut yaml_path = file_path.to_path_buf();
            yaml_path.set_file_name(format!("{}.yaml", block_number));

            let yaml = serde_yaml::to_string(&content_key_value)
                .with_context(|| "Failed to serialize content key-value to YAML")?;

            fs::write(&yaml_path, yaml).with_context(|| {
                format!(
                    "Failed to write content key-value YAML file: {}",
                    yaml_path.display()
                )
            })?;

            println!(
                "  Saved content key-value for block {} to: {}",
                block_number,
                yaml_path.display()
            );
            println!("  Content key: {}", content_key_hex);
            println!(
                "  Content value length: {} bytes",
                history_content_value.encode().len()
            );
        }
    } else {
        println!("  No blocks found to extract headers");
    }

    Ok(())
}

/// Extract execution block number from a beacon block if available
fn get_execution_block_number(block: &SignedBeaconBlock) -> u64 {
    block.execution_block_number()
}

pub fn pre_pectra_execution_payload_to_header(
    payload: ExecutionPayloadDeneb,
    transactions: &[TxEnvelope],
    withdrawals: &[Withdrawal],
) -> anyhow::Result<Header> {
    pub const EMPTY_UNCLE_ROOT_HASH: B256 =
        b256!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347");

    let transactions_root = calculate_transaction_root(transactions);
    let withdrawals_root = calculate_withdrawals_root(withdrawals);
    Ok(Header {
        parent_hash: payload.parent_hash,
        ommers_hash: EMPTY_UNCLE_ROOT_HASH,
        beneficiary: payload.fee_recipient,
        state_root: payload.state_root,
        transactions_root,
        receipts_root: payload.receipts_root,
        logs_bloom: Bloom::from_slice(payload.logs_bloom.to_vec().as_slice()),
        difficulty: U256::ZERO,
        number: payload.block_number,
        gas_limit: payload.gas_limit,
        gas_used: payload.gas_used,
        timestamp: payload.timestamp,
        extra_data: payload.extra_data.to_vec().into(),
        mix_hash: payload.prev_randao,
        nonce: B64::ZERO,
        base_fee_per_gas: Some(payload.base_fee_per_gas.to()),
        withdrawals_root: Some(withdrawals_root),
        blob_gas_used: None,
        excess_blob_gas: None,
        parent_beacon_block_root: None,
        requests_hash: None,
    })
}

pub fn decode_transactions(transactions: &Transactions) -> anyhow::Result<Vec<TxEnvelope>> {
    transactions
        .into_par_iter()
        .map(|raw_tx| {
            TxEnvelope::decode(&mut &**raw_tx)
                .map_err(|err| anyhow::anyhow!("Failed decoding transaction rlp: {err:?}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()
}
