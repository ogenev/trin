use tokio::time::Duration;

/// The timeout in seconds is applied from when the request starts connecting until the response
/// body has finished. Also considered a total deadline.
pub const DEFAULT_TOTAL_REQUEST_TIMEOUT: u64 = 20;

// Number of seconds to wait before retrying a provider request
pub const FALLBACK_RETRY_AFTER: Duration = Duration::from_secs(5);

// PANDAOPS refers to the group of clients provisioned by the EF devops team.
// These are only intended to be used by core team members who have access to the nodes.
//
/// Execution layer PandaOps endpoint
// This endpoint points towards an archive node (erigon) and skips dshackle (by using el-cl url
// format), shackle is known to be somewhat buggy has caused some invalid responses.
// Reth's archive node, has also exhibited some problems with the concurrent requests rate we
// currently use.
pub const DEFAULT_BASE_EL_ENDPOINT: &str = "https://geth-lighthouse.mainnet.eu1.ethpandaops.io/";
pub const FALLBACK_BASE_EL_ENDPOINT: &str = "https://geth-lighthouse.mainnet.eu1.ethpandaops.io/";
/// Consensus layer PandaOps endpoint
/// We use Nimbus as the CL client, because it supports light client data by default.
pub const DEFAULT_BASE_CL_ENDPOINT: &str = "https://nimbus-geth.mainnet.eu1.ethpandaops.io/";
pub const FALLBACK_BASE_CL_ENDPOINT: &str = "https://nimbus.mainnet.na1.ethpandaops.io/";

// Number of seconds to wait before retrying a provider request for get_receipts
pub const GET_RECEIPTS_RETRY_AFTER: Duration = Duration::from_secs(1);
