//! Settlement service implementation.

use anyhow::Result;
use auction_types::{AuctionConfig, DecryptionKey, EncryptedBid, SP1AuctionProof};

/// Configuration for the settlement service.
#[derive(Debug, Clone)]
pub struct SettlerConfig {
    /// RPC endpoint for the rollup
    pub rpc_endpoint: String,
    /// Private key for submitting transactions
    pub private_key: Option<String>,
    /// Whether to use GPU proving
    pub use_gpu: bool,
    /// Polling interval in seconds
    pub poll_interval_secs: u64,
}

impl Default for SettlerConfig {
    fn default() -> Self {
        Self {
            rpc_endpoint: "http://localhost:26657".to_string(),
            private_key: None,
            use_gpu: false,
            poll_interval_secs: 10,
        }
    }
}

/// The settlement service.
pub struct SettlementService {
    config: SettlerConfig,
}

impl SettlementService {
    /// Create a new settlement service.
    pub fn new(config: SettlerConfig) -> Self {
        Self { config }
    }

    /// Start the settlement service.
    pub async fn start(&self) -> Result<()> {
        // TODO: Implement service loop
        // 1. Poll for auctions ready for settlement
        // 2. Fetch bids and decryption keys
        // 3. Generate proofs
        // 4. Submit settlements
        Ok(())
    }

    /// Settle a specific auction.
    pub async fn settle_auction(&self, auction_id: u64) -> Result<SP1AuctionProof> {
        // TODO: Implement auction settlement
        // 1. Fetch auction config
        // 2. Fetch encrypted bids
        // 3. Fetch decryption key
        // 4. Decrypt bids
        // 5. Run auction logic
        // 6. Generate SP1 proof
        todo!("Implement settle_auction")
    }

    /// Decrypt all bids for an auction using the decryption key.
    pub fn decrypt_bids(
        &self,
        bids: &[EncryptedBid],
        decryption_key: &DecryptionKey,
    ) -> Result<Vec<(u64, [u8; 32])>> {
        use auction_crypto::decrypt;

        let mut decrypted = Vec::with_capacity(bids.len());

        for bid in bids {
            let plaintext = decrypt(&bid.ciphertext, &decryption_key.sigma)?;

            // Parse plaintext: bid_value (8 bytes) || randomness (32 bytes)
            if plaintext.len() < 40 {
                anyhow::bail!("Invalid plaintext length");
            }

            let bid_value = u64::from_le_bytes(plaintext[..8].try_into()?);
            let mut randomness = [0u8; 32];
            randomness.copy_from_slice(&plaintext[8..40]);

            decrypted.push((bid_value, randomness));
        }

        Ok(decrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settler_config_default() {
        let config = SettlerConfig::default();
        assert_eq!(config.poll_interval_secs, 10);
        assert!(!config.use_gpu);
    }
}
