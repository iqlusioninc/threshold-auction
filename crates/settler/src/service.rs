//! Settlement service implementation.

use anyhow::Result;
use auction_crypto::decrypt;
use auction_types::{
    circuit_io::AuctionTypeCompact, Address, AuctionConfig, AuctionState, DecryptionKey,
    EncryptedBid, PedersenCommitment, SP1AuctionProof,
};
use tracing::{info, warn};

use crate::prover::generate_mock_proof;

/// Configuration for the settlement service.
#[derive(Debug, Clone)]
pub struct SettlerConfig {
    /// RPC endpoint for the rollup
    pub rpc_endpoint: String,
    /// Private key for submitting transactions (hex encoded)
    pub private_key: Option<String>,
    /// Whether to use GPU proving
    pub use_gpu: bool,
    /// Polling interval in seconds
    pub poll_interval_secs: u64,
    /// Use mock proofs instead of real SP1 proving
    pub mock_proving: bool,
}

impl Default for SettlerConfig {
    fn default() -> Self {
        Self {
            rpc_endpoint: "http://localhost:26657".to_string(),
            private_key: None,
            use_gpu: false,
            poll_interval_secs: 10,
            mock_proving: true, // Default to mock for development
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

    /// Start the settlement service loop.
    pub async fn start(&self) -> Result<()> {
        info!("Starting settlement service");
        info!("RPC endpoint: {}", self.config.rpc_endpoint);
        info!("Mock proving: {}", self.config.mock_proving);

        loop {
            // Poll for auctions ready for settlement
            match self.poll_and_settle().await {
                Ok(settled) => {
                    if settled > 0 {
                        info!("Settled {} auctions", settled);
                    }
                }
                Err(e) => {
                    warn!("Settlement error: {}", e);
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(self.config.poll_interval_secs))
                .await;
        }
    }

    /// Poll for settleable auctions and settle them.
    async fn poll_and_settle(&self) -> Result<usize> {
        // TODO: Implement actual RPC polling
        // For now, this is a placeholder
        Ok(0)
    }

    /// Settle a specific auction given all required data.
    pub fn settle_auction(
        &self,
        auction: &AuctionConfig,
        bids: &[EncryptedBid],
        decryption_key: &DecryptionKey,
    ) -> Result<SP1AuctionProof> {
        // Verify auction is in correct state
        if auction.state != AuctionState::Decrypted && auction.state != AuctionState::Sealed {
            anyhow::bail!(
                "Auction {} not ready for settlement (state: {:?})",
                auction.auction_id,
                auction.state
            );
        }

        // Decrypt all bids
        let decrypted = self.decrypt_bids(bids, decryption_key)?;

        // Extract data for proving
        let commitments: Vec<PedersenCommitment> =
            bids.iter().map(|b| b.commitment.clone()).collect();

        let bid_values: Vec<u64> = decrypted.iter().map(|(v, _)| *v).collect();
        let randomness: Vec<[u8; 32]> = decrypted.iter().map(|(_, r)| *r).collect();

        // Get quality scores if GSP
        let quality_scores = match &auction.auction_type {
            auction_types::AuctionType::GeneralizedSecondPrice { quality_scores } => {
                // Map addresses to scores
                bids.iter()
                    .map(|b| {
                        quality_scores
                            .iter()
                            .find(|(addr, _)| addr == &b.bidder)
                            .map(|(_, score)| *score)
                            .unwrap_or(100)
                    })
                    .collect()
            }
            _ => vec![],
        };

        let auction_type = match &auction.auction_type {
            auction_types::AuctionType::FirstPrice => AuctionTypeCompact::FirstPrice,
            auction_types::AuctionType::SecondPrice => AuctionTypeCompact::SecondPrice,
            auction_types::AuctionType::GeneralizedSecondPrice { .. } => AuctionTypeCompact::GSP,
        };

        // Generate proof
        if self.config.mock_proving {
            generate_mock_proof(
                auction.auction_id,
                auction_type,
                commitments,
                bid_values,
                randomness,
                quality_scores,
                auction.reserve_price,
            )
        } else {
            // TODO: Use real SP1 prover when ELF is built
            anyhow::bail!("Real SP1 proving not yet implemented - use mock_proving=true")
        }
    }

    /// Decrypt all bids for an auction using the decryption key.
    pub fn decrypt_bids(
        &self,
        bids: &[EncryptedBid],
        decryption_key: &DecryptionKey,
    ) -> Result<Vec<(u64, [u8; 32])>> {
        let mut decrypted = Vec::with_capacity(bids.len());

        for bid in bids {
            let plaintext = decrypt(&bid.ciphertext, &decryption_key.sigma)?;

            // Parse plaintext: bid_value (8 bytes) || randomness (32 bytes)
            if plaintext.len() < 40 {
                anyhow::bail!("Invalid plaintext length for bid from {:?}", bid.bidder);
            }

            let bid_value = u64::from_le_bytes(plaintext[..8].try_into()?);
            let mut randomness = [0u8; 32];
            randomness.copy_from_slice(&plaintext[8..40]);

            decrypted.push((bid_value, randomness));
        }

        Ok(decrypted)
    }

    /// Get winner address from proof result.
    pub fn get_winner(&self, bids: &[EncryptedBid], winner_index: u32) -> Option<Address> {
        bids.get(winner_index as usize).map(|b| b.bidder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auction_types::{G1Point, G2Point, ThresholdCiphertext};

    fn mock_encrypted_bid(bidder: Address, deposit: u64) -> EncryptedBid {
        EncryptedBid {
            bidder,
            commitment: PedersenCommitment {
                point: G1Point([1u8; 48]),
            },
            ciphertext: ThresholdCiphertext {
                ephemeral_pubkey: G2Point([0u8; 96]),
                ciphertext: vec![0u8; 48],
                tag: [0u8; 16],
                nonce: [0u8; 12],
            },
            deposit,
            timestamp: 0,
        }
    }

    #[test]
    fn test_settler_config_default() {
        let config = SettlerConfig::default();
        assert_eq!(config.poll_interval_secs, 10);
        assert!(config.mock_proving);
    }

    #[test]
    fn test_get_winner() {
        let service = SettlementService::new(SettlerConfig::default());
        let bids = vec![
            mock_encrypted_bid([1u8; 32], 100),
            mock_encrypted_bid([2u8; 32], 200),
            mock_encrypted_bid([3u8; 32], 150),
        ];

        assert_eq!(service.get_winner(&bids, 0), Some([1u8; 32]));
        assert_eq!(service.get_winner(&bids, 1), Some([2u8; 32]));
        assert_eq!(service.get_winner(&bids, 2), Some([3u8; 32]));
        assert_eq!(service.get_winner(&bids, 3), None);
    }
}
