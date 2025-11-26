//! Query functions for auction state.

use auction_types::{AuctionConfig, AuctionResult, AuctionState, EncryptedBid};

/// Query interface for auction data.
///
/// In production, this would interact with the rollup RPC.
pub trait AuctionQuery {
    /// Get auction configuration by ID.
    fn get_auction(&self, auction_id: u64) -> Option<AuctionConfig>;

    /// Get auction state by ID.
    fn get_auction_state(&self, auction_id: u64) -> Option<AuctionState>;

    /// Get all bids for an auction.
    fn get_auction_bids(&self, auction_id: u64) -> Vec<EncryptedBid>;

    /// Get auction result if settled.
    fn get_auction_result(&self, auction_id: u64) -> Option<AuctionResult>;

    /// Get user's escrow balance.
    fn get_escrow_balance(&self, address: &[u8; 32]) -> u64;

    /// Check if user has bid in auction.
    fn has_bid(&self, auction_id: u64, bidder: &[u8; 32]) -> bool;
}

/// Mock query client for testing.
#[derive(Default)]
pub struct MockQueryClient {
    // In-memory state for testing
}

impl MockQueryClient {
    pub fn new() -> Self {
        Self::default()
    }
}

impl AuctionQuery for MockQueryClient {
    fn get_auction(&self, _auction_id: u64) -> Option<AuctionConfig> {
        None
    }

    fn get_auction_state(&self, _auction_id: u64) -> Option<AuctionState> {
        None
    }

    fn get_auction_bids(&self, _auction_id: u64) -> Vec<EncryptedBid> {
        vec![]
    }

    fn get_auction_result(&self, _auction_id: u64) -> Option<AuctionResult> {
        None
    }

    fn get_escrow_balance(&self, _address: &[u8; 32]) -> u64 {
        0
    }

    fn has_bid(&self, _auction_id: u64, _bidder: &[u8; 32]) -> bool {
        false
    }
}
