//! Query handlers for the auction module.
//!
//! These functions provide read-only access to auction state.

use crate::state::AuctionState as ModuleState;
use auction_types::{
    Address, AuctionConfig, AuctionResult, AuctionState, DecryptionKey, EncryptedBid,
    MasterPublicKey,
};
use serde::{Deserialize, Serialize};

/// Query request types.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AuctionQuery {
    /// Get auction details by ID.
    GetAuction { auction_id: u64 },

    /// Get all auctions (paginated).
    ListAuctions { offset: u64, limit: u64 },

    /// Get all bids for an auction.
    GetAuctionBids { auction_id: u64 },

    /// Get a specific bid.
    GetBid { auction_id: u64, bidder: Address },

    /// Get auction result.
    GetResult { auction_id: u64 },

    /// Get user's escrow balance.
    GetEscrow { address: Address },

    /// Get decryption key for auction round.
    GetDecryptionKey { auction_id: u64, round: u64 },

    /// Get partial shares count for auction round.
    GetPartialSharesCount { auction_id: u64, round: u64 },

    /// Get master public key.
    GetMasterPublicKey,

    /// Check if SP1 vkey is set.
    IsSP1Configured,
}

/// Query response types.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AuctionQueryResponse {
    /// Auction details.
    Auction(Option<AuctionConfig>),

    /// List of auctions.
    AuctionList(Vec<AuctionConfig>),

    /// Bids for an auction.
    Bids(Vec<EncryptedBid>),

    /// Single bid.
    Bid(Option<EncryptedBid>),

    /// Auction result.
    Result(Option<AuctionResult>),

    /// Escrow balance.
    Escrow(u64),

    /// Decryption key.
    DecryptionKey(Option<DecryptionKey>),

    /// Partial shares count.
    PartialSharesCount(usize),

    /// Master public key.
    MasterPublicKey(Option<MasterPublicKey>),

    /// SP1 configuration status.
    SP1Configured(bool),
}

/// Handle a query.
pub fn handle_query(state: &ModuleState, query: AuctionQuery) -> AuctionQueryResponse {
    match query {
        AuctionQuery::GetAuction { auction_id } => {
            AuctionQueryResponse::Auction(state.get_auction(auction_id).cloned())
        }

        AuctionQuery::ListAuctions { offset, limit } => {
            let auctions: Vec<AuctionConfig> = state
                .auctions
                .values()
                .skip(offset as usize)
                .take(limit as usize)
                .cloned()
                .collect();
            AuctionQueryResponse::AuctionList(auctions)
        }

        AuctionQuery::GetAuctionBids { auction_id } => {
            let bids = state
                .get_auction_bids(auction_id)
                .into_iter()
                .cloned()
                .collect();
            AuctionQueryResponse::Bids(bids)
        }

        AuctionQuery::GetBid { auction_id, bidder } => {
            let bid = state.bids.get(&(auction_id, bidder)).cloned();
            AuctionQueryResponse::Bid(bid)
        }

        AuctionQuery::GetResult { auction_id } => {
            AuctionQueryResponse::Result(state.results.get(&auction_id).cloned())
        }

        AuctionQuery::GetEscrow { address } => {
            AuctionQueryResponse::Escrow(state.get_escrow(&address))
        }

        AuctionQuery::GetDecryptionKey { auction_id, round } => {
            let key = state.decryption_keys.get(&(auction_id, round)).cloned();
            AuctionQueryResponse::DecryptionKey(key)
        }

        AuctionQuery::GetPartialSharesCount { auction_id, round } => {
            let count = state.count_partial_shares(auction_id, round);
            AuctionQueryResponse::PartialSharesCount(count)
        }

        AuctionQuery::GetMasterPublicKey => {
            AuctionQueryResponse::MasterPublicKey(state.master_public_key.clone())
        }

        AuctionQuery::IsSP1Configured => {
            AuctionQueryResponse::SP1Configured(state.sp1_vkey.is_some())
        }
    }
}

/// Summary of an auction for listing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuctionSummary {
    pub auction_id: u64,
    pub creator: Address,
    pub ad_slot_id: Option<String>,
    pub state: AuctionState,
    pub start_time: u64,
    pub end_time: u64,
    pub num_bids: usize,
}

impl AuctionSummary {
    /// Create summary from auction config and state.
    pub fn from_auction(config: &AuctionConfig, num_bids: usize) -> Self {
        Self {
            auction_id: config.auction_id,
            creator: config.creator,
            ad_slot_id: config.metadata.ad_slot_id.clone(),
            state: config.state.clone(),
            start_time: config.start_time,
            end_time: config.end_time,
            num_bids,
        }
    }
}

/// Get auction summaries for listing.
pub fn get_auction_summaries(
    state: &ModuleState,
    offset: usize,
    limit: usize,
) -> Vec<AuctionSummary> {
    state
        .auctions
        .values()
        .skip(offset)
        .take(limit)
        .map(|config| {
            let num_bids = state
                .auction_bidders
                .get(&config.auction_id)
                .map(|v| v.len())
                .unwrap_or(0);
            AuctionSummary::from_auction(config, num_bids)
        })
        .collect()
}

/// Get active auctions (currently accepting bids).
pub fn get_active_auctions(state: &ModuleState, current_time: u64) -> Vec<AuctionSummary> {
    state
        .auctions
        .values()
        .filter(|config| {
            (config.state == AuctionState::Created || config.state == AuctionState::Open)
                && current_time >= config.start_time
                && current_time <= config.end_time
        })
        .map(|config| {
            let num_bids = state
                .auction_bidders
                .get(&config.auction_id)
                .map(|v| v.len())
                .unwrap_or(0);
            AuctionSummary::from_auction(config, num_bids)
        })
        .collect()
}

/// Get auctions pending decryption.
pub fn get_pending_decryption(state: &ModuleState, current_time: u64) -> Vec<(u64, u64)> {
    state
        .auctions
        .values()
        .filter(|config| {
            config.state == AuctionState::Sealed
                && current_time >= config.decryption_round
                && !state
                    .decryption_keys
                    .contains_key(&(config.auction_id, config.decryption_round))
        })
        .map(|config| (config.auction_id, config.decryption_round))
        .collect()
}

/// Get auctions pending settlement.
pub fn get_pending_settlement(state: &ModuleState, current_time: u64) -> Vec<u64> {
    state
        .auctions
        .values()
        .filter(|config| {
            config.state == AuctionState::Decrypted
                && current_time >= config.decryption_round
                && current_time <= config.settlement_deadline
                && state
                    .decryption_keys
                    .contains_key(&(config.auction_id, config.decryption_round))
                && !state.results.contains_key(&config.auction_id)
        })
        .map(|config| config.auction_id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_escrow_query() {
        let mut state = ModuleState::new();
        let addr = [1u8; 32];
        state.add_escrow(addr, 100);

        let response = handle_query(&state, AuctionQuery::GetEscrow { address: addr });
        assert!(matches!(response, AuctionQueryResponse::Escrow(100)));
    }

    #[test]
    fn test_get_master_public_key_none() {
        let state = ModuleState::new();
        let response = handle_query(&state, AuctionQuery::GetMasterPublicKey);
        assert!(matches!(
            response,
            AuctionQueryResponse::MasterPublicKey(None)
        ));
    }

    #[test]
    fn test_sp1_configured_false() {
        let state = ModuleState::new();
        let response = handle_query(&state, AuctionQuery::IsSP1Configured);
        assert!(matches!(response, AuctionQueryResponse::SP1Configured(false)));
    }
}
