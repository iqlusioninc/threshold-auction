//! On-chain state structures for the auction module.

use auction_types::{
    Address, AuctionConfig, AuctionResult, DecryptionKey, EncryptedBid, G1Point, MasterPublicKey,
    PartialDecryptionShare,
};
use std::collections::HashMap;

/// Auction module state.
///
/// In a real Sovereign SDK implementation, these would be StateMap/StateValue types.
/// This is a simplified in-memory representation for development.
#[derive(Debug, Default)]
pub struct AuctionState {
    /// Next auction ID to assign
    pub next_auction_id: u64,

    /// All auctions by ID
    pub auctions: HashMap<u64, AuctionConfig>,

    /// Encrypted bids: (auction_id, bidder) -> bid
    pub bids: HashMap<(u64, Address), EncryptedBid>,

    /// Bidders per auction
    pub auction_bidders: HashMap<u64, Vec<Address>>,

    /// Settlement results
    pub results: HashMap<u64, AuctionResult>,

    /// User escrow balances
    pub escrow: HashMap<Address, u64>,

    /// Master public key for threshold IBE
    pub master_public_key: Option<MasterPublicKey>,

    /// Decryption keys: (auction_id, round) -> key
    pub decryption_keys: HashMap<(u64, u64), DecryptionKey>,

    /// Partial decryption shares: (auction_id, round, validator_index) -> share
    pub partial_shares: HashMap<(u64, u64, u32), PartialDecryptionShare>,

    /// Validator public keys for verification
    pub validator_pubkeys: HashMap<u32, G1Point>,

    /// SP1 verification key
    pub sp1_vkey: Option<Vec<u8>>,

    /// SP1 vkey hash
    pub sp1_vkey_hash: Option<[u8; 32]>,
}

impl AuctionState {
    /// Create a new auction state.
    pub fn new() -> Self {
        Self {
            next_auction_id: 1,
            ..Default::default()
        }
    }

    /// Get the next auction ID and increment.
    pub fn allocate_auction_id(&mut self) -> u64 {
        let id = self.next_auction_id;
        self.next_auction_id += 1;
        id
    }

    /// Get auction by ID.
    pub fn get_auction(&self, auction_id: u64) -> Option<&AuctionConfig> {
        self.auctions.get(&auction_id)
    }

    /// Get mutable auction by ID.
    pub fn get_auction_mut(&mut self, auction_id: u64) -> Option<&mut AuctionConfig> {
        self.auctions.get_mut(&auction_id)
    }

    /// Get all bids for an auction.
    pub fn get_auction_bids(&self, auction_id: u64) -> Vec<&EncryptedBid> {
        self.auction_bidders
            .get(&auction_id)
            .map(|bidders| {
                bidders
                    .iter()
                    .filter_map(|bidder| self.bids.get(&(auction_id, *bidder)))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get user's escrow balance.
    pub fn get_escrow(&self, address: &Address) -> u64 {
        self.escrow.get(address).copied().unwrap_or(0)
    }

    /// Add to user's escrow.
    pub fn add_escrow(&mut self, address: Address, amount: u64) {
        *self.escrow.entry(address).or_insert(0) += amount;
    }

    /// Subtract from user's escrow.
    pub fn subtract_escrow(&mut self, address: &Address, amount: u64) -> bool {
        if let Some(balance) = self.escrow.get_mut(address) {
            if *balance >= amount {
                *balance -= amount;
                return true;
            }
        }
        false
    }

    /// Count partial shares for an auction round.
    pub fn count_partial_shares(&self, auction_id: u64, round: u64) -> usize {
        self.partial_shares
            .keys()
            .filter(|(aid, r, _)| *aid == auction_id && *r == round)
            .count()
    }

    /// Get all partial shares for an auction round.
    pub fn get_partial_shares(
        &self,
        auction_id: u64,
        round: u64,
    ) -> Vec<(u32, &PartialDecryptionShare)> {
        self.partial_shares
            .iter()
            .filter(|((aid, r, _), _)| *aid == auction_id && *r == round)
            .map(|((_, _, idx), share)| (*idx, share))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_auction_id() {
        let mut state = AuctionState::new();
        assert_eq!(state.allocate_auction_id(), 1);
        assert_eq!(state.allocate_auction_id(), 2);
        assert_eq!(state.allocate_auction_id(), 3);
    }

    #[test]
    fn test_escrow_operations() {
        let mut state = AuctionState::new();
        let addr = [1u8; 32];

        assert_eq!(state.get_escrow(&addr), 0);

        state.add_escrow(addr, 100);
        assert_eq!(state.get_escrow(&addr), 100);

        state.add_escrow(addr, 50);
        assert_eq!(state.get_escrow(&addr), 150);

        assert!(state.subtract_escrow(&addr, 75));
        assert_eq!(state.get_escrow(&addr), 75);

        assert!(!state.subtract_escrow(&addr, 100));
        assert_eq!(state.get_escrow(&addr), 75);
    }
}
