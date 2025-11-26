//! Call message types for the auction module.

use auction_types::{
    AuctionMetadata, AuctionType, G1Point, MasterPublicKey, PartialDecryptionShare,
    PedersenCommitment, SP1AuctionProof, ThresholdCiphertext,
};
use borsh::{BorshDeserialize, BorshSerialize};

/// Call messages for the auction module.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum AuctionCall {
    // === Auction Lifecycle ===
    /// Create a new auction.
    CreateAuction {
        auction_type: AuctionType,
        start_time: u64,
        end_time: u64,
        decryption_round: u64,
        settlement_deadline: u64,
        min_bid: u64,
        reserve_price: Option<u64>,
        metadata: AuctionMetadata,
    },

    /// Submit an encrypted bid with Pedersen commitment.
    SubmitBid {
        auction_id: u64,
        commitment: PedersenCommitment,
        ciphertext: ThresholdCiphertext,
        deposit: u64,
    },

    /// Settle auction with SP1 proof (permissionless).
    SettleAuction {
        auction_id: u64,
        winner: [u8; 32],
        winning_price: u64,
        proof: SP1AuctionProof,
    },

    /// Claim refund after auction settlement.
    ClaimRefund { auction_id: u64 },

    // === Threshold Key Management ===
    /// Submit partial decryption share (validators only).
    SubmitPartialDecryption {
        auction_id: u64,
        round: u64,
        partial: PartialDecryptionShare,
    },

    /// Aggregate partial shares into decryption key (anyone).
    AggregateDecryptionKey {
        auction_id: u64,
        round: u64,
        validator_indices: Vec<u32>,
    },

    // === Admin ===
    /// Set master public key (governance/DKG).
    SetMasterPublicKey {
        mpk: MasterPublicKey,
        validator_pubkeys: Vec<(u32, G1Point)>,
    },

    /// Update SP1 verification key.
    UpdateSP1VerificationKey { vkey: Vec<u8> },
}
