//! RPC-compatible types for the mock chain.
//!
//! These types are JSON-serializable versions of the core auction types.

use auction_types::{AuctionConfig, AuctionResult, AuctionState, AuctionType, EncryptedBid};
use serde::{Deserialize, Serialize};

/// Genesis configuration for RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfigRpc {
    pub threshold_t: Option<u32>,
    pub threshold_n: Option<u32>,
    pub initial_timestamp: Option<u64>,
}

/// Block info response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockInfo {
    pub height: u64,
    pub timestamp: u64,
}

/// Master public key for RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterPublicKeyRpc {
    /// Hex-encoded G2 point (96 bytes)
    pub mpk: String,
    pub threshold: u32,
    pub total_validators: u32,
}

/// Validator key config for RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorKeyRpc {
    pub index: u32,
    /// Hex-encoded G1 point (48 bytes)
    pub public_key: String,
}

/// Parameters for creating an auction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAuctionParams {
    pub sender: String,
    /// "first_price", "second_price", or "gsp"
    pub auction_type: String,
    pub start_time: u64,
    pub end_time: u64,
    pub decryption_round: u64,
    pub settlement_deadline: u64,
    pub min_bid: u64,
    pub reserve_price: Option<u64>,
    /// For GSP: (address, quality_score) pairs
    pub quality_scores: Option<Vec<(String, u32)>>,
}

/// Ciphertext for RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdCiphertextRpc {
    /// Hex-encoded G2 point (96 bytes)
    pub ephemeral_pubkey: String,
    /// Hex-encoded ciphertext bytes
    pub ciphertext: String,
    /// Hex-encoded tag (16 bytes)
    pub tag: String,
    /// Hex-encoded nonce (12 bytes)
    pub nonce: String,
}

/// Parameters for submitting a bid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitBidParams {
    pub sender: String,
    pub auction_id: u64,
    /// Hex-encoded G1 point (48 bytes)
    pub commitment: String,
    pub ciphertext: ThresholdCiphertextRpc,
    pub deposit: u64,
}

/// Parameters for submitting a partial decryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitPartialDecryptionParams {
    pub auction_id: u64,
    pub round: u64,
    pub validator_index: u32,
    /// Hex-encoded G1 point (48 bytes)
    pub partial_sig: String,
    /// Hex-encoded scalar (32 bytes)
    pub proof_challenge: String,
    /// Hex-encoded scalar (32 bytes)
    pub proof_response: String,
}

/// Decryption key for RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionKeyRpc {
    /// Hex-encoded G1 point (48 bytes)
    pub sigma: String,
    pub round: u64,
}

/// Parameters for settling an auction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettleAuctionParams {
    pub sender: String,
    pub auction_id: u64,
    pub winner: String,
    pub winning_price: u64,
    pub winner_index: u32,
    pub num_valid_bids: u32,
    /// Hex-encoded commitments hash
    pub commitments_hash: String,
    /// Hex-encoded proof bytes
    pub proof_bytes: String,
}

/// Auction configuration for RPC responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuctionConfigRpc {
    pub auction_id: u64,
    pub creator: String,
    pub auction_type: String,
    pub state: String,
    pub start_time: u64,
    pub end_time: u64,
    pub decryption_round: u64,
    pub settlement_deadline: u64,
    pub min_bid: u64,
    pub reserve_price: Option<u64>,
    pub identity: String,
}

impl From<&AuctionConfig> for AuctionConfigRpc {
    fn from(c: &AuctionConfig) -> Self {
        Self {
            auction_id: c.auction_id,
            creator: hex::encode(c.creator),
            auction_type: match &c.auction_type {
                AuctionType::FirstPrice => "first_price".to_string(),
                AuctionType::SecondPrice => "second_price".to_string(),
                AuctionType::GeneralizedSecondPrice { .. } => "gsp".to_string(),
            },
            state: match c.state {
                AuctionState::Created => "created",
                AuctionState::Open => "open",
                AuctionState::Sealed => "sealed",
                AuctionState::Decrypted => "decrypted",
                AuctionState::Settled => "settled",
                AuctionState::Cancelled => "cancelled",
            }
            .to_string(),
            start_time: c.start_time,
            end_time: c.end_time,
            decryption_round: c.decryption_round,
            settlement_deadline: c.settlement_deadline,
            min_bid: c.min_bid,
            reserve_price: c.reserve_price,
            identity: hex::encode(c.identity),
        }
    }
}

/// Encrypted bid for RPC responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBidRpc {
    pub bidder: String,
    pub commitment: String,
    pub ciphertext: ThresholdCiphertextRpc,
    pub deposit: u64,
    pub timestamp: u64,
}

impl From<&EncryptedBid> for EncryptedBidRpc {
    fn from(b: &EncryptedBid) -> Self {
        Self {
            bidder: hex::encode(b.bidder),
            commitment: hex::encode(b.commitment.point.0),
            ciphertext: ThresholdCiphertextRpc {
                ephemeral_pubkey: hex::encode(b.ciphertext.ephemeral_pubkey.0),
                ciphertext: hex::encode(&b.ciphertext.ciphertext),
                tag: hex::encode(b.ciphertext.tag),
                nonce: hex::encode(b.ciphertext.nonce),
            },
            deposit: b.deposit,
            timestamp: b.timestamp,
        }
    }
}

/// Auction result for RPC responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuctionResultRpc {
    pub auction_id: u64,
    pub winner: String,
    pub winning_price: u64,
    pub num_valid_bids: u32,
    pub settlement_time: u64,
    pub proof_hash: String,
    pub settler: String,
}

impl From<AuctionResult> for AuctionResultRpc {
    fn from(r: AuctionResult) -> Self {
        Self {
            auction_id: r.auction_id,
            winner: hex::encode(r.winner),
            winning_price: r.winning_price,
            num_valid_bids: r.num_valid_bids,
            settlement_time: r.settlement_time,
            proof_hash: hex::encode(r.proof_hash),
            settler: hex::encode(r.settler),
        }
    }
}
