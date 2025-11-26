//! Core type definitions for threshold-encrypted auctions.
//!
//! This crate provides the shared data structures used across the auction system,
//! including cryptographic primitives, auction configurations, and proof types.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

pub mod circuit_io;

// =========================
// CRYPTOGRAPHIC PRIMITIVES
// =========================

/// Compressed G1 point on BLS12-381 (48 bytes)
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct G1Point(#[serde_as(as = "[_; 48]")] pub [u8; 48]);

impl Default for G1Point {
    fn default() -> Self {
        Self([0u8; 48])
    }
}

/// Compressed G2 point on BLS12-381 (96 bytes)
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct G2Point(#[serde_as(as = "[_; 96]")] pub [u8; 96]);

impl Default for G2Point {
    fn default() -> Self {
        Self([0u8; 96])
    }
}

/// Scalar field element (32 bytes, little-endian)
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Scalar(#[serde_as(as = "[_; 32]")] pub [u8; 32]);

impl Default for Scalar {
    fn default() -> Self {
        Self([0u8; 32])
    }
}

/// Pedersen commitment: C = g^value * h^randomness
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct PedersenCommitment {
    pub point: G1Point,
}

// =========================
// THRESHOLD ENCRYPTION
// =========================

/// Threshold IBE ciphertext (Commonware-compatible)
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct ThresholdCiphertext {
    /// Ephemeral public key: U = r·G2
    pub ephemeral_pubkey: G2Point,

    /// Encrypted payload (bid_value || randomness || padding)
    /// Using AES-256-GCM with key derived from pairing
    pub ciphertext: Vec<u8>,

    /// Authentication tag
    pub tag: [u8; 16],

    /// Nonce for AEAD
    pub nonce: [u8; 12],
}

/// Partial decryption share from a validator
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct PartialDecryptionShare {
    pub validator_index: u32,
    pub partial_sig: G1Point,
    pub proof: DiscreteLogProof,
}

/// DLEQ proof for partial signature correctness
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct DiscreteLogProof {
    pub challenge: Scalar,
    pub response: Scalar,
}

/// Aggregated decryption key (threshold signature)
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct DecryptionKey {
    pub sigma: G1Point,
    pub round: u64,
}

/// Master public key for threshold encryption
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct MasterPublicKey {
    pub mpk: G2Point,
    pub threshold: u32,
    pub total_validators: u32,
}

// =========================
// AUCTION TYPES
// =========================

/// Generic address type (32 bytes)
pub type Address = [u8; 32];

/// Types of auctions supported
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub enum AuctionType {
    /// Winner pays their bid
    FirstPrice,

    /// Winner pays second-highest bid
    SecondPrice,

    /// Google-style: rank by bid * quality_score
    GeneralizedSecondPrice {
        quality_scores: Vec<(Address, u32)>,
    },
}

/// Auction lifecycle state
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub enum AuctionState {
    /// Before start_time
    Created,
    /// Accepting bids
    Open,
    /// Bids locked, waiting for decryption
    Sealed,
    /// Decryption key available, awaiting settlement
    Decrypted,
    /// Auction complete
    Settled,
    /// No valid bids or timeout
    Cancelled,
}

/// Full auction configuration
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct AuctionConfig {
    pub auction_id: u64,
    pub creator: Address,
    pub auction_type: AuctionType,
    pub state: AuctionState,

    // Timing
    pub start_time: u64,
    pub end_time: u64,
    pub decryption_round: u64,
    pub settlement_deadline: u64,

    // Rules
    pub min_bid: u64,
    pub reserve_price: Option<u64>,

    // Derived
    pub identity: [u8; 32],

    // Metadata
    pub metadata: AuctionMetadata,
}

/// Optional metadata for ad auctions
#[derive(Clone, Debug, Default, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct AuctionMetadata {
    pub ad_slot_id: Option<String>,
    pub placement: Option<String>,
    pub targeting_hash: Option<[u8; 32]>,
}

/// A submitted encrypted bid (stored on-chain)
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct EncryptedBid {
    pub bidder: Address,
    pub commitment: PedersenCommitment,
    pub ciphertext: ThresholdCiphertext,
    pub deposit: u64,
    pub timestamp: u64,
}

/// Decrypted bid (used off-chain for proving)
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct DecryptedBid {
    pub bidder: Address,
    pub commitment: PedersenCommitment,
    pub bid_value: u64,
    pub randomness: Scalar,
    pub index: usize,
}

/// Auction settlement result
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct AuctionResult {
    pub auction_id: u64,
    pub winner: Address,
    pub winning_price: u64,
    pub num_valid_bids: u32,
    pub settlement_time: u64,
    pub proof_hash: [u8; 32],
    pub settler: Address,
}

// =========================
// SP1 PROOF
// =========================

/// SP1 proof of auction correctness
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct SP1AuctionProof {
    /// Serialized SP1 proof
    pub proof_bytes: Vec<u8>,

    /// Public values from the proof
    pub public_values: AuctionPublicValues,

    /// Verification key hash (for upgradability)
    pub vkey_hash: [u8; 32],
}

/// Public values output by SP1 circuit
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct AuctionPublicValues {
    pub auction_id: u64,
    pub commitments_hash: [u8; 32],
    pub winner_index: u32,
    pub winning_price: u64,
    pub num_valid_bids: u32,
}

// =========================
// HELPER FUNCTIONS
// =========================

/// Compute the IBE identity for an auction's decryption round
pub fn compute_auction_identity(auction_id: u64, decryption_round: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"AUCTION_IDENTITY_V1:");
    hasher.update(auction_id.to_le_bytes());
    hasher.update(decryption_round.to_le_bytes());
    hasher.finalize().into()
}

/// Compute SHA-256 hash
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_auction_identity() {
        let id1 = compute_auction_identity(1, 100);
        let id2 = compute_auction_identity(1, 101);
        let id3 = compute_auction_identity(2, 100);

        assert_ne!(id1, id2);
        assert_ne!(id1, id3);
        assert_ne!(id2, id3);
    }

    #[test]
    fn test_g1_point_serialization() {
        let point = G1Point([42u8; 48]);
        let encoded = borsh::to_vec(&point).unwrap();
        let decoded: G1Point = borsh::from_slice(&encoded).unwrap();
        assert_eq!(point, decoded);
    }

    #[test]
    fn test_auction_state_transitions() {
        let state = AuctionState::Created;
        assert_eq!(state, AuctionState::Created);
    }
}
