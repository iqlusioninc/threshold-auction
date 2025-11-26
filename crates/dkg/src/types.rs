//! DKG type definitions.

use auction_types::{G1Point, G2Point, Scalar};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// DKG configuration.
#[derive(Debug, Clone)]
pub struct DkgConfig {
    /// Total number of participants
    pub n: u32,
    /// Threshold (minimum shares needed for decryption)
    pub threshold: u32,
    /// This participant's index (1-based)
    pub participant_index: u32,
}

impl DkgConfig {
    pub fn new(n: u32, threshold: u32, participant_index: u32) -> Self {
        assert!(threshold <= n, "Threshold must be <= n");
        assert!(threshold > 0, "Threshold must be > 0");
        assert!(participant_index > 0 && participant_index <= n, "Invalid participant index");
        Self {
            n,
            threshold,
            participant_index,
        }
    }
}

/// Round 1 message: polynomial commitments
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct DkgRound1Message {
    /// Sender's participant index
    pub sender: u32,
    /// Feldman commitments: g^{a_i} for polynomial coefficients
    pub commitments: Vec<G2Point>,
}

/// Round 2 message: encrypted share for a specific recipient
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct DkgRound2Message {
    /// Sender's participant index
    pub sender: u32,
    /// Recipient's participant index
    pub recipient: u32,
    /// Encrypted share (using recipient's encryption key)
    pub encrypted_share: Vec<u8>,
}

/// Output of DKG for a participant.
#[derive(Debug, Clone)]
pub struct DkgOutput {
    /// This participant's secret share
    pub secret_share: Scalar,
    /// This participant's public key (g^{sk_i})
    pub public_key: G1Point,
    /// Master public key (g^s where s is the combined secret)
    pub master_public_key: G2Point,
    /// All participants' public keys
    pub participant_pubkeys: Vec<(u32, G1Point)>,
    /// Threshold
    pub threshold: u32,
}

/// Verification data for a share.
#[derive(Debug, Clone)]
pub struct ShareVerification {
    /// The share value
    pub share: Scalar,
    /// Commitments to verify against
    pub commitments: Vec<G2Point>,
    /// Recipient index for evaluation
    pub recipient_index: u32,
}
