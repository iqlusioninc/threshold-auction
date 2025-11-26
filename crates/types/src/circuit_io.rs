//! Circuit I/O types for SP1 zkVM proving.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::PedersenCommitment;

/// Compact auction type for circuit (no associated data)
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub enum AuctionTypeCompact {
    FirstPrice,
    SecondPrice,
    GSP,
}

/// Input to SP1 circuit (private to prover)
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct SP1CircuitInput {
    /// Auction identifier
    pub auction_id: u64,

    /// Auction type (determines pricing rule)
    pub auction_type: AuctionTypeCompact,

    /// All Pedersen commitments (from chain)
    pub commitments: Vec<PedersenCommitment>,

    /// Decrypted bid values (from threshold decryption)
    pub bid_values: Vec<u64>,

    /// Randomness for each bid (from threshold decryption)
    pub randomness: Vec<[u8; 32]>,

    /// Quality scores for GSP auctions (index -> score)
    pub quality_scores: Vec<u32>,
}

impl SP1CircuitInput {
    /// Hash all commitments for binding
    pub fn commitments_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for c in &self.commitments {
            hasher.update(&c.point.0);
        }
        hasher.finalize().into()
    }

    /// Validate input consistency
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.commitments.len() != self.bid_values.len() {
            return Err("Commitment count mismatch");
        }
        if self.commitments.len() != self.randomness.len() {
            return Err("Randomness count mismatch");
        }
        if matches!(self.auction_type, AuctionTypeCompact::GSP)
            && self.quality_scores.len() != self.bid_values.len()
        {
            return Err("Quality scores count mismatch for GSP auction");
        }
        Ok(())
    }
}

/// Output from SP1 circuit (public values)
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct SP1CircuitOutput {
    /// Auction identifier
    pub auction_id: u64,

    /// Hash of all commitments (links to on-chain data)
    pub commitments_hash: [u8; 32],

    /// Index of the winning bidder
    pub winner_index: u32,

    /// Price the winner pays
    pub winning_price: u64,

    /// Number of valid bids processed
    pub num_valid_bids: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::G1Point;

    #[test]
    fn test_circuit_input_validation() {
        let input = SP1CircuitInput {
            auction_id: 1,
            auction_type: AuctionTypeCompact::SecondPrice,
            commitments: vec![PedersenCommitment {
                point: G1Point([0u8; 48]),
            }],
            bid_values: vec![100],
            randomness: vec![[0u8; 32]],
            quality_scores: vec![],
        };

        assert!(input.validate().is_ok());
    }

    #[test]
    fn test_circuit_input_validation_mismatch() {
        let input = SP1CircuitInput {
            auction_id: 1,
            auction_type: AuctionTypeCompact::SecondPrice,
            commitments: vec![PedersenCommitment {
                point: G1Point([0u8; 48]),
            }],
            bid_values: vec![100, 200], // Mismatch
            randomness: vec![[0u8; 32]],
            quality_scores: vec![],
        };

        assert!(input.validate().is_err());
    }

    #[test]
    fn test_commitments_hash() {
        let input = SP1CircuitInput {
            auction_id: 1,
            auction_type: AuctionTypeCompact::FirstPrice,
            commitments: vec![
                PedersenCommitment {
                    point: G1Point([1u8; 48]),
                },
                PedersenCommitment {
                    point: G1Point([2u8; 48]),
                },
            ],
            bid_values: vec![100, 200],
            randomness: vec![[0u8; 32], [1u8; 32]],
            quality_scores: vec![],
        };

        let hash = input.commitments_hash();
        assert_ne!(hash, [0u8; 32]);
    }
}
