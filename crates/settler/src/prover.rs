//! SP1 proof generation for auction settlement.

use anyhow::Result;
use auction_types::{
    circuit_io::AuctionTypeCompact, AuctionPublicValues, PedersenCommitment, SP1AuctionProof,
};
use sha2::{Digest, Sha256};

/// Convert auction type to u8 for circuit input.
pub fn auction_type_to_u8(t: &AuctionTypeCompact) -> u8 {
    match t {
        AuctionTypeCompact::FirstPrice => 0,
        AuctionTypeCompact::SecondPrice => 1,
        AuctionTypeCompact::GSP => 2,
    }
}

/// Generate a settlement proof without SP1 (for testing/development).
///
/// This runs the auction logic locally and creates a mock proof.
pub fn generate_mock_proof(
    auction_id: u64,
    auction_type: AuctionTypeCompact,
    commitments: Vec<PedersenCommitment>,
    bid_values: Vec<u64>,
    _randomness: Vec<[u8; 32]>,
    quality_scores: Vec<u32>,
    reserve_price: Option<u64>,
) -> Result<SP1AuctionProof> {
    // Compute commitments hash
    let mut hasher = Sha256::new();
    for c in &commitments {
        hasher.update(&c.point.0);
    }
    let commitments_hash: [u8; 32] = hasher.finalize().into();

    // Run auction logic
    let winner = auction_circuit::compute_winner(&auction_type, &bid_values, &quality_scores, reserve_price)
        .ok_or_else(|| anyhow::anyhow!("No valid bids"))?;

    let public_values = AuctionPublicValues {
        auction_id,
        commitments_hash,
        winner_index: winner.winner_index,
        winning_price: winner.winning_price,
        num_valid_bids: winner.num_valid_bids,
    };

    // Mock proof
    Ok(SP1AuctionProof {
        proof_bytes: vec![0u8; 256],
        public_values,
        vkey_hash: [0u8; 32],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use auction_types::G1Point;

    #[test]
    fn test_generate_mock_proof() {
        let commitments = vec![
            PedersenCommitment {
                point: G1Point([1u8; 48]),
            },
            PedersenCommitment {
                point: G1Point([2u8; 48]),
            },
        ];

        let result = generate_mock_proof(
            1,
            AuctionTypeCompact::SecondPrice,
            commitments,
            vec![100, 200],
            vec![[0u8; 32], [1u8; 32]],
            vec![],
            None,
        );

        assert!(result.is_ok());
        let proof = result.unwrap();
        assert_eq!(proof.public_values.auction_id, 1);
        assert_eq!(proof.public_values.winner_index, 1);
        assert_eq!(proof.public_values.winning_price, 100);
    }

    #[test]
    fn test_auction_type_conversion() {
        assert_eq!(auction_type_to_u8(&AuctionTypeCompact::FirstPrice), 0);
        assert_eq!(auction_type_to_u8(&AuctionTypeCompact::SecondPrice), 1);
        assert_eq!(auction_type_to_u8(&AuctionTypeCompact::GSP), 2);
    }
}
