//! SP1 proof generation for auction settlement.

use anyhow::Result;
use auction_types::{
    circuit_io::{AuctionTypeCompact, SP1CircuitInput, SP1CircuitOutput},
    AuctionPublicValues, PedersenCommitment, SP1AuctionProof,
};

/// Generate an SP1 proof for auction settlement.
///
/// This function:
/// 1. Prepares the circuit input
/// 2. Runs the SP1 prover
/// 3. Returns the proof with public values
pub fn generate_settlement_proof(
    auction_id: u64,
    auction_type: AuctionTypeCompact,
    commitments: Vec<PedersenCommitment>,
    bid_values: Vec<u64>,
    randomness: Vec<[u8; 32]>,
    quality_scores: Vec<u32>,
    _vkey: &[u8],
) -> Result<SP1AuctionProof> {
    // Prepare circuit input
    let input = SP1CircuitInput {
        auction_id,
        auction_type: auction_type.clone(),
        commitments: commitments.clone(),
        bid_values: bid_values.clone(),
        randomness,
        quality_scores: quality_scores.clone(),
    };

    input.validate().map_err(|e| anyhow::anyhow!(e))?;

    // Compute expected output
    let commitments_hash = input.commitments_hash();

    // Run auction logic to determine winner
    let winner = auction_circuit::compute_winner(
        &auction_type,
        &bid_values,
        &quality_scores,
        None, // TODO: Pass reserve price
    )
    .ok_or_else(|| anyhow::anyhow!("No valid bids"))?;

    // TODO: Actually run SP1 prover
    // For now, create a mock proof
    let public_values = AuctionPublicValues {
        auction_id,
        commitments_hash,
        winner_index: winner.winner_index,
        winning_price: winner.winning_price,
        num_valid_bids: winner.num_valid_bids,
    };

    // Mock proof bytes (in production, this would be actual SP1 proof)
    let proof_bytes = vec![0u8; 256];
    let vkey_hash = [0u8; 32]; // TODO: Compute actual vkey hash

    Ok(SP1AuctionProof {
        proof_bytes,
        public_values,
        vkey_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use auction_types::G1Point;

    #[test]
    fn test_generate_proof_mock() {
        let commitments = vec![
            PedersenCommitment {
                point: G1Point([1u8; 48]),
            },
            PedersenCommitment {
                point: G1Point([2u8; 48]),
            },
        ];

        let result = generate_settlement_proof(
            1,
            AuctionTypeCompact::SecondPrice,
            commitments,
            vec![100, 200],
            vec![[0u8; 32], [1u8; 32]],
            vec![],
            &[],
        );

        assert!(result.is_ok());
        let proof = result.unwrap();
        assert_eq!(proof.public_values.auction_id, 1);
        assert_eq!(proof.public_values.winner_index, 1);
        assert_eq!(proof.public_values.winning_price, 100); // Second price
    }
}
