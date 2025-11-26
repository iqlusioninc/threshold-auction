//! Call handlers for the auction module.
//!
//! These functions implement the business logic for each call type.

use crate::error::AuctionError;
use crate::state::AuctionState as ModuleState;
use auction_crypto::threshold::{aggregate_partial_signatures, verify_partial_signature};
use auction_types::{
    Address, AuctionConfig, AuctionMetadata, AuctionResult, AuctionState, AuctionType,
    DecryptionKey, EncryptedBid, G1Point, MasterPublicKey, PartialDecryptionShare,
    PedersenCommitment, SP1AuctionProof, ThresholdCiphertext,
};
use sha2::{Digest, Sha256};

/// Context provided by the runtime for each call.
pub struct CallContext {
    /// Sender of the transaction
    pub sender: Address,
    /// Current block height
    pub block_height: u64,
    /// Current timestamp
    pub timestamp: u64,
    /// Value attached to the call (for deposits)
    pub value: u64,
}

/// Result type for handlers.
pub type HandlerResult<T> = Result<T, AuctionError>;

/// Handle CreateAuction call.
pub fn handle_create_auction(
    state: &mut ModuleState,
    ctx: &CallContext,
    auction_type: AuctionType,
    start_time: u64,
    end_time: u64,
    decryption_round: u64,
    settlement_deadline: u64,
    min_bid: u64,
    reserve_price: Option<u64>,
    metadata: AuctionMetadata,
) -> HandlerResult<u64> {
    // Validate timing
    if end_time <= start_time || decryption_round < end_time || settlement_deadline < decryption_round {
        return Err(AuctionError::InvalidTiming);
    }

    // Ensure master public key is set
    if state.master_public_key.is_none() {
        return Err(AuctionError::MasterKeyNotSet);
    }

    // Allocate auction ID
    let auction_id = state.allocate_auction_id();

    // Create auction config
    let config = AuctionConfig {
        auction_id,
        creator: ctx.sender,
        auction_type,
        state: AuctionState::Created,
        start_time,
        end_time,
        decryption_round,
        settlement_deadline,
        min_bid,
        reserve_price,
        metadata,
        identity: auction_types::compute_auction_identity(auction_id, decryption_round),
    };

    // Store auction
    state.auctions.insert(auction_id, config);
    state.auction_bidders.insert(auction_id, Vec::new());

    Ok(auction_id)
}

/// Handle SubmitBid call.
pub fn handle_submit_bid(
    state: &mut ModuleState,
    ctx: &CallContext,
    auction_id: u64,
    commitment: PedersenCommitment,
    ciphertext: ThresholdCiphertext,
    deposit: u64,
) -> HandlerResult<()> {
    // Get auction
    let auction = state
        .get_auction(auction_id)
        .ok_or(AuctionError::AuctionNotFound(auction_id))?;

    // Check bidding period
    if ctx.timestamp < auction.start_time {
        return Err(AuctionError::BiddingNotStarted);
    }
    if ctx.timestamp > auction.end_time {
        return Err(AuctionError::BiddingEnded);
    }

    // Check auction is in valid state for bidding (Created or Open)
    if auction.state != AuctionState::Created && auction.state != AuctionState::Open {
        return Err(AuctionError::InvalidState {
            expected: AuctionState::Open,
            got: auction.state.clone(),
        });
    }

    // Check not already bid
    if state.bids.contains_key(&(auction_id, ctx.sender)) {
        return Err(AuctionError::AlreadyBid);
    }

    // Check deposit
    if deposit < auction.min_bid {
        return Err(AuctionError::InsufficientDeposit {
            required: auction.min_bid,
            got: deposit,
        });
    }

    // Create encrypted bid
    let bid = EncryptedBid {
        bidder: ctx.sender,
        commitment,
        ciphertext,
        deposit,
        timestamp: ctx.timestamp,
    };

    // Update auction state to Open if it was Created
    if let Some(auction) = state.get_auction_mut(auction_id) {
        if auction.state == AuctionState::Created {
            auction.state = AuctionState::Open;
        }
    }

    // Store bid
    state.bids.insert((auction_id, ctx.sender), bid);
    state
        .auction_bidders
        .entry(auction_id)
        .or_default()
        .push(ctx.sender);

    // Add to escrow
    state.add_escrow(ctx.sender, deposit);

    Ok(())
}

/// Handle SubmitPartialDecryption call.
pub fn handle_submit_partial_decryption(
    state: &mut ModuleState,
    _ctx: &CallContext,
    auction_id: u64,
    round: u64,
    partial: PartialDecryptionShare,
) -> HandlerResult<()> {
    // Check auction exists
    let auction = state
        .get_auction(auction_id)
        .ok_or(AuctionError::AuctionNotFound(auction_id))?;

    // Check decryption round is valid
    if round != auction.decryption_round {
        return Err(AuctionError::RoundMismatch);
    }

    // Check validator is registered
    let validator_pk = state
        .validator_pubkeys
        .get(&partial.validator_index)
        .ok_or(AuctionError::ValidatorNotRegistered)?;

    // Verify the DLEQ proof
    verify_partial_signature(&partial, &auction.identity, validator_pk)
        .map_err(|_| AuctionError::InvalidProof)?;

    // Store partial share
    state.partial_shares.insert(
        (auction_id, round, partial.validator_index),
        partial,
    );

    Ok(())
}

/// Handle AggregateDecryptionKey call.
pub fn handle_aggregate_decryption_key(
    state: &mut ModuleState,
    _ctx: &CallContext,
    auction_id: u64,
    round: u64,
    validator_indices: Vec<u32>,
) -> HandlerResult<DecryptionKey> {
    // Check auction exists
    let _auction = state
        .get_auction(auction_id)
        .ok_or(AuctionError::AuctionNotFound(auction_id))?;

    // Check we have a minimum threshold (e.g., 2/3)
    let threshold = (validator_indices.len() * 2 + 2) / 3;
    if validator_indices.len() < threshold {
        return Err(AuctionError::InsufficientShares);
    }

    // Collect shares
    let mut shares: Vec<(u32, G1Point)> = Vec::new();
    for idx in &validator_indices {
        let share = state
            .partial_shares
            .get(&(auction_id, round, *idx))
            .ok_or(AuctionError::InsufficientShares)?;
        shares.push((*idx, share.partial_sig.clone()));
    }

    // Aggregate
    let aggregated = aggregate_partial_signatures(&shares, threshold)
        .map_err(|_| AuctionError::InsufficientShares)?;

    // Create decryption key
    let key = DecryptionKey {
        sigma: aggregated,
        round,
    };

    // Store
    state.decryption_keys.insert((auction_id, round), key.clone());

    // Update auction state to Decrypted
    if let Some(auction) = state.get_auction_mut(auction_id) {
        if auction.state == AuctionState::Sealed {
            auction.state = AuctionState::Decrypted;
        }
    }

    Ok(key)
}

/// Handle SettleAuction call.
pub fn handle_settle_auction(
    state: &mut ModuleState,
    ctx: &CallContext,
    auction_id: u64,
    winner: Address,
    winning_price: u64,
    proof: SP1AuctionProof,
) -> HandlerResult<AuctionResult> {
    // Get auction
    let auction = state
        .get_auction_mut(auction_id)
        .ok_or(AuctionError::AuctionNotFound(auction_id))?;

    // Check not already settled
    if auction.state == AuctionState::Settled {
        return Err(AuctionError::AlreadySettled);
    }

    // Verify SP1 proof
    // In production, this would verify the actual SP1 proof against the vkey
    // For now, we do basic validation

    // Verify vkey hash matches
    if let Some(expected_vkey_hash) = state.sp1_vkey_hash {
        if proof.vkey_hash != expected_vkey_hash {
            return Err(AuctionError::InvalidProof);
        }
    }

    // Verify public values
    if proof.public_values.auction_id != auction_id {
        return Err(AuctionError::PublicValuesMismatch);
    }

    // Verify commitments hash matches stored bids
    let bids = state.get_auction_bids(auction_id);
    let mut hasher = Sha256::new();
    for bid in &bids {
        hasher.update(&bid.commitment.point.0);
    }
    let computed_hash: [u8; 32] = hasher.finalize().into();

    if computed_hash != proof.public_values.commitments_hash {
        return Err(AuctionError::PublicValuesMismatch);
    }

    // Update auction status
    let auction = state.get_auction_mut(auction_id).unwrap();
    auction.state = AuctionState::Settled;

    // Create result
    let result = AuctionResult {
        auction_id,
        winner,
        winning_price,
        num_valid_bids: proof.public_values.num_valid_bids,
        settlement_time: ctx.timestamp,
        proof_hash: {
            let mut hasher = Sha256::new();
            hasher.update(&proof.proof_bytes);
            hasher.finalize().into()
        },
        settler: ctx.sender,
    };

    // Store result
    state.results.insert(auction_id, result.clone());

    // Deduct winner's payment from escrow
    state.subtract_escrow(&winner, winning_price);

    Ok(result)
}

/// Handle ClaimRefund call.
pub fn handle_claim_refund(
    state: &mut ModuleState,
    ctx: &CallContext,
    auction_id: u64,
) -> HandlerResult<u64> {
    // Get auction
    let auction = state
        .get_auction(auction_id)
        .ok_or(AuctionError::AuctionNotFound(auction_id))?;

    // Check auction is settled
    if auction.state != AuctionState::Settled {
        return Err(AuctionError::RefundNotAvailable);
    }

    // Check user had a bid
    let bid = state
        .bids
        .get(&(auction_id, ctx.sender))
        .ok_or(AuctionError::RefundNotAvailable)?;

    // Get result
    let result = state
        .results
        .get(&auction_id)
        .ok_or(AuctionError::RefundNotAvailable)?;

    // If user is winner, no refund (payment already deducted in settle)
    if result.winner == ctx.sender {
        return Err(AuctionError::RefundNotAvailable);
    }

    // Calculate refund amount (full deposit for non-winners)
    let refund = bid.deposit;

    // Subtract from escrow
    if !state.subtract_escrow(&ctx.sender, refund) {
        return Err(AuctionError::RefundNotAvailable);
    }

    Ok(refund)
}

/// Handle SetMasterPublicKey call.
pub fn handle_set_master_public_key(
    state: &mut ModuleState,
    _ctx: &CallContext,
    mpk: MasterPublicKey,
    validator_pubkeys: Vec<(u32, G1Point)>,
) -> HandlerResult<()> {
    // In production, this would require governance authorization
    state.master_public_key = Some(mpk);

    for (idx, pk) in validator_pubkeys {
        state.validator_pubkeys.insert(idx, pk);
    }

    Ok(())
}

/// Handle UpdateSP1VerificationKey call.
pub fn handle_update_sp1_verification_key(
    state: &mut ModuleState,
    _ctx: &CallContext,
    vkey: Vec<u8>,
) -> HandlerResult<()> {
    // In production, this would require governance authorization

    // Compute vkey hash
    let mut hasher = Sha256::new();
    hasher.update(&vkey);
    let vkey_hash: [u8; 32] = hasher.finalize().into();

    state.sp1_vkey = Some(vkey);
    state.sp1_vkey_hash = Some(vkey_hash);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use auction_types::G2Point;

    fn test_context(sender: Address) -> CallContext {
        CallContext {
            sender,
            block_height: 100,
            timestamp: 1000,
            value: 0,
        }
    }

    fn setup_state_with_mpk() -> ModuleState {
        let mut state = ModuleState::new();
        state.master_public_key = Some(MasterPublicKey {
            mpk: G2Point([2u8; 96]),
            threshold: 2,
            total_validators: 3,
        });
        state
    }

    #[test]
    fn test_create_auction() {
        let mut state = setup_state_with_mpk();
        let ctx = test_context([1u8; 32]);

        let result = handle_create_auction(
            &mut state,
            &ctx,
            AuctionType::SecondPrice,
            500,  // start
            1500, // end
            2000, // decryption
            3000, // settlement
            10,   // min_bid
            None, // reserve
            AuctionMetadata {
                ad_slot_id: Some("test-slot-1".to_string()),
                placement: Some("banner".to_string()),
                targeting_hash: None,
            },
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);
        assert!(state.auctions.contains_key(&1));
    }

    #[test]
    fn test_create_auction_invalid_timing() {
        let mut state = setup_state_with_mpk();
        let ctx = test_context([1u8; 32]);

        // End before start
        let result = handle_create_auction(
            &mut state,
            &ctx,
            AuctionType::FirstPrice,
            1000,
            500, // end before start
            1500,
            2000,
            10,
            None,
            AuctionMetadata {
                ad_slot_id: None,
                placement: None,
                targeting_hash: None,
            },
        );

        assert!(matches!(result, Err(AuctionError::InvalidTiming)));
    }

    #[test]
    fn test_create_auction_no_mpk() {
        let mut state = ModuleState::new();
        let ctx = test_context([1u8; 32]);

        let result = handle_create_auction(
            &mut state,
            &ctx,
            AuctionType::FirstPrice,
            500,
            1000,
            1500,
            2000,
            10,
            None,
            AuctionMetadata {
                ad_slot_id: None,
                placement: None,
                targeting_hash: None,
            },
        );

        assert!(matches!(result, Err(AuctionError::MasterKeyNotSet)));
    }

    #[test]
    fn test_submit_bid_success() {
        let mut state = setup_state_with_mpk();
        let creator = [1u8; 32];
        let bidder = [2u8; 32];

        // Create auction
        let create_ctx = CallContext {
            sender: creator,
            block_height: 100,
            timestamp: 400, // Before start
            value: 0,
        };

        let auction_id = handle_create_auction(
            &mut state,
            &create_ctx,
            AuctionType::SecondPrice,
            500,
            1500,
            2000,
            3000,
            10,
            None,
            AuctionMetadata {
                ad_slot_id: None,
                placement: None,
                targeting_hash: None,
            },
        )
        .unwrap();

        // Submit bid during bidding period
        let bid_ctx = CallContext {
            sender: bidder,
            block_height: 110,
            timestamp: 1000, // During bidding
            value: 100,
        };

        let result = handle_submit_bid(
            &mut state,
            &bid_ctx,
            auction_id,
            PedersenCommitment {
                point: G1Point([3u8; 48]),
            },
            ThresholdCiphertext {
                ephemeral_pubkey: G2Point([4u8; 96]),
                ciphertext: vec![0u8; 64],
                tag: [0u8; 16],
                nonce: [0u8; 12],
            },
            100,
        );

        assert!(result.is_ok());
        assert!(state.bids.contains_key(&(auction_id, bidder)));
        assert_eq!(state.get_escrow(&bidder), 100);
    }

    #[test]
    fn test_submit_bid_after_end() {
        let mut state = setup_state_with_mpk();
        let creator = [1u8; 32];
        let bidder = [2u8; 32];

        let create_ctx = CallContext {
            sender: creator,
            block_height: 100,
            timestamp: 400,
            value: 0,
        };

        let auction_id = handle_create_auction(
            &mut state,
            &create_ctx,
            AuctionType::SecondPrice,
            500,
            1500,
            2000,
            3000,
            10,
            None,
            AuctionMetadata {
                ad_slot_id: None,
                placement: None,
                targeting_hash: None,
            },
        )
        .unwrap();

        // Submit bid after end time
        let bid_ctx = CallContext {
            sender: bidder,
            block_height: 200,
            timestamp: 2000, // After bidding
            value: 100,
        };

        let result = handle_submit_bid(
            &mut state,
            &bid_ctx,
            auction_id,
            PedersenCommitment {
                point: G1Point([3u8; 48]),
            },
            ThresholdCiphertext {
                ephemeral_pubkey: G2Point([4u8; 96]),
                ciphertext: vec![],
                tag: [0u8; 16],
                nonce: [0u8; 12],
            },
            100,
        );

        assert!(matches!(result, Err(AuctionError::BiddingEnded)));
    }
}
