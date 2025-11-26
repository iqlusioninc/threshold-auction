//! Auction module error types.

use thiserror::Error;

use auction_types::AuctionState;

/// Errors that can occur in the auction module.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuctionError {
    #[error("Auction not found: {0}")]
    AuctionNotFound(u64),

    #[error("Invalid state. Expected: {expected:?}, Got: {got:?}")]
    InvalidState {
        expected: AuctionState,
        got: AuctionState,
    },

    #[error("Bidding period ended")]
    BiddingEnded,

    #[error("Bidding period not started")]
    BiddingNotStarted,

    #[error("Decryption round not reached")]
    DecryptionNotReady,

    #[error("Settlement deadline passed")]
    SettlementDeadlinePassed,

    #[error("Insufficient deposit: need {required}, got {got}")]
    InsufficientDeposit { required: u64, got: u64 },

    #[error("Already submitted bid")]
    AlreadyBid,

    #[error("Already settled")]
    AlreadySettled,

    #[error("Invalid SP1 proof")]
    InvalidProof,

    #[error("Public values mismatch")]
    PublicValuesMismatch,

    #[error("Decryption key not available")]
    DecryptionKeyNotAvailable,

    #[error("Invalid ciphertext")]
    InvalidCiphertext,

    #[error("Master public key not set")]
    MasterKeyNotSet,

    #[error("Validator not registered")]
    ValidatorNotRegistered,

    #[error("Invalid timing configuration")]
    InvalidTiming,

    #[error("Insufficient threshold shares")]
    InsufficientShares,

    #[error("Round mismatch")]
    RoundMismatch,

    #[error("Not authorized")]
    NotAuthorized,

    #[error("Refund not available")]
    RefundNotAvailable,
}
