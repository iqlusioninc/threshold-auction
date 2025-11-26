//! Sovereign SDK auction module with threshold encryption.
//!
//! This module implements on-chain logic for threshold-encrypted auctions:
//!
//! - Auction creation with configurable timing and rules
//! - Encrypted bid submission with Pedersen commitments
//! - Threshold decryption key management
//! - SP1 proof verification for settlement
//! - Escrow and refund handling

pub mod call;
pub mod error;
pub mod state;

pub use call::AuctionCall;
pub use error::AuctionError;
