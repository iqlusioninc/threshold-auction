//! Permissionless settlement service for threshold-encrypted auctions.
//!
//! The settler service:
//! 1. Monitors auctions that have reached their decryption round
//! 2. Fetches encrypted bids and decryption keys from chain
//! 3. Decrypts all bids using the threshold decryption key
//! 4. Runs the auction logic to determine winner and price
//! 5. Generates an SP1 proof of correctness
//! 6. Submits the settlement transaction with proof
//!
//! Anyone can run this service - settlements are permissionless and
//! incentivized through gas refunds or explicit rewards.

pub mod prover;
pub mod service;

pub use service::SettlementService;
