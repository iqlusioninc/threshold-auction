//! Client SDK for bidding in threshold-encrypted auctions.
//!
//! This crate provides a high-level API for:
//! - Creating encrypted bids with Pedersen commitments
//! - Submitting bids to the auction module
//! - Querying auction state
//! - Claiming refunds after settlement

pub mod bid;
pub mod query;

pub use bid::{create_bid, BidBuilder};
