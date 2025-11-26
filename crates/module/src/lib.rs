//! Sovereign SDK auction module with threshold encryption.
//!
//! This module implements on-chain logic for threshold-encrypted auctions:
//!
//! - Auction creation with configurable timing and rules
//! - Encrypted bid submission with Pedersen commitments
//! - Threshold decryption key management
//! - SP1 proof verification for settlement
//! - Escrow and refund handling
//!
//! # Architecture
//!
//! The module follows Sovereign SDK patterns:
//! - `call`: Message types for state-changing operations
//! - `handlers`: Business logic for processing calls
//! - `queries`: Read-only state access
//! - `state`: On-chain state structures
//! - `genesis`: Initial configuration
//! - `error`: Error types
//!
//! # Example
//!
//! ```ignore
//! use auction_module::{AuctionCall, handlers, state::AuctionState};
//!
//! let mut state = AuctionState::new();
//! let ctx = handlers::CallContext { ... };
//!
//! // Create an auction
//! let auction_id = handlers::handle_create_auction(&mut state, &ctx, ...)?;
//!
//! // Submit a bid
//! handlers::handle_submit_bid(&mut state, &ctx, auction_id, ...)?;
//! ```

pub mod call;
pub mod error;
pub mod genesis;
pub mod handlers;
pub mod queries;
pub mod state;

pub use call::AuctionCall;
pub use error::AuctionError;
pub use genesis::{AuctionGenesisConfig, DefaultAuctionParams, ThresholdConfig};
pub use handlers::{CallContext, HandlerResult};
pub use queries::{AuctionQuery, AuctionQueryResponse};
pub use state::AuctionState;
