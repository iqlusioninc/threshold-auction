//! SP1 zkVM circuit for proving auction correctness.
//!
//! This circuit proves that:
//! 1. All Pedersen commitments are correctly opened
//! 2. The winner has the highest bid (or highest bid*quality for GSP)
//! 3. The winning price is computed correctly per auction rules
//!
//! # Public Inputs
//! - auction_id
//! - commitments_hash (binds to on-chain data)
//! - winner_index
//! - winning_price
//! - num_valid_bids
//!
//! # Private Inputs
//! - bid_values[]
//! - randomness[]
//! - quality_scores[] (for GSP)

pub mod auction_logic;
pub mod commitment;

pub use auction_logic::{compute_gsp_winner, compute_second_price_winner, compute_winner};
pub use commitment::verify_commitment_opening;

#[cfg(target_os = "zkvm")]
pub mod zkvm;
