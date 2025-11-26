//! Distributed Key Generation for threshold BLS encryption.
//!
//! Implements a (t, n) threshold key generation protocol using Feldman VSS:
//!
//! 1. Each participant generates a random polynomial of degree t-1
//! 2. Participants exchange encrypted shares
//! 3. Participants verify shares against polynomial commitments
//! 4. Each participant combines shares to get their secret share
//! 5. Master public key is computed from commitments
//!
//! # Security
//!
//! - Requires honest majority (> n/2) for correctness
//! - Privacy holds against up to t-1 corrupt participants
//! - Uses Feldman commitments for verifiability

pub mod feldman;
pub mod participant;
pub mod types;

pub use participant::DkgParticipant;
pub use types::{DkgConfig, DkgOutput, DkgRound1Message, DkgRound2Message};
