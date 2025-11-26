//! Threshold BLS encryption primitives for private auctions.
//!
//! This crate implements Identity-Based Encryption (IBE) using threshold BLS
//! signatures on the BLS12-381 curve, compatible with Commonware's Battleware.
//!
//! # Overview
//!
//! The threshold IBE scheme works as follows:
//!
//! 1. **Setup (DKG)**: Validators generate a shared master public key (MPK) via
//!    distributed key generation. Each validator holds a secret share sk_i.
//!
//! 2. **Encryption**: Anyone can encrypt to an identity (e.g., auction round)
//!    using only the MPK. The ciphertext can only be decrypted when validators
//!    produce a threshold signature on the identity.
//!
//! 3. **Decryption Key Production**: At the designated time, validators produce
//!    partial signatures σ_i = sk_i · H(identity). These are aggregated into
//!    the decryption key σ = Σ λ_i · σ_i.
//!
//! 4. **Decryption**: Anyone with σ can decrypt ciphertexts for that identity.

pub mod error;
pub mod ibe;
pub mod pedersen;
pub mod threshold;

pub use error::CryptoError;
pub use ibe::{decrypt, encrypt, IbeParams};
pub use pedersen::{pedersen_commit, pedersen_verify, PedersenParams};
pub use threshold::{
    aggregate_partial_signatures, generate_partial_signature, verify_partial_signature,
};
