//! Bid creation and encryption.

use rand::{CryptoRng, RngCore};
use thiserror::Error;

use auction_crypto::{encrypt, pedersen_commit, IbeParams, PedersenParams};
use auction_types::{G2Point, PedersenCommitment, Scalar, ThresholdCiphertext};

/// Errors that can occur during bid creation.
#[derive(Debug, Error)]
pub enum BidError {
    #[error("Invalid master public key")]
    InvalidMpk,

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Bid value exceeds maximum")]
    BidTooLarge,
}

/// A prepared bid ready for submission.
#[derive(Debug, Clone)]
pub struct PreparedBid {
    /// Pedersen commitment to the bid value
    pub commitment: PedersenCommitment,
    /// Threshold-encrypted bid data
    pub ciphertext: ThresholdCiphertext,
    /// Randomness used (keep secret until after auction)
    pub randomness: Scalar,
    /// Original bid value (keep secret)
    pub bid_value: u64,
}

/// Create an encrypted bid for an auction.
///
/// # Arguments
/// * `mpk` - Master public key for threshold encryption
/// * `auction_id` - ID of the auction to bid in
/// * `decryption_round` - Round when bids will be decrypted
/// * `bid_value` - The bid amount
/// * `rng` - Cryptographically secure random number generator
///
/// # Returns
/// A prepared bid with commitment and ciphertext
pub fn create_bid<R: RngCore + CryptoRng>(
    mpk: &G2Point,
    auction_id: u64,
    decryption_round: u64,
    bid_value: u64,
    rng: &mut R,
) -> Result<PreparedBid, BidError> {
    // Create Pedersen commitment
    let pedersen_params = PedersenParams::new();
    let (commitment, randomness) = pedersen_commit(&pedersen_params, bid_value, rng);

    // Prepare IBE parameters
    let ibe_params =
        IbeParams::from_g2_point(mpk).map_err(|_| BidError::InvalidMpk)?;

    // Compute identity for encryption
    let identity = auction_types::compute_auction_identity(auction_id, decryption_round);

    // Prepare plaintext: bid_value (8 bytes) || randomness (32 bytes)
    let mut plaintext = Vec::with_capacity(40);
    plaintext.extend_from_slice(&bid_value.to_le_bytes());
    plaintext.extend_from_slice(&randomness.0);

    // Encrypt
    let ciphertext = encrypt(&ibe_params, &identity, &plaintext, rng)
        .map_err(|e| BidError::EncryptionFailed(e.to_string()))?;

    Ok(PreparedBid {
        commitment,
        ciphertext,
        randomness,
        bid_value,
    })
}

/// Builder for creating bids with additional options.
pub struct BidBuilder {
    mpk: G2Point,
    auction_id: u64,
    decryption_round: u64,
    bid_value: u64,
}

impl BidBuilder {
    /// Create a new bid builder.
    pub fn new(mpk: G2Point, auction_id: u64, decryption_round: u64) -> Self {
        Self {
            mpk,
            auction_id,
            decryption_round,
            bid_value: 0,
        }
    }

    /// Set the bid value.
    pub fn bid_value(mut self, value: u64) -> Self {
        self.bid_value = value;
        self
    }

    /// Build the prepared bid.
    pub fn build<R: RngCore + CryptoRng>(self, rng: &mut R) -> Result<PreparedBid, BidError> {
        create_bid(
            &self.mpk,
            self.auction_id,
            self.decryption_round,
            self.bid_value,
            rng,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls12_381::{G2Projective, Scalar as BlsScalar};
    use group::Curve;
    use rand::rngs::OsRng;

    fn generate_test_mpk() -> G2Point {
        let mut rng = OsRng;
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        let secret = BlsScalar::from_bytes_wide(&bytes);
        let mpk = (G2Projective::generator() * secret).to_affine();
        G2Point(mpk.to_compressed())
    }

    #[test]
    fn test_create_bid() {
        let mut rng = OsRng;
        let mpk = generate_test_mpk();

        let bid = create_bid(&mpk, 1, 100, 1000, &mut rng);
        assert!(bid.is_ok());

        let prepared = bid.unwrap();
        assert_eq!(prepared.bid_value, 1000);
        assert!(!prepared.ciphertext.ciphertext.is_empty());
    }

    #[test]
    fn test_bid_builder() {
        let mut rng = OsRng;
        let mpk = generate_test_mpk();

        let bid = BidBuilder::new(mpk, 1, 100)
            .bid_value(500)
            .build(&mut rng);

        assert!(bid.is_ok());
        assert_eq!(bid.unwrap().bid_value, 500);
    }
}
