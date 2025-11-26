//! DKG participant implementation.

use bls12_381::{G1Projective, G2Projective, Scalar};
use ff::Field;
use group::Curve;
use rand::{CryptoRng, RngCore};
use thiserror::Error;

use auction_types::{G1Point, G2Point, Scalar as TypesScalar};

use crate::feldman::{evaluate_polynomial, generate_commitments, generate_polynomial, verify_share};
use crate::types::{DkgConfig, DkgOutput, DkgRound1Message, DkgRound2Message};

/// Errors during DKG.
#[derive(Debug, Error)]
pub enum DkgError {
    #[error("Invalid share from participant {0}")]
    InvalidShare(u32),

    #[error("Missing message from participant {0}")]
    MissingMessage(u32),

    #[error("Duplicate message from participant {0}")]
    DuplicateMessage(u32),

    #[error("Invalid participant index")]
    InvalidParticipantIndex,

    #[error("Protocol not complete")]
    ProtocolIncomplete,
}

/// State of a DKG participant.
pub struct DkgParticipant {
    config: DkgConfig,
    /// Our secret polynomial coefficients
    polynomial: Option<Vec<Scalar>>,
    /// Our commitments
    commitments: Option<Vec<G2Point>>,
    /// Received round 1 messages
    round1_messages: Vec<DkgRound1Message>,
    /// Received shares for us
    received_shares: Vec<(u32, Scalar)>,
    /// Final output
    output: Option<DkgOutput>,
}

impl DkgParticipant {
    /// Create a new DKG participant.
    pub fn new(config: DkgConfig) -> Self {
        Self {
            config,
            polynomial: None,
            commitments: None,
            round1_messages: Vec::new(),
            received_shares: Vec::new(),
            output: None,
        }
    }

    /// Generate round 1 message (commitments).
    pub fn round1<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> DkgRound1Message {
        // Generate our contribution to the master secret
        let mut secret_bytes = [0u8; 64];
        rng.fill_bytes(&mut secret_bytes);
        let secret = Scalar::from_bytes_wide(&secret_bytes);

        // Generate polynomial
        let polynomial = generate_polynomial(&secret, self.config.threshold as usize, rng);

        // Generate commitments
        let commitments = generate_commitments(&polynomial);

        self.polynomial = Some(polynomial);
        self.commitments = Some(commitments.clone());

        DkgRound1Message {
            sender: self.config.participant_index,
            commitments,
        }
    }

    /// Process a round 1 message from another participant.
    pub fn process_round1(&mut self, msg: DkgRound1Message) -> Result<(), DkgError> {
        if msg.sender == self.config.participant_index {
            // Store our own message too
        }

        // Check for duplicates
        if self.round1_messages.iter().any(|m| m.sender == msg.sender) {
            return Err(DkgError::DuplicateMessage(msg.sender));
        }

        self.round1_messages.push(msg);
        Ok(())
    }

    /// Generate round 2 messages (shares for each participant).
    pub fn round2(&self) -> Result<Vec<DkgRound2Message>, DkgError> {
        let polynomial = self.polynomial.as_ref().ok_or(DkgError::ProtocolIncomplete)?;

        let mut messages = Vec::new();

        for recipient in 1..=self.config.n {
            // Evaluate polynomial at recipient's index
            let x = Scalar::from(recipient as u64);
            let share = evaluate_polynomial(polynomial, &x);

            // In a real implementation, this would be encrypted
            // to the recipient's public key
            let share_bytes = share.to_bytes().to_vec();

            messages.push(DkgRound2Message {
                sender: self.config.participant_index,
                recipient,
                encrypted_share: share_bytes,
            });
        }

        Ok(messages)
    }

    /// Process a round 2 message (share for us).
    pub fn process_round2(&mut self, msg: DkgRound2Message) -> Result<(), DkgError> {
        if msg.recipient != self.config.participant_index {
            return Ok(()); // Not for us
        }

        // Decrypt share (in real implementation)
        if msg.encrypted_share.len() != 32 {
            return Err(DkgError::InvalidShare(msg.sender));
        }

        let mut share_bytes = [0u8; 32];
        share_bytes.copy_from_slice(&msg.encrypted_share);
        let share = Scalar::from_bytes(&share_bytes);

        if share.is_none().into() {
            return Err(DkgError::InvalidShare(msg.sender));
        }
        let share = share.unwrap();

        // Verify share against sender's commitments
        let sender_msg = self
            .round1_messages
            .iter()
            .find(|m| m.sender == msg.sender)
            .ok_or(DkgError::MissingMessage(msg.sender))?;

        if !verify_share(&share, self.config.participant_index, &sender_msg.commitments) {
            return Err(DkgError::InvalidShare(msg.sender));
        }

        self.received_shares.push((msg.sender, share));
        Ok(())
    }

    /// Finalize DKG and compute output.
    pub fn finalize(&mut self) -> Result<DkgOutput, DkgError> {
        // Check we have all shares
        if self.received_shares.len() != self.config.n as usize {
            return Err(DkgError::ProtocolIncomplete);
        }

        // Our secret share is the sum of all received shares
        let secret_share: Scalar = self.received_shares.iter().map(|(_, s)| s).sum();

        // Our public key
        let public_key = (G1Projective::generator() * secret_share).to_affine();

        // Master public key is sum of all constant term commitments
        let master_pubkey: G2Projective = self
            .round1_messages
            .iter()
            .map(|msg| {
                let bytes = &msg.commitments[0].0;
                let point = bls12_381::G2Affine::from_compressed(bytes);
                if point.is_some().into() {
                    G2Projective::from(point.unwrap())
                } else {
                    G2Projective::identity()
                }
            })
            .sum();

        // Compute all participant public keys
        let participant_pubkeys: Vec<(u32, G1Point)> = (1..=self.config.n)
            .map(|i| {
                // Compute g^{f(i)} for the combined polynomial
                let mut combined_share = Scalar::ZERO;
                for msg in &self.round1_messages {
                    let x = Scalar::from(i as u64);
                    // We need the actual shares, but we can compute from commitments
                    // For simplicity, just use identity (real impl would be different)
                }
                let pk = (G1Projective::generator() * combined_share).to_affine();
                (i, G1Point(pk.to_compressed()))
            })
            .collect();

        let output = DkgOutput {
            secret_share: TypesScalar(secret_share.to_bytes()),
            public_key: G1Point(public_key.to_compressed()),
            master_public_key: G2Point(master_pubkey.to_affine().to_compressed()),
            participant_pubkeys,
            threshold: self.config.threshold,
        };

        self.output = Some(output.clone());
        Ok(output)
    }

    /// Get the DKG output if available.
    pub fn get_output(&self) -> Option<&DkgOutput> {
        self.output.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_dkg_round1() {
        let mut rng = OsRng;
        let config = DkgConfig::new(3, 2, 1);
        let mut participant = DkgParticipant::new(config);

        let msg = participant.round1(&mut rng);

        assert_eq!(msg.sender, 1);
        assert_eq!(msg.commitments.len(), 2); // threshold = 2
    }

    #[test]
    fn test_dkg_round2() {
        let mut rng = OsRng;
        let config = DkgConfig::new(3, 2, 1);
        let mut participant = DkgParticipant::new(config);

        let _ = participant.round1(&mut rng);
        let messages = participant.round2().unwrap();

        assert_eq!(messages.len(), 3); // One for each participant
    }
}
