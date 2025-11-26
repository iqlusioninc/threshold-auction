//! Threshold Decryption Coordinator
//!
//! This module coordinates the decryption of threshold-encrypted bids by:
//! 1. Collecting partial decryption shares from validators
//! 2. Verifying DLEQ proofs on each share
//! 3. Aggregating shares once threshold is met
//! 4. Producing the final decryption key

use anyhow::{anyhow, Result};
use auction_crypto::threshold::{aggregate_partial_signatures, verify_partial_signature};
use auction_types::{G1Point, PartialDecryptionShare, ThresholdCiphertext};
use bls12_381::{pairing, G1Affine, G2Affine, Gt};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Errors that can occur during decryption coordination.
#[derive(Error, Debug)]
pub enum CoordinatorError {
    #[error("Duplicate share from validator {0}")]
    DuplicateShare(u32),

    #[error("Invalid DLEQ proof from validator {0}")]
    InvalidProof(u32),

    #[error("Threshold not met: have {have}, need {need}")]
    ThresholdNotMet { have: usize, need: usize },

    #[error("Invalid validator index {0}")]
    InvalidValidator(u32),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid point encoding")]
    InvalidPoint,
}

/// State of a decryption request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptionState {
    /// Collecting partial shares
    Collecting,
    /// Threshold met, ready to aggregate
    Ready,
    /// Decryption completed
    Completed,
    /// Decryption failed
    Failed(String),
}

/// A single decryption request being coordinated.
#[derive(Debug, Clone)]
pub struct DecryptionRequest {
    /// Unique identifier for this decryption request
    pub request_id: [u8; 32],
    /// The ciphertext being decrypted
    pub ciphertext: ThresholdCiphertext,
    /// Identity used for IBE (e.g., "auction-{id}-round-{round}")
    pub identity: Vec<u8>,
    /// Auction ID this decryption is for
    pub auction_id: u64,
    /// Bid index within the auction
    pub bid_index: u32,
    /// Collected partial decryption shares (validator_index -> share)
    pub shares: HashMap<u32, PartialDecryptionShare>,
    /// Current state
    pub state: DecryptionState,
    /// Threshold required for decryption
    pub threshold: usize,
    /// Total number of validators
    pub total_validators: usize,
}

impl DecryptionRequest {
    /// Create a new decryption request.
    pub fn new(
        auction_id: u64,
        bid_index: u32,
        ciphertext: ThresholdCiphertext,
        identity: Vec<u8>,
        threshold: usize,
        total_validators: usize,
    ) -> Self {
        // Generate request ID from auction_id, bid_index, and ciphertext
        let mut hasher = Sha256::new();
        hasher.update(auction_id.to_le_bytes());
        hasher.update(bid_index.to_le_bytes());
        hasher.update(&ciphertext.ephemeral_pubkey.0);
        let request_id: [u8; 32] = hasher.finalize().into();

        Self {
            request_id,
            ciphertext,
            identity,
            auction_id,
            bid_index,
            shares: HashMap::new(),
            state: DecryptionState::Collecting,
            threshold,
            total_validators,
        }
    }

    /// Check if threshold is met.
    pub fn threshold_met(&self) -> bool {
        self.shares.len() >= self.threshold
    }
}

/// Coordinator for managing threshold decryption of auction bids.
#[derive(Debug)]
pub struct DecryptionCoordinator {
    /// Active decryption requests
    requests: HashMap<[u8; 32], DecryptionRequest>,
    /// Public keys of validators (index -> pk)
    validator_public_keys: HashMap<u32, G1Point>,
    /// Default threshold
    threshold: usize,
    /// Total validators
    total_validators: usize,
}

impl DecryptionCoordinator {
    /// Create a new decryption coordinator.
    pub fn new(threshold: usize, total_validators: usize) -> Self {
        Self {
            requests: HashMap::new(),
            validator_public_keys: HashMap::new(),
            threshold,
            total_validators,
        }
    }

    /// Register a validator's public key.
    pub fn register_validator(&mut self, index: u32, public_key: G1Point) {
        info!(validator_index = index, "Registered validator public key");
        self.validator_public_keys.insert(index, public_key);
    }

    /// Start a new decryption request.
    pub fn start_decryption(
        &mut self,
        auction_id: u64,
        bid_index: u32,
        ciphertext: ThresholdCiphertext,
        identity: Vec<u8>,
    ) -> [u8; 32] {
        let request = DecryptionRequest::new(
            auction_id,
            bid_index,
            ciphertext,
            identity,
            self.threshold,
            self.total_validators,
        );
        let request_id = request.request_id;

        info!(
            request_id = hex::encode(request_id),
            auction_id,
            bid_index,
            "Started decryption request"
        );

        self.requests.insert(request_id, request);
        request_id
    }

    /// Submit a partial decryption share.
    pub fn submit_share(
        &mut self,
        request_id: [u8; 32],
        share: PartialDecryptionShare,
    ) -> Result<DecryptionState, CoordinatorError> {
        let validator_index = share.validator_index;

        let request = self
            .requests
            .get_mut(&request_id)
            .ok_or(CoordinatorError::DecryptionFailed("Request not found".into()))?;

        // Check for duplicate
        if request.shares.contains_key(&validator_index) {
            return Err(CoordinatorError::DuplicateShare(validator_index));
        }

        // Get validator's public key
        let validator_pk = self
            .validator_public_keys
            .get(&validator_index)
            .ok_or(CoordinatorError::InvalidValidator(validator_index))?;

        // Verify the DLEQ proof
        let verification_result = verify_partial_signature(&share, &request.identity, validator_pk);

        if verification_result.is_err() {
            warn!(
                validator_index,
                request_id = hex::encode(request_id),
                "Invalid DLEQ proof"
            );
            return Err(CoordinatorError::InvalidProof(validator_index));
        }

        debug!(
            validator_index,
            request_id = hex::encode(request_id),
            shares_collected = request.shares.len() + 1,
            threshold = request.threshold,
            "Accepted partial share"
        );

        // Store the share
        request.shares.insert(validator_index, share);

        // Check if threshold is met
        if request.threshold_met() {
            request.state = DecryptionState::Ready;
            info!(
                request_id = hex::encode(request_id),
                "Threshold met, ready to aggregate"
            );
        }

        Ok(request.state.clone())
    }

    /// Aggregate shares and complete decryption.
    pub fn aggregate_and_decrypt(
        &mut self,
        request_id: [u8; 32],
    ) -> Result<Vec<u8>, CoordinatorError> {
        let request = self
            .requests
            .get_mut(&request_id)
            .ok_or(CoordinatorError::DecryptionFailed("Request not found".into()))?;

        if !request.threshold_met() {
            return Err(CoordinatorError::ThresholdNotMet {
                have: request.shares.len(),
                need: request.threshold,
            });
        }

        // Collect shares for aggregation
        let shares: Vec<(u32, G1Point)> = request
            .shares
            .iter()
            .take(request.threshold)
            .map(|(idx, pd)| (*idx, pd.partial_sig.clone()))
            .collect();

        // Aggregate partial signatures using Lagrange interpolation
        let aggregated_point = aggregate_partial_signatures(&shares, request.threshold)
            .map_err(|e| CoordinatorError::DecryptionFailed(e.to_string()))?;

        // Decrypt: compute pairing and derive key
        let decrypted = decrypt_with_key(&request.ciphertext, &aggregated_point)
            .map_err(|e| CoordinatorError::DecryptionFailed(e.to_string()))?;

        request.state = DecryptionState::Completed;

        info!(
            request_id = hex::encode(request_id),
            decrypted_len = decrypted.len(),
            "Decryption completed"
        );

        Ok(decrypted)
    }

    /// Get the state of a decryption request.
    pub fn get_state(&self, request_id: &[u8; 32]) -> Option<DecryptionState> {
        self.requests.get(request_id).map(|r| r.state.clone())
    }

    /// Get all pending request IDs.
    pub fn pending_requests(&self) -> Vec<[u8; 32]> {
        self.requests
            .iter()
            .filter(|(_, r)| matches!(r.state, DecryptionState::Collecting | DecryptionState::Ready))
            .map(|(id, _)| *id)
            .collect()
    }

    /// Remove a completed request.
    pub fn remove_request(&mut self, request_id: &[u8; 32]) -> Option<DecryptionRequest> {
        self.requests.remove(request_id)
    }
}

/// Decrypt ciphertext using the aggregated decryption key.
fn decrypt_with_key(ciphertext: &ThresholdCiphertext, decryption_key: &G1Point) -> Result<Vec<u8>> {
    // Parse the decryption key point
    let dk_bytes: [u8; 48] = decryption_key.0;
    let dk_affine = G1Affine::from_compressed(&dk_bytes)
        .into_option()
        .ok_or_else(|| anyhow!("Invalid decryption key point"))?;

    // Parse the ephemeral public key
    let epk_bytes: [u8; 96] = ciphertext.ephemeral_pubkey.0;
    let epk_affine = G2Affine::from_compressed(&epk_bytes)
        .into_option()
        .ok_or_else(|| anyhow!("Invalid ephemeral public key"))?;

    // Compute pairing: e(dk, epk)
    let pairing_result: Gt = pairing(&dk_affine, &epk_affine);

    // Hash the pairing result to get symmetric key
    let gt_bytes = format!("{:?}", pairing_result);
    let mut hasher = Sha256::new();
    hasher.update(gt_bytes.as_bytes());
    let key_hash: [u8; 32] = hasher.finalize().into();

    // For now, use simple XOR decryption (in production, use AES-GCM with the key)
    // This matches the IBE encryption scheme
    let ct = &ciphertext.ciphertext;
    let mut plaintext = vec![0u8; ct.len()];
    for (i, byte) in ct.iter().enumerate() {
        plaintext[i] = byte ^ key_hash[i % 32];
    }

    Ok(plaintext)
}

/// Batch decryption coordinator for processing multiple bids efficiently.
#[derive(Debug)]
pub struct BatchDecryptionCoordinator {
    coordinator: DecryptionCoordinator,
    /// Batch of request IDs being processed together
    batch: Vec<[u8; 32]>,
}

impl BatchDecryptionCoordinator {
    /// Create a new batch coordinator.
    pub fn new(threshold: usize, total_validators: usize) -> Self {
        Self {
            coordinator: DecryptionCoordinator::new(threshold, total_validators),
            batch: Vec::new(),
        }
    }

    /// Register validator public key.
    pub fn register_validator(&mut self, index: u32, public_key: G1Point) {
        self.coordinator.register_validator(index, public_key);
    }

    /// Add multiple ciphertexts to batch.
    pub fn add_to_batch(
        &mut self,
        auction_id: u64,
        ciphertexts: Vec<(ThresholdCiphertext, Vec<u8>)>,
    ) -> Vec<[u8; 32]> {
        let mut request_ids = Vec::new();
        for (i, (ct, identity)) in ciphertexts.into_iter().enumerate() {
            let id = self.coordinator.start_decryption(auction_id, i as u32, ct, identity);
            self.batch.push(id);
            request_ids.push(id);
        }
        request_ids
    }

    /// Submit shares for all requests in batch from a single validator.
    pub fn submit_batch_shares(
        &mut self,
        shares: Vec<([u8; 32], PartialDecryptionShare)>,
    ) -> Vec<Result<DecryptionState, CoordinatorError>> {
        shares
            .into_iter()
            .map(|(request_id, share)| self.coordinator.submit_share(request_id, share))
            .collect()
    }

    /// Aggregate all ready requests and return decrypted values.
    pub fn aggregate_batch(&mut self) -> Vec<([u8; 32], Result<Vec<u8>, CoordinatorError>)> {
        let ready_requests: Vec<[u8; 32]> = self
            .batch
            .iter()
            .filter(|id| {
                matches!(
                    self.coordinator.get_state(id),
                    Some(DecryptionState::Ready)
                )
            })
            .copied()
            .collect();

        ready_requests
            .into_iter()
            .map(|id| (id, self.coordinator.aggregate_and_decrypt(id)))
            .collect()
    }

    /// Check if all batch items are completed.
    pub fn is_batch_complete(&self) -> bool {
        self.batch.iter().all(|id| {
            matches!(
                self.coordinator.get_state(id),
                Some(DecryptionState::Completed)
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auction_types::G2Point;
    use bls12_381::{G1Projective, G2Projective, Scalar};
    use ff::Field;
    use group::Curve;
    use rand::rngs::OsRng;

    fn generate_test_keypair() -> (Scalar, G1Point) {
        let sk = Scalar::random(&mut OsRng);
        let pk = (G1Projective::generator() * sk).to_affine();
        let pk_bytes = pk.to_compressed();
        (sk, G1Point(pk_bytes))
    }

    #[test]
    fn test_coordinator_creation() {
        let coordinator = DecryptionCoordinator::new(3, 5);
        assert_eq!(coordinator.threshold, 3);
        assert_eq!(coordinator.total_validators, 5);
        assert!(coordinator.pending_requests().is_empty());
    }

    #[test]
    fn test_start_decryption_request() {
        let mut coordinator = DecryptionCoordinator::new(2, 3);

        // Create a valid ephemeral pubkey
        let epk = G2Projective::generator().to_affine();

        let ciphertext = ThresholdCiphertext {
            ephemeral_pubkey: G2Point(epk.to_compressed()),
            ciphertext: vec![0u8; 32],
            tag: [0u8; 16],
            nonce: [0u8; 12],
        };

        let identity = b"auction-1-round-5".to_vec();
        let request_id = coordinator.start_decryption(1, 0, ciphertext, identity);

        assert_eq!(coordinator.pending_requests().len(), 1);
        assert_eq!(
            coordinator.get_state(&request_id),
            Some(DecryptionState::Collecting)
        );
    }

    #[test]
    fn test_threshold_not_met_error() {
        let mut coordinator = DecryptionCoordinator::new(3, 5);

        let epk = G2Projective::generator().to_affine();

        let ciphertext = ThresholdCiphertext {
            ephemeral_pubkey: G2Point(epk.to_compressed()),
            ciphertext: vec![0u8; 32],
            tag: [0u8; 16],
            nonce: [0u8; 12],
        };

        let identity = b"test".to_vec();
        let request_id = coordinator.start_decryption(1, 0, ciphertext, identity);

        let result = coordinator.aggregate_and_decrypt(request_id);
        assert!(matches!(
            result,
            Err(CoordinatorError::ThresholdNotMet { have: 0, need: 3 })
        ));
    }

    #[test]
    fn test_batch_coordinator() {
        let mut batch = BatchDecryptionCoordinator::new(2, 3);

        let epk = G2Projective::generator().to_affine();

        let ciphertexts = vec![
            (
                ThresholdCiphertext {
                    ephemeral_pubkey: G2Point(epk.to_compressed()),
                    ciphertext: vec![0u8; 32],
                    tag: [0u8; 16],
                    nonce: [0u8; 12],
                },
                b"bid-0".to_vec(),
            ),
            (
                ThresholdCiphertext {
                    ephemeral_pubkey: G2Point(epk.to_compressed()),
                    ciphertext: vec![1u8; 32],
                    tag: [0u8; 16],
                    nonce: [0u8; 12],
                },
                b"bid-1".to_vec(),
            ),
        ];

        let request_ids = batch.add_to_batch(1, ciphertexts);
        assert_eq!(request_ids.len(), 2);
        assert!(!batch.is_batch_complete());
    }

    #[test]
    fn test_validator_registration() {
        let mut coordinator = DecryptionCoordinator::new(2, 3);

        let (_, pk1) = generate_test_keypair();
        let (_, pk2) = generate_test_keypair();
        let (_, pk3) = generate_test_keypair();

        coordinator.register_validator(0, pk1);
        coordinator.register_validator(1, pk2);
        coordinator.register_validator(2, pk3);

        assert_eq!(coordinator.validator_public_keys.len(), 3);
    }

    #[test]
    fn test_invalid_validator_error() {
        let mut coordinator = DecryptionCoordinator::new(2, 3);

        // Don't register any validators

        let epk = G2Projective::generator().to_affine();

        let ciphertext = ThresholdCiphertext {
            ephemeral_pubkey: G2Point(epk.to_compressed()),
            ciphertext: vec![0u8; 32],
            tag: [0u8; 16],
            nonce: [0u8; 12],
        };

        let identity = b"test".to_vec();
        let request_id = coordinator.start_decryption(1, 0, ciphertext, identity);

        let share = PartialDecryptionShare {
            validator_index: 99, // Invalid index
            partial_sig: G1Point([0u8; 48]),
            proof: auction_types::DiscreteLogProof {
                challenge: auction_types::Scalar([0u8; 32]),
                response: auction_types::Scalar([0u8; 32]),
            },
        };

        let result = coordinator.submit_share(request_id, share);
        assert!(matches!(result, Err(CoordinatorError::InvalidValidator(99))));
    }
}
