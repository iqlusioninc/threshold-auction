//! Genesis configuration for the auction module.
//!
//! This module defines the initial state and configuration for the auction
//! system when the chain starts.

use auction_types::{G1Point, MasterPublicKey};
use serde::{Deserialize, Serialize};

/// Genesis configuration for the auction module.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuctionGenesisConfig {
    /// Optional master public key (can be set via DKG after genesis)
    pub master_public_key: Option<MasterPublicKey>,

    /// Initial validator public keys for threshold decryption
    pub validator_pubkeys: Vec<ValidatorKeyConfig>,

    /// SP1 verification key (can be updated later via governance)
    pub sp1_vkey: Option<Vec<u8>>,

    /// Default auction parameters
    pub default_params: DefaultAuctionParams,

    /// Threshold for decryption (t-of-n)
    pub threshold: ThresholdConfig,
}

/// Configuration for a single validator's key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorKeyConfig {
    /// Validator index (1-based for Shamir)
    pub index: u32,
    /// Validator's public key for verifying partial signatures
    pub public_key: G1Point,
}

/// Threshold configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Minimum number of shares required (threshold)
    pub t: u32,
    /// Total number of validators
    pub n: u32,
}

/// Default parameters for new auctions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DefaultAuctionParams {
    /// Default minimum bid amount
    pub min_bid: u64,
    /// Minimum duration from start to end (seconds)
    pub min_duration: u64,
    /// Minimum time from end to decryption round
    pub min_decryption_delay: u64,
    /// Minimum time from decryption to settlement deadline
    pub min_settlement_window: u64,
}

impl Default for DefaultAuctionParams {
    fn default() -> Self {
        Self {
            min_bid: 1,
            min_duration: 3600,         // 1 hour
            min_decryption_delay: 600,  // 10 minutes
            min_settlement_window: 3600, // 1 hour
        }
    }
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self { t: 2, n: 3 }
    }
}

impl Default for AuctionGenesisConfig {
    fn default() -> Self {
        Self {
            master_public_key: None,
            validator_pubkeys: Vec::new(),
            sp1_vkey: None,
            default_params: DefaultAuctionParams::default(),
            threshold: ThresholdConfig::default(),
        }
    }
}

impl AuctionGenesisConfig {
    /// Create a new genesis config with a preset master public key.
    pub fn with_master_key(mpk: MasterPublicKey, validators: Vec<ValidatorKeyConfig>) -> Self {
        Self {
            master_public_key: Some(mpk),
            validator_pubkeys: validators,
            ..Default::default()
        }
    }

    /// Validate the genesis configuration.
    pub fn validate(&self) -> Result<(), GenesisValidationError> {
        // Check threshold makes sense
        if self.threshold.t == 0 {
            return Err(GenesisValidationError::InvalidThreshold(
                "Threshold cannot be zero".into(),
            ));
        }
        if self.threshold.t > self.threshold.n {
            return Err(GenesisValidationError::InvalidThreshold(
                "Threshold cannot exceed total validators".into(),
            ));
        }

        // Check validator count matches
        if !self.validator_pubkeys.is_empty()
            && self.validator_pubkeys.len() as u32 != self.threshold.n
        {
            return Err(GenesisValidationError::ValidatorCountMismatch {
                expected: self.threshold.n,
                got: self.validator_pubkeys.len() as u32,
            });
        }

        // Validate default params
        if self.default_params.min_duration == 0 {
            return Err(GenesisValidationError::InvalidDefaultParams(
                "Minimum duration cannot be zero".into(),
            ));
        }

        Ok(())
    }
}

/// Errors that can occur during genesis validation.
#[derive(Debug, Clone, thiserror::Error)]
pub enum GenesisValidationError {
    #[error("Invalid threshold configuration: {0}")]
    InvalidThreshold(String),

    #[error("Validator count mismatch: expected {expected}, got {got}")]
    ValidatorCountMismatch { expected: u32, got: u32 },

    #[error("Invalid default parameters: {0}")]
    InvalidDefaultParams(String),

    #[error("Invalid master public key")]
    InvalidMasterKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AuctionGenesisConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_threshold_zero() {
        let mut config = AuctionGenesisConfig::default();
        config.threshold.t = 0;
        assert!(matches!(
            config.validate(),
            Err(GenesisValidationError::InvalidThreshold(_))
        ));
    }

    #[test]
    fn test_invalid_threshold_exceeds_n() {
        let mut config = AuctionGenesisConfig::default();
        config.threshold.t = 5;
        config.threshold.n = 3;
        assert!(matches!(
            config.validate(),
            Err(GenesisValidationError::InvalidThreshold(_))
        ));
    }

    #[test]
    fn test_validator_count_mismatch() {
        let mut config = AuctionGenesisConfig::default();
        config.threshold.n = 5;
        config.validator_pubkeys = vec![ValidatorKeyConfig {
            index: 1,
            public_key: G1Point([0u8; 48]),
        }];
        assert!(matches!(
            config.validate(),
            Err(GenesisValidationError::ValidatorCountMismatch { .. })
        ));
    }
}
