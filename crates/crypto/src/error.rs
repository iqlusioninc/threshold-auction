//! Error types for cryptographic operations.

use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid G1 point encoding")]
    InvalidG1Point,

    #[error("Invalid G2 point encoding")]
    InvalidG2Point,

    #[error("Invalid scalar encoding")]
    InvalidScalar,

    #[error("Point not on curve")]
    PointNotOnCurve,

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Invalid ciphertext format")]
    InvalidCiphertextFormat,

    #[error("Invalid commitment")]
    InvalidCommitment,

    #[error("DLEQ proof verification failed")]
    DleqVerificationFailed,

    #[error("Insufficient threshold shares: need {required}, got {got}")]
    InsufficientShares { required: usize, got: usize },

    #[error("Invalid share index")]
    InvalidShareIndex,

    #[error("Duplicate share index")]
    DuplicateShareIndex,

    #[error("Lagrange interpolation failed")]
    LagrangeInterpolationFailed,

    #[error("Key derivation failed")]
    KeyDerivationFailed,

    #[error("Serialization error: {0}")]
    SerializationError(String),
}
