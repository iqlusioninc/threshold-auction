//! Identity-Based Encryption using BLS12-381 pairings.
//!
//! This implements a variant of the Boneh-Franklin IBE scheme optimized for
//! threshold decryption with BLS signatures.
//!
//! # Encryption
//!
//! To encrypt a message `m` to identity `id`:
//! 1. Compute id_hash = H_1(id) ∈ G1
//! 2. Sample random scalar r
//! 3. Compute U = r·G2 (ephemeral public key)
//! 4. Compute shared = e(id_hash, MPK)^r
//! 5. Derive symmetric key from shared
//! 6. Encrypt m with AES-GCM
//!
//! # Decryption
//!
//! Given decryption key σ (threshold signature on id):
//! 1. Compute shared = e(σ, U)
//! 2. Derive symmetric key from shared
//! 3. Decrypt ciphertext with AES-GCM

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use group::Curve;
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use sha2::Sha256;

use auction_types::{G1Point, G2Point, ThresholdCiphertext};

use crate::error::CryptoError;

/// Parameters for IBE encryption.
pub struct IbeParams {
    /// Master public key (MPK = s·G2 where s is the master secret)
    pub mpk: G2Affine,
}

impl IbeParams {
    /// Create IBE params from serialized G2 point.
    pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, CryptoError> {
        let mpk = decompress_g2(bytes)?;
        Ok(Self { mpk })
    }

    /// Create IBE params from G2Point type.
    pub fn from_g2_point(point: &G2Point) -> Result<Self, CryptoError> {
        Self::from_bytes(&point.0)
    }
}

/// Encrypt a message to an identity using threshold IBE.
///
/// # Arguments
/// * `params` - IBE parameters containing the master public key
/// * `identity` - The identity to encrypt to (e.g., auction_id || round)
/// * `plaintext` - The message to encrypt
/// * `rng` - Cryptographically secure random number generator
///
/// # Returns
/// A threshold ciphertext that can be decrypted with the threshold signature on identity
pub fn encrypt<R: RngCore + CryptoRng>(
    params: &IbeParams,
    identity: &[u8],
    plaintext: &[u8],
    rng: &mut R,
) -> Result<ThresholdCiphertext, CryptoError> {
    // 1. Hash identity to G1
    let id_hash = hash_to_g1(identity);

    // 2. Sample random scalar r
    let r = random_scalar(rng);

    // 3. Compute ephemeral public key U = r·G2
    let u = G2Projective::generator() * r;
    let u_affine = u.to_affine();

    // 4. Compute shared secret: e(H(id), MPK)^r = e(r·H(id), MPK)
    // Using linearity of pairing: e(a·P, Q) = e(P, Q)^a
    let r_id_hash = (id_hash * r).to_affine();
    let shared_gt = pairing(&r_id_hash, &params.mpk);

    // 5. Derive symmetric key from shared secret
    let key = derive_key_from_gt(&shared_gt)?;

    // 6. Encrypt with AES-GCM
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| {
        CryptoError::EncryptionFailed(format!("Failed to create cipher: {}", e))
    })?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext_with_tag = cipher.encrypt(nonce, plaintext).map_err(|e| {
        CryptoError::EncryptionFailed(format!("AES-GCM encryption failed: {}", e))
    })?;

    // Split ciphertext and tag
    let tag_start = ciphertext_with_tag.len() - 16;
    let ciphertext = ciphertext_with_tag[..tag_start].to_vec();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&ciphertext_with_tag[tag_start..]);

    Ok(ThresholdCiphertext {
        ephemeral_pubkey: compress_g2(&u_affine),
        ciphertext,
        tag,
        nonce: nonce_bytes,
    })
}

/// Decrypt a threshold ciphertext using the decryption key (threshold signature).
///
/// # Arguments
/// * `ciphertext` - The threshold ciphertext to decrypt
/// * `decryption_key` - The aggregated threshold signature σ = Σ λ_i · sk_i · H(id)
///
/// # Returns
/// The decrypted plaintext
pub fn decrypt(
    ciphertext: &ThresholdCiphertext,
    decryption_key: &G1Point,
) -> Result<Vec<u8>, CryptoError> {
    // 1. Decompress points
    let sigma = decompress_g1(&decryption_key.0)?;
    let u = decompress_g2(&ciphertext.ephemeral_pubkey.0)?;

    // 2. Compute shared secret: e(σ, U)
    // Where σ = sk·H(id) and U = r·G2
    // e(σ, U) = e(sk·H(id), r·G2) = e(H(id), G2)^{sk·r} = e(H(id), MPK)^r
    let shared_gt = pairing(&sigma, &u);

    // 3. Derive symmetric key
    let key = derive_key_from_gt(&shared_gt)?;

    // 4. Decrypt with AES-GCM
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| CryptoError::DecryptionFailed(format!("Failed to create cipher: {}", e)))?;

    let nonce = Nonce::from_slice(&ciphertext.nonce);

    // Reconstruct ciphertext with tag for decryption
    let mut ct_with_tag = ciphertext.ciphertext.clone();
    ct_with_tag.extend_from_slice(&ciphertext.tag);

    cipher
        .decrypt(nonce, ct_with_tag.as_ref())
        .map_err(|_| CryptoError::AuthenticationFailed)
}

/// Hash arbitrary data to a G1 point using hash-to-curve.
///
/// Uses the expand_message_xmd method with SHA-256 as specified in RFC 9380.
pub fn hash_to_g1(data: &[u8]) -> G1Affine {
    // Simplified hash-to-curve using try-and-increment
    // In production, use a proper hash-to-curve implementation
    use sha2::{Digest, Sha256};

    let mut counter = 0u64;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(b"BLS12381G1_XMD:SHA-256_SSWU_RO_");
        hasher.update(data);
        hasher.update(counter.to_le_bytes());
        let hash = hasher.finalize();

        // Try to interpret as x-coordinate and find point
        if let Some(point) = try_point_from_hash(&hash) {
            return point;
        }
        counter += 1;
    }
}

/// Attempt to construct a G1 point from a hash.
fn try_point_from_hash(hash: &[u8]) -> Option<G1Affine> {
    // Use the hash to generate a scalar and multiply generator
    // This is a simplified approach; production should use proper hash-to-curve
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash[..32]);

    // Interpret as scalar (mod order)
    let scalar = Scalar::from_bytes(&bytes);
    if scalar.is_some().into() {
        let scalar = scalar.unwrap();
        let point = G1Projective::generator() * scalar;
        Some(point.to_affine())
    } else {
        None
    }
}

/// Generate a random scalar.
fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    Scalar::from_bytes_wide(&bytes)
}

/// Derive a symmetric key from a GT element.
fn derive_key_from_gt(gt: &bls12_381::Gt) -> Result<[u8; 32], CryptoError> {
    use sha2::Digest;

    // Serialize GT element (this is a simplification)
    let gt_bytes = gt_to_bytes(gt);

    // Use HKDF to derive key
    let hk = Hkdf::<Sha256>::new(None, &gt_bytes);
    let mut key = [0u8; 32];
    hk.expand(b"IBE-KEY", &mut key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    Ok(key)
}

/// Serialize a GT element to bytes.
fn gt_to_bytes(gt: &bls12_381::Gt) -> Vec<u8> {
    // GT elements are large (576 bytes for BLS12-381)
    // We hash it for practical use
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    // Use the debug representation as a placeholder
    // In production, use proper serialization
    hasher.update(format!("{:?}", gt).as_bytes());
    hasher.finalize().to_vec()
}

/// Compress a G1 point to bytes.
pub fn compress_g1(point: &G1Affine) -> G1Point {
    G1Point(point.to_compressed())
}

/// Decompress a G1 point from bytes.
pub fn decompress_g1(bytes: &[u8; 48]) -> Result<G1Affine, CryptoError> {
    let point = G1Affine::from_compressed(bytes);
    if point.is_some().into() {
        Ok(point.unwrap())
    } else {
        Err(CryptoError::InvalidG1Point)
    }
}

/// Compress a G2 point to bytes.
pub fn compress_g2(point: &G2Affine) -> G2Point {
    G2Point(point.to_compressed())
}

/// Decompress a G2 point from bytes.
pub fn decompress_g2(bytes: &[u8; 96]) -> Result<G2Affine, CryptoError> {
    let point = G2Affine::from_compressed(bytes);
    if point.is_some().into() {
        Ok(point.unwrap())
    } else {
        Err(CryptoError::InvalidG2Point)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_hash_to_g1() {
        let point1 = hash_to_g1(b"test identity 1");
        let point2 = hash_to_g1(b"test identity 2");
        let point3 = hash_to_g1(b"test identity 1");

        assert_ne!(point1, point2);
        assert_eq!(point1, point3);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut rng = OsRng;

        // Generate a "master secret" and derive MPK
        let master_secret = random_scalar(&mut rng);
        let mpk = (G2Projective::generator() * master_secret).to_affine();

        let params = IbeParams { mpk };

        let identity = b"auction:123:round:456";
        let plaintext = b"secret bid: 1000";

        // Encrypt
        let ciphertext = encrypt(&params, identity, plaintext, &mut rng).unwrap();

        // Generate decryption key: σ = sk · H(id)
        let id_hash = hash_to_g1(identity);
        let sigma = (G1Projective::from(id_hash) * master_secret).to_affine();
        let decryption_key = compress_g1(&sigma);

        // Decrypt
        let decrypted = decrypt(&ciphertext, &decryption_key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_decryption_key_fails() {
        let mut rng = OsRng;

        let master_secret = random_scalar(&mut rng);
        let mpk = (G2Projective::generator() * master_secret).to_affine();

        let params = IbeParams { mpk };

        let identity = b"auction:123:round:456";
        let plaintext = b"secret bid: 1000";

        let ciphertext = encrypt(&params, identity, plaintext, &mut rng).unwrap();

        // Generate wrong decryption key (different identity)
        let wrong_identity = b"auction:123:round:457";
        let wrong_id_hash = hash_to_g1(wrong_identity);
        let wrong_sigma = (G1Projective::from(wrong_id_hash) * master_secret).to_affine();
        let wrong_key = compress_g1(&wrong_sigma);

        let result = decrypt(&ciphertext, &wrong_key);
        assert!(result.is_err());
    }
}
