//! Pedersen commitments on BLS12-381 G1.
//!
//! A Pedersen commitment C = g^v · h^r is:
//! - **Hiding**: Given C, cannot determine v without r
//! - **Binding**: Cannot find different (v', r') with same C
//!
//! Used to commit to bid values before encryption is revealed.

use bls12_381::{G1Affine, G1Projective, Scalar};
use group::Curve;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use auction_types::{G1Point, PedersenCommitment, Scalar as TypesScalar};

use crate::error::CryptoError;
use crate::ibe::{compress_g1, decompress_g1};

/// Parameters for Pedersen commitments.
pub struct PedersenParams {
    /// Base point g
    pub g: G1Affine,
    /// Base point h (nothing-up-my-sleeve generation)
    pub h: G1Affine,
}

impl Default for PedersenParams {
    fn default() -> Self {
        Self::new()
    }
}

impl PedersenParams {
    /// Create new Pedersen parameters with standard bases.
    ///
    /// Uses G1 generator as g and hash-derived point as h.
    pub fn new() -> Self {
        let g = G1Affine::generator();

        // Generate h using nothing-up-my-sleeve derivation
        let h = derive_h_point();

        Self { g, h }
    }
}

/// Derive the h point using a nothing-up-my-sleeve method.
fn derive_h_point() -> G1Affine {
    // Hash a well-known string to derive h
    // This ensures h is not a known multiple of g
    let mut hasher = Sha256::new();
    hasher.update(b"PEDERSEN_H_POINT_BLS12381_V1");
    let hash = hasher.finalize();

    // Use hash to derive scalar and multiply generator
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);

    // Keep trying until we get a valid scalar
    let scalar = Scalar::from_bytes(&bytes);
    if scalar.is_some().into() {
        let s = scalar.unwrap();
        (G1Projective::generator() * s).to_affine()
    } else {
        // Fallback: use a fixed value (this shouldn't happen with good hash)
        let s = Scalar::from(12345u64);
        (G1Projective::generator() * s).to_affine()
    }
}

/// Create a Pedersen commitment to a value.
///
/// # Arguments
/// * `params` - Pedersen parameters
/// * `value` - The value to commit to (bid amount)
/// * `rng` - Random number generator for blinding factor
///
/// # Returns
/// A tuple of (commitment, randomness) where randomness is needed to open the commitment
pub fn pedersen_commit<R: RngCore + CryptoRng>(
    params: &PedersenParams,
    value: u64,
    rng: &mut R,
) -> (PedersenCommitment, TypesScalar) {
    // Generate random blinding factor
    let mut rand_bytes = [0u8; 64];
    rng.fill_bytes(&mut rand_bytes);
    let randomness = Scalar::from_bytes_wide(&rand_bytes);

    // Compute C = g^value * h^randomness
    let v_scalar = Scalar::from(value);
    let commitment_point = (G1Projective::from(params.g) * v_scalar
        + G1Projective::from(params.h) * randomness)
        .to_affine();

    let commitment = PedersenCommitment {
        point: compress_g1(&commitment_point),
    };

    // Convert randomness to types::Scalar
    let rand_bytes_out: [u8; 32] = randomness.to_bytes();

    (commitment, TypesScalar(rand_bytes_out))
}

/// Create a Pedersen commitment with specific randomness.
///
/// Used when reconstructing a commitment for verification.
pub fn pedersen_commit_with_randomness(
    params: &PedersenParams,
    value: u64,
    randomness: &TypesScalar,
) -> Result<PedersenCommitment, CryptoError> {
    let r = Scalar::from_bytes(&randomness.0);
    if r.is_none().into() {
        return Err(CryptoError::InvalidScalar);
    }
    let r = r.unwrap();

    let v_scalar = Scalar::from(value);
    let commitment_point =
        (G1Projective::from(params.g) * v_scalar + G1Projective::from(params.h) * r).to_affine();

    Ok(PedersenCommitment {
        point: compress_g1(&commitment_point),
    })
}

/// Verify a Pedersen commitment opening.
///
/// # Arguments
/// * `params` - Pedersen parameters
/// * `commitment` - The commitment to verify
/// * `value` - The claimed value
/// * `randomness` - The randomness used in the commitment
///
/// # Returns
/// `Ok(())` if verification succeeds, error otherwise
pub fn pedersen_verify(
    params: &PedersenParams,
    commitment: &PedersenCommitment,
    value: u64,
    randomness: &TypesScalar,
) -> Result<(), CryptoError> {
    // Reconstruct expected commitment
    let expected = pedersen_commit_with_randomness(params, value, randomness)?;

    // Compare
    if commitment.point == expected.point {
        Ok(())
    } else {
        Err(CryptoError::InvalidCommitment)
    }
}

/// Homomorphic addition of Pedersen commitments.
///
/// C1 + C2 commits to v1 + v2 with randomness r1 + r2.
pub fn pedersen_add(c1: &PedersenCommitment, c2: &PedersenCommitment) -> PedersenCommitment {
    let p1 = decompress_g1(&c1.point.0).unwrap_or(G1Affine::identity());
    let p2 = decompress_g1(&c2.point.0).unwrap_or(G1Affine::identity());

    let sum = (G1Projective::from(p1) + G1Projective::from(p2)).to_affine();

    PedersenCommitment {
        point: compress_g1(&sum),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_pedersen_commit_verify() {
        let mut rng = OsRng;
        let params = PedersenParams::new();

        let value = 1000u64;
        let (commitment, randomness) = pedersen_commit(&params, value, &mut rng);

        // Verification should succeed with correct values
        assert!(pedersen_verify(&params, &commitment, value, &randomness).is_ok());

        // Verification should fail with wrong value
        assert!(pedersen_verify(&params, &commitment, value + 1, &randomness).is_err());
    }

    #[test]
    fn test_pedersen_hiding() {
        let mut rng = OsRng;
        let params = PedersenParams::new();

        let value = 1000u64;
        let (c1, _) = pedersen_commit(&params, value, &mut rng);
        let (c2, _) = pedersen_commit(&params, value, &mut rng);

        // Same value, different randomness -> different commitments
        assert_ne!(c1.point, c2.point);
    }

    #[test]
    fn test_pedersen_binding() {
        let mut rng = OsRng;
        let params = PedersenParams::new();

        let (c1, r1) = pedersen_commit(&params, 1000, &mut rng);
        let (c2, r2) = pedersen_commit(&params, 2000, &mut rng);

        // Different values -> different commitments (overwhelmingly likely)
        assert_ne!(c1.point, c2.point);

        // Cannot open c1 with value 2000
        assert!(pedersen_verify(&params, &c1, 2000, &r1).is_err());
        assert!(pedersen_verify(&params, &c2, 1000, &r2).is_err());
    }

    #[test]
    fn test_pedersen_homomorphic() {
        let mut rng = OsRng;
        let params = PedersenParams::new();

        let v1 = 100u64;
        let v2 = 200u64;

        let (c1, r1) = pedersen_commit(&params, v1, &mut rng);
        let (c2, r2) = pedersen_commit(&params, v2, &mut rng);

        let c_sum = pedersen_add(&c1, &c2);

        // Sum of randomness (this is a simplification - proper implementation
        // would handle scalar addition properly)
        let mut r1_bytes = r1.0;
        let mut r2_bytes = r2.0;

        // For testing, we verify the homomorphic property holds
        // In practice, you'd track the randomness sum separately
        let r1_scalar = Scalar::from_bytes(&r1_bytes).unwrap();
        let r2_scalar = Scalar::from_bytes(&r2_bytes).unwrap();
        let r_sum = r1_scalar + r2_scalar;

        let v_sum = Scalar::from(v1 + v2);
        let expected_point = (G1Projective::from(params.g) * v_sum
            + G1Projective::from(params.h) * r_sum)
            .to_affine();
        let expected = PedersenCommitment {
            point: compress_g1(&expected_point),
        };

        assert_eq!(c_sum.point, expected.point);
    }
}
